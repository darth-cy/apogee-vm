//! The `POSEIDON2` family's circuit: one width-3 Poseidon2 permutation a row,
//! invoked by the `ecall::PRECOMPILE_POSEIDON2` ecall and never decoded.
//!
//! `docs/spec/delegation.md` §12 is normative. The permutation is
//! `transcript::poseidon2_permute` — the same 4 + 56 + 4 rounds, the same
//! `x^5` S-box, the same two matrices and the *same* round constants, read
//! from `constants::POSEIDON2_RC3_*` with no second copy anywhere.
//!
//! ```text
//! frame     M[0..100]: cycle live base anchor_value, then 4 per word
//! words 8i..8i+8       lane i, canonical little-endian Fr, read and written
//! W[0..972]            the frame's own: 38 gap bits a word, then the base's bounds
//! W[972..4092]         per lane in then out, 256 word bits and 264 canonicity bits
//! ```
//!
//! # The rounds as layers
//!
//! A round is **three** gate lists, and the same three whether it is full or
//! partial:
//!
//! ```text
//! sub 0   q_i = (state_i + c_i)^2      and   t_i = state_i + c_i
//! sub 1   q2_i = q_i · q_i             and   t_i carried
//! sub 2   the linear layer over v_i = q2_i · t_i
//! ```
//!
//! `x^5 = x^4 · x` needs `x^4`, `x^4 = (x^2)^2` needs `x^2`, and each step is
//! one multiplication: two multiplication layers per S-box, which is the
//! degree ceiling's price and not a choice. The round constant and the linear
//! layer are degree 1 and fold into a neighbour — the constant into sub 0's
//! square, the matrix into sub 2's products — so a round costs three layers
//! and no more.
//!
//! **`x^2` is computed, not committed.** A committed helper would be readable
//! by gate list 0 alone (`docs/spec/gkr.md` §2), so the 80 of them would have
//! to be carried up through every layer that has not consumed them yet: 5,040
//! pass-through columns against 736 of actual work. Computing it costs one
//! more gate list a round and nothing else, and it is *stronger* — a layer
//! value is forced by its gate, where a committed one would need an enforcing
//! gate to be forced at all.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::poseidon2 as p2;
use constants::{address_space, memory as mem};
use field::Fr;

use crate::delegation as d;
use crate::lookup::ChannelSpec;
use crate::{
    CircuitArtifact, Coeff, GateDef, PolyAddress, Padding, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};

/// The frame's words: three lanes of eight.
const WORDS: usize = p2::FRAME_WORDS;

/// Gate lists a round takes.
const SUB: usize = 3;

/// The permutation's gate lists: three a round, all 64 rounds.
const ROUND_LAYERS: usize = SUB * p2::ROUNDS;

/// Leaves a side, padded to a power of two: the 24 frame words and the anchor.
const LEAVES: usize = 32;
/// Gate list 0's memory columns: both sides.
const TREE_TOP: usize = 2 * LEAVES;
/// Row-wise lists that reduce `TREE_TOP` columns to two: `64 >> 5 == 2`.
const TREE_DEPTH: usize = 5;

/// The columns carried to the top: `live` and the three written lane values,
/// which the last list compares with the permutation's output.
const CARRY: usize = 1 + p2::WIDTH;

/// `M` columns.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;
/// `W` columns: the frame's own, then six values' bits — three read, three
/// written.
pub const WITNESS_COLUMNS: usize =
    d::GAP_BITS * WORDS + d::BASE_LOW_BITS + d::BASE_ROOM_BITS
        + 2 * p2::WIDTH * (d::VALUE_BITS + d::CANONICITY_BITS);

const fn w(i: usize) -> PolyAddress {
    PolyAddress::Witness(i as u32)
}

// The frame's committed addresses, re-exported so a fill or a checker names a
// column rather than a number.

/// `M[0]`: the requesting cycle.
pub const CYCLE: PolyAddress = d::CYCLE;
/// `M[1]`: the row's one mask.
pub const LIVE: PolyAddress = d::LIVE;
/// `M[2]`: the frame base pointer.
pub const BASE: PolyAddress = d::BASE;
/// `M[3]`: the anchor teardown's value, free on both sides.
pub const ANCHOR_VALUE: PolyAddress = d::ANCHOR_VALUE;
/// A frame word's address field.
pub const WORD_ADDR: u32 = d::WORD_ADDR;
/// A frame word's read-timestamp field.
pub const WORD_READ_TS: u32 = d::WORD_READ_TS;
/// A frame word's read-value field.
pub const WORD_READ_VALUE: u32 = d::WORD_READ_VALUE;
/// A frame word's write-value field.
pub const WORD_WRITE_VALUE: u32 = d::WORD_WRITE_VALUE;

/// `M[4 + 4j + field]`: one field of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    d::word(j, field)
}

/// Bit `bit` of frame word `j`'s timestamp gap.
pub fn gap_bit(j: usize, bit: usize) -> PolyAddress {
    d::gap_bit(j, bit)
}

/// Bit `bit` of `(base − RAM_ORIGIN) / 4`.
pub fn base_low_bit(bit: usize) -> PolyAddress {
    d::base_low_bit(WORDS, bit)
}

/// Bit `bit` of `2^31 − frame bytes − base`.
pub fn base_room_bit(bit: usize) -> PolyAddress {
    d::base_room_bit(WORDS, bit)
}

/// Value `v`: `0..3` are the input lanes, `3..6` the output lanes.
fn value_bits(v: usize) -> usize {
    d::frame_witness(WORDS) + v * (d::VALUE_BITS + d::CANONICITY_BITS)
}

fn value_canon(v: usize) -> usize {
    value_bits(v) + d::VALUE_BITS
}

/// Bit `t` of word `k` of value `v`.
pub fn value_bit(v: usize, k: usize, t: usize) -> PolyAddress {
    w(value_bits(v) + 32 * k + t)
}

/// Bit `t` of limb `k` of value `v`'s canonicity difference, `X − p`.
pub fn diff_bit(v: usize, k: usize, t: usize) -> PolyAddress {
    w(value_canon(v) + 32 * k + t)
}

/// Borrow `k` of value `v`'s canonicity chain.
pub fn borrow_bit(v: usize, k: usize) -> PolyAddress {
    w(value_canon(v) + 32 * d::WORDS_PER_VALUE + k)
}

// ---------------------------------------------------------------------------
// The permutation's parameters, read from `constants`
// ---------------------------------------------------------------------------

/// Whether round `r` S-boxes every lane. The first four and the last four do;
/// the 56 between them S-box lane 0 alone.
fn is_full(r: usize) -> bool {
    r < p2::ROUNDS_FULL / 2 || r >= p2::ROUNDS - p2::ROUNDS_FULL / 2
}

/// Round `r`'s constant for lane `i`, from `constants::POSEIDON2_RC3_*`.
///
/// A partial round adds one constant, to lane 0; upstream stores zeros in the
/// other two and `constants` does not vendor them, so they are zero here.
fn rc(r: usize, i: usize) -> Fr {
    let hex = if r < p2::ROUNDS_FULL / 2 {
        constants::POSEIDON2_RC3_INITIAL[r][i]
    } else if r < p2::ROUNDS_FULL / 2 + p2::ROUNDS_PARTIAL {
        if i != 0 {
            return Fr::ZERO;
        }
        constants::POSEIDON2_RC3_INTERNAL[r - p2::ROUNDS_FULL / 2]
    } else {
        constants::POSEIDON2_RC3_TERMINAL[r - p2::ROUNDS_FULL / 2 - p2::ROUNDS_PARTIAL][i]
    };
    Fr::from_hex(hex).expect("a frozen round constant is a canonical hex literal")
}

// ---------------------------------------------------------------------------
// The layer geometry
// ---------------------------------------------------------------------------

/// Layer `k`'s memory-tree columns.
fn tree_width(k: usize) -> usize {
    if k == 0 {
        0
    } else if k <= TREE_DEPTH {
        TREE_TOP >> (k - 1)
    } else {
        2
    }
}

/// Layer `k`'s carried columns: `live` and the three written lane values,
/// which only the last list reads.
fn carry_width(k: usize) -> usize {
    if k >= 1 && k <= ROUND_LAYERS {
        CARRY
    } else {
        0
    }
}

/// Layer `k`'s permutation columns. Layer `k` holds sub-layer `k − 1`.
fn perm_width(k: usize) -> usize {
    if k == 0 || k > ROUND_LAYERS {
        return 0;
    }
    let s = k - 1;
    let (r, sub) = (s / SUB, s % SUB);
    match sub {
        0 | 1 => {
            if is_full(r) {
                2 * p2::WIDTH
            } else {
                // `q`, `t`, and the two lanes the partial round only carries.
                2 + (p2::WIDTH - 1)
            }
        }
        _ => p2::WIDTH,
    }
}

fn tree(k: usize, i: usize) -> PolyAddress {
    d::inner(k, i)
}

fn carry(k: usize, i: usize) -> PolyAddress {
    d::inner(k, tree_width(k) + i)
}

fn perm(k: usize, i: usize) -> PolyAddress {
    d::inner(k, tree_width(k) + carry_width(k) + i)
}

// ---------------------------------------------------------------------------
// The round block
// ---------------------------------------------------------------------------

/// Lane `i`'s value entering round 0, as a linear form over the frame: the
/// initial `external_matrix` folded into the first square, so it costs no
/// layer of its own.
///
/// `M_ext = [[2,1,1],[1,2,1],[1,1,2]]`, which is "add the state's sum to every
/// lane", so lane `i` takes coefficient 2 on its own words and 1 on the rest.
fn initial_lane(i: usize) -> Vec<(Coeff, PolyAddress)> {
    let mut terms = Vec::with_capacity(p2::WIDTH * d::WORDS_PER_VALUE);
    for lane in 0..p2::WIDTH {
        let scale = if lane == i { Fr::from_u64(2) } else { Fr::ONE };
        for k in 0..d::WORDS_PER_VALUE {
            terms.push((
                Coeff::Literal(scale * d::word_weight(k)),
                word(p2::WORDS_PER_LANE * lane + k, WORD_READ_VALUE),
            ));
        }
    }
    terms
}

/// Round `r`'s sub-layer `sub`, reading layer `k = SUB·r + sub`.
fn round_sub(r: usize, sub: usize) -> Vec<(String, GateDef)> {
    let k = SUB * r + sub;
    let full = is_full(r);
    let lanes = if full { p2::WIDTH } else { 1 };
    let mut out: Vec<(String, GateDef)> = Vec::new();
    match sub {
        // `q_i = (state_i + c_i)^2` and `t_i = state_i + c_i`. The constant
        // add is degree 1, so it folds into both.
        0 => {
            // Every `q` first, then every `t`, then the lanes a partial round
            // only carries: sub-layer 1 addresses this layer by region, so the
            // three groups are contiguous and in that order.
            let lane_terms = |i: usize| -> Vec<(Coeff, PolyAddress)> {
                if r == 0 {
                    initial_lane(i)
                } else {
                    vec![(d::lit(1), perm(k, i))]
                }
            };
            for i in 0..lanes {
                let constant = Coeff::Literal(rc(r, i));
                let terms = lane_terms(i);
                out.push((
                    format!("r{r}_q{i}"),
                    GateDef::AffineProduct {
                        left: terms.clone(),
                        left_constant: constant,
                        right: terms,
                        right_constant: constant,
                    },
                ));
            }
            for i in 0..lanes {
                out.push((
                    format!("r{r}_t{i}"),
                    GateDef::Linear {
                        terms: lane_terms(i),
                        constant: Coeff::Literal(rc(r, i)),
                    },
                ));
            }
            // A partial round carries lanes 1 and 2 untouched.
            for i in lanes..p2::WIDTH {
                out.push((format!("r{r}_s{i}"), d::copy(perm(k, i))));
            }
        }
        // `q2_i = q_i · q_i`, with `t_i` and any carried lanes copied.
        1 => {
            for i in 0..lanes {
                out.push((
                    format!("r{r}_q2{i}"),
                    GateDef::Product {
                        coeff: d::lit(1),
                        left: perm(k, i),
                        right: perm(k, i),
                    },
                ));
            }
            for i in 0..lanes {
                out.push((format!("r{r}_t{i}_up"), d::copy(perm(k, lanes + i))));
            }
            for i in lanes..p2::WIDTH {
                out.push((
                    format!("r{r}_s{i}_up"),
                    d::copy(perm(k, 2 * lanes + i - lanes)),
                ));
            }
        }
        // The S-box's last multiply and the linear layer, in one gate a lane.
        _ => {
            if full {
                // `M_ext·v`, with `v_i = q2_i·t_i`: lane `j` is
                // `2·v_j + Σ_{i≠j} v_i`.
                for j in 0..p2::WIDTH {
                    let products = (0..p2::WIDTH)
                        .map(|i| {
                            let c = if i == j { d::lit(2) } else { d::lit(1) };
                            (c, perm(k, i), perm(k, p2::WIDTH + i))
                        })
                        .collect();
                    out.push((format!("r{r}_out{j}"), d::quadratic(vec![], products)));
                }
            } else {
                // `internal_matrix` over `(v_0, s_1, s_2)`, which is
                // `1 + diag(1,1,2)`: lane 0 is `2·v_0 + s_1 + s_2`, lane 1 is
                // `v_0 + 2·s_1 + s_2`, lane 2 is `v_0 + s_1 + 3·s_2`.
                let (q2, t, s1, s2) = (perm(k, 0), perm(k, 1), perm(k, 2), perm(k, 3));
                for (j, (cv, c1, c2)) in [(2u64, 1u64, 1u64), (1, 2, 1), (1, 1, 3)]
                    .into_iter()
                    .enumerate()
                {
                    out.push((
                        format!("r{r}_out{j}"),
                        d::quadratic(
                            vec![(d::lit(c1), s1), (d::lit(c2), s2)],
                            vec![(d::lit(cv), q2, t)],
                        ),
                    ));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/// The family's circuit over `2^trace_vars` rows.
///
/// Validated, held to `crate::memory::check_memory` and to [`check_shape`];
/// panics if any of the three refuses it.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut a = d::Assembly::new();

    // Gate list 0 -> layer 1: the memory leaves, the carried columns, and the
    // first sub-layer, beside every gate the frame and the six frame values
    // owe.
    let [reads, writes] = d::leaves(address_space::DELEGATION_POSEIDON2, WORDS);
    let mut producing: Vec<(String, GateDef)> = reads.into_iter().chain(writes).collect();
    producing.push(("live_1".to_string(), d::copy(LIVE)));
    for j in 0..p2::WIDTH {
        producing.push((
            format!("out{j}_1"),
            GateDef::Linear {
                terms: d::value_terms(p2::WORDS_PER_LANE * j, WORD_WRITE_VALUE),
                constant: d::lit(0),
            },
        ));
    }
    producing.extend(round_sub(0, 0));
    a.push(1, false, trace_vars, producing, list0_enforcing());

    for layer in 1..=ROUND_LAYERS {
        let mut producing: Vec<(String, GateDef)> = Vec::new();
        if tree_width(layer) > 2 {
            for i in 0..tree_width(layer) / 2 {
                producing.push((
                    format!("tree_{layer}_{i}"),
                    GateDef::Product {
                        coeff: d::lit(1),
                        left: tree(layer, 2 * i),
                        right: tree(layer, 2 * i + 1),
                    },
                ));
            }
        } else {
            producing.push((format!("read_up{layer}"), d::copy(tree(layer, 0))));
            producing.push((format!("write_up{layer}"), d::copy(tree(layer, 1))));
        }
        let mut enforcing: Vec<(String, GateDef)> = Vec::new();
        if layer < ROUND_LAYERS {
            for i in 0..CARRY {
                producing.push((format!("carry_{layer}_{i}"), d::copy(carry(layer, i))));
            }
            producing.extend(round_sub(layer / SUB, layer % SUB));
        } else {
            enforcing = output_gates(layer);
        }
        a.push(layer + 1, false, trace_vars, producing, enforcing);
    }

    for step in 0..trace_vars as usize {
        let layer = ROUND_LAYERS + 2 + step;
        let producing = (0..2)
            .map(|i| {
                let name = if step + 1 == trace_vars as usize {
                    ["read_root", "write_root"][i].to_string()
                } else {
                    format!("halve_{layer}_{i}")
                };
                (
                    name,
                    GateDef::TreeProduct {
                        input: d::inner(layer - 1, i),
                    },
                )
            })
            .collect();
        a.push(
            layer,
            true,
            trace_vars - step as u32 - 1,
            producing,
            Vec::new(),
        );
    }

    let top = ROUND_LAYERS + 1 + trace_vars as usize;
    let committed = MEMORY_COLUMNS + WITNESS_COLUMNS;
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars,
        memory: d::memory_names(WORDS),
        witness: witness_names(),
        setup: Vec::new(),
        virtuals: Vec::new(),
        layers: a.layers,
        relations: a.relations,
        lookups: Vec::new(),
        scratch: a.scratch,
        outputs: vec![
            d::inner(top, mem::READ_ROOT),
            d::inner(top, mem::WRITE_ROOT),
        ],
        padding: Padding {
            row: vec![Fr::ZERO; committed],
            zero_row_valid: true,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("poseidon2: {e}");
    }
    if let Err(e) = crate::memory::check_memory(&artifact) {
        panic!("poseidon2: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// Gate list 0's enforcing gates: the frame's own, then the six frame values'
/// word decompositions and canonicity proofs.
fn list0_enforcing() -> Vec<(String, GateDef)> {
    let mut out = d::frame_gates(WORDS, p2::FRAME_BYTES as u64);
    for v in 0..2 * p2::WIDTH {
        let lane = v % p2::WIDTH;
        let field = if v < p2::WIDTH {
            WORD_READ_VALUE
        } else {
            WORD_WRITE_VALUE
        };
        let name = if v < p2::WIDTH {
            format!("in{lane}")
        } else {
            format!("out{lane}")
        };
        out.extend(d::canonical_gates(
            &name,
            p2::WORDS_PER_LANE * lane,
            field,
            value_bits(v),
            value_canon(v),
        ));
    }
    out
}

/// The last list's enforcing gates: the permutation's output equals what the
/// invocation wrote.
///
/// Gated on `live`, and it must be: a padding row's committed cells are zero,
/// the circuit still computes the permutation of the zero state there, and an
/// ungated gate would demand the written lane equal it.
fn output_gates(layer: usize) -> Vec<(String, GateDef)> {
    let live = carry(layer, 0);
    (0..p2::WIDTH)
        .map(|j| {
            (
                format!("out_lane{j}"),
                d::quadratic(
                    vec![],
                    vec![
                        (d::lit(1), live, perm(layer, j)),
                        (d::neg(1), live, carry(layer, 1 + j)),
                    ],
                ),
            )
        })
        .collect()
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out = d::witness_names(WORDS);
    for v in 0..2 * p2::WIDTH {
        let name = if v < p2::WIDTH {
            format!("in{v}")
        } else {
            format!("out{}", v - p2::WIDTH)
        };
        for k in 0..d::WORDS_PER_VALUE {
            for t in 0..32 {
                out.push(format!("{name}_bit{k}_{t}"));
            }
        }
        for k in 0..d::WORDS_PER_VALUE {
            for t in 0..32 {
                out.push(format!("{name}_diff{k}_{t}"));
            }
        }
        for k in 0..d::WORDS_PER_VALUE {
            out.push(format!("{name}_borrow{k}"));
        }
    }
    out
}

/// The family carries **no lookup channel** (`docs/spec/delegation.md` §9).
pub fn channels() -> Vec<ChannelSpec> {
    Vec::new()
}

/// What the emitted artifact must be, counted on the artifact rather than on
/// the vectors handed in.
fn check_shape(a: &CircuitArtifact) {
    assert_eq!(a.memory.len(), MEMORY_COLUMNS, "poseidon2: M columns");
    assert_eq!(a.witness.len(), WITNESS_COLUMNS, "poseidon2: W columns");
    assert!(a.setup.is_empty(), "poseidon2: no setup column");
    assert!(a.lookups.is_empty(), "poseidon2: no lookup obligation");
    assert!(a.virtuals.is_empty(), "poseidon2: no virtual table");
    assert_eq!(
        a.layers.len(),
        ROUND_LAYERS + 1 + a.trace_vars as usize,
        "poseidon2: gate lists"
    );
    // Every layer is exactly as wide as the three regions say. A layer one
    // column wider or narrower than they think would read a neighbour's
    // column with no other symptom.
    for (k, list) in a.layers.iter().enumerate() {
        if list.halving {
            continue;
        }
        let want = tree_width(k + 1) + carry_width(k + 1) + perm_width(k + 1);
        assert_eq!(list.width as usize, want, "poseidon2: layer {} width", k + 1);
    }
    for name in ["base_aligned", "base_in_window"] {
        assert!(
            a.relations.iter().any(|r| r.name == name),
            "poseidon2: the emitted artifact has no relation `{name}`"
        );
    }
    for (prefix, want) in [
        ("addr_w", WORDS),
        ("gap_w", WORDS),
        ("out_lane", p2::WIDTH),
    ] {
        let got = a
            .relations
            .iter()
            .filter(|r| r.name.starts_with(prefix) && !r.name.ends_with("_boolean"))
            .count();
        assert_eq!(got, want, "poseidon2: {got} `{prefix}*` relations, not {want}");
    }
    assert_eq!(
        a.layers[ROUND_LAYERS].enforcing.len(),
        p2::WIDTH,
        "poseidon2: the last round list carries the output comparison and nothing else"
    );
    assert!(
        !a.relations.iter().any(|r| r.name.contains("assume")),
        "poseidon2: no relation may be an unchecked hypothesis"
    );
}
