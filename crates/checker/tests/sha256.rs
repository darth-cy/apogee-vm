//! The SHA-256 compression circuit, gate by gate.
//!
//! `docs/spec/delegation.md` §15 is what this suite restates: the 24-word
//! frame, the anchor's two tuples, the message schedule, the sixty-four rounds
//! over two carried sequences, and the eight output sums.
//!
//! The compression is checked by running the circuit's **forward pass** and
//! comparing the words it writes against this file's own FIPS 180-4
//! implementation — which is pinned to the standard's published one-block and
//! two-block digests before any negative control uses it, so the reference is
//! not merely a second copy of the thing it checks. It shares no line with
//! `crates/emulator`'s executor, with `guest-sdk`'s fallback or with the
//! prover's fill.
//!
//! **Why a forward pass here and a row-local evaluation in
//! `tests/mod_mul.rs`.** That family carries the `RANGE16` channel, so its
//! circuit exists only at `2^16` and a whole-shard pass is impossible; this one
//! carries no channel (`docs/spec/delegation.md` §9), so it builds at four rows
//! and the pass is a few megabytes.
//!
//! Every negative control corrupts one cell of an otherwise honest witness and
//! names the relation that must catch it. A circuit whose gates are right and
//! whose *addressing* is wrong passes no negative control, which is why each
//! one names its gate.
//!
//! # What is deliberately not here: an anchor twin
//!
//! `checker::assert_anchor_twins_refused` is not called for this family, or
//! for `EC_ADD`. The anchor is **one mechanism**, built by
//! `constraints::delegation` identically for all six families and already
//! proved refused at block level over four of them — `tests/tamper.rs` covers
//! `KECCAK_F`, `POSEIDON2`, `FR_ARITH` and `MOD_MUL`, the last of which also
//! carries a lookup channel, so even that combination is not new here. A fifth
//! and sixth replay would be the same mutation set at two more re-proofs in
//! the slowest deferred suite, which is the cost the root `CLAUDE.md`'s test
//! rule exists to refuse: name the mutation nothing else catches, or do not
//! add the test.

use constants::sha256 as f;
use constants::{challenge_slot, delegation, guest_memory, memory as mem};
use constraints::sha256;
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{BaseLayer, ExternalChallenges, LayerValues};
use poly::{MultilinearPoly, PolyBacking};

/// Four rows: two live invocations and two padding rows.
const VARS: u32 = 2;
const ROWS: usize = 1 << VARS;

/// Bits in a word.
const BITS: usize = 32;

// ---------------------------------------------------------------------------
// FIPS 180-4, written here
// ---------------------------------------------------------------------------

/// Everything one compression produces, in the shape the witness needs.
struct Compression {
    /// `W_0..W_63`: the frame's sixteen and the forty-eight derived.
    w: [u32; f::ROUNDS],
    /// The derived words' carries, `W_16..W_63`.
    cw: [u32; f::ROUNDS - f::BLOCK_WORDS],
    /// `A_{-3}..A_64`, offset so that index `i + 3` is `A_i`.
    a: [u32; f::ROUNDS + 4],
    /// `E_{-3}..E_64`, likewise.
    e: [u32; f::ROUNDS + 4],
    /// The rounds' two carries.
    ca: [u32; f::ROUNDS],
    ce: [u32; f::ROUNDS],
    /// The eight output words and their carries.
    out: [u32; f::STATE_WORDS],
    co: [u32; f::STATE_WORDS],
}

fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
fn ch(e: u32, g: u32, h: u32) -> u32 {
    (e & g) ^ (!e & h)
}
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// One compression, keeping every intermediate the circuit commits.
///
/// The recurrence is the circuit's, over **two** sequences rather than eight
/// working words: `b`, `c` and `d` are `A_{i-1}`, `A_{i-2}` and `A_{i-3}`, and
/// `f`, `g` and `h` are `E_{i-1}`, `E_{i-2}` and `E_{i-3}`. Writing it that way
/// here rather than shuffling eight variables is what makes the comparison
/// against the circuit's columns direct.
fn compress(state: &[u32; f::STATE_WORDS], block: &[u32; f::BLOCK_WORDS]) -> Compression {
    let mut w = [0u32; f::ROUNDS];
    w[..f::BLOCK_WORDS].copy_from_slice(block);
    let mut cw = [0u32; f::ROUNDS - f::BLOCK_WORDS];
    for i in f::BLOCK_WORDS..f::ROUNDS {
        let total = small_sigma1(w[i - 2]) as u64
            + w[i - 7] as u64
            + small_sigma0(w[i - 15]) as u64
            + w[i - 16] as u64;
        w[i] = total as u32;
        cw[i - f::BLOCK_WORDS] = (total >> 32) as u32;
    }

    // `A_i` at index `i + 3`; the four non-positive indices are `H0..H3`
    // descending, which is exactly `constraints::sha256::a_bit`'s mapping.
    let mut a = [0u32; f::ROUNDS + 4];
    let mut e = [0u32; f::ROUNDS + 4];
    for j in 0..4 {
        a[3 - j] = state[j];
        e[3 - j] = state[4 + j];
    }
    let mut ca = [0u32; f::ROUNDS];
    let mut ce = [0u32; f::ROUNDS];
    for i in 0..f::ROUNDS {
        let at = i + 3;
        let t1 = e[at - 3] as u64
            + big_sigma1(e[at]) as u64
            + ch(e[at], e[at - 1], e[at - 2]) as u64
            + w[i] as u64
            + f::ROUND_CONSTANTS[i] as u64;
        let t2 = big_sigma0(a[at]) as u64 + maj(a[at], a[at - 1], a[at - 2]) as u64;
        a[at + 1] = (t1 + t2) as u32;
        ca[i] = ((t1 + t2) >> 32) as u32;
        let e_total = a[at - 3] as u64 + t1;
        e[at + 1] = e_total as u32;
        ce[i] = (e_total >> 32) as u32;
    }

    // `V = (A_64, A_63, A_62, A_61, E_64, E_63, E_62, E_61)`.
    let mut out = [0u32; f::STATE_WORDS];
    let mut co = [0u32; f::STATE_WORDS];
    for j in 0..f::STATE_WORDS {
        let v = match j < 4 {
            true => a[f::ROUNDS + 3 - j],
            false => e[f::ROUNDS + 3 - (j - 4)],
        };
        let total = state[j] as u64 + v as u64;
        out[j] = total as u32;
        co[j] = (total >> 32) as u32;
    }
    Compression {
        w,
        cw,
        a,
        e,
        ca,
        ce,
        out,
        co,
    }
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

/// One invocation as a witness builder sees it.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    state: [u32; f::STATE_WORDS],
    block: [u32; f::BLOCK_WORDS],
}

impl Invocation {
    /// The frame's 24 read words: the chaining state, then the block.
    fn read(&self) -> [u32; f::FRAME_WORDS] {
        core::array::from_fn(|j| match j < f::STATE_WORDS {
            true => self.state[j],
            false => self.block[j - f::STATE_WORDS],
        })
    }

    /// The frame's 24 write words: the new state, then the block unchanged.
    fn write(&self) -> [u32; f::FRAME_WORDS] {
        let done = compress(&self.state, &self.block);
        core::array::from_fn(|j| match j < f::STATE_WORDS {
            true => done.out[j],
            false => self.block[j - f::STATE_WORDS],
        })
    }
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

/// The honest base layer for `live`, padded to [`ROWS`] with zero rows.
fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    assert!(live.len() <= ROWS);
    let at = |r: usize, g: &dyn Fn(&Invocation) -> u64| -> u64 { live.get(r).map_or(0, g) };
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, g: &dyn Fn(&Invocation) -> u64| {
        out.push((address, column((0..ROWS).map(|r| at(r, g)).collect())));
    };

    push(sha256::CYCLE, &|i| i.cycle);
    push(sha256::LIVE, &|_| 1);
    push(sha256::BASE, &|i| i.base as u64);
    push(sha256::ANCHOR_VALUE, &|_| 0);
    for j in 0..f::FRAME_WORDS {
        push(
            sha256::word(j, constraints::delegation::WORD_ADDR),
            &move |i| i.base as u64 + 4 * j as u64,
        );
        // Read at the previous cycle's last slot, so the gap is 0.
        push(
            sha256::word(j, constraints::delegation::WORD_READ_TS),
            &move |i| mem::TS_STEP * i.cycle - 1,
        );
        push(
            sha256::word(j, constraints::delegation::WORD_READ_VALUE),
            &move |i| i.read()[j] as u64,
        );
        push(
            sha256::word(j, constraints::delegation::WORD_WRITE_VALUE),
            &move |i| i.write()[j] as u64,
        );
    }
    for j in 0..f::FRAME_WORDS {
        for bit in 0..constraints::delegation::GAP_BITS {
            push(sha256::gap_bit(j, bit), &move |i| {
                let gap = mem::TS_STEP * i.cycle + delegation::FRAME_DELTA
                    - (mem::TS_STEP * i.cycle - 1)
                    - 1;
                (gap >> bit) & 1
            });
        }
    }
    // Wrapping, not saturating: a base the frame rules refuse has no honest
    // decomposition, and these tests are about the gate that says so.
    for bit in 0..constraints::delegation::BASE_LOW_BITS {
        push(sha256::base_low_bit(bit), &move |i| {
            let q = (i.base as u64).wrapping_sub(guest_memory::RAM_ORIGIN as u64) / 4;
            (q >> bit) & 1
        });
    }
    for bit in 0..constraints::delegation::BASE_ROOM_BITS {
        push(sha256::base_room_bit(bit), &move |i| {
            let room = ((1u64 << 31) - f::FRAME_BYTES as u64).wrapping_sub(i.base as u64);
            (room >> bit) & 1
        });
    }

    // Every frame word's read value, bit by bit: the circuit's only view of
    // the chaining state and the block.
    for j in 0..f::FRAME_WORDS {
        for t in 0..BITS {
            push(sha256::in_bit(j, t), &move |i| {
                ((i.read()[j] >> t) & 1) as u64
            });
        }
    }
    // The eight written state words, and their carries.
    for j in 0..f::STATE_WORDS {
        for t in 0..BITS {
            push(sha256::out_bit(j, t), &move |i| {
                ((compress(&i.state, &i.block).out[j] >> t) & 1) as u64
            });
        }
        push(sha256::out_carry(j), &move |i| {
            compress(&i.state, &i.block).co[j] as u64
        });
    }
    // The message schedule's forty-eight derived words, and their carries.
    for i_w in f::BLOCK_WORDS..f::ROUNDS {
        for t in 0..BITS {
            push(sha256::sched_bit(i_w, t), &move |i| {
                ((compress(&i.state, &i.block).w[i_w] >> t) & 1) as u64
            });
        }
        for t in 0..f::CARRY_W_BITS {
            push(sha256::sched_carry_bit(i_w, t), &move |i| {
                ((compress(&i.state, &i.block).cw[i_w - f::BLOCK_WORDS] >> t) & 1) as u64
            });
        }
    }
    // The two carried sequences, and the two round carries.
    for r in 1..=f::ROUNDS {
        for t in 0..BITS {
            push(sha256::a_bit(r as isize, t), &move |i| {
                ((compress(&i.state, &i.block).a[r + 3] >> t) & 1) as u64
            });
        }
    }
    for r in 1..=f::ROUNDS {
        for t in 0..BITS {
            push(sha256::e_bit(r as isize, t), &move |i| {
                ((compress(&i.state, &i.block).e[r + 3] >> t) & 1) as u64
            });
        }
    }
    for r in 0..f::ROUNDS {
        for t in 0..f::CARRY_A_BITS {
            push(sha256::ca_bit(r, t), &move |i| {
                ((compress(&i.state, &i.block).ca[r] >> t) & 1) as u64
            });
        }
    }
    for r in 0..f::ROUNDS {
        for t in 0..f::CARRY_E_BITS {
            push(sha256::ce_bit(r, t), &move |i| {
                ((compress(&i.state, &i.block).ce[r] >> t) & 1) as u64
            });
        }
    }
    out
}

fn challenges() -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, value) in [
        (challenge_slot::MEM_GAMMA, 3u64),
        (challenge_slot::MEM_ALPHA_ADDR, 5),
        (challenge_slot::MEM_ALPHA_TS, 7),
        (challenge_slot::MEM_ALPHA_VAL, 11),
    ] {
        ch.insert(slot, Fr::from_u64(value));
    }
    ch
}

fn forward(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> LayerValues {
    gkr::forward(a, &BaseLayer::new(columns), &challenges())
}

/// Replace one cell of one column, returning the corrupted base.
fn corrupt(
    mut columns: Vec<(PolyAddress, MultilinearPoly)>,
    address: PolyAddress,
    row: usize,
    value: Fr,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let slot = columns
        .iter_mut()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"));
    let mut values: Vec<Fr> = (0..ROWS).map(|r| slot.1.get(r)).collect();
    values[row] = value;
    slot.1 = MultilinearPoly::new(PolyBacking::Fr(values));
    columns
}

/// The honest witness with one **bit** flipped — 0 for 1, 1 for 0.
///
/// A bit set to 1 that was already 1 is no corruption at all, and a suite that
/// hard-codes the replacement value silently passes for that reason on half its
/// choices. So the value comes from the column.
fn flip(address: PolyAddress, row: usize) -> Vec<(PolyAddress, MultilinearPoly)> {
    let columns = witness(&honest());
    let honest_bit = columns
        .iter()
        .find(|(at, _)| *at == address)
        .unwrap_or_else(|| panic!("{address} is not a committed column"))
        .1
        .get(row);
    assert!(
        honest_bit == Fr::ZERO || honest_bit == Fr::ONE,
        "{address} is not a bit"
    );
    let to = match honest_bit == Fr::ZERO {
        true => Fr::ONE,
        false => Fr::ZERO,
    };
    corrupt(columns, address, row, to)
}

/// The relation `self_check` must name, or a panic saying it passed.
fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    match gkr::self_check(a, &forward(a, columns), &challenges()) {
        Ok(()) => panic!("the corrupted witness satisfies every gate"),
        Err(e) => e.relation,
    }
}

/// Two honest invocations: `"abc"`'s one padded block from the IV, whose
/// answer is a published digest, and a pseudo-random state and block, whose
/// answer is nothing in particular — which is the point, a circuit correct
/// only on the standard's vectors being a circuit correct on one input.
fn honest() -> Vec<Invocation> {
    let mut rng = test_support::Rng::new(0x5236_0526);
    vec![
        Invocation {
            cycle: 7,
            base: guest_memory::RAM_ORIGIN + 4 * 1000,
            state: f::IV,
            block: ABC_BLOCK,
        },
        Invocation {
            cycle: 11,
            base: guest_memory::RAM_ORIGIN + 4 * 4096,
            state: core::array::from_fn(|_| rng.next_u64() as u32),
            block: core::array::from_fn(|_| rng.next_u64() as u32),
        },
    ]
}

/// FIPS 180-4 §A.1's `"abc"`, padded into its one block.
const ABC_BLOCK: [u32; f::BLOCK_WORDS] = [
    0x6162_6380,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x0000_0018,
];

/// `sha256("abc")`, the published digest, as eight big-endian state words.
const ABC_DIGEST: [u32; f::STATE_WORDS] = [
    0xba78_16bf,
    0x8f01_cfea,
    0x4141_40de,
    0x5dae_2223,
    0xb003_61a3,
    0x9617_7a9c,
    0xb410_ff61,
    0xf200_15ad,
];

// ---------------------------------------------------------------------------
// The reference is the standard's
// ---------------------------------------------------------------------------

/// [`compress`] against FIPS 180-4's own two vectors, **before** any negative
/// control leans on it.
///
/// Without this every test below would be holding the circuit to a
/// hand-written function with nothing holding *it* to anything, which is the
/// failure mode of a suite that checks an implementation against a second copy
/// of itself.
#[test]
fn the_reference_is_the_published_one() {
    // §A.1: `"abc"` is one padded block, so the compressed state is the digest.
    assert_eq!(compress(&f::IV, &ABC_BLOCK).out, ABC_DIGEST);

    // §A.2: 56 bytes, so two blocks, and the chaining between them is what the
    // one-block vector cannot show.
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let mut padded = [0u8; 128];
    padded[..message.len()].copy_from_slice(message);
    padded[message.len()] = 0x80;
    padded[120..].copy_from_slice(&((message.len() as u64) * 8).to_be_bytes());
    let block = |b: &[u8]| -> [u32; f::BLOCK_WORDS] {
        core::array::from_fn(|i| {
            u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
        })
    };
    let first = compress(&f::IV, &block(&padded[..64])).out;
    assert_eq!(
        compress(&first, &block(&padded[64..])).out,
        [
            0x248d_6a61,
            0xd206_38b8,
            0xe5c0_2693,
            0x0c3e_6039,
            0xa33c_e459,
            0x64ff_2167,
            0xf6ec_edd4,
            0x19db_06c1,
        ]
    );
}

// ---------------------------------------------------------------------------
// The circuit keeps every rule
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = sha256::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("a padding row is the product's identity");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    constraints::lookup::check_discharge(&a, &sha256::channels())
        .expect("a circuit with no channel discharges nothing");
    assert!(
        sha256::channels().is_empty(),
        "this delegation family carries no lookup channel: at 2^8 no table fits"
    );
    sha256::check_shape(&a);
}

#[test]
fn the_shape_is_the_documents() {
    let a = sha256::artifact(VARS);
    assert_eq!(a.memory.len(), sha256::MEMORY_COLUMNS);
    assert_eq!(a.memory.len(), 4 + 4 * f::FRAME_WORDS);
    assert_eq!(a.witness.len(), sha256::WITNESS_COLUMNS);
    assert!(a.setup.is_empty());
    assert!(a.virtuals.is_empty());
    assert!(a.lookups.is_empty());
    assert_eq!(a.outputs.len(), 2);
    let root = |i: usize| {
        a.scratch
            .iter()
            .find(|s| s.address == a.outputs[i])
            .map(|s| s.name.as_str())
            .unwrap_or("?")
    };
    assert_eq!(root(mem::READ_ROOT), "read_root");
    assert_eq!(root(mem::WRITE_ROOT), "write_root");
}

#[test]
fn an_honest_witness_satisfies_every_gate() {
    let a = sha256::artifact(VARS);
    let values = forward(&a, witness(&honest()));
    gkr::self_check(&a, &values, &challenges()).expect("the honest witness holds");
}

/// The circuit's answer **is** the compression, read off the frame's write
/// columns rather than off a witness column the same gates set.
///
/// This is the test that the addressing is right: every negative control below
/// says a gate catches a corruption, and none of them would notice a circuit
/// that computed a correct SHA-256 of the wrong sixteen words.
#[test]
fn the_written_state_is_the_compression() {
    let a = sha256::artifact(VARS);
    let live = honest();
    let columns = witness(&live);
    for (r, invocation) in live.iter().enumerate() {
        let done = compress(&invocation.state, &invocation.block);
        for j in 0..f::STATE_WORDS {
            let address = sha256::word(j, constraints::delegation::WORD_WRITE_VALUE);
            let cell = columns
                .iter()
                .find(|(at, _)| *at == address)
                .expect("the frame's write column")
                .1
                .get(r);
            assert_eq!(cell, Fr::from_u64(done.out[j] as u64), "row {r}, word {j}");
        }
        // And the block's sixteen words come back unchanged.
        for j in f::BLOCK_WORD..f::FRAME_WORDS {
            let address = sha256::word(j, constraints::delegation::WORD_WRITE_VALUE);
            let cell = columns
                .iter()
                .find(|(at, _)| *at == address)
                .expect("the frame's write column")
                .1
                .get(r);
            assert_eq!(cell, Fr::from_u64(invocation.read()[j] as u64));
        }
    }
    gkr::self_check(&a, &forward(&a, columns), &challenges()).expect("and the gates agree");
}

// ---------------------------------------------------------------------------
// The negative controls
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_output_word_is_refused() {
    let a = sha256::artifact(VARS);
    // Bit 0 of the first output word, flipped. Its own gate is `output_h0`,
    // but the write-back gate ties the frame word to the bits, so whichever
    // fires first, one must.
    let name = refusal(&a, flip(sha256::out_bit(0, 0), 0));
    assert!(
        name.contains("out") || name.contains("write"),
        "an output bit's corruption was caught by {name}"
    );
}

#[test]
fn a_wrong_round_word_is_refused() {
    let a = sha256::artifact(VARS);
    // `A_1`, the first round's result. Every later round reads it, so this is
    // also the check that the chain is a chain.
    assert_eq!(refusal(&a, flip(sha256::a_bit(1, 5), 0)), "round_a0");
}

#[test]
fn a_wrong_e_sequence_word_is_refused() {
    let a = sha256::artifact(VARS);
    assert_eq!(refusal(&a, flip(sha256::e_bit(1, 5), 0)), "round_e0");
}

#[test]
fn a_wrong_schedule_word_is_refused() {
    let a = sha256::artifact(VARS);
    // `W_16`, the first word the message schedule derives.
    assert_eq!(
        refusal(&a, flip(sha256::sched_bit(16, 3), 0)),
        "schedule_w16"
    );
}

#[test]
fn the_last_round_and_the_last_schedule_word_are_constrained_too() {
    // The first of a sequence is the easy one to constrain; the last is where
    // an off-by-one in the loop bound shows.
    let a = sha256::artifact(VARS);
    for (address, relation) in [
        (sha256::a_bit(f::ROUNDS as isize, 0), "round_a63"),
        (sha256::e_bit(f::ROUNDS as isize, 0), "round_e63"),
        (sha256::sched_bit(f::ROUNDS - 1, 0), "schedule_w63"),
    ] {
        assert_eq!(refusal(&a, flip(address, 0)), relation);
    }
}

#[test]
fn a_wrong_round_carry_is_refused() {
    let a = sha256::artifact(VARS);
    assert_eq!(refusal(&a, flip(sha256::ca_bit(0, 0), 0)), "round_a0");
}

#[test]
fn a_non_boolean_bit_is_refused() {
    let a = sha256::artifact(VARS);
    // 2 is neither 0 nor 1, and booleanity is what makes a bit decomposition a
    // bound rather than a re-spelling.
    let broken = corrupt(witness(&honest()), sha256::in_bit(0, 0), 0, Fr::from_u64(2));
    let name = refusal(&a, broken);
    assert!(
        name.contains("bool"),
        "a non-boolean bit was caught by {name}"
    );
}

#[test]
fn a_frame_word_that_disagrees_with_its_bits_is_refused() {
    let a = sha256::artifact(VARS);
    // The state word the circuit reads and the bits it computes from must be
    // the same number: this is the join between the memory columns and the
    // witness, and a circuit that got it wrong would compress whatever the
    // bits said while the multiset carried whatever the word said.
    let broken = corrupt(
        witness(&honest()),
        sha256::word(0, constraints::delegation::WORD_READ_VALUE),
        0,
        Fr::from_u64(0x1234_5678),
    );
    let name = refusal(&a, broken);
    assert!(
        name.contains("in") || name.contains("bits") || name.contains("word"),
        "a frame word out of step with its bits was caught by {name}"
    );
}

#[test]
fn a_block_word_rewritten_on_the_way_out_is_refused() {
    let a = sha256::artifact(VARS);
    // The schedule's sixteen words are read and written back unchanged. A
    // circuit that let them move would let a caller's block be rewritten by an
    // invocation, which the caller has no way to notice.
    let broken = corrupt(
        witness(&honest()),
        sha256::word(f::BLOCK_WORD, constraints::delegation::WORD_WRITE_VALUE),
        0,
        Fr::from_u64(0xdead_beef),
    );
    let name = refusal(&a, broken);
    assert!(
        name.contains("write"),
        "a rewritten block word was caught by {name}"
    );
}
