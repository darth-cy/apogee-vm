//! The Fr-arithmetic delegation circuit, gate by gate.
//!
//! `docs/spec/delegation.md` §13 is what this suite restates: the 25-word
//! frame, the anchor's two tuples, the three operations, and the canonicity of
//! every value that crosses the frame. The arithmetic itself is checked the
//! only way a circuit can be — by running its forward pass over a witness
//! built from **host `field::Fr`** and asserting the circuit accepts it. That
//! is acceptance 1: if the circuit computed anything but what `Fr` computes,
//! an honest witness would fail its own gates.
//!
//! Every negative control corrupts one cell of an otherwise honest witness and
//! names the relation that must catch it.

use constants::fr_arith as f;
use constants::{challenge_slot, guest_memory, memory as mem};
use constraints::fr_arith;
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{BaseLayer, ExternalChallenges, LayerValues};
use poly::{MultilinearPoly, PolyBacking};

/// Four rows: room for live invocations and padding both.
const VARS: u32 = 2;
const ROWS: usize = 1 << VARS;

/// One invocation as a witness builder sees it: the operation, its two
/// operands as *host* `Fr` values, and where the frame sits.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    op: u32,
    a: Fr,
    b: Fr,
}

impl Invocation {
    /// What `field::Fr` says the result is, with the delegation's `inv(0) = 0`
    /// convention in place of `Fr::inverse`'s `None`.
    fn result(&self) -> Fr {
        match self.op {
            f::OP_ADD => self.a + self.b,
            f::OP_MUL => self.a * self.b,
            f::OP_INV => self.a.inverse().unwrap_or(Fr::ZERO),
            other => panic!("no such operation {other}"),
        }
    }

    /// The three frame values, in frame order, as the wire carries them.
    fn values(&self) -> [[u8; 32]; 3] {
        [
            self.a.to_memory_bytes(),
            self.b.to_memory_bytes(),
            self.result().to_memory_bytes(),
        ]
    }

    /// The frame's 25 read values and 25 write values.
    fn frame(&self) -> ([u32; f::FRAME_WORDS], [u32; f::FRAME_WORDS]) {
        let values = self.values();
        let mut read = [0u32; f::FRAME_WORDS];
        let mut write = [0u32; f::FRAME_WORDS];
        read[f::OPCODE_WORD] = self.op;
        write[f::OPCODE_WORD] = self.op;
        for (v, first) in [f::A_WORD, f::B_WORD, f::OUT_WORD].into_iter().enumerate() {
            for k in 0..f::WORDS_PER_VALUE {
                let mut word = [0u8; 4];
                word.copy_from_slice(&values[v][4 * k..4 * k + 4]);
                let word = u32::from_le_bytes(word);
                // The result's eight words are the only ones the invocation
                // computes; the rest are written back unchanged. The result's
                // *read* value is whatever the guest left there, and nothing
                // constrains it: 0xdeadbeef says so out loud.
                if first == f::OUT_WORD {
                    read[first + k] = 0xdead_beef;
                    write[first + k] = word;
                } else {
                    read[first + k] = word;
                    write[first + k] = word;
                }
            }
        }
        (read, write)
    }
}

/// `p` as eight little-endian 32-bit limbs.
fn modulus() -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, limb) in constants::FR_MODULUS.iter().enumerate() {
        out[2 * i] = limb & 0xffff_ffff;
        out[2 * i + 1] = limb >> 32;
    }
    out
}

/// The borrow chain of `X − p` over eight 32-bit limbs: the difference limbs
/// and the borrows. The last borrow is 1 exactly when `X < p`.
fn borrow_chain(words: &[u32; 8]) -> ([u64; 8], [u64; 8]) {
    let p = modulus();
    let mut diff = [0u64; 8];
    let mut borrow = [0u64; 8];
    let mut carry = 0i64;
    for i in 0..8 {
        let d = words[i] as i64 - p[i] as i64 - carry;
        if d < 0 {
            diff[i] = (d + (1i64 << 32)) as u64;
            carry = 1;
        } else {
            diff[i] = d as u64;
            carry = 0;
        }
        borrow[i] = carry as u64;
    }
    (diff, borrow)
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

fn fr_column(values: Vec<Fr>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// `ρ = 2^256 mod p`, the factor `Fr`'s in-memory representation carries.
fn rho() -> Fr {
    let mut bytes = [0u8; 32];
    for (i, limb) in constants::FR_R.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    Fr::from_bytes(&bytes).expect("the radix is reduced")
}

/// The base layer for `live` invocations, padded to `ROWS` with zero rows.
fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    assert!(live.len() <= ROWS);
    let at = |r: usize, g: &dyn Fn(&Invocation) -> u64| -> u64 { live.get(r).map_or(0, g) };
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, g: &dyn Fn(&Invocation) -> u64| {
        out.push((address, column((0..ROWS).map(|r| at(r, g)).collect())));
    };
    push(fr_arith::CYCLE, &|i| i.cycle);
    push(fr_arith::LIVE, &|_| 1);
    push(fr_arith::BASE, &|i| i.base as u64);
    push(fr_arith::ANCHOR_VALUE, &|_| 0);
    for j in 0..f::FRAME_WORDS {
        push(fr_arith::word(j, fr_arith::WORD_ADDR), &move |i| {
            i.base as u64 + 4 * j as u64
        });
        // Read at the previous cycle's last slot, so the gap is 0.
        push(fr_arith::word(j, fr_arith::WORD_READ_TS), &move |i| {
            mem::TS_STEP * i.cycle - 1
        });
        push(fr_arith::word(j, fr_arith::WORD_READ_VALUE), &move |i| {
            i.frame().0[j] as u64
        });
        push(fr_arith::word(j, fr_arith::WORD_WRITE_VALUE), &move |i| {
            i.frame().1[j] as u64
        });
    }
    for j in 0..f::FRAME_WORDS {
        for bit in 0..38 {
            push(fr_arith::gap_bit(j, bit), &|_| 0);
        }
    }
    for bit in 0..29 {
        push(fr_arith::base_low_bit(bit), &move |i| {
            let q = (i.base as u64).wrapping_sub(guest_memory::RAM_ORIGIN as u64) / 4;
            (q >> bit) & 1
        });
    }
    for bit in 0..31 {
        push(fr_arith::base_room_bit(bit), &move |i| {
            let room = ((1u64 << 31) - f::FRAME_BYTES as u64).wrapping_sub(i.base as u64);
            (room >> bit) & 1
        });
    }
    for v in 0..3 {
        let words = move |i: &Invocation| -> [u32; 8] {
            let bytes = i.values()[v];
            core::array::from_fn(|k| {
                let mut word = [0u8; 4];
                word.copy_from_slice(&bytes[4 * k..4 * k + 4]);
                u32::from_le_bytes(word)
            })
        };
        for k in 0..8 {
            for t in 0..32 {
                push(fr_arith::value_bit(v, k, t), &move |i| {
                    (words(i)[k] as u64 >> t) & 1
                });
            }
        }
        for k in 0..8 {
            for t in 0..32 {
                push(fr_arith::diff_bit(v, k, t), &move |i| {
                    (borrow_chain(&words(i)).0[k] >> t) & 1
                });
            }
        }
        for k in 0..8 {
            push(fr_arith::borrow_bit(v, k), &move |i| {
                borrow_chain(&words(i)).1[k]
            });
        }
    }
    for (s, op) in f::OPS.iter().enumerate() {
        push(fr_arith::selector(s), &move |i| u64::from(i.op == *op));
    }
    // The three `Fr`-valued witnesses, which are field elements rather than
    // small integers and so are pushed directly.
    let value = |i: &Invocation, v: usize| -> Fr {
        Fr::from_bytes(&i.values()[v]).expect("a frame value is canonical")
    };
    let a_of = |i: &Invocation| value(i, 0);
    out.push((
        fr_arith::prod(),
        fr_column(
            (0..ROWS)
                .map(|r| live.get(r).map_or(Fr::ZERO, |i| a_of(i) * value(i, 1)))
                .collect(),
        ),
    ));
    out.push((
        fr_arith::inv(),
        fr_column(
            (0..ROWS)
                .map(|r| {
                    live.get(r).map_or(Fr::ZERO, |i| {
                        if i.op == f::OP_INV {
                            a_of(i).inverse().unwrap_or(Fr::ZERO)
                        } else {
                            Fr::ZERO
                        }
                    })
                })
                .collect(),
        ),
    ));
    out.push((
        fr_arith::is_zero(),
        fr_column(
            (0..ROWS)
                .map(|r| {
                    live.get(r).map_or(Fr::ZERO, |i| {
                        if i.op == f::OP_INV && a_of(i) == Fr::ZERO {
                            Fr::ONE
                        } else {
                            Fr::ZERO
                        }
                    })
                })
                .collect(),
        ),
    ));
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

/// The relation `self_check` must name, or a panic saying it passed.
fn refusal(a: &CircuitArtifact, columns: Vec<(PolyAddress, MultilinearPoly)>) -> String {
    let values = forward(a, columns);
    match gkr::self_check(a, &values, &challenges()) {
        Ok(()) => panic!("the corrupted witness satisfies every gate"),
        Err(e) => e.relation,
    }
}

/// A pseudo-random wide `Fr`, built from four 64-bit words so the operands
/// exercise every limb rather than the bottom one.
fn wide(rng: &mut test_support::Rng) -> Fr {
    let mut x = Fr::ZERO;
    for _ in 0..4 {
        x = x * Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32) + Fr::from_u64(rng.next_u64());
    }
    x
}

fn honest() -> Vec<Invocation> {
    let mut rng = test_support::Rng::new(0x5233_0523);
    let base = |k: u32| guest_memory::RAM_ORIGIN + 4 * k;
    vec![
        Invocation {
            cycle: 7,
            base: base(1000),
            op: f::OP_ADD,
            a: wide(&mut rng),
            b: wide(&mut rng),
        },
        Invocation {
            cycle: 11,
            base: base(4096),
            op: f::OP_MUL,
            a: wide(&mut rng),
            b: wide(&mut rng),
        },
        Invocation {
            cycle: 13,
            base: base(8192),
            op: f::OP_INV,
            a: wide(&mut rng),
            b: Fr::ZERO,
        },
    ]
}

// ---------------------------------------------------------------------------
// The circuit keeps every rule
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_keeps_every_rule() {
    let a = fr_arith::artifact(VARS);
    a.validate().expect("the circuit is a circuit");
    checker::check_laws(&a).expect("the standalone validators agree");
    checker::check_padding(&a).expect("the padding contract holds");
    checker::check_padding_identity(&a).expect("a padding row is the product's identity");
    constraints::memory::check_memory(&a).expect("the memory provenance rules hold");
    constraints::lookup::check_discharge(&a, &fr_arith::channels())
        .expect("a circuit with no channel discharges nothing");
}

// ---------------------------------------------------------------------------
// The arithmetic is `field::Fr`'s
// ---------------------------------------------------------------------------

/// Acceptance 1. An honest witness built from host `Fr` satisfies every gate,
/// for add, mul, inverse, `inverse(0)`, and a round trip `a·inverse(a) = 1`.
#[test]
fn the_forward_pass_is_field_fr() {
    let a = fr_arith::artifact(VARS);
    let mut rng = test_support::Rng::new(0x0523_5233);
    let base = |k: u32| guest_memory::RAM_ORIGIN + 4 * k;

    let x = wide(&mut rng);
    let y = wide(&mut rng);
    let cases: Vec<Vec<Invocation>> = vec![
        honest(),
        // inverse(0) = 0, the convention the circuit enforces rather than
        // asserts, and the padding-adjacent case worth its own witness.
        vec![Invocation {
            cycle: 3,
            base: base(64),
            op: f::OP_INV,
            a: Fr::ZERO,
            b: Fr::ZERO,
        }],
        // The round trip: `a`, then its inverse, then their product, which
        // must be `Fr::ONE`.
        vec![
            Invocation {
                cycle: 5,
                base: base(64),
                op: f::OP_INV,
                a: x,
                b: Fr::ZERO,
            },
            Invocation {
                cycle: 6,
                base: base(128),
                op: f::OP_MUL,
                a: x,
                b: x.inverse().expect("nonzero"),
            },
            Invocation {
                cycle: 9,
                base: base(256),
                op: f::OP_ADD,
                a: x,
                b: y,
            },
        ],
        // Every operation on operands that are 0 and 1, where a wrong `R`
        // factor would be least visible.
        vec![
            Invocation {
                cycle: 2,
                base: base(64),
                op: f::OP_MUL,
                a: Fr::ONE,
                b: Fr::ONE,
            },
            Invocation {
                cycle: 4,
                base: base(128),
                op: f::OP_MUL,
                a: Fr::ZERO,
                b: y,
            },
            Invocation {
                cycle: 8,
                base: base(256),
                op: f::OP_ADD,
                a: Fr::MINUS_ONE,
                b: Fr::ONE,
            },
        ],
    ];
    for (i, case) in cases.iter().enumerate() {
        let values = forward(&a, witness(case));
        gkr::self_check(&a, &values, &challenges())
            .unwrap_or_else(|e| panic!("case {i}: an honest witness failed `{}`", e.relation));
    }
    // And the round trip really is one: the second invocation's result is 1.
    assert_eq!(
        x * x.inverse().expect("nonzero"),
        Fr::ONE,
        "a·inverse(a) = 1"
    );
}

/// The in-memory encoding is what the frame carries, and it is canonical.
#[test]
fn the_frame_encoding_is_frs_own_limbs() {
    let mut rng = test_support::Rng::new(0x1234_5678);
    for _ in 0..64 {
        let x = wide(&mut rng);
        let bytes = x.to_memory_bytes();
        // Canonical: it decodes, so it is below the modulus, which is exactly
        // what the circuit's canonicity gates prove of a frame value.
        let element = Fr::from_bytes(&bytes).expect("the limbs are reduced");
        // And the element it spells is `x·ρ`.
        assert_eq!(element, x * rho());
        assert_eq!(Fr::from_memory_bytes(&bytes), Some(x));
    }
}

// ---------------------------------------------------------------------------
// Negative controls
// ---------------------------------------------------------------------------

#[test]
fn a_corrupted_result_is_refused() {
    let a = fr_arith::artifact(VARS);
    // The multiply's low result word, moved by one.
    let columns = corrupt(
        witness(&honest()),
        fr_arith::word(f::OUT_WORD, fr_arith::WORD_WRITE_VALUE),
        1,
        Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, columns), "out_word0");
}

#[test]
fn a_corrupted_product_helper_is_refused() {
    let a = fr_arith::artifact(VARS);
    let columns = corrupt(witness(&honest()), fr_arith::prod(), 1, Fr::from_u64(7));
    assert_eq!(refusal(&a, columns), "prod_rule");
}

#[test]
fn a_forged_inverse_is_refused() {
    let a = fr_arith::artifact(VARS);
    let columns = corrupt(witness(&honest()), fr_arith::inv(), 2, Fr::from_u64(3));
    assert_eq!(refusal(&a, columns), "inv_is_an_inverse");
}

/// The gate the prompt's constraint set leaves out: at `a = 0` the witnessed
/// inverse is otherwise free, and "inverse(0) = 0" would be prose.
#[test]
fn a_free_inverse_at_zero_is_refused() {
    let a = fr_arith::artifact(VARS);
    let zero = vec![Invocation {
        cycle: 3,
        base: guest_memory::RAM_ORIGIN + 256,
        op: f::OP_INV,
        a: Fr::ZERO,
        b: Fr::ZERO,
    }];
    let columns = corrupt(witness(&zero), fr_arith::inv(), 0, Fr::from_u64(5));
    assert_eq!(refusal(&a, columns), "inverse_of_zero_is_zero");
}

/// Acceptance 7: a row claiming two operations at once.
///
/// The forgery is chosen so that no *other* gate catches it first, which is
/// what makes this a test of `one_op_a_live_row` rather than of the opcode.
/// The operation codes are 1, 2 and 3, so `add + mul` spells the same opcode
/// word as `inv`: on an inverse row a prover may set `f_add` and `f_mul`
/// instead and `opcode_rule` still holds. Exactly one selector a live row is
/// the only thing that refuses it.
#[test]
fn a_row_claiming_two_operations_is_refused() {
    assert_eq!(f::OP_ADD + f::OP_MUL, f::OP_INV, "the forgery below needs this");
    let a = fr_arith::artifact(VARS);
    // Row 2 of `honest()` is the inverse.
    let columns = witness(&honest());
    let columns = corrupt(columns, fr_arith::selector(0), 2, Fr::ONE);
    let columns = corrupt(columns, fr_arith::selector(1), 2, Fr::ONE);
    let columns = corrupt(columns, fr_arith::selector(2), 2, Fr::ZERO);
    assert_eq!(refusal(&a, columns), "one_op_a_live_row");
}

/// Acceptance 3: a frame operand at or above the modulus has no witness.
#[test]
fn a_non_canonical_operand_is_refused() {
    let a = fr_arith::artifact(VARS);
    let columns = witness(&honest());
    // `p` itself: every word of the borrow chain still recomposes, but the
    // last borrow is 0, so `a_below_modulus` cannot hold.
    let p = modulus();
    let mut columns = columns;
    for k in 0..8 {
        for field in [fr_arith::WORD_READ_VALUE, fr_arith::WORD_WRITE_VALUE] {
            columns = corrupt(
                columns,
                fr_arith::word(f::A_WORD + k, field),
                0,
                Fr::from_u64(p[k]),
            );
        }
        for t in 0..32 {
            columns = corrupt(
                columns,
                fr_arith::value_bit(0, k, t),
                0,
                Fr::from_u64((p[k] >> t) & 1),
            );
        }
    }
    let words: [u32; 8] = core::array::from_fn(|k| p[k] as u32);
    let (diff, borrow) = borrow_chain(&words);
    assert_eq!(borrow[7], 0, "p is not below p");
    for k in 0..8 {
        for t in 0..32 {
            columns = corrupt(
                columns,
                fr_arith::diff_bit(0, k, t),
                0,
                Fr::from_u64((diff[k] >> t) & 1),
            );
        }
        columns = corrupt(columns, fr_arith::borrow_bit(0, k), 0, Fr::from_u64(borrow[k]));
    }
    assert_eq!(refusal(&a, columns), "a_below_modulus");
}

/// The frame pointer's two bounds, by name.
#[test]
fn a_bad_frame_pointer_is_refused() {
    let a = fr_arith::artifact(VARS);
    let mut misaligned = honest();
    misaligned[0].base += 2;
    assert_eq!(refusal(&a, witness(&misaligned)), "base_aligned");

    let mut below = honest();
    below[0].base = guest_memory::RAM_ORIGIN - 4;
    assert_eq!(refusal(&a, witness(&below)), "base_aligned");

    let mut past = honest();
    past[0].base = (1u32 << 31) - 4;
    assert_eq!(refusal(&a, witness(&past)), "base_in_window");
}

/// A frame word whose address is not `base + 4j`.
#[test]
fn a_moved_frame_word_is_refused() {
    let a = fr_arith::artifact(VARS);
    let columns = corrupt(
        witness(&honest()),
        fr_arith::word(5, fr_arith::WORD_ADDR),
        0,
        Fr::from_u64(guest_memory::RAM_ORIGIN as u64),
    );
    assert_eq!(refusal(&a, columns), "addr_w5");
}

/// An operand the invocation did not write back.
#[test]
fn a_clobbered_operand_is_refused() {
    let a = fr_arith::artifact(VARS);
    let columns = corrupt(
        witness(&honest()),
        fr_arith::word(f::A_WORD, fr_arith::WORD_WRITE_VALUE),
        0,
        Fr::from_u64(1),
    );
    assert_eq!(refusal(&a, columns), format!("writes_back_w{}", f::A_WORD));
}
