//! The 256-bit modular multiplication circuit, gate by gate.
//!
//! `docs/spec/delegation.md` §14 is what this suite restates: the 32-word frame,
//! the anchor's two tuples, the schoolbook identity `a·b = q·m + out` with
//! `out < m`, and the 32-bit bound on every limb that crosses the frame.
//!
//! The arithmetic is checked the only way a circuit can be — by running its
//! forward pass over a witness built from **`u128` host arithmetic**, and
//! asserting the circuit accepts it. Nothing here shares a line with
//! `crates/prover`'s fill or with `crates/emulator`'s executor: the modulus, the
//! operands, the product, the quotient, the remainder and every carry are
//! computed here from `u128` primitives, so a circuit that stated anything but
//! `a·b mod m` would reject an honest witness.
//!
//! Every negative control corrupts one cell of an otherwise honest witness and
//! names the relation that must catch it.

use constants::mod_mul as f;
use constants::{challenge_slot, guest_memory, memory as mem};
use constraints::mod_mul;
use constraints::{CircuitArtifact, PolyAddress};
use field::Fr;
use gkr::{BaseLayer, ExternalChallenges, LayerValues};
use poly::{MultilinearPoly, PolyBacking};

/// Four rows: room for live invocations and padding both.
const VARS: u32 = 2;
const ROWS: usize = 1 << VARS;

/// A 256-bit value as eight little-endian 32-bit limbs, held as `u128` halves so
/// the test's own arithmetic needs no big-integer type.
///
/// Every operand here fits two `u128`s and every product fits four, which is why
/// the suite can compute the whole identity in primitives: `u128` holds 128 bits
/// and a 256-bit value is two of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct U256 {
    lo: u128,
    hi: u128,
}

impl U256 {
    fn from_limbs(limbs: [u32; f::LIMBS]) -> U256 {
        let word = |k: usize| limbs[k] as u128;
        U256 {
            lo: word(0) | word(1) << 32 | word(2) << 64 | word(3) << 96,
            hi: word(4) | word(5) << 32 | word(6) << 64 | word(7) << 96,
        }
    }

    fn limbs(&self) -> [u32; f::LIMBS] {
        core::array::from_fn(|k| match k < 4 {
            true => (self.lo >> (32 * k)) as u32,
            false => (self.hi >> (32 * (k - 4))) as u32,
        })
    }
}

/// `a · b mod m` and the quotient, over `u128` limb arithmetic.
///
/// Schoolbook multiply into sixteen 32-bit lanes, then shift-and-subtract
/// division from the top bit. Written here rather than called from anywhere,
/// because a suite that called the prover's own helper would be checking the
/// circuit against the code that fills it.
fn mul_div(a: &U256, b: &U256, m: &U256) -> (U256, U256) {
    let (al, bl, ml) = (a.limbs(), b.limbs(), m.limbs());
    let mut product = [0u64; 2 * f::LIMBS];
    for i in 0..f::LIMBS {
        let mut carry = 0u64;
        for j in 0..f::LIMBS {
            let total = product[i + j] + al[i] as u64 * bl[j] as u64 + carry;
            product[i + j] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let mut at = i + f::LIMBS;
        while carry != 0 {
            let total = product[at] + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
            at += 1;
        }
    }
    let mut quotient = [0u32; 2 * f::LIMBS];
    let mut rem = [0u64; f::LIMBS + 1];
    for bit in (0..32 * 2 * f::LIMBS).rev() {
        let mut carry = (product[bit / 32] >> (bit % 32)) & 1;
        for word in rem.iter_mut() {
            let total = (*word << 1) | carry;
            *word = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let ge = rem[f::LIMBS] != 0
            || (0..f::LIMBS)
                .rev()
                .find(|k| rem[*k] != ml[*k] as u64)
                .is_none_or(|k| rem[k] > ml[k] as u64);
        if ge {
            let mut borrow = 0i64;
            for k in 0..f::LIMBS {
                let d = rem[k] as i64 - ml[k] as i64 - borrow;
                borrow = i64::from(d < 0);
                rem[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
            }
            rem[f::LIMBS] -= borrow as u64;
            quotient[bit / 32] |= 1 << (bit % 32);
        }
    }
    for (k, limb) in quotient.iter().enumerate().skip(f::LIMBS) {
        assert_eq!(*limb, 0, "the quotient does not fit eight limbs (limb {k})");
    }
    (
        U256::from_limbs(core::array::from_fn(|k| rem[k] as u32)),
        U256::from_limbs(core::array::from_fn(|k| quotient[k])),
    )
}

/// One invocation as a witness builder sees it.
#[derive(Clone, Copy)]
struct Invocation {
    cycle: u64,
    base: u32,
    m: U256,
    a: U256,
    b: U256,
}

impl Invocation {
    fn result(&self) -> U256 {
        mul_div(&self.a, &self.b, &self.m).0
    }

    fn quotient(&self) -> U256 {
        mul_div(&self.a, &self.b, &self.m).1
    }

    /// The four frame values, in frame order.
    fn values(&self) -> [U256; 4] {
        [self.m, self.a, self.b, self.result()]
    }

    /// The frame's 32 read values and 32 write values.
    fn frame(&self) -> ([u32; f::FRAME_WORDS], [u32; f::FRAME_WORDS]) {
        let values = self.values();
        let mut read = [0u32; f::FRAME_WORDS];
        let mut write = [0u32; f::FRAME_WORDS];
        for (v, first) in [f::M_WORD, f::A_WORD, f::B_WORD, f::OUT_WORD]
            .into_iter()
            .enumerate()
        {
            for (k, word) in values[v].limbs().into_iter().enumerate() {
                // The result's eight words are the only ones the invocation
                // computes; the rest are written back unchanged. The result's
                // *read* value is whatever the guest left there and nothing
                // constrains it: `0xdeadbeef` says so out loud.
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

    /// The fifteen positions' signed carries of this invocation's identity.
    fn carries(&self) -> Vec<i128> {
        let (m, a, b) = (self.m.limbs(), self.a.limbs(), self.b.limbs());
        let (out, q) = (self.result().limbs(), self.quotient().limbs());
        let part = |x: &[u32; f::LIMBS], y: &[u32; f::LIMBS], k: usize| -> i128 {
            (0..f::LIMBS)
                .filter_map(|i| k.checked_sub(i).filter(|j| *j < f::LIMBS).map(|j| (i, j)))
                .map(|(i, j)| x[i] as i128 * y[j] as i128)
                .sum()
        };
        let mut out_carries = Vec::new();
        let mut carry = 0i128;
        for k in 0..f::POSITIONS {
            let mut lhs = part(&a, &b, k) - part(&q, &m, k) + carry;
            if let Some(limb) = out.get(k) {
                lhs -= *limb as i128;
            }
            assert_eq!(lhs.rem_euclid(1 << 32), 0, "position {k} does not divide");
            carry = lhs / (1 << 32);
            if k < f::CARRIES {
                out_carries.push(carry);
            }
        }
        assert_eq!(carry, 0, "the identity leaves a carry");
        out_carries
    }
}

/// The borrow chain of `x − y` over eight 32-bit limbs.
fn borrow_chain(x: &[u32; f::LIMBS], y: &[u32; f::LIMBS]) -> ([u64; f::LIMBS], [u64; f::LIMBS]) {
    let (mut diff, mut borrow) = ([0u64; f::LIMBS], [0u64; f::LIMBS]);
    let mut carry = 0i64;
    for i in 0..f::LIMBS {
        let d = x[i] as i64 - y[i] as i64 - carry;
        carry = i64::from(d < 0);
        diff[i] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
        borrow[i] = carry as u64;
    }
    (diff, borrow)
}

fn column(values: Vec<u64>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(
        values.into_iter().map(Fr::from_u64).collect(),
    ))
}

/// The honest witness of `live`, padded to [`ROWS`].
fn witness(live: &[Invocation]) -> Vec<(PolyAddress, MultilinearPoly)> {
    let mut out: Vec<(PolyAddress, MultilinearPoly)> = Vec::new();
    let mut push = |address: PolyAddress, of: &dyn Fn(&Invocation) -> u64| {
        let values = (0..ROWS).map(|r| live.get(r).map_or(0, of)).collect();
        out.push((address, column(values)));
    };
    push(mod_mul::CYCLE, &|i| i.cycle);
    push(mod_mul::LIVE, &|_| 1);
    push(mod_mul::BASE, &|i| i.base as u64);
    push(mod_mul::ANCHOR_VALUE, &|_| 0);
    for j in 0..f::FRAME_WORDS {
        push(mod_mul::word(j, mod_mul::WORD_ADDR), &move |i| {
            i.base as u64 + 4 * j as u64
        });
        // Every frame word's read timestamp is 0 here: the frame's words are
        // untouched before the call, so their gaps are the whole timestamp.
        push(mod_mul::word(j, mod_mul::WORD_READ_TS), &|_| 0);
        push(mod_mul::word(j, mod_mul::WORD_READ_VALUE), &move |i| {
            i.frame().0[j] as u64
        });
        push(mod_mul::word(j, mod_mul::WORD_WRITE_VALUE), &move |i| {
            i.frame().1[j] as u64
        });
    }
    // The gap bits: `4·cycle + FRAME_DELTA − 0 − 1`, 38 bits a word.
    for j in 0..f::FRAME_WORDS {
        for bit in 0..38 {
            let address = constraints::delegation::gap_bit(j, bit);
            let values = (0..ROWS)
                .map(|r| {
                    live.get(r).map_or(0, |i| {
                        let gap = mem::TS_STEP * i.cycle + constants::delegation::FRAME_DELTA - 1;
                        (gap >> bit) & 1
                    })
                })
                .collect();
            out.push((address, column(values)));
        }
    }
    for bit in 0..constraints::delegation::BASE_LOW_BITS {
        let address = constraints::delegation::base_low_bit(f::FRAME_WORDS, bit);
        let values = (0..ROWS)
            .map(|r| {
                live.get(r).map_or(0, |i| {
                    (((i.base - guest_memory::RAM_ORIGIN) / 4) >> bit) as u64 & 1
                })
            })
            .collect();
        out.push((address, column(values)));
    }
    for bit in 0..constraints::delegation::BASE_ROOM_BITS {
        let address = constraints::delegation::base_room_bit(f::FRAME_WORDS, bit);
        let values = (0..ROWS)
            .map(|r| {
                live.get(r).map_or(0, |i| {
                    let room = (1u64 << 31) - f::FRAME_BYTES as u64 - i.base as u64;
                    (room >> bit) & 1
                })
            })
            .collect();
        out.push((address, column(values)));
    }
    // The four values' word bits.
    for v in 0..4 {
        for k in 0..f::LIMBS {
            for t in 0..32 {
                let values = (0..ROWS)
                    .map(|r| {
                        live.get(r)
                            .map_or(0, |i| ((i.values()[v].limbs()[k] >> t) & 1) as u64)
                    })
                    .collect();
                out.push((mod_mul::value_bit(v, k, t), column(values)));
            }
        }
    }
    // The quotient: its limbs, then its bits.
    for k in 0..f::LIMBS {
        let values = (0..ROWS)
            .map(|r| live.get(r).map_or(0, |i| i.quotient().limbs()[k] as u64))
            .collect();
        out.push((mod_mul::q_limb(k), column(values)));
    }
    for k in 0..f::LIMBS {
        for t in 0..32 {
            let values = (0..ROWS)
                .map(|r| {
                    live.get(r)
                        .map_or(0, |i| ((i.quotient().limbs()[k] >> t) & 1) as u64)
                })
                .collect();
            out.push((mod_mul::q_bit(k, t), column(values)));
        }
    }
    // The `out < m` chain.
    for i in 0..f::LIMBS {
        for t in 0..32 {
            let values = (0..ROWS)
                .map(|r| {
                    live.get(r).map_or(0, |inv| {
                        let (diff, _) = borrow_chain(&inv.result().limbs(), &inv.m.limbs());
                        (diff[i] >> t) & 1
                    })
                })
                .collect();
            out.push((mod_mul::diff_bit(i, t), column(values)));
        }
    }
    for i in 0..f::LIMBS {
        let values = (0..ROWS)
            .map(|r| {
                live.get(r).map_or(0, |inv| {
                    borrow_chain(&inv.result().limbs(), &inv.m.limbs()).1[i]
                })
            })
            .collect();
        out.push((mod_mul::borrow_bit(i), column(values)));
    }
    // The carries, offset.
    for k in 0..f::CARRIES {
        for t in 0..f::CARRY_BITS {
            let values = (0..ROWS)
                .map(|r| {
                    live.get(r).map_or(0, |i| {
                        let offset = i.carries()[k] + f::CARRY_OFFSET as i128;
                        ((offset >> t) & 1) as u64
                    })
                })
                .collect();
            out.push((mod_mul::carry_bit(k, t), column(values)));
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

/// secp256k1's base field prime, `2^256 − 2^32 − 977`: the modulus a mainnet
/// block spends 44% of its cycles multiplying modulo
/// (`docs/handoff/S26-cycle.md`), and the reason this family exists.
fn secp256k1_p() -> U256 {
    let mut limbs = [0xffff_ffffu32; f::LIMBS];
    limbs[0] = 0xffff_fc2f;
    limbs[1] = 0xffff_fffe;
    U256::from_limbs(limbs)
}

/// BN254's scalar field modulus, the one `FR_ARITH` has as a constant: a second
/// modulus, to say out loud that this family is not curve-specific.
fn bn254_r() -> U256 {
    let mut limbs = [0u32; f::LIMBS];
    for (i, limb) in constants::FR_MODULUS.iter().enumerate() {
        limbs[2 * i] = (limb & 0xffff_ffff) as u32;
        limbs[2 * i + 1] = (limb >> 32) as u32;
    }
    U256::from_limbs(limbs)
}

/// A pseudo-random value below `m`, exercising every limb rather than the
/// bottom one.
fn wide(rng: &mut test_support::Rng, m: &U256) -> U256 {
    let value = U256 {
        lo: rng.next_u64() as u128 | (rng.next_u64() as u128) << 64,
        hi: rng.next_u64() as u128 | (rng.next_u64() as u128) << 64,
    };
    // `value mod m`, through the one reduction this file has.
    mul_div(&value, &U256 { lo: 1, hi: 0 }, m).0
}

/// Three invocations: two moduli, and the corner where `a·b` is exactly a
/// multiple of `m` so the remainder is zero.
fn honest() -> Vec<Invocation> {
    let mut rng = test_support::Rng::new(0x5236_0526);
    let base = |k: u32| guest_memory::RAM_ORIGIN + 4 * k;
    let p = secp256k1_p();
    vec![
        Invocation {
            cycle: 7,
            base: base(1000),
            m: p,
            a: wide(&mut rng, &p),
            b: wide(&mut rng, &p),
        },
        Invocation {
            cycle: 11,
            base: base(4096),
            m: bn254_r(),
            a: wide(&mut rng, &bn254_r()),
            b: wide(&mut rng, &bn254_r()),
        },
        // `a = 0`, so the product and the remainder are both zero and every
        // carry is zero: the row where the identity is degenerate.
        Invocation {
            cycle: 13,
            base: base(8192),
            m: p,
            a: U256 { lo: 0, hi: 0 },
            b: wide(&mut rng, &p),
        },
    ]
}

// ---------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_validates_and_keeps_the_memory_rule() {
    let a = mod_mul::artifact(VARS);
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(constraints::memory::check_memory(&a), Ok(()));
    assert_eq!(a.memory.len(), mod_mul::MEMORY_COLUMNS);
    assert_eq!(a.witness.len(), mod_mul::WITNESS_COLUMNS);
    assert!(a.setup.is_empty());
    assert!(a.lookups.is_empty(), "a delegation family has no lookup");
    assert_eq!(
        checker::check_laws(&a),
        Ok(()),
        "the checker's own reading of the laws"
    );
    assert_eq!(checker::check_padding(&a), Ok(()));
}

/// **Acceptance: the circuit computes `a·b mod m`.**
///
/// The witness is built from `u128` arithmetic in this file and from nothing the
/// prover or the executor owns. If the circuit stated any other relation — a
/// dropped carry, a wrong weight, a modulus read from the wrong words — an
/// honest witness would fail its own gates.
#[test]
fn an_honest_witness_satisfies_every_gate() {
    let a = mod_mul::artifact(VARS);
    let live = honest();
    let values = forward(&a, witness(&live));
    assert_eq!(gkr::self_check(&a, &values, &challenges()), Ok(()));
}

/// The padding row alone, with nothing live: every gate holds on the all-zero
/// row, which is the padding contract's second clause
/// (`docs/spec/delegation.md` §6.1).
#[test]
fn the_all_zero_row_satisfies_every_gate() {
    let a = mod_mul::artifact(VARS);
    let values = forward(&a, witness(&[]));
    assert_eq!(gkr::self_check(&a, &values, &challenges()), Ok(()));
}

// ---------------------------------------------------------------------------
// The negative controls
// ---------------------------------------------------------------------------

/// A wrong result is caught by the limb identity, not by anything softer: the
/// product and the quotient are unchanged, so the first position whose sum no
/// longer divides is the one that names it.
#[test]
fn a_changed_result_word_is_refused() {
    let a = mod_mul::artifact(VARS);
    let columns = witness(&honest());
    let bad = corrupt(
        columns,
        mod_mul::word(f::OUT_WORD, mod_mul::WORD_WRITE_VALUE),
        0,
        Fr::from_u64(1),
    );
    let relation = refusal(&a, bad);
    assert!(
        relation.starts_with("limb") || relation == "out_word0" || relation == "chain0",
        "a changed result is refused by the identity, its decode or the chain: {relation}"
    );
}

/// A result at or above the modulus: the borrow chain refuses it, and nothing
/// else does.
///
/// This is the reduction itself. Without `out < m` a prover could answer
/// `r + m` with the quotient one lower: the identity `a·b = (q−1)·m + (r + m)`
/// holds over the integers just as well, every limb is still below `2^32`, every
/// carry still divides, and the *only* statement it breaks is that the result is
/// reduced. So the twin is built as an honest prover of that claim would build
/// it — the result, the quotient, their bits, every carry and the whole borrow
/// chain recomputed — and the one relation left to refuse it is named.
///
/// It runs on the **BN254** row and not the secp256k1 one for an arithmetical
/// reason worth recording: secp256k1's `p` is `2^256 − 2^32 − 977`, so `r + p`
/// overflows eight limbs for all but the smallest `r` and the twin is not
/// representable at all. BN254's `r` is just under `2^254`, so `r + m` fits.
#[test]
fn a_result_not_below_the_modulus_is_refused() {
    let a = mod_mul::artifact(VARS);
    let live = honest();
    // Row 1 is the BN254 one.
    let row = 1;
    let inv = live[row];
    let (r, q) = mul_div(&inv.a, &inv.b, &inv.m);

    let add = |x: &U256, y: &U256| -> U256 {
        let (xl, yl) = (x.limbs(), y.limbs());
        let mut sum = [0u32; f::LIMBS];
        let mut carry = 0u64;
        for k in 0..f::LIMBS {
            let total = xl[k] as u64 + yl[k] as u64 + carry;
            sum[k] = total as u32;
            carry = total >> 32;
        }
        assert_eq!(carry, 0, "r + m fits eight limbs for this modulus");
        U256::from_limbs(sum)
    };
    let dec = |x: &U256| -> U256 {
        let xl = x.limbs();
        let mut diff = [0u32; f::LIMBS];
        let mut borrow = 0i64;
        for k in 0..f::LIMBS {
            let d = xl[k] as i64 - i64::from(k == 0) - borrow;
            borrow = i64::from(d < 0);
            diff[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u32;
        }
        assert_eq!(borrow, 0, "the quotient is not zero");
        U256::from_limbs(diff)
    };
    let bumped = add(&r, &inv.m);
    let lower = dec(&q);

    // The carries of the shifted identity, computed the same way the honest
    // ones are — which is also the assertion that it *is* an identity.
    let part = |x: &[u32; f::LIMBS], y: &[u32; f::LIMBS], k: usize| -> i128 {
        (0..f::LIMBS)
            .filter_map(|i| k.checked_sub(i).filter(|j| *j < f::LIMBS).map(|j| (i, j)))
            .map(|(i, j)| x[i] as i128 * y[j] as i128)
            .sum()
    };
    let (ml, al, bl) = (inv.m.limbs(), inv.a.limbs(), inv.b.limbs());
    let (outl, ql) = (bumped.limbs(), lower.limbs());
    let mut carries = Vec::new();
    let mut carry = 0i128;
    for k in 0..f::POSITIONS {
        let mut lhs = part(&al, &bl, k) - part(&ql, &ml, k) + carry;
        if let Some(limb) = outl.get(k) {
            lhs -= *limb as i128;
        }
        assert_eq!(lhs.rem_euclid(1 << 32), 0, "the shifted identity divides");
        carry = lhs / (1 << 32);
        if k < f::CARRIES {
            assert!(
                carry.unsigned_abs() < f::CARRY_OFFSET as u128,
                "the shifted identity's carry {k} is in range"
            );
            carries.push(carry);
        }
    }
    assert_eq!(carry, 0, "the shifted identity closes");

    let mut columns = witness(&live);
    for k in 0..f::LIMBS {
        columns = corrupt(
            columns,
            mod_mul::word(f::OUT_WORD + k, mod_mul::WORD_WRITE_VALUE),
            row,
            Fr::from_u64(outl[k] as u64),
        );
        columns = corrupt(columns, mod_mul::q_limb(k), row, Fr::from_u64(ql[k] as u64));
        for t in 0..32 {
            columns = corrupt(
                columns,
                mod_mul::value_bit(3, k, t),
                row,
                Fr::from_u64(((outl[k] >> t) & 1) as u64),
            );
            columns = corrupt(
                columns,
                mod_mul::q_bit(k, t),
                row,
                Fr::from_u64(((ql[k] >> t) & 1) as u64),
            );
        }
    }
    let (diff, borrow) = borrow_chain(&outl, &ml);
    for i in 0..f::LIMBS {
        columns = corrupt(
            columns,
            mod_mul::borrow_bit(i),
            row,
            Fr::from_u64(borrow[i]),
        );
        for t in 0..32 {
            columns = corrupt(
                columns,
                mod_mul::diff_bit(i, t),
                row,
                Fr::from_u64((diff[i] >> t) & 1),
            );
        }
    }
    for (k, c) in carries.iter().enumerate().take(f::CARRIES) {
        for t in 0..f::CARRY_BITS {
            let offset = *c + f::CARRY_OFFSET as i128;
            columns = corrupt(
                columns,
                mod_mul::carry_bit(k, t),
                row,
                Fr::from_u64(((offset >> t) & 1) as u64),
            );
        }
    }
    assert_eq!(
        refusal(&a, columns),
        "out_below_modulus",
        "the identity holds for (q−1, r+m) and only `out < m` refuses it"
    );
}

/// A changed quotient limb: the identity no longer divides.
#[test]
fn a_changed_quotient_is_refused() {
    let a = mod_mul::artifact(VARS);
    let columns = witness(&honest());
    let bad = corrupt(columns, mod_mul::q_limb(0), 0, Fr::from_u64(7));
    let relation = refusal(&a, bad);
    assert!(
        relation.starts_with("limb") || relation == "q_word0",
        "a changed quotient is refused by the identity or its decode: {relation}"
    );
}

/// A changed carry: the position that reads it.
#[test]
fn a_changed_carry_is_refused() {
    let a = mod_mul::artifact(VARS);
    let columns = witness(&honest());
    let bad = corrupt(columns, mod_mul::carry_bit(0, 0), 0, Fr::from_u64(1));
    let relation = refusal(&a, bad);
    assert!(
        relation.starts_with("limb"),
        "a changed carry is refused by a limb identity: {relation}"
    );
}

/// A limb above `2^32` — the bound without which the limb identity is an `Fr`
/// equation rather than an integer one. The word's own decode refuses it.
#[test]
fn a_limb_above_its_bound_is_refused() {
    let a = mod_mul::artifact(VARS);
    let columns = witness(&honest());
    let bad = corrupt(
        columns,
        mod_mul::word(f::A_WORD, mod_mul::WORD_READ_VALUE),
        0,
        Fr::from_u64(1 << 33),
    );
    let relation = refusal(&a, bad);
    assert!(
        relation == "a_word0" || relation.starts_with("limb") || relation == "writes_back_w8",
        "a limb past 2^32 is refused by its decode: {relation}"
    );
}

/// A non-boolean bit anywhere: the booleanity gate of that bit.
#[test]
fn a_non_boolean_bit_is_refused() {
    let a = mod_mul::artifact(VARS);
    for (address, name) in [
        (mod_mul::value_bit(0, 0, 0), "m_bit0_0_boolean"),
        (mod_mul::q_bit(3, 5), "q_bit3_5_boolean"),
        (mod_mul::diff_bit(2, 7), "diff2_7_boolean"),
        (mod_mul::carry_bit(4, 9), "carry4_9_boolean"),
    ] {
        let bad = corrupt(witness(&honest()), address, 0, Fr::from_u64(2));
        assert_eq!(refusal(&a, bad), name, "{address}");
    }
}

/// A modulus word the invocation did not write back: the read-only rule.
#[test]
fn a_modulus_the_call_rewrote_is_refused() {
    let a = mod_mul::artifact(VARS);
    let columns = witness(&honest());
    let bad = corrupt(
        columns,
        mod_mul::word(f::M_WORD, mod_mul::WORD_WRITE_VALUE),
        0,
        Fr::from_u64(3),
    );
    assert_eq!(refusal(&a, bad), "writes_back_w0");
}

/// The shape `docs/spec/constraint-manifest.md` §18 accounts for, at the family's
/// **own** height — not `VARS`, which the rest of this file shrinks to four rows
/// so a forward pass fits an ordinary test.
///
/// A digest that moves says only *that* something moved; these numbers say what.
/// `crates/constraints/tests/vectors/mod_mul.txt` carries the same counts beside
/// the digest, and `tools/kat-gen` writes them from the same constructor — this
/// is the third reading, and the one a reviewer can compare against the page.
#[test]
fn the_shape_is_the_manifests() {
    let a = mod_mul::artifact(8);
    assert_eq!(a.trace_vars, 8);
    assert_eq!(a.memory.len(), mod_mul::MEMORY_COLUMNS, "M");
    assert_eq!(a.witness.len(), mod_mul::WITNESS_COLUMNS, "W");
    assert!(a.setup.is_empty(), "no setup column");
    assert!(a.virtuals.is_empty(), "no virtual table");
    assert!(a.lookups.is_empty(), "no lookup");
    assert!(mod_mul::channels().is_empty(), "no channel");
    assert_eq!(a.outputs.len(), 2, "the two memory roots");

    // `lists (row-wise + halving)` and `top`, §1.2's columns.
    assert_eq!(a.layers.len(), 15, "gate lists");
    let halving = a.layers.iter().filter(|l| l.halving).count();
    assert_eq!(halving, 8, "one halving list per trace variable");

    // `inner` is the width of every layer above the base, summed.
    let inner: usize = a.layers.iter().map(|l| l.width as usize).sum();
    assert_eq!(inner, 270, "inner columns");
    assert_eq!(a.relations.len(), 3_763, "relations");

    // The `enforcing (d1/d2)` split. An enforcing relation is one with no
    // output, and **its degree is 1 exactly when no term multiplies two
    // columns** — which in this family means exactly `GateDef::Linear`, every
    // other gate here carrying either a `live` factor or a real product. The
    // degree-1 gates are the 24 `writes_back_w`, the 32 `*_word`, the 8
    // `q_word`, the 8 `chain` and `out_below_modulus`: 73, and nothing else.
    let enforcing: Vec<&constraints::Relation> =
        a.relations.iter().filter(|r| r.output.is_none()).collect();
    let degree1 = enforcing
        .iter()
        .filter(|r| matches!(r.gate, constraints::GateDef::Linear { .. }))
        .count();
    assert_eq!(
        (enforcing.len(), degree1, enforcing.len() - degree1),
        (3_493, 73, 3_420),
        "enforcing (d1/d2)"
    );
    assert_eq!(a.to_bytes().len(), 1_420_188, "wire bytes");
}
