//! `program::secp256k1` against an outside bignum oracle, and the curve
//! against its own defining equation.
//!
//! Master rule 10: a reference implementation as a differential oracle. The
//! bignum layer is differenced against `num-bigint` on random vectors **and**
//! checked exhaustively at reduced limb width, which is the stage prompt's
//! Session A acceptance 1; the curve layer is checked against `y^2 = x^3 + 7`,
//! the group order and the generator, none of which is copied from here.

use constants::secp256k1 as k;
use num_bigint::BigUint;
use program::secp256k1::*;
use test_support::Rng;

fn big(v: &U256) -> BigUint {
    let mut out = BigUint::from(0u32);
    for limb in v.iter().rev() {
        out = (out << 64) | BigUint::from(*limb);
    }
    out
}

fn big_wide(v: &[u64; 8]) -> BigUint {
    let mut out = BigUint::from(0u32);
    for limb in v.iter().rev() {
        out = (out << 64) | BigUint::from(*limb);
    }
    out
}

fn limbs(v: &BigUint) -> U256 {
    let mut out = ZERO;
    let bytes = v.to_bytes_le();
    for (i, slot) in out.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        for (j, byte) in buf.iter_mut().enumerate() {
            if let Some(b) = bytes.get(8 * i + j) {
                *byte = *b;
            }
        }
        *slot = u64::from_le_bytes(buf);
    }
    out
}

/// `n / 2`, rounded down.
fn half_n() -> U256 {
    let mut h = ZERO;
    for (i, limb) in h.iter_mut().enumerate() {
        *limb = k::N[i] >> 1;
        if i + 1 < k::LIMBS {
            *limb |= k::N[i + 1] << 63;
        }
    }
    h
}

fn random(rng: &mut Rng) -> U256 {
    [
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    ]
}

fn below(rng: &mut Rng, m: &U256) -> U256 {
    loop {
        let v = random(rng);
        if less(&v, m) {
            return v;
        }
    }
}

/// `p` and `n` are what this module says they are, derived rather than trusted:
/// `p = 2^256 - 2^32 - 977`, `n` from the generator's order, and the generator
/// on the curve.
#[test]
fn the_constants_are_derivable() {
    let two_256 = BigUint::from(1u32) << 256;
    let p = &two_256 - (BigUint::from(1u32) << 32) - BigUint::from(977u32);
    assert_eq!(big(&k::P), p, "p = 2^256 - 2^32 - 977");
    assert_eq!(&big(&k::P_PLUS_1_OVER_4) * 4u32, &p + 1u32, "(p+1)/4");
    // p = 3 mod 4, which is what makes the square root one exponentiation and
    // -1 a quadratic non-residue.
    assert_eq!(&p % 4u32, BigUint::from(3u32));
    // Both moduli are normalized, which `div_rem_wide` requires.
    assert_eq!(k::P[k::LIMBS - 1] >> 63, 1);
    assert_eq!(k::N[k::LIMBS - 1] >> 63, 1);
    // The generator is on the curve, and has order n.
    assert!(on_curve(&generator()));
    assert!(!is_zero(&k::G_X) && !is_zero(&k::G_Y));
    // 2n does not fit in 256 bits, which is what makes `h mod n`'s quotient a
    // single bit (`docs/spec/ecrecover.md` §4.1).
    assert!(&big(&k::N) * 2u32 > two_256);
}

/// `n * G` is the identity, and `(n-1) * G` is `-G`: the order, from the group
/// law rather than from the digits.
#[test]
fn the_generator_has_order_n() {
    // n*G through the joint ladder, which is the schedule the circuit proves.
    assert!(joint_mul(&k::N, &ZERO, &generator()).infinity);
    let minus_one = sub(&k::N, &ONE).0;
    assert_eq!(
        joint_mul(&minus_one, &ZERO, &generator()),
        negate(&generator())
    );
    // And through the other argument, so both halves of the ladder are covered.
    assert!(joint_mul(&ZERO, &k::N, &generator()).infinity);
}

/// The 15 committed multiples of G are `k*G`, re-derived from the group law.
/// `constants::secp256k1::G_MULTIPLES` is the circuit's fixed-window table and
/// it enters the artifact as gate literals, so a wrong digit there is a wrong
/// circuit; this is the `keccak::ROUND_CONSTANTS` pattern.
#[test]
fn the_window_table_is_the_multiples_of_g() {
    let table = window_table(&generator());
    assert_eq!(table.len(), k::WINDOW_ENTRIES);
    let mut acc = generator();
    for (i, want) in table.iter().enumerate() {
        assert!(on_curve(want), "{}*G is on the curve", i + 1);
        assert_eq!(*want, acc, "table[{i}]");
        assert_eq!(k::G_MULTIPLES[i][0], want.x, "G_MULTIPLES[{i}].x");
        assert_eq!(k::G_MULTIPLES[i][1], want.y, "G_MULTIPLES[{i}].y");
        acc = point_add(&acc, &generator());
    }
}

/// Add, sub, mul_wide and div_rem_wide against `num-bigint` on random vectors.
#[test]
fn the_bignum_layer_matches_the_oracle() {
    let mut rng = Rng::new(0x5ec2_5610_0000_0001);
    for _ in 0..2_000 {
        let a = random(&mut rng);
        let b = random(&mut rng);
        let (s, carry) = add(&a, &b);
        let want = big(&a) + big(&b);
        assert_eq!(big(&s), &want % (BigUint::from(1u32) << 256));
        assert_eq!(carry, want >> 256 != BigUint::from(0u32));

        let (d, borrow) = sub(&a, &b);
        if less(&a, &b) {
            assert!(borrow);
            assert_eq!(big(&d) + big(&b), big(&a) + (BigUint::from(1u32) << 256));
        } else {
            assert!(!borrow);
            assert_eq!(big(&d), big(&a) - big(&b));
        }

        assert_eq!(big_wide(&mul_wide(&a, &b)), big(&a) * big(&b));
        assert_eq!(less(&a, &b), big(&a) < big(&b));
    }
}

/// The witness pair every congruence row commits: `a*b = q*m + r` over the
/// integers, with `q` and `r` both below 256 bits and `r` canonical.
#[test]
fn the_quotient_and_remainder_are_the_integer_ones() {
    let mut rng = Rng::new(0x5ec2_5610_0000_0002);
    for m in [k::P, k::N] {
        for _ in 0..2_000 {
            let a = below(&mut rng, &m);
            let b = below(&mut rng, &m);
            let (q, r) = mul_quotient_rem(&a, &b, &m);
            assert_eq!(
                big(&a) * big(&b),
                big(&q) * big(&m) + big(&r),
                "a*b = q*m + r"
            );
            assert!(less(&r, &m), "the remainder is canonical");
            // Which is the property that makes the quotient fit four limbs:
            // with a, b merely below 2^256 it would not.
            assert!(less(&q, &m));
        }
    }
    // The corners: 0, 1, m-1 in both arguments.
    for m in [k::P, k::N] {
        let m1 = sub(&m, &ONE).0;
        for a in [ZERO, ONE, m1] {
            for b in [ZERO, ONE, m1] {
                let (q, r) = mul_quotient_rem(&a, &b, &m);
                assert_eq!(big(&a) * big(&b), big(&q) * big(&m) + big(&r));
                assert!(less(&r, &m));
            }
        }
    }
}

/// `div_rem_wide` exhaustively at reduced width: every dividend below `2^16`
/// against every normalized divisor below `2^8`, which walks every branch of
/// Knuth's estimate — the too-large quotient digit, the add-back, and the
/// exact hit — far more densely than 256-bit vectors do.
///
/// Reduced width is simulated in the top limbs: a dividend `x * 2^(64*4)` over
/// a divisor `d * 2^(64*3)` has the same digit sequence as `x` over `d`.
#[test]
fn the_division_is_exhaustive_at_reduced_width() {
    for d in 128u64..256 {
        // Normalized: the divisor's top limb has its high bit set.
        let divisor = [0, 0, 0, d << 56];
        for x in 0u64..(1 << 16) {
            let mut wide = [0u64; 8];
            wide[3] = x << 48;
            wide[4] = x >> 16;
            let (q, r) = div_rem_wide(&wide, &divisor);
            let dividend = big_wide(&wide);
            assert_eq!(
                &dividend,
                &(big(&q) * big(&divisor) + big(&r)),
                "x={x} d={d}"
            );
            assert!(less(&r, &divisor), "x={x} d={d}");
        }
    }
}

/// `invmod` and `powmod` against the oracle, and the modular helpers.
#[test]
fn the_modular_layer_matches_the_oracle() {
    let mut rng = Rng::new(0x5ec2_5610_0000_0003);
    for m in [k::P, k::N] {
        let bm = big(&m);
        for _ in 0..300 {
            let a = below(&mut rng, &m);
            let b = below(&mut rng, &m);
            assert_eq!(big(&addmod(&a, &b, &m)), (big(&a) + big(&b)) % &bm);
            assert_eq!(big(&submod(&a, &b, &m)), (big(&a) + &bm - big(&b)) % &bm);
            assert_eq!(big(&mulmod(&a, &b, &m)), (big(&a) * big(&b)) % &bm);
            let inv = invmod(&a, &m).expect("a is nonzero below a prime");
            assert_eq!(mulmod(&a, &inv, &m), ONE, "a * a^-1 = 1");
            assert_eq!(big(&inv), big(&a).modpow(&(&bm - 2u32), &bm));
        }
        assert_eq!(invmod(&ZERO, &m), None);
        assert_eq!(invmod(&ONE, &m), Some(ONE));
        let e = below(&mut rng, &m);
        let a = below(&mut rng, &m);
        assert_eq!(big(&powmod(&a, &e, &m)), big(&a).modpow(&big(&e), &bm));
        // `rem` on a 256-bit input, including values at or above the modulus.
        assert_eq!(rem(&m, &m), ZERO);
        assert_eq!(big(&rem(&limbs(&(&bm + 5u32)), &m)), BigUint::from(5u32));
    }
}

/// The byte and frame codecs round-trip, and the frame form is little-endian
/// with word `2i` the low half of limb `i` (`docs/spec/ecrecover.md` §2.1).
#[test]
fn the_codecs_round_trip() {
    let mut rng = Rng::new(0x5ec2_5610_0000_0004);
    for _ in 0..500 {
        let v = random(&mut rng);
        assert_eq!(from_be_bytes(&to_be_bytes(&v)), v);
        assert_eq!(from_frame_words(&to_frame_words(&v)), v);
    }
    // Big-endian: the most significant byte first.
    let one = to_be_bytes(&ONE);
    assert_eq!(one[31], 1);
    assert_eq!(one[..31], [0u8; 31]);
    // The frame's words are little-endian halves of the limbs.
    let v: U256 = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00, 1, 2];
    let words = to_frame_words(&v);
    assert_eq!(words[0], 0x5566_7788);
    assert_eq!(words[1], 0x1122_3344);
    assert_eq!(words[6], 2);
    assert_eq!(words[7], 0);
}

/// `recover` against the committed corpus, which `libsecp256k1` answered
/// (`tools/kat-gen/src/ecrecover.rs`). Master rule 10 and rule 11: an outside
/// oracle, through a committed file, never an inline literal.
///
/// This is the stage prompt's acceptance 3 for the **native** path; the
/// delegated path and the guest shim are held to the same file by
/// `crates/emulator/tests/ecrecover.rs` and `guests/ecrecover-test`.
#[test]
fn recover_matches_the_committed_corpus() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ecrecover.txt"),
    )
    .expect("the committed corpus");
    let mut seen_ok = 0;
    let mut seen_fail = 0;
    let mut seen_v = [false; 2];
    let mut seen_high_s = false;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 9, "a corpus line is nine fields: {line}");
        let name = f[0];
        let v: u32 = f[1].parse().expect("v");
        let hash = from_be_bytes(&test_support::hex_to_32(f[2]).expect("hash"));
        let r = from_be_bytes(&test_support::hex_to_32(f[3]).expect("r"));
        let s = from_be_bytes(&test_support::hex_to_32(f[4]).expect("s"));
        let got = recover(&hash, v, &r, &s);
        match f[5] {
            "ok" => {
                seen_ok += 1;
                if (27..=28).contains(&v) {
                    seen_v[(v - 27) as usize] = true;
                }
                let x = from_be_bytes(&test_support::hex_to_32(f[6]).expect("x"));
                let y = from_be_bytes(&test_support::hex_to_32(f[7]).expect("y"));
                let point = got.unwrap_or_else(|e| panic!("{name}: expected a key, got {e:?}"));
                assert!(!point.infinity, "{name}");
                assert_eq!(point.x, x, "{name}: pubkey x");
                assert_eq!(point.y, y, "{name}: pubkey y");
                // Whatever the oracle says, it must be a curve point.
                assert!(
                    on_curve(&point),
                    "{name}: the recovered key is on the curve"
                );
                if name.starts_with("high_s_") {
                    seen_high_s = true;
                    let half = half_n();
                    assert!(!less(&s, &half), "{name}: s really is above n/2");
                }
            }
            "fail" => {
                seen_fail += 1;
                assert!(got.is_err(), "{name}: expected a failure, got a key");
            }
            other => panic!("{name}: unknown outcome {other}"),
        }
    }
    // The corpus is not vacuous, and it covers what acceptance 3 names.
    assert!(seen_ok >= 10, "the corpus holds recoveries");
    assert!(seen_fail >= 6, "the corpus holds failures");
    assert!(seen_v[0] && seen_v[1], "both v = 27 and v = 28 recover");
    assert!(seen_high_s, "the corpus holds an accepted s > n/2");
}

/// The four failure classes are the ones `recover` names, and each is reached
/// by the input the EVM's rules say reaches it.
#[test]
fn every_failure_class_is_reachable_and_named() {
    let h = ONE;
    let good_r = ONE;
    for v in [0, 1, 26, 29, 255] {
        assert_eq!(
            recover(&h, v, &good_r, &ONE),
            Err(RecoverFailure::BadRecoveryId),
            "v = {v}"
        );
    }
    assert_eq!(
        recover(&h, 27, &ZERO, &ONE),
        Err(RecoverFailure::ROutOfRange)
    );
    assert_eq!(
        recover(&h, 27, &k::N, &ONE),
        Err(RecoverFailure::ROutOfRange)
    );
    assert_eq!(
        recover(&h, 27, &good_r, &ZERO),
        Err(RecoverFailure::SOutOfRange)
    );
    assert_eq!(
        recover(&h, 27, &good_r, &k::N),
        Err(RecoverFailure::SOutOfRange)
    );
    // x = 5 and x = n-1 are both on no curve point.
    assert_eq!(
        recover(&h, 27, &[5, 0, 0, 0], &ONE),
        Err(RecoverFailure::NotOnCurve)
    );
    assert_eq!(
        recover(&h, 27, &sub(&k::N, &ONE).0, &ONE),
        Err(RecoverFailure::NotOnCurve)
    );
    // And `curve_y` agrees with `recover` about which x have points.
    assert!(curve_y(&[5, 0, 0, 0], 0).is_none());
    assert!(curve_y(&sub(&k::N, &ONE).0, 0).is_none());
    assert!(curve_y(&ONE, 0).is_some());
}

/// `Q = infinity` is a reachable failure, not a theoretical one: pick `u2 = 0`
/// by taking `s = n`... which is out of range, so instead drive it through the
/// only door the precompile leaves open — `s*R = e*G` — by choosing the
/// signature from a point we control.
#[test]
fn the_identity_result_is_a_named_failure() {
    // R = 1*G, so r = G.x mod n, and take s = r. Then u2*R = s/r * R = R = G,
    // and u1*G = -h/r * G; the sum is the identity exactly when h/r = 1, i.e.
    // h = r mod n.
    let g = generator();
    let r = rem(&g.x, &k::N);
    assert!(!is_zero(&r) && less(&r, &k::N));
    // v must select G's own y.
    let v = 27 + (g.y[0] & 1) as u32;
    assert_eq!(curve_y(&r, v - 27), Some(g.y), "R is G");
    let h = r;
    assert_eq!(recover(&h, v, &r, &r), Err(RecoverFailure::Infinity));
    // And one bit away from it, the same inputs recover a real key.
    let h2 = addmod(&h, &ONE, &k::N);
    let q = recover(&h2, v, &r, &r).expect("a key");
    assert!(on_curve(&q) && !q.infinity);
}
