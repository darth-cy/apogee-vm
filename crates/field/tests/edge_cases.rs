//! Explicit edge cases, wire-format rules, and `batch_inverse` behaviour.

mod common;

use common::{ark_to_bytes, to_ark, Rng};
use constants::{FR_MODULUS, FR_R, FR_R2};
use field::{batch_inverse, Fr};

const SEED: u64 = 0xed6e_ca5e_0000_0001;

fn limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[8 * i..8 * i + 8].copy_from_slice(&limbs[i].to_le_bytes());
    }
    b
}

/// 0, 1, p-1, R and R^2 as field element *values*.
fn edge_set() -> Vec<(&'static str, Fr)> {
    let r = Fr::from_bytes(&limbs_to_bytes(&FR_R)).expect("R < p");
    let r2 = Fr::from_bytes(&limbs_to_bytes(&FR_R2)).expect("R^2 < p");
    vec![
        ("0", Fr::ZERO),
        ("1", Fr::ONE),
        ("p-1", Fr::MINUS_ONE),
        ("R", r),
        ("R^2", r2),
    ]
}

#[test]
fn edge_values_match_arkworks_for_every_op() {
    for (na, a) in edge_set() {
        for (nb, b) in edge_set() {
            let (aa, ab) = (to_ark(&a), to_ark(&b));
            assert_eq!((a + b).to_bytes(), ark_to_bytes(&(aa + ab)), "{na} + {nb}");
            assert_eq!((a - b).to_bytes(), ark_to_bytes(&(aa - ab)), "{na} - {nb}");
            assert_eq!((a * b).to_bytes(), ark_to_bytes(&(aa * ab)), "{na} * {nb}");
        }

        let aa = to_ark(&a);
        assert_eq!(a.square().to_bytes(), ark_to_bytes(&(aa * aa)), "{na}^2");
        assert_eq!((-a).to_bytes(), ark_to_bytes(&(-aa)), "-{na}");

        match (a.inverse(), ark_ff::Field::inverse(&aa)) {
            (None, None) => assert_eq!(a, Fr::ZERO, "only zero has no inverse"),
            (Some(o), Some(t)) => assert_eq!(o.to_bytes(), ark_to_bytes(&t), "1/{na}"),
            _ => panic!("inverse disagrees with arkworks on {na}"),
        }

        for e in [[0u64; 4], [1, 0, 0, 0], [2, 0, 0, 0], [u64::MAX; 4]] {
            let theirs = ark_ff::Field::pow(&aa, e);
            assert_eq!(a.pow(&e).to_bytes(), ark_to_bytes(&theirs), "{na}^{e:?}");
        }
    }
}

#[test]
fn inverse_of_zero_is_none() {
    assert_eq!(Fr::ZERO.inverse(), None);
}

#[test]
fn minus_one_identities() {
    assert_eq!(Fr::MINUS_ONE + Fr::ONE, Fr::ZERO, "(p-1) + 1 == 0");
    assert_eq!(Fr::MINUS_ONE * Fr::MINUS_ONE, Fr::ONE, "(p-1) * (p-1) == 1");
    assert_eq!(Fr::MINUS_ONE, Fr::ZERO - Fr::ONE, "the MINUS_ONE literal");
    assert_eq!(Fr::MINUS_ONE, -Fr::ONE);
    assert_eq!(Fr::MINUS_ONE.inverse(), Some(Fr::MINUS_ONE));
}

#[test]
fn identities_hold() {
    assert_eq!(Fr::ZERO + Fr::ZERO, Fr::ZERO);
    assert_eq!(Fr::ZERO - Fr::ZERO, Fr::ZERO);
    assert_eq!(
        -Fr::ZERO,
        Fr::ZERO,
        "negating zero must stay canonical zero"
    );
    assert_eq!(Fr::ZERO * Fr::ONE, Fr::ZERO);
    assert_eq!(Fr::ONE * Fr::ONE, Fr::ONE);
    assert_eq!(Fr::ZERO.square(), Fr::ZERO);
    assert_eq!(Fr::ONE.square(), Fr::ONE);
    assert_eq!(Fr::ZERO.pow(&[0, 0, 0, 0]), Fr::ONE, "x^0 == 1 for every x");
    assert_eq!(Fr::ZERO.pow(&[1, 0, 0, 0]), Fr::ZERO);
    assert_eq!(Fr::ONE.inverse(), Some(Fr::ONE));
    assert_eq!(Fr::from_u64(0), Fr::ZERO);
    assert_eq!(Fr::from_u64(1), Fr::ONE);
}

#[test]
fn one_serializes_as_non_montgomery() {
    let mut want = [0u8; 32];
    want[0] = 1;
    assert_eq!(
        Fr::ONE.to_bytes(),
        want,
        "ONE must be 1 followed by 31 zero bytes, not the Montgomery limbs"
    );
    assert_eq!(Fr::ZERO.to_bytes(), [0u8; 32]);

    // p - 1 on the wire, computed from the frozen modulus limbs.
    let mut minus_one = limbs_to_bytes(&FR_MODULUS);
    minus_one[0] -= 1;
    assert_eq!(Fr::MINUS_ONE.to_bytes(), minus_one);
}

#[test]
fn non_canonical_input_is_rejected() {
    assert_eq!(Fr::from_bytes(&limbs_to_bytes(&FR_MODULUS)), None, "p");
    assert_eq!(Fr::from_bytes(&[0xff; 32]), None, "2^256 - 1");

    // p + 1 and p - 1 straddle the boundary.
    let mut p_plus_one = limbs_to_bytes(&FR_MODULUS);
    p_plus_one[0] += 1;
    assert_eq!(Fr::from_bytes(&p_plus_one), None, "p + 1");

    let mut p_minus_one = limbs_to_bytes(&FR_MODULUS);
    p_minus_one[0] -= 1;
    assert_eq!(Fr::from_bytes(&p_minus_one), Some(Fr::MINUS_ONE), "p - 1");
}

#[test]
fn wire_roundtrip_over_random_elements() {
    let mut rng = Rng::new(SEED);
    for _ in 0..1_000 {
        let x = rng.next_fr();
        assert_eq!(Fr::from_bytes(&x.to_bytes()), Some(x));
    }
}

#[test]
fn serde_roundtrip_over_random_elements() {
    let mut rng = Rng::new(SEED ^ 1);
    for _ in 0..1_000 {
        let x = rng.next_fr();
        let mut buf = [0u8; 64];
        let wire = postcard::to_slice(&x, &mut buf).expect("serializing Fr cannot fail");
        assert_eq!(wire, &x.to_bytes()[..], "serde emits canonical bytes");
        let back: Fr = postcard::from_bytes(wire).expect("roundtrip");
        assert_eq!(back, x);
    }
}

#[test]
fn serde_rejects_non_canonical_bytes() {
    assert!(
        postcard::from_bytes::<Fr>(&[0xff; 32]).is_err(),
        "deserialization must refuse a value >= p"
    );
    assert!(
        postcard::from_bytes::<Fr>(&limbs_to_bytes(&FR_MODULUS)).is_err(),
        "deserialization must refuse exactly p"
    );
}

#[test]
fn debug_prints_canonical_big_endian_hex() {
    assert_eq!(
        format!("{:?}", Fr::ONE),
        "Fr(0x0000000000000000000000000000000000000000000000000000000000000001)"
    );
    assert_eq!(
        format!("{:?}", Fr::MINUS_ONE),
        "Fr(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000)"
    );
}

/// Reference: element-wise `inverse`, zeros preserved.
fn naive_batch_inverse(xs: &[Fr]) -> Vec<Fr> {
    xs.iter().map(|x| x.inverse().unwrap_or(Fr::ZERO)).collect()
}

#[test]
fn batch_inverse_at_required_lengths() {
    let mut rng = Rng::new(SEED ^ 2);
    for len in [0usize, 1, 2, 1_000] {
        // Zeros interleaved with nonzeros; every length also gets an all-zero
        // and an all-nonzero variant.
        let mixed: Vec<Fr> = (0..len)
            .map(|i| if i % 3 == 0 { Fr::ZERO } else { rng.next_fr() })
            .collect();
        let all_zero: Vec<Fr> = vec![Fr::ZERO; len];
        let all_nonzero: Vec<Fr> = (0..len).map(|_| rng.next_fr()).collect();

        for input in [mixed, all_zero, all_nonzero] {
            let want = naive_batch_inverse(&input);
            let mut got = input.clone();
            batch_inverse(&mut got);
            assert_eq!(got, want, "batch_inverse at len {len}");

            for (x, inv) in input.iter().zip(got.iter()) {
                if *x == Fr::ZERO {
                    assert_eq!(*inv, Fr::ZERO, "zero must stay zero");
                } else {
                    assert_eq!(*x * *inv, Fr::ONE, "x * x^-1 == 1");
                }
            }
        }
    }
}

#[test]
fn batch_inverse_boundary_shapes() {
    // Leading zero, trailing zero, adjacent zeros, and the edge values.
    let mut rng = Rng::new(SEED ^ 3);
    let a = rng.next_fr();
    let b = rng.next_fr();
    let cases: Vec<Vec<Fr>> = vec![
        vec![Fr::ZERO],
        vec![Fr::ONE],
        vec![Fr::ZERO, a],
        vec![a, Fr::ZERO],
        vec![Fr::ZERO, Fr::ZERO],
        vec![Fr::ZERO, Fr::ZERO, a, Fr::ZERO, Fr::ZERO, b, Fr::ZERO],
        vec![Fr::ONE, Fr::MINUS_ONE, Fr::ZERO, Fr::ONE],
    ];
    for input in cases {
        let want = naive_batch_inverse(&input);
        let mut got = input.clone();
        batch_inverse(&mut got);
        assert_eq!(got, want, "batch_inverse on {input:?}");
    }
}

// ---------------------------------------------------------------------------
// `from_hex`: the source-literal form for frozen constant tables.
//
// Big-endian, `0x`-prefixed, exactly 64 lowercase digits — the order `Debug`
// prints and the order upstream tables are written in, deliberately not the
// little-endian byte order of `to_bytes`.
// ---------------------------------------------------------------------------

/// Big-endian hex for a value, the way `from_hex` expects to read it.
fn be_hex(x: &Fr) -> String {
    let mut s = String::from("0x");
    for b in x.to_bytes().iter().rev() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn from_hex_reads_big_endian() {
    let one = format!("0x{:0>64}", "1");
    assert_eq!(Fr::from_hex(&one), Some(Fr::ONE));
    assert_eq!(Fr::from_hex(&format!("0x{:0>64}", "0")), Some(Fr::ZERO));

    // 0x0102 is 258, not 513: the last digits are the least significant.
    assert_eq!(
        Fr::from_hex(&format!("0x{:0>64}", "102")),
        Some(Fr::from_u64(258))
    );

    // The same value, read as little-endian bytes, is something else entirely.
    let mut le = [0u8; 32];
    le[30] = 0x01;
    le[31] = 0x02;
    assert_ne!(Fr::from_bytes(&le), Some(Fr::from_u64(258)));
}

#[test]
fn from_hex_round_trips_every_edge_value_and_random_ones() {
    let mut values = vec![Fr::ZERO, Fr::ONE, Fr::MINUS_ONE, Fr::from_u64(u64::MAX)];
    let mut rng = Rng::new(SEED ^ 7);
    for _ in 0..200 {
        values.push(rng.next_fr());
    }
    for x in values {
        assert_eq!(Fr::from_hex(&be_hex(&x)), Some(x), "round trip for {x:?}");
        // `Debug` prints the same digits, which is the point of the ordering.
        assert_eq!(format!("{x:?}"), format!("Fr({})", be_hex(&x)));
    }
}

#[test]
fn from_hex_has_exactly_one_accepted_spelling() {
    let valid = be_hex(&Fr::from_u64(0xdead_beef));
    assert!(Fr::from_hex(&valid).is_some(), "the control must parse");

    let digits = valid.trim_start_matches("0x");
    let rejected = [
        digits.to_string(),                     // no prefix
        format!("0X{digits}"),                  // uppercase prefix
        format!("0x{}", &digits[1..]),          // 63 digits
        format!("0x0{digits}"),                 // 65 digits
        format!("0x{}", digits.to_uppercase()), // uppercase digits
        format!("0x{}g", &digits[1..]),         // non-hex digit
        format!("0x{}", " ".repeat(64)),        // whitespace
        String::new(),
        "0x".to_string(),
    ];
    for s in rejected {
        assert_eq!(Fr::from_hex(&s), None, "must reject {s:?}");
    }
}

#[test]
fn from_hex_rejects_values_at_or_above_the_modulus() {
    // p itself, and p written one digit larger, and the all-ones word.
    let p = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    assert_eq!(Fr::from_hex(p), None, "p is not canonical");

    let p_plus_one = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002";
    assert_eq!(Fr::from_hex(p_plus_one), None);

    assert_eq!(Fr::from_hex(&format!("0x{}", "f".repeat(64))), None);

    // p - 1 is the largest value it does accept.
    let p_minus_one = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
    assert_eq!(Fr::from_hex(p_minus_one), Some(Fr::MINUS_ONE));
}
