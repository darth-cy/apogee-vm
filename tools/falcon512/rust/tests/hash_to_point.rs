//! HashToPoint, the key digest K and the address: functions of their inputs,
//! into their ranges, and moved by any bit of them; the address's text reads
//! back and refuses any digit changed.

use apogee_falcon512::{address, format_address, hash_to_point, key_digest, keygen, parse_address};

/// `p = 2^64 − 59`.
const P: u64 = 0xFFFF_FFFF_FFFF_FFC5;

fn flip(bytes: &[u8], at: usize, bit: u32) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes[at] ^= 1 << bit;
    bytes
}

/// The same inputs give the same point, each coefficient below `q`.
#[test]
fn the_point_is_a_function_into_z_q() {
    let (_, pk) = keygen([0x5a; 32]);
    let c = hash_to_point(&pk, &[7; 40], b"a message", b"a context");
    assert_eq!(c, hash_to_point(&pk, &[7; 40], b"a message", b"a context"));
    assert!(c.iter().all(|&x| x < 12289));
}

/// The first or the last bit of the key, the salt, the message or the context
/// flipped, a zero byte appended to the message or the context, which the
/// lengths tell apart, or the message moved into the context: each moves the
/// point.
#[test]
fn any_input_bit_moves_the_point() {
    let (_, pk) = keygen([0x5a; 32]);
    let (salt, context) = ([7; 40], b"a context");
    let msg: Vec<u8> = (0..92).collect();
    let c = hash_to_point(&pk, &salt, &msg, context);
    for (at, bit) in [(0, 7), (896, 0)] {
        assert_ne!(hash_to_point(&flip(&pk, at, bit), &salt, &msg, context), c);
    }
    for (at, bit) in [(0, 7), (39, 0)] {
        let salt = flip(&salt, at, bit).try_into().unwrap();
        assert_ne!(hash_to_point(&pk, &salt, &msg, context), c);
    }
    for (at, bit) in [(0, 7), (91, 0)] {
        assert_ne!(hash_to_point(&pk, &salt, &flip(&msg, at, bit), context), c);
    }
    for (at, bit) in [(0, 7), (8, 0)] {
        assert_ne!(hash_to_point(&pk, &salt, &msg, &flip(context, at, bit)), c);
    }
    assert_ne!(
        hash_to_point(&pk, &salt, &[&msg[..], &[0]].concat(), context),
        c
    );
    assert_ne!(
        hash_to_point(&pk, &salt, &msg, &[&context[..], &[0]].concat()),
        c
    );
    let moved = hash_to_point(&pk, &salt, &[], &msg);
    assert_ne!(moved, hash_to_point(&pk, &salt, &msg, &[]));
}

/// K is eight canonical lanes, the address is its first 32 bytes, and a key
/// one bit off has another.
#[test]
fn the_key_digest_is_canonical_and_binds_the_key() {
    let (_, pk) = keygen([0x5a; 32]);
    let k = key_digest(&pk);
    let lane = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().unwrap());
    assert!(k.chunks(8).all(|bytes| lane(bytes) < P));
    assert_eq!(address(&pk)[..], k[..32]);
    assert_ne!(key_digest(&flip(&pk, 500, 0)), k);
}

/// The address's text is `0x` and 72 lowercase hex digits; it reads back, its
/// digits in either case, and any one digit changed, the `0x` left out or
/// written `0X`, or a digit more or fewer, is refused.
#[test]
fn the_address_text_reads_back_and_refuses_a_changed_digit() {
    let (_, pk) = keygen([0x5a; 32]);
    let address = address(&pk);
    let text = format_address(&address);
    let lower = |d: u8| matches!(d, b'0'..=b'9' | b'a'..=b'f');
    assert!(text.len() == 74 && text.starts_with("0x") && text[2..].bytes().all(lower));
    assert_eq!(parse_address(&text), Some(address));
    assert_eq!(
        parse_address(&format!("0x{}", text[2..].to_uppercase())),
        Some(address)
    );
    for at in 2..74 {
        let mut changed = text.clone().into_bytes();
        changed[at] = if changed[at] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(changed).unwrap();
        assert_eq!(parse_address(&changed), None, "digit {at}");
    }
    let others: [&str; 4] = [
        &text[2..],
        &text.replacen("0x", "0X", 1),
        &format!("{text}0"),
        &text[..73],
    ];
    for other in others {
        assert_eq!(parse_address(other), None, "{other}");
    }
}
