//! A key's and a signature's advised forms, the guest SDK's: the encodings
//! without their headers and the signature's padding, each a whole number of
//! words, and nothing else converted.

use apogee_falcon512::{key_advice, keygen, sign, signature_advice, SIGNATURE_BYTES};

/// Keys from two seeds and their signatures of messages of 0, 92 and 200
/// bytes: the key's advice is the key after its header, and the signature's
/// the signature after its header through the word holding its last nonzero
/// byte, at most 668 bytes; each header and the zeros after put back give
/// the encoding again.
#[test]
fn advice_is_the_encoding_without_its_header_and_padding() {
    for seed in [[0x5a; 32], [0xc3; 32]] {
        let (sk, pk) = keygen(seed);
        assert_eq!([&[0x09], &key_advice(&pk).unwrap()[..]].concat(), pk);
        for len in [0, 92, 200] {
            let sig = sign(&sk, &vec![seed[0]; len], b"a context");
            let advice = signature_advice(&sig).unwrap();
            assert!(advice.len().is_multiple_of(4) && advice.len() <= 668);
            assert_ne!(
                advice[advice.len() - 4..],
                [0; 4],
                "the last word holds a one"
            );
            let mut encoding = [&[0x39], &advice[..]].concat();
            encoding.resize(SIGNATURE_BYTES, 0);
            assert_eq!(encoding, sig);
        }
    }
}

/// A key or a signature a byte short or a byte long, or under another
/// header, is refused. A one after a signature's last coefficient is the
/// guest's to refuse, and is kept: one in the last byte makes the advice run
/// to its longest, 668 bytes.
#[test]
fn advice_refuses_another_length_or_header() {
    let (sk, pk) = keygen([0x5a; 32]);
    let sig = sign(&sk, b"a message", b"");
    let long = |bytes: &[u8]| [bytes, &[0]].concat();
    let header = |bytes: &[u8], first: u8| [&[first], &bytes[1..]].concat();
    assert_eq!(key_advice(&pk[..896]), Err("a public key is 897 bytes"));
    assert_eq!(key_advice(&long(&pk)), Err("a public key is 897 bytes"));
    assert_eq!(
        key_advice(&header(&pk, 0x0a)),
        Err("a public key's header is 0x09")
    );
    assert_eq!(
        signature_advice(&sig[..665]),
        Err("a signature is 666 bytes")
    );
    assert_eq!(
        signature_advice(&long(&sig)),
        Err("a signature is 666 bytes")
    );
    assert_eq!(
        signature_advice(&header(&sig, 0x29)),
        Err("a signature's header is 0x39")
    );
    let mut stray = sig.clone();
    stray[SIGNATURE_BYTES - 1] |= 1;
    assert_eq!(signature_advice(&stray).unwrap().len(), 668);
}
