//! S16's curve-free G1 absorption, `docs/spec/mercury.md` §4 over a point's
//! 64-byte encoding: all-zero is infinity and absorbs the sentinel four times,
//! anything else splits each coordinate at byte 16, and a list is one message.
//! `crates/pcs/tests/kats.rs`' arkworks-derived absorption vectors hold the
//! same split through `pcs::append_g1_list`, which calls this.

use constants::transcript_tags as tags;
use field::Fr;
use transcript::{append_g1_points, g1_limbs, Transcript, TranscriptEvent};

fn limb(bytes: &[u8]) -> Fr {
    let mut b = [0u8; 32];
    b[..bytes.len()].copy_from_slice(bytes);
    Fr::from_bytes(&b).unwrap()
}

#[test]
fn the_generator_and_infinity_absorb_as_the_spec_says() {
    // (1, 2): x low 1, x high 0, y low 2, y high 0.
    let mut g = [0u8; 64];
    g[0] = 1;
    g[32] = 2;
    assert_eq!(g1_limbs(&g), [Fr::ONE, Fr::ZERO, Fr::from_u64(2), Fr::ZERO]);
    let sentinel = Fr::from_hex(constants::G1_INFINITY_SENTINEL).unwrap();
    assert_eq!(g1_limbs(&[0; 64]), [sentinel; 4]);
    // Each byte lands in its own limb.
    let mut p = [0u8; 64];
    for (i, b) in p.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    assert_eq!(
        g1_limbs(&p),
        [
            limb(&p[..16]),
            limb(&p[16..32]),
            limb(&p[32..48]),
            limb(&p[48..])
        ]
    );
    // A limb is never the sentinel: all-ones halves stay below 2^128.
    assert!(g1_limbs(&[0xff; 64]).iter().all(|l| *l != sentinel));
    // One nonzero byte anywhere is not infinity.
    let mut one = [0u8; 64];
    one[63] = 1;
    assert_ne!(g1_limbs(&one), [sentinel; 4]);
}

#[test]
fn a_list_is_one_message_of_every_limb() {
    let mut p = [0u8; 64];
    p[5] = 9;
    let points = [p, [0; 64], p];
    let mut a = Transcript::new();
    append_g1_points(&mut a, tags::COMMITMENT, &points);
    let mut b = Transcript::new();
    let limbs: Vec<Fr> = points.iter().flat_map(g1_limbs).collect();
    b.append_scalars(tags::COMMITMENT, &limbs);
    assert_eq!(a.snapshot(), b.snapshot());
    assert_eq!(
        a.event_log(),
        &[TranscriptEvent::Absorb {
            tag: tags::COMMITMENT,
            n_scalars: 12
        }]
    );
    let mut empty = Transcript::new();
    append_g1_points(&mut empty, tags::COMMITMENT, &[]);
    assert_eq!(
        empty.event_log(),
        &[TranscriptEvent::Absorb {
            tag: tags::COMMITMENT,
            n_scalars: 0
        }]
    );
}
