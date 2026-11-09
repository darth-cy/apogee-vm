//! The duplex and its typed messages, by what `docs/spec/transcript.md` §2–§3
//! says of them: that the duplex is Chiesa–Orrù's, what a challenge depends
//! on, what a snapshot resumes, what decoding refuses, and what `io_digest`
//! binds.

use constants::transcript_tags::{
    PUBLIC_INPUTS, SUMCHECK_CHALLENGE, SUMCHECK_FINAL_EVALS, SUMCHECK_ROUND,
};
use field_a64_c5::{Fp, Fp2, A64_C5};
use test_support::Rng;
use transcript_a64_c5::{
    io_digest, poseidon2_permute, Transcript, TranscriptEvent, TranscriptSnapshot, PROTOCOL_ID,
    RATE, WIDTH,
};

/// Chiesa–Orrù's duplex as spongefish writes it (`DuplexSponge`: slice absorb
/// and squeeze over `absorb_pos` and `squeeze_pos`), started from §2's state
/// and framed by §3, sharing only the permutation with the crate.
struct Co25 {
    state: [Fp; WIDTH],
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl Co25 {
    fn new() -> Co25 {
        let mut state = [Fp::ZERO; WIDTH];
        for (i, chunk) in PROTOCOL_ID.chunks(7).enumerate() {
            let mut le = [0u8; 8];
            le[..chunk.len()].copy_from_slice(chunk);
            state[RATE + i] = Fp::from_canonical(u64::from_le_bytes(le)).unwrap();
        }
        Co25 {
            state,
            absorb_pos: 0,
            squeeze_pos: RATE,
        }
    }

    fn absorb(&mut self, mut input: &[Fp]) {
        if input.is_empty() {
            return;
        }
        self.squeeze_pos = RATE;
        while !input.is_empty() {
            if self.absorb_pos == RATE {
                poseidon2_permute(&mut self.state);
                self.absorb_pos = 0;
            } else {
                let n = input.len().min(RATE - self.absorb_pos);
                self.state[self.absorb_pos..self.absorb_pos + n].copy_from_slice(&input[..n]);
                self.absorb_pos += n;
                input = &input[n..];
            }
        }
    }

    fn squeeze(&mut self, mut output: &mut [Fp]) {
        if output.is_empty() {
            return;
        }
        self.absorb_pos = 0;
        while !output.is_empty() {
            if self.squeeze_pos == RATE {
                self.squeeze_pos = 0;
                poseidon2_permute(&mut self.state);
            }
            let n = output.len().min(RATE - self.squeeze_pos);
            let (chunk, rest) = std::mem::take(&mut output).split_at_mut(n);
            chunk.copy_from_slice(&self.state[self.squeeze_pos..self.squeeze_pos + n]);
            self.squeeze_pos += n;
            output = rest;
        }
    }

    fn message(&mut self, tag: u64, n: usize, payload: &[Fp]) {
        self.absorb(&[Fp::from_u64(tag), Fp::from_u64(n as u64)]);
        self.absorb(payload);
    }
}

/// The transcript is the CO25 duplex over §3's framing: every challenge and the
/// closing digest agree on seeded scripts whose messages straddle the rate.
#[test]
fn the_duplex_is_chiesa_orrus() {
    let mut rng = Rng::new(20261107);
    for _ in 0..64 {
        let (mut t, mut model) = (Transcript::new(), Co25::new());
        for _ in 0..(rng.next_u64() % 24) {
            let len = (rng.next_u64() % 19) as usize;
            match rng.next_u64() % 4 {
                0 => {
                    let xs: Vec<Fp> = (0..len).map(|_| Fp::from_u64(rng.next_u64())).collect();
                    t.append_scalars(SUMCHECK_ROUND, &xs);
                    model.message(SUMCHECK_ROUND, len, &xs);
                }
                3 => {
                    let lanes: Vec<Fp> =
                        (0..2 * len).map(|_| Fp::from_u64(rng.next_u64())).collect();
                    let xs: Vec<Fp2> = lanes
                        .chunks(2)
                        .map(|c| Fp2 { c0: c[0], c1: c[1] })
                        .collect();
                    t.append_ext(SUMCHECK_ROUND, &xs);
                    model.message(SUMCHECK_ROUND, 2 * len, &lanes);
                }
                1 => {
                    let bytes = rng.next_bytes(len);
                    let lanes: Vec<Fp> = bytes
                        .chunks(7)
                        .map(|c| Fp::from_u64(c.iter().rev().fold(0, |v, &b| (v << 8) | b as u64)))
                        .collect();
                    t.append_bytes(PUBLIC_INPUTS, &bytes);
                    model.message(PUBLIC_INPUTS, len, &lanes);
                }
                _ => {
                    let mut c = [Fp::ZERO; 2];
                    model.absorb(&[Fp::from_u64(SUMCHECK_CHALLENGE)]);
                    model.squeeze(&mut c);
                    assert_eq!(t.challenge(SUMCHECK_CHALLENGE), Fp2 { c0: c[0], c1: c[1] });
                }
            }
        }
        let mut digest = [Fp::ZERO; RATE];
        model.squeeze(&mut digest);
        assert_eq!(t.digest(), digest);
    }
}

fn all_distinct<T: PartialEq + std::fmt::Debug>(xs: &[T]) {
    for (i, x) in xs.iter().enumerate() {
        for (j, y) in xs[..i].iter().enumerate() {
            assert_ne!(x, y, "cases {j} and {i} agree");
        }
    }
}

/// Scripts that differ in any message, by its tag, its length, a value or a
/// split, draw different challenges. Each pair is one the framing has to keep
/// apart, and the 8-lane rate boundary falls inside several of them.
#[test]
fn every_difference_in_the_messages_moves_the_challenge() {
    let a = Fp::from_u64(7);
    let z = Fp::ZERO;
    let scripts: [&dyn Fn(&mut Transcript); 15] = [
        &|_| {},
        &|t| t.append_scalars(SUMCHECK_ROUND, &[]),
        &|t| t.append_scalar(SUMCHECK_ROUND, a),
        &|t| t.append_scalar(SUMCHECK_FINAL_EVALS, a),
        &|t| t.append_scalars(SUMCHECK_ROUND, &[a, z]),
        &|t| {
            t.append_scalar(SUMCHECK_ROUND, a);
            t.append_scalar(SUMCHECK_ROUND, z);
        },
        &|t| t.append_scalars(SUMCHECK_ROUND, &[a; 6]),
        &|t| t.append_scalars(SUMCHECK_ROUND, &[a; 7]),
        &|t| t.append_bytes(PUBLIC_INPUTS, b""),
        &|t| t.append_bytes(PUBLIC_INPUTS, b"abc"),
        &|t| t.append_bytes(PUBLIC_INPUTS, b"abc\0"),
        &|t| {
            t.append_bytes(PUBLIC_INPUTS, b"ab");
            t.append_bytes(PUBLIC_INPUTS, b"c");
        },
        &|t| t.append_bytes(PUBLIC_INPUTS, &[0xff; 7]),
        &|t| t.append_bytes(PUBLIC_INPUTS, &[0xff; 8]),
        &|t| {
            t.challenge(SUMCHECK_CHALLENGE);
        },
    ];
    let drawn: Vec<Fp2> = scripts
        .iter()
        .map(|script| {
            let mut t = Transcript::new();
            script(&mut t);
            t.challenge(SUMCHECK_CHALLENGE)
        })
        .collect();
    all_distinct(&drawn);
}

/// One step of a script that passes the rate boundary at many offsets.
fn step(t: &mut Transcript, i: usize) -> Option<Fp2> {
    match i % 3 {
        0 => t.append_scalars(SUMCHECK_ROUND, &vec![Fp::from_u64(i as u64); i % 11]),
        1 => t.append_bytes(PUBLIC_INPUTS, &vec![i as u8; 3 * i]),
        _ => return Some(t.challenge(SUMCHECK_CHALLENGE)),
    }
    None
}

/// A snapshot taken after any step, through `postcard`, resumes the stream:
/// every later challenge and the digest agree, and the log starts empty.
#[test]
fn a_snapshot_resumes_the_stream() {
    const STEPS: usize = 30;
    for cut in 0..=STEPS {
        let mut original = Transcript::new();
        for i in 0..cut {
            let _ = step(&mut original, i);
        }

        let mut buf = [0u8; 256];
        let bytes = postcard::to_slice(&original.snapshot(), &mut buf).expect("a snapshot fits");
        let snapshot: TranscriptSnapshot = postcard::from_bytes(bytes).expect("it decodes");
        let mut resumed = Transcript::restore(&snapshot);
        assert!(resumed.event_log().is_empty());

        for i in cut..STEPS {
            assert_eq!(
                step(&mut original, i),
                step(&mut resumed, i),
                "step {i} after {cut}"
            );
        }
        assert_eq!(original.digest(), resumed.digest());
    }
}

/// Decoding refuses a lane at or above `p` and duplex positions no operation
/// sequence reaches; it accepts the positions one does.
#[test]
fn decoding_refuses_what_no_transcript_produces() {
    let decode = |lanes: [u64; WIDTH], absorbed: u8, squeezed: u8| {
        let mut buf = [0u8; 256];
        let lanes = lanes.map(u64::to_le_bytes);
        let bytes = postcard::to_slice(&(lanes, absorbed, squeezed), &mut buf).unwrap();
        assert_eq!(bytes.len(), 8 * WIDTH + 2, "a fixed-size form");
        postcard::from_bytes::<TranscriptSnapshot>(bytes).is_ok()
    };
    let lanes = [1u64; WIDTH];
    let mut high = lanes;
    high[WIDTH - 1] = A64_C5;

    assert!(decode(lanes, 0, 8) && decode(lanes, 8, 8) && decode(lanes, 0, 2));
    assert!(!decode(high, 0, 8), "a lane equal to p");
    assert!(!decode(lanes, 9, 8), "past the rate");
    assert!(!decode(lanes, 0, 9), "past the rate");
    assert!(!decode(lanes, 0, 0), "permuted, nothing read");
    assert!(!decode(lanes, 3, 2), "absorbed and squeezed at once");
}

/// `io_digest` moves when the ordered pair does: swapped, extended by a zero
/// byte, a bit flipped, a byte moved from one stream to the other, or a chunk
/// boundary crossed.
#[test]
fn io_digest_binds_the_ordered_pair() {
    let (a, b) = (b"apogee".to_vec(), b"tenacity".to_vec());
    let mut flipped = a.clone();
    flipped[3] ^= 0x10;
    let pairs = [
        (vec![], vec![]),
        (vec![0], vec![]),
        (vec![], vec![0]),
        (a.clone(), b.clone()),
        (b.clone(), a.clone()),
        ([&a[..], &[0]].concat(), b.clone()),
        (flipped, b.clone()),
        (a[..5].to_vec(), [&a[5..], &b[..]].concat()),
        (vec![7; 7], vec![]),
        (vec![7; 8], vec![]),
    ];
    let digests: Vec<_> = pairs.iter().map(|(i, o)| io_digest(i, o)).collect();
    all_distinct(&digests);
}

#[test]
fn the_event_log_names_each_typed_operation() {
    let mut t = Transcript::new();
    t.append_scalars(SUMCHECK_ROUND, &[Fp::ONE; 3]);
    t.append_bytes(PUBLIC_INPUTS, &[0; 15]);
    t.challenge(SUMCHECK_CHALLENGE);
    assert_eq!(
        t.event_log(),
        [
            TranscriptEvent::Absorb {
                tag: SUMCHECK_ROUND,
                n: 3
            },
            TranscriptEvent::Absorb {
                tag: PUBLIC_INPUTS,
                n: 3
            },
            TranscriptEvent::Challenge {
                tag: SUMCHECK_CHALLENGE
            },
        ]
    );
}
