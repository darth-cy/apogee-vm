//! Regenerates the committed transcript vectors from the reference
//! implementations.
//!
//!     cargo run --manifest-path tools/transcript-ref/Cargo.toml
//!
//! This is the *second implementation* the stage requires. It links the Plonky3
//! Poseidon2 permutation and the HorizenLabs `RC3` constants, and it implements
//! `docs/spec/transcript.md` from the spec text — the duplex, the typed layer,
//! the byte encoding — without ever touching `crates/transcript`. Everything the
//! repository's tests assert about the transcript is produced here.
//!
//! Three files are written, all under `crates/transcript/tests/vectors/`:
//!
//! * `poseidon2_rc3.txt`    — the full upstream 64x3 `RC3` table.
//! * `poseidon2_perm.txt`   — permutation known-answer vectors.
//! * `transcript_cases.txt` — replayable transcript scripts with expected output.
//!
//! Deterministic: same revisions in, byte-identical files out, so a refresh is
//! run-and-diff. CI runs exactly that.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use p3_bn254::{Bn254, Poseidon2Bn254};
use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::Permutation;
use zkhash::ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use zkhash::fields::bn256::FpBN256;
use zkhash::poseidon2::poseidon2_instance_bn256::RC3;

const P3_REV: &str = "7230fc572870436e6651762f35c6c3f3f48960d2";
const ZKHASH_REV: &str = "055bde3f4782731ba5f5ce5888a440a94327eaf3";

/// Seed for the deterministic input stream. splitmix64, owned here so the
/// fixtures do not depend on any RNG crate's stream staying stable.
const SEED: u64 = 20260907;

/// Random permutation vectors, on top of the structured ones. The stage asks
/// for at least 100 in total.
const RANDOM_PERMUTATIONS: usize = 120;

// ---------------------------------------------------------------------------
// Frozen numbers, transcribed from the spec rather than imported.
//
// `constants::transcript_tags` holds the same values in the repository, and
// `crates/transcript/tests/duplex.rs` looks each name up there when it
// replays a case: if the two ever disagree, the absorbed stream changes and the
// replay fails.
// ---------------------------------------------------------------------------

const RATE: usize = 2;

fn tag(name: &str) -> u64 {
    match name {
        "PROTOCOL_SUITE" => 1,
        "PUBLIC_INPUTS" => 2,
        "COMMITMENT" => 3,
        "SUMCHECK_ROUND" => 4,
        "SUMCHECK_CHALLENGE" => 5,
        "EVALUATION_CLAIM" => 6,
        "PCS_OPENING" => 7,
        other => panic!("unknown transcript tag name: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Field helpers over the reference field type.
// ---------------------------------------------------------------------------

fn ark_to_le32(x: FpBN256) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_le();
    assert!(bytes.len() <= 32, "an Fr fits in 32 bytes");
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

fn le32_to_limbs(b: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[8 * i..8 * i + 8]);
        *limb = u64::from_le_bytes(w);
    }
    limbs
}

/// Canonical (non-Montgomery) 32-byte little-endian, the one wire encoding.
fn to_le32(x: Bn254) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.as_canonical_biguint().to_bytes_le();
    assert!(bytes.len() <= 32, "an Fr fits in 32 bytes");
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

/// Any 256-bit little-endian value, reduced mod p.
fn from_le32(b: [u8; 32]) -> Bn254 {
    Bn254::new(le32_to_limbs(b))
}

fn from_u64(x: u64) -> Bn254 {
    Bn254::new([x, 0, 0, 0])
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 * b.len());
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn hex_fr(x: Bn254) -> String {
    hex(&to_le32(x))
}

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_fr(&mut self) -> Bn254 {
        let mut b = [0u8; 32];
        for i in 0..4 {
            b[8 * i..8 * i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
        }
        from_le32(b)
    }

    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

// ---------------------------------------------------------------------------
// The reference permutation: Plonky3's width-3 BN254 Poseidon2, keyed with the
// upstream RC3 constants exactly as Plonky3's own differential test does.
// ---------------------------------------------------------------------------

fn reference_permutation() -> Poseidon2Bn254<3> {
    let mut rounds: Vec<[Bn254; 3]> = RC3
        .iter()
        .map(|row| {
            let mut out = [Bn254::ZERO; 3];
            for (lane, c) in out.iter_mut().zip(row.iter()) {
                *lane = Bn254::new(le32_to_limbs(ark_to_le32(*c)));
            }
            out
        })
        .collect();
    assert_eq!(rounds.len(), 64, "RC3 has 8 full + 56 partial rounds");

    // Rows 4..60 are the partial rounds and contribute lane 0 only; what is left
    // is 4 initial and 4 terminal full rounds.
    let internal: Vec<Bn254> = rounds.drain(4..60).map(|row| row[0]).collect();
    let external = ExternalLayerConstants::new(rounds[..4].to_vec(), rounds[4..].to_vec());
    Poseidon2Bn254::new(external, internal)
}

// ---------------------------------------------------------------------------
// The duplex, written out from the spec text.
//
// Spec sections 5, 6 and 7, transcribed from the prose rather than imported —
// which is what makes the committed vectors a check on the specification and
// not only on Plonky3.
// ---------------------------------------------------------------------------

struct SpecDuplex {
    perm: Poseidon2Bn254<3>,
    state: [Bn254; 3],
    input: Vec<Bn254>,
    output: Vec<Bn254>,
}

impl SpecDuplex {
    fn new() -> SpecDuplex {
        SpecDuplex {
            perm: reference_permutation(),
            state: [Bn254::ZERO; 3],
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    /// Spec section 7. Overwrite absorption; an absorb of `n > 0` elements
    /// zero-fills the rest of the rate and adds `n` to the capacity; a step with
    /// nothing pending is a pure squeeze and does neither.
    fn duplexing(&mut self) {
        let n = self.input.len();
        assert!(n <= RATE, "the input buffer never exceeds the rate");

        for (i, v) in self.input.drain(..).enumerate() {
            self.state[i] = v;
        }
        if n > 0 {
            for lane in self.state[n..RATE].iter_mut() {
                *lane = Bn254::ZERO;
            }
            self.state[RATE] += from_u64(n as u64);
        }

        self.perm.permute_mut(&mut self.state);

        self.output.clear();
        self.output.extend_from_slice(&self.state[..RATE]);
    }

    /// Spec section 5.
    fn observe(&mut self, x: Bn254) {
        self.output.clear();
        self.input.push(x);
        if self.input.len() == RATE {
            self.duplexing();
        }
    }

    /// Spec section 6. Challenges leave the rate from the end.
    fn sample(&mut self) -> Bn254 {
        if !self.input.is_empty() || self.output.is_empty() {
            self.duplexing();
        }
        self.output.pop().expect("duplexing refills the output")
    }
}

// ---------------------------------------------------------------------------
// The driver.
//
// Spec sections 5-7 are also exactly Plonky3's `DuplexChallenger` at width 3 and
// rate 2, so every raw operation runs through both and must agree: the committed
// values come from the spec transcription above, and the reference type confirms
// each one as it is produced. A disagreement fails the generator, and therefore
// CI. Sections 9, 10 and 11 — the framing — are this protocol's own and have no
// upstream counterpart, so they are written out once.
// ---------------------------------------------------------------------------

type Challenger = DuplexChallenger<Bn254, Poseidon2Bn254<3>, 3, RATE>;

struct Duplex {
    spec: SpecDuplex,
    reference: Challenger,
}

impl Duplex {
    fn new() -> Duplex {
        Duplex {
            spec: SpecDuplex::new(),
            reference: DuplexChallenger::new(reference_permutation()),
        }
    }

    /// Spec section 5.
    fn observe(&mut self, x: Bn254) {
        self.spec.observe(x);
        self.reference.observe(x);
    }

    /// Spec section 6.
    fn sample(&mut self) -> Bn254 {
        let from_spec = self.spec.sample();
        let from_reference: Bn254 = self.reference.sample();
        assert_eq!(
            from_spec, from_reference,
            "the spec duplex and Plonky3's DuplexChallenger disagree"
        );
        from_spec
    }

    /// Spec section 9.
    fn append_scalars(&mut self, tag_name: &str, xs: &[Bn254]) {
        self.observe(from_u64(tag(tag_name)));
        self.observe(from_u64(xs.len() as u64));
        for x in xs {
            self.observe(*x);
        }
    }

    /// Spec section 10. 31-byte little-endian chunks, the last zero-padded.
    fn append_bytes(&mut self, tag_name: &str, bytes: &[u8]) {
        self.observe(from_u64(tag(tag_name)));
        self.observe(from_u64(bytes.len() as u64));
        for chunk in bytes.chunks(31) {
            let mut limb = [0u8; 32];
            limb[..chunk.len()].copy_from_slice(chunk);
            self.observe(from_le32(limb));
        }
    }

    /// Spec section 11.
    fn challenge(&mut self, tag_name: &str) -> Bn254 {
        self.observe(from_u64(tag(tag_name)));
        self.sample()
    }
}

// ---------------------------------------------------------------------------
// Case scripts.
// ---------------------------------------------------------------------------

enum Op {
    Observe(Bn254),
    Sample,
    AppendScalar(&'static str, Bn254),
    AppendScalars(&'static str, Vec<Bn254>),
    AppendBytes(&'static str, Vec<u8>),
    Challenge(&'static str),
}

/// Run one case and render it as `case <name> ... end`, with every output
/// filled in from the reference.
fn render_case(name: &str, ops: &[Op]) -> String {
    let mut d = Duplex::new();
    let mut out = format!("case {name}\n");
    for op in ops {
        match op {
            Op::Observe(x) => {
                d.observe(*x);
                let _ = writeln!(out, "  observe {}", hex_fr(*x));
            }
            Op::Sample => {
                let c = d.sample();
                let _ = writeln!(out, "  sample {}", hex_fr(c));
            }
            Op::AppendScalar(t, x) => {
                d.append_scalars(t, &[*x]);
                let _ = writeln!(out, "  append_scalar {t} {}", hex_fr(*x));
            }
            Op::AppendScalars(t, xs) => {
                d.append_scalars(t, xs);
                let _ = write!(out, "  append_scalars {t} {}", xs.len());
                for x in xs {
                    let _ = write!(out, " {}", hex_fr(*x));
                }
                out.push('\n');
            }
            Op::AppendBytes(t, b) => {
                d.append_bytes(t, b);
                // `-` is the empty byte string: an empty field would be
                // invisible in a whitespace-delimited line.
                let rendered = if b.is_empty() {
                    "-".to_string()
                } else {
                    hex(b)
                };
                let _ = writeln!(out, "  append_bytes {t} {} {rendered}", b.len());
            }
            Op::Challenge(t) => {
                let c = d.challenge(t);
                let _ = writeln!(out, "  challenge {t} {}", hex_fr(c));
            }
        }
    }
    out.push_str("end\n\n");
    out
}

fn cases() -> Vec<(String, Vec<Op>)> {
    let mut rng = Rng(SEED);
    let f = |n: u64| from_u64(n);

    let a = rng.next_fr();
    let b = rng.next_fr();

    // The stage's cases A-E.
    let mut v: Vec<(String, Vec<Op>)> = vec![("A".into(), vec![Op::Observe(f(1)), Op::Sample])];
    v.push((
        "B".into(),
        vec![Op::Observe(f(1)), Op::Observe(f(2)), Op::Sample, Op::Sample],
    ));
    v.push((
        "C".into(),
        vec![Op::Observe(f(1)), Op::Sample, Op::Observe(f(2)), Op::Sample],
    ));
    v.push(("D".into(), vec![Op::Observe(f(0)), Op::Sample]));
    v.push((
        "E".into(),
        vec![Op::Observe(f(0)), Op::Observe(f(0)), Op::Sample],
    ));

    // Output order: two samples after one absorb are state[1] then state[0].
    v.push((
        "F_order".into(),
        vec![Op::Observe(f(7)), Op::Sample, Op::Sample],
    ));

    // Repeated squeezing: the third sample has no buffered output left and must
    // permute again.
    v.push((
        "G_squeeze".into(),
        vec![
            Op::Observe(f(3)),
            Op::Sample,
            Op::Sample,
            Op::Sample,
            Op::Sample,
        ],
    ));

    // Three absorbs: the rate fills mid-message, so a duplexing happens with the
    // caller none the wiser.
    v.push((
        "H_three".into(),
        vec![
            Op::Observe(f(5)),
            Op::Observe(f(9)),
            Op::Observe(f(11)),
            Op::Sample,
            Op::Sample,
            Op::Sample,
        ],
    ));

    // Typed layer: tag separation, and per-message framing.
    v.push((
        "T1_tag_x".into(),
        vec![
            Op::AppendScalar("COMMITMENT", a),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));
    v.push((
        "T2_tag_y".into(),
        vec![
            Op::AppendScalar("EVALUATION_CLAIM", a),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));
    v.push((
        "T3_run".into(),
        vec![
            Op::AppendScalars("COMMITMENT", vec![a, b]),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));
    v.push((
        "T4_split".into(),
        vec![
            Op::AppendScalar("COMMITMENT", a),
            Op::AppendScalar("COMMITMENT", b),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));
    v.push((
        "T5_empty_run".into(),
        vec![
            Op::AppendScalars("COMMITMENT", vec![]),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));

    // Byte encoding at every boundary of the 31-byte chunk.
    for n in [0usize, 1, 30, 31, 32, 62, 100] {
        v.push((
            format!("Y{n}_bytes"),
            vec![
                Op::AppendBytes("PUBLIC_INPUTS", rng.next_bytes(n)),
                Op::Challenge("SUMCHECK_CHALLENGE"),
            ],
        ));
    }

    // The length prefix is what keeps "ab" apart from "a" then "b".
    v.push((
        "Y_ab".into(),
        vec![
            Op::AppendBytes("PUBLIC_INPUTS", b"ab".to_vec()),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));
    v.push((
        "Y_a_b".into(),
        vec![
            Op::AppendBytes("PUBLIC_INPUTS", b"a".to_vec()),
            Op::AppendBytes("PUBLIC_INPUTS", b"b".to_vec()),
            Op::Challenge("SUMCHECK_CHALLENGE"),
        ],
    ));

    // A 20-operation mixed script. `crates/transcript/tests/snapshot.rs`
    // snapshots after operation 10 and replays the rest into a fresh transcript.
    let s: Vec<Op> = vec![
        Op::AppendScalar("PROTOCOL_SUITE", rng.next_fr()),
        Op::AppendBytes("PUBLIC_INPUTS", rng.next_bytes(8)),
        Op::Challenge("SUMCHECK_CHALLENGE"),
        Op::AppendScalars(
            "COMMITMENT",
            vec![rng.next_fr(), rng.next_fr(), rng.next_fr()],
        ),
        Op::Observe(rng.next_fr()),
        Op::Sample,
        Op::AppendScalar("SUMCHECK_ROUND", rng.next_fr()),
        Op::Challenge("SUMCHECK_CHALLENGE"),
        Op::Observe(rng.next_fr()),
        Op::Observe(rng.next_fr()),
        // --- snapshot is taken here, after operation 10 ---
        Op::Sample,
        Op::AppendBytes("PUBLIC_INPUTS", rng.next_bytes(33)),
        Op::Challenge("SUMCHECK_CHALLENGE"),
        Op::AppendScalars("EVALUATION_CLAIM", vec![rng.next_fr()]),
        Op::Sample,
        Op::Observe(rng.next_fr()),
        Op::AppendScalar("PCS_OPENING", rng.next_fr()),
        Op::AppendScalar("COMMITMENT", rng.next_fr()),
        Op::Sample,
        Op::Challenge("SUMCHECK_CHALLENGE"),
    ];
    assert_eq!(s.len(), 20, "the snapshot script is 20 operations");
    v.push(("S_mixed".into(), s));

    v
}

// ---------------------------------------------------------------------------
// File writers.
// ---------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/transcript/tests/vectors")
        .canonicalize()
        .expect("crates/transcript/tests/vectors must exist")
}

fn write(name: &str, body: String) {
    let path = vectors_dir().join(name);
    fs::write(&path, body).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    println!("wrote {}", path.display());
}

fn provenance(title: &str) -> String {
    format!(
        "# {title}\n\
         # generated by tools/transcript-ref; do not edit by hand\n\
         # regenerate: cargo run --manifest-path tools/transcript-ref/Cargo.toml\n\
         # permutation: Plonky3 @ {P3_REV}\n\
         # constants:   HorizenLabs/poseidon2 @ {ZKHASH_REV} (RC3)\n\
         # field elements are 32 bytes of lowercase hex, little-endian canonical\n\
         #\n"
    )
}

fn write_rc3() {
    let mut out = provenance("poseidon2_rc3 v1 -- the upstream BN254 width-3 RC3 table");
    out.push_str(
        "# rc <round 0..64> <lane 0..3> <constant>\n\
         # Rows 4..60 are the partial rounds; upstream stores zero in lanes 1 and 2\n\
         # there, which is why `constants` keeps lane 0 only for those rows.\n\n",
    );
    for (round, row) in RC3.iter().enumerate() {
        for (lane, c) in row.iter().enumerate() {
            let _ = writeln!(out, "rc {round} {lane} {}", hex(&ark_to_le32(*c)));
        }
    }
    write("poseidon2_rc3.txt", out);
}

fn write_permutations() {
    let perm = reference_permutation();
    let mut out = provenance("poseidon2_perm v1 -- width-3 BN254 Poseidon2 known-answer vectors");
    out.push_str(
        "# perm <in0> <in1> <in2> <out0> <out1> <out2>\n\
         # The first vector is the stage's [0, 1, 2] KAT; then structured inputs,\n\
         # then random ones.\n\n",
    );

    let minus_one = Bn254::ZERO - Bn254::ONE;
    let mut inputs: Vec<[Bn254; 3]> = vec![
        [from_u64(0), from_u64(1), from_u64(2)],
        [Bn254::ZERO; 3],
        [Bn254::ONE; 3],
        [minus_one; 3],
        [from_u64(1), Bn254::ZERO, Bn254::ZERO],
        [Bn254::ZERO, Bn254::ZERO, from_u64(1)],
        [minus_one, Bn254::ZERO, Bn254::ONE],
        [from_u64(2), from_u64(3), from_u64(5)],
    ];

    let mut rng = Rng(SEED);
    for _ in 0..RANDOM_PERMUTATIONS {
        inputs.push([rng.next_fr(), rng.next_fr(), rng.next_fr()]);
    }

    for input in &inputs {
        let mut state = *input;
        perm.permute_mut(&mut state);
        let _ = writeln!(
            out,
            "perm {} {} {} {} {} {}",
            hex_fr(input[0]),
            hex_fr(input[1]),
            hex_fr(input[2]),
            hex_fr(state[0]),
            hex_fr(state[1]),
            hex_fr(state[2]),
        );
    }
    write("poseidon2_perm.txt", out);
}

fn write_cases() {
    let mut out = provenance("transcript_cases v1 -- replayable duplex and typed-layer scripts");
    out.push_str(
        "# case <name> ... end. One operation per line, in order:\n\
         #\n\
         #   observe        <scalar>                     raw absorb\n\
         #   sample         <expected>                   raw squeeze\n\
         #   append_scalar  <tag> <scalar>               typed, one scalar\n\
         #   append_scalars <tag> <n> <scalar>...        typed, a run of n\n\
         #   append_bytes   <tag> <len> <bytes|->        typed, `-` is empty\n\
         #   challenge      <tag> <expected>             typed challenge\n\
         #\n\
         # Tags are names; the replay resolves them through\n\
         # `constants::transcript_tags`, so a renumbering there breaks this file.\n\n",
    );
    for (name, ops) in cases() {
        out.push_str(&render_case(&name, &ops));
    }
    write("transcript_cases.txt", out);
}

fn main() {
    write_rc3();
    write_permutations();
    write_cases();
}
