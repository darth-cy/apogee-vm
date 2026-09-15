//! The toy circuit, a satisfying base for it, and the harness both sides of
//! the protocol share: bind the base, draw the external challenge after it,
//! prove, verify, discharge.

#![allow(dead_code)]

use constants::{challenge_slot, transcript_tags};
use constraints::{
    CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION,
};
use field::Fr;
use gkr::{
    forward, prove, verify, BaseClaim, BaseLayer, ExternalChallenges, GkrError, GkrProof,
    LayerValues, OutputClaims,
};
use poly::{MultilinearPoly, PolyBacking};
use sumcheck::{absorb_witness_digest, witness_digest};
use test_support::{sha256, to_hex, Rng};
use transcript::Transcript;

pub const TOY_CACHED_SHA256: &str =
    "ee27e1192c4bcf9afa003509f6c06fead29628b02a4c17f86e381bf5609f1c70";
pub const TOY_CACHE_FREE_SHA256: &str =
    "5318afeb5b5ba5d09871358c89db36a0db12680fa9559a70c67c50b41181251d";

/// A committed artifact, pinned before it is decoded.
pub fn fixture(name: &str, digest: &str) -> CircuitArtifact {
    let path = format!(
        "{}/../constraints/tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    assert_eq!(
        to_hex(&sha256(&bytes)),
        digest,
        "{name} changed: regenerate with `cargo run -p kat-gen -- gkr` and repin"
    );
    CircuitArtifact::from_bytes(&bytes).unwrap_or_else(|e| panic!("decoding {name}: {e}"))
}

pub fn toy() -> CircuitArtifact {
    fixture("toy_cached.bin", TOY_CACHED_SHA256)
}

pub fn toy_cache_free() -> CircuitArtifact {
    fixture("toy_cache_free.bin", TOY_CACHE_FREE_SHA256)
}

/// The toy's committed columns, in layout order `m, a, b, c, e, s`, as raw
/// tables. `a`, `b`, `c`, `m` random; `s` random bits; `e = a` wherever
/// `s = 1` and random elsewhere, so the gated equality holds on every row.
pub struct ToyColumns {
    pub m: Vec<u32>,
    pub a: Vec<u32>,
    pub b: Vec<u32>,
    pub c: Vec<u32>,
    pub e: Vec<u32>,
    pub s: Vec<u32>,
}

pub const TOY_ROWS: usize = 16;

pub fn toy_columns(seed: u64) -> ToyColumns {
    let mut rng = Rng::new(seed);
    let mut draw = || -> Vec<u32> { (0..TOY_ROWS).map(|_| rng.next_u64() as u32).collect() };
    let (m, a, b, c, mut e) = (draw(), draw(), draw(), draw(), draw());
    let s: Vec<u32> = draw().iter().map(|x| x & 1).collect();
    for y in 0..TOY_ROWS {
        if s[y] == 1 {
            e[y] = a[y];
        }
    }
    ToyColumns { m, a, b, c, e, s }
}

/// The columns as a base layer, each at its natural width.
pub fn toy_base(cols: &ToyColumns) -> BaseLayer {
    let u32s = |v: &[u32]| MultilinearPoly::new(PolyBacking::U32(v.to_vec()));
    let bits = |v: &[u32]| {
        let mut limb = 0u64;
        for (y, x) in v.iter().enumerate() {
            limb |= (*x as u64) << y;
        }
        MultilinearPoly::new(PolyBacking::U1(vec![limb], v.len()))
    };
    BaseLayer::new(vec![
        (PolyAddress::Memory(0), u32s(&cols.m)),
        (PolyAddress::Witness(0), u32s(&cols.a)),
        (PolyAddress::Witness(1), u32s(&cols.b)),
        (PolyAddress::Witness(2), u32s(&cols.c)),
        (PolyAddress::Witness(3), u32s(&cols.e)),
        (PolyAddress::Setup(0), bits(&cols.s)),
    ])
}

/// A base layer with one column replaced by `Fr` values.
pub fn with_column(
    base: &BaseLayer,
    artifact: &CircuitArtifact,
    address: PolyAddress,
    values: Vec<Fr>,
) -> BaseLayer {
    BaseLayer::new(
        artifact
            .committed()
            .into_iter()
            .map(|a| {
                let column = if a == address {
                    MultilinearPoly::new(PolyBacking::Fr(values.clone()))
                } else {
                    base.get(a).expect("a committed column").clone()
                };
                (a, column)
            })
            .collect(),
    )
}

/// The committed columns in layout order: what the digest binds and what
/// `BaseClaim`s are discharged against.
pub fn committed_columns(artifact: &CircuitArtifact, base: &BaseLayer) -> Vec<MultilinearPoly> {
    artifact
        .committed()
        .iter()
        .map(|a| base.get(*a).expect("a committed column").clone())
        .collect()
}

/// Bind the base's digest into a fresh transcript, then draw the toy's
/// external challenge from it — after the binding, as the caller must.
pub fn bind(artifact: &CircuitArtifact, base: &BaseLayer) -> (Transcript, ExternalChallenges) {
    let mut t = Transcript::new();
    absorb_witness_digest(&mut t, witness_digest(&committed_columns(artifact, base)));
    let mut challenges = ExternalChallenges::new();
    challenges.insert(
        challenge_slot::TOY,
        t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE),
    );
    (t, challenges)
}

/// The top layer as the verifier is told it: one table per output-map entry.
pub fn output_claims(artifact: &CircuitArtifact, values: &LayerValues) -> OutputClaims {
    let top = values.layers.last().expect("a circuit has a top layer");
    OutputClaims {
        tables: artifact
            .outputs
            .iter()
            .map(|out| match *out {
                PolyAddress::Inner { offset, .. } => top[offset as usize].clone(),
                other => panic!("an output is an inner address, not {other}"),
            })
            .collect(),
    }
}

/// One honest run: forward over `base`, prove over `values` (which a test may
/// have tampered with), and verify against `outputs`, each side on its own
/// transcript bound to `bound` — the base the digest is taken over.
pub fn run(
    artifact: &CircuitArtifact,
    bound: &BaseLayer,
    values: &LayerValues,
    outputs: &OutputClaims,
) -> (GkrProof, Result<Vec<BaseClaim>, GkrError>) {
    let (mut prover, challenges) = bind(artifact, bound);
    let proof = prove(artifact, values, &challenges, &mut prover);
    let (mut verifier, challenges) = bind(artifact, bound);
    let result = verify(artifact, &proof, outputs, &challenges, &mut verifier);
    (proof, result)
}

/// Forward, then `run` with the honest outputs.
pub fn honest(
    artifact: &CircuitArtifact,
    base: &BaseLayer,
) -> (LayerValues, GkrProof, Result<Vec<BaseClaim>, GkrError>) {
    let (_, challenges) = bind(artifact, base);
    let values = forward(artifact, base, &challenges);
    let outputs = output_claims(artifact, &values);
    let (proof, result) = run(artifact, base, &values, &outputs);
    (values, proof, result)
}

/// The discharge a Mercury opening will replace: every base claim against the
/// committed column it names.
pub fn discharge(base: &BaseLayer, claims: &[BaseClaim]) -> Result<(), String> {
    for claim in claims {
        let column = base
            .get(claim.address)
            .ok_or_else(|| format!("no committed column {}", claim.address))?;
        let actual = column.evaluate(&claim.point);
        if actual != claim.value {
            return Err(format!(
                "{}: claimed {:?}, the column evaluates to {actual:?}",
                claim.address, claim.value
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Circuits beyond the toy, built in the tests that need them
// ---------------------------------------------------------------------------

/// A base of `Fr` columns, given in layout order.
pub fn fr_base(artifact: &CircuitArtifact, columns: Vec<Vec<Fr>>) -> BaseLayer {
    let committed = artifact.committed();
    assert_eq!(
        columns.len(),
        committed.len(),
        "one column per committed address"
    );
    BaseLayer::new(
        committed
            .into_iter()
            .zip(columns)
            .map(|(a, c)| (a, MultilinearPoly::new(PolyBacking::Fr(c))))
            .collect(),
    )
}

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn copy(x: PolyAddress) -> GateDef {
    GateDef::Linear {
        terms: vec![(lit(1), x)],
        constant: lit(0),
    }
}

fn relation(name: &str, output: Option<u32>, gate: GateDef) -> Relation {
    Relation {
        name: name.into(),
        output,
        gate,
    }
}

/// A witness-only circuit whose all-zero row is its padding row, validated.
pub fn circuit(
    trace_vars: u32,
    witness: &[&str],
    layers: Vec<LayerSpec>,
    relations: Vec<Relation>,
    scratch: &[(&str, PolyAddress)],
    outputs: Vec<PolyAddress>,
) -> CircuitArtifact {
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars,
        memory: vec![],
        witness: witness.iter().map(|n| n.to_string()).collect(),
        setup: vec![],
        virtuals: vec![],
        layers,
        relations,
        lookups: vec![],
        scratch: scratch
            .iter()
            .map(|(name, address)| ScratchSlot {
                name: name.to_string(),
                address: *address,
            })
            .collect(),
        outputs,
        padding: Padding {
            row: vec![Fr::ZERO; witness.len()],
            zero_row_valid: true,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("a test circuit is not a circuit: {e}");
    }
    artifact
}

/// The smallest shapes `docs/spec/gkr.md` calls legal, in one circuit:
///
/// ```text
/// base      W[0] a                               2 rows: trace_vars 1
/// list 0    L{1}[0] sq   = a·(a − 1)             row-wise, 1 variable
/// list 1    L{2}[0] root = sq(·,0)·sq(·,1)       halving, down to 0 variables
/// list 2    0 = root                             row-wise over 0 variables, enforcing only
/// outputs   none                                 layer 3 has width 0
/// ```
///
/// Transitions 1 and 2 have no rounds, so each final check is all that ties
/// its claims to anything. Every row of `a` in `{0, 1}` satisfies it.
pub fn root_circuit() -> CircuitArtifact {
    let a = PolyAddress::Witness(0);
    let sq = PolyAddress::Inner {
        layer: 1,
        offset: 0,
    };
    let root = PolyAddress::Inner {
        layer: 2,
        offset: 0,
    };
    let square = |x: PolyAddress| GateDef::AffineProduct {
        left: vec![(lit(1), x)],
        left_constant: lit(0),
        right: vec![(lit(1), x)],
        right_constant: neg(1),
    };
    circuit(
        1,
        &["a"],
        vec![
            LayerSpec {
                halving: false,
                num_vars: 1,
                width: 1,
                cached: vec![],
                producing: vec![ProducingEntry {
                    relation: 0,
                    output: sq,
                    gate: square(a),
                }],
                enforcing: vec![],
            },
            LayerSpec {
                halving: true,
                num_vars: 0,
                width: 1,
                cached: vec![],
                producing: vec![ProducingEntry {
                    relation: 1,
                    output: root,
                    gate: GateDef::TreeProduct { input: sq },
                }],
                enforcing: vec![],
            },
            LayerSpec {
                halving: false,
                num_vars: 0,
                width: 0,
                cached: vec![],
                producing: vec![],
                enforcing: vec![EnforcingEntry {
                    relation: 2,
                    gate: copy(root),
                }],
            },
        ],
        vec![
            relation("define_sq", Some(0), square(a)),
            relation(
                "define_root",
                Some(1),
                GateDef::TreeProduct {
                    input: PolyAddress::Scratch(0),
                },
            ),
            relation("root_is_zero", None, copy(PolyAddress::Scratch(1))),
        ],
        &[("sq", sq), ("root", root)],
        vec![],
    )
}

/// Two enforcing gates in one list, each the other's negation:
///
/// ```text
/// base      W[0] a   W[1] b                      4 rows
/// list 0    L{1}[0] copy = a
///           0 = a − b                            (enforcing, a_eq_b)
///           0 = b − a                            (enforcing, b_eq_a)
/// outputs   L{1}[0]
/// ```
///
/// Where `a ≠ b` the two residuals cancel on every row, so only their distinct
/// batch weights keep a violation visible.
pub fn opposed_circuit() -> CircuitArtifact {
    let (a, b) = (PolyAddress::Witness(0), PolyAddress::Witness(1));
    let out = PolyAddress::Inner {
        layer: 1,
        offset: 0,
    };
    let minus = |x: PolyAddress, y: PolyAddress| GateDef::Linear {
        terms: vec![(lit(1), x), (neg(1), y)],
        constant: lit(0),
    };
    circuit(
        2,
        &["a", "b"],
        vec![LayerSpec {
            halving: false,
            num_vars: 2,
            width: 1,
            cached: vec![],
            producing: vec![ProducingEntry {
                relation: 0,
                output: out,
                gate: copy(a),
            }],
            enforcing: vec![
                EnforcingEntry {
                    relation: 1,
                    gate: minus(a, b),
                },
                EnforcingEntry {
                    relation: 2,
                    gate: minus(b, a),
                },
            ],
        }],
        vec![
            relation("define_copy", Some(0), copy(a)),
            relation("a_eq_b", None, minus(a, b)),
            relation("b_eq_a", None, minus(b, a)),
        ],
        &[("copy", out)],
        vec![out],
    )
}
