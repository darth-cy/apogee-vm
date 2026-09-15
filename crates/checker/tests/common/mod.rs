//! The two committed toy artifacts, pinned by digest, and the small editing
//! helpers the suites share. Test-only.
//!
//! The toy, as `tools/kat-gen/src/gkr.rs`'s header describes it: base columns
//! `M[0] m, W[0] a, W[1] b, W[2] c, W[3] e, S[0] s` and `V[row]` over 16 rows;
//! list 0 writes `ab = a·b`, `fingerprint = (γ·a + row)·c` (the parenthesis a
//! cached entry in one compilation, inline in the other) and
//! `masked_m = m·s + (1 − s)`, and enforces `0 = e·s − a·s` (a `Quadratic`); list 1 writes
//! `abm = ab·masked_m` and `fingerprint3 = fingerprint + 3`; list 2 halves
//! both into their products; the outputs are `L{3}[1]` then `L{3}[0]`.

#![allow(dead_code)]

use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use test_support::{sha256, to_hex, Rng};

pub const CACHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/toy_cached.bin"
);
pub const CACHE_FREE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/toy_cache_free.bin"
);
const CACHED_SHA256: &str = "ee27e1192c4bcf9afa003509f6c06fead29628b02a4c17f86e381bf5609f1c70";
const CACHE_FREE_SHA256: &str = "5318afeb5b5ba5d09871358c89db36a0db12680fa9559a70c67c50b41181251d";

/// The committed layout's positions: `m, a, b, c, e, s`.
pub const M: usize = 0;
pub const A: usize = 1;
pub const B: usize = 2;
pub const C: usize = 3;
pub const E: usize = 4;
pub const S: usize = 5;

pub const M0: PolyAddress = PolyAddress::Memory(0);
pub const W0: PolyAddress = PolyAddress::Witness(0);
pub const W1: PolyAddress = PolyAddress::Witness(1);
pub const W2: PolyAddress = PolyAddress::Witness(2);
pub const W3: PolyAddress = PolyAddress::Witness(3);
pub const V: PolyAddress = PolyAddress::Virtual(VirtualKind::RowIndex);

pub fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

pub fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

/// Read a fixture, check its pin, decode it.
pub fn load(path: &str) -> CircuitArtifact {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let pin = if path == CACHED {
        CACHED_SHA256
    } else {
        CACHE_FREE_SHA256
    };
    assert_eq!(
        to_hex(&sha256(&bytes)),
        pin,
        "{path} is not the pinned fixture"
    );
    CircuitArtifact::from_bytes(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Both compilations, cached first, with a label for messages.
pub fn toys() -> [(&'static str, CircuitArtifact); 2] {
    [("cached", load(CACHED)), ("cache-free", load(CACHE_FREE))]
}

pub fn relation(a: &CircuitArtifact, name: &str) -> usize {
    a.relations
        .iter()
        .position(|r| r.name == name)
        .unwrap_or_else(|| panic!("the toy has no relation {name}"))
}

pub fn slot(a: &CircuitArtifact, name: &str) -> usize {
    a.scratch
        .iter()
        .position(|s| s.name == name)
        .unwrap_or_else(|| panic!("the toy has no scratch slot {name}"))
}

/// A pseudo-random field element below `2^252`.
pub fn fr(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x0f;
    Fr::from_bytes(&b).expect("below 2^252")
}

/// A `Linear` gate's terms and constant.
pub fn linear(gate: &mut GateDef) -> (&mut Vec<(Coeff, PolyAddress)>, &mut Coeff) {
    match gate {
        GateDef::Linear { terms, constant } => (terms, constant),
        other => panic!("not a Linear gate: {other:?}"),
    }
}

/// Every term of `gate` reading `operand` gets coefficient `c`; the count. A
/// `Quadratic` product is such a term when either of its factors is `operand`.
pub fn set_coefficient(gate: &mut GateDef, operand: PolyAddress, c: Coeff) -> usize {
    let terms: Vec<&mut (Coeff, PolyAddress)> = match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().collect(),
        GateDef::AffineProduct { left, right, .. } => left.iter_mut().chain(right).collect(),
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let mut changed = 0;
            for (b, y, z) in products.iter_mut() {
                if *y == operand || *z == operand {
                    *b = c;
                    changed += 1;
                }
            }
            linear.iter_mut().for_each(|term| {
                if term.1 == operand {
                    term.0 = c;
                    changed += 1;
                }
            });
            return changed;
        }
        _ => Vec::new(),
    };
    let mut changed = 0;
    for term in terms {
        if term.1 == operand {
            term.0 = c;
            changed += 1;
        }
    }
    changed
}

/// Every read of `from` in `gate` becomes a read of `to`; the count.
pub fn set_operand(gate: &mut GateDef, from: PolyAddress, to: PolyAddress) -> usize {
    let operands: Vec<&mut PolyAddress> = match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().map(|t| &mut t.1).collect(),
        GateDef::Product { left, right, .. } => vec![left, right],
        GateDef::MaskIntoIdentity { input, mask } => vec![input, mask],
        GateDef::AffineProduct { left, right, .. } => {
            left.iter_mut().chain(right).map(|t| &mut t.1).collect()
        }
        GateDef::TreeProduct { input } => vec![input],
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let mut ops: Vec<&mut PolyAddress> = linear.iter_mut().map(|t| &mut t.1).collect();
            for (_, y, z) in products.iter_mut() {
                ops.push(y);
                ops.push(z);
            }
            ops
        }
    };
    let mut changed = 0;
    for op in operands {
        if *op == from {
            *op = to;
            changed += 1;
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// Memory statements over a committed guest
// ---------------------------------------------------------------------------

use checker::{memory_roots, WitnessRow};
use constants::challenge_slot::{MEM_ALPHA_VAL, MEM_GAMMA};
use constants::{family, transcript_tags};
use constraints::memory::{frame_artifact, image_window_artifact, zero_window_artifact};
use emulator::{trace_run, GuestIo};
use gkr::{
    boundary_factors, forward, prove, reconciles, verify, window_challenges, BaseLayer,
    BoundaryFinals, ExternalChallenges, GkrError, LayerValues, OutputClaims,
};
use loader::{load_elf, ProgramImage};
use poly::{MultilinearPoly, PolyBacking};
use program::{decode_program, ProgramParams, VmConfig};
use sumcheck::{absorb_witness_digest, witness_digest};
use trace::{
    build_frame_witness, build_init_teardown_columns, build_memory_columns, init_windows,
    CycleProfile, FamilyTraces, MemoryEventLog,
};
use transcript::Transcript;

/// Every family's height: the init families' `h`, and tall enough for every
/// instruction table of every committed guest but `consistency`.
pub const HEIGHT: u32 = 1 << 16;

/// The guests, each on the input `crates/emulator/tests/common` runs it on:
/// fib's is `fib_io.txt`'s `n = 24`, heap's 40.
pub const GUESTS: [(&str, u32); 2] = [("fib", 24), ("heap", 40)];

/// One committed guest, decoded at `HEIGHT` and traced to its exit: what a
/// statement's memory shards are built from.
pub struct Traced {
    pub image: ProgramImage,
    pub config: VmConfig,
    pub traces: FamilyTraces,
    pub log: MemoryEventLog,
    pub profile: CycleProfile,
    /// `1..=n`, every cycle the execution ran.
    pub cycles: Vec<u64>,
}

/// The ELF is `crates/loader/tests/vectors`', pinned by digest in that crate's
/// suite.
pub fn traced(name: &str, input: u32) -> Traced {
    let path = format!(
        "{}/../loader/tests/vectors/{name}.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let image = load_elf(&elf).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let params = ProgramParams {
        heights: [HEIGHT; family::COUNT as usize],
        ..ProgramParams::defaults()
    };
    let (tables, config) =
        decode_program(&image, &params).unwrap_or_else(|e| panic!("{name}: {e}"));
    let io = GuestIo {
        input: input.to_le_bytes().to_vec(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(&image, &io, &tables, &config).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(execution.exit_code, 0, "{name}");
    Traced {
        image,
        config,
        traces,
        log,
        profile,
        cycles: (1..=execution.cycle_count).collect(),
    }
}

/// Slots 1–4, drawn from a fresh transcript that binds nothing. S16's global
/// transcript owns the real schedule — the statement, every memory column's
/// commitment and the boundary absorbed before the squeeze
/// (`docs/spec/memory.md` §6.1). Here they are only values no trace was chosen
/// against.
pub fn memory_challenges() -> ExternalChallenges {
    let mut t = Transcript::new();
    let mut memory = ExternalChallenges::new();
    for slot in MEM_GAMMA..=MEM_ALPHA_VAL {
        memory.insert(
            slot,
            t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE),
        );
    }
    memory
}

/// One memory shard: its artifact, its base and the challenges its gates read.
#[derive(Clone)]
pub struct Shard {
    pub label: String,
    pub artifact: CircuitArtifact,
    pub base: BaseLayer,
    pub challenges: ExternalChallenges,
}

/// A frame shard of `log` over `cycles`, in the order given, at `height` rows.
pub fn frame_shard(
    log: &MemoryEventLog,
    cycles: &[u64],
    height: usize,
    memory: &ExternalChallenges,
) -> Shard {
    let mut columns = build_memory_columns(log, cycles, height);
    columns.extend(build_frame_witness(log, cycles, height));
    Shard {
        label: "frame".to_string(),
        artifact: frame_artifact(height.trailing_zeros()),
        base: BaseLayer::new(columns),
        challenges: memory.clone(),
    }
}

/// Every memory shard of `t`'s statement: the frame, one shard over every
/// cycle at the smallest power-of-two height holding them; then its windows.
pub fn shards(t: &Traced, memory: &ExternalChallenges) -> Vec<Shard> {
    let height = t.cycles.len().next_power_of_two();
    let mut out = vec![frame_shard(&t.log, &t.cycles, height, memory)];
    out.extend(window_shards(t, memory));
    out
}

/// A RAM window shard of `image` and `log` at `HEIGHT`: `INIT_TEARDOWN`'s
/// artifact for window 0, `ZERO_WINDOWS`' for any other.
pub fn window_shard(
    log: &MemoryEventLog,
    image: &ProgramImage,
    w: u32,
    memory: &ExternalChallenges,
) -> Shard {
    let vars = HEIGHT.trailing_zeros();
    let artifact = match w {
        0 => image_window_artifact(vars),
        _ => zero_window_artifact(vars),
    };
    let columns = build_init_teardown_columns(log, image, w, HEIGHT as usize);
    Shard {
        label: format!("window {w}"),
        artifact,
        base: BaseLayer::new(columns),
        challenges: window_challenges(memory, w, vars),
    }
}

/// `t`'s window shards at `HEIGHT`: `INIT_TEARDOWN`, window 0, and one
/// `ZERO_WINDOWS` shard per id of `init_windows`.
pub fn window_shards(t: &Traced, memory: &ExternalChallenges) -> Vec<Shard> {
    let mut out = vec![window_shard(&t.log, &t.image, 0, memory)];
    for w in init_windows(&t.log, HEIGHT) {
        out.push(window_shard(&t.log, &t.image, w, memory));
    }
    out
}

/// A shard's committed columns, in layout order.
pub fn committed(shard: &Shard) -> Vec<MultilinearPoly> {
    let columns = shard.artifact.committed().into_iter();
    let column = |a| shard.base.get(a).expect("a committed column").clone();
    columns.map(column).collect()
}

/// The value of `shard`'s column `address` at row `row`.
pub fn cell(shard: &Shard, address: PolyAddress, row: usize) -> Fr {
    shard
        .base
        .get(address)
        .expect("a committed column")
        .get(row)
}

/// `shard` with each `(address, row, value)` of `cells` written into its base,
/// every other cell as it was.
pub fn with_cells(shard: &Shard, cells: &[(PolyAddress, usize, Fr)]) -> Shard {
    let mut columns: Vec<(PolyAddress, Vec<Fr>)> = shard
        .artifact
        .committed()
        .into_iter()
        .map(|address| {
            let column = shard.base.get(address).expect("a committed column");
            (address, (0..column.len()).map(|y| column.get(y)).collect())
        })
        .collect();
    for &(address, row, value) in cells {
        let (_, column) = columns
            .iter_mut()
            .find(|(a, _)| *a == address)
            .unwrap_or_else(|| panic!("{}: no committed column {address}", shard.label));
        column[row] = value;
    }
    let columns = columns
        .into_iter()
        .map(|(a, c)| (a, MultilinearPoly::new(PolyBacking::Fr(c))))
        .collect();
    Shard {
        label: shard.label.clone(),
        artifact: shard.artifact.clone(),
        base: BaseLayer::new(columns),
        challenges: shard.challenges.clone(),
    }
}

/// A shard forwarded honestly over its base.
pub fn forwarded_shard(shard: &Shard) -> LayerValues {
    forward(&shard.artifact, &shard.base, &shard.challenges)
}

/// Every shard's `(read root, write root)`, forwarded and recomputed by
/// `memory_roots`.
pub fn roots(shards: &[Shard]) -> (Vec<Fr>, Vec<Fr>) {
    let (mut reads, mut writes) = (Vec::new(), Vec::new());
    for shard in shards {
        let values = forwarded_shard(shard);
        let (read, write) = memory_roots(&shard.artifact, &values)
            .unwrap_or_else(|e| panic!("{}: {e}", shard.label));
        reads.push(read);
        writes.push(write);
    }
    (reads, writes)
}

/// Whether `shards`' roots reconcile with the boundary `finals` at `entry_pc`.
pub fn reconciled(
    shards: &[Shard],
    memory: &ExternalChallenges,
    entry_pc: u32,
    finals: &BoundaryFinals,
) -> bool {
    let (reads, writes) = roots(shards);
    reconciles(&reads, &writes, boundary_factors(memory, entry_pc, finals))
}

/// Row `row` of a forwarded artifact as the flat list reads it: every committed
/// column's value, and the scratch slots of every row-wise layer — the leaves
/// and the row-wise products — from `values`. A halving layer's slots, which no
/// row-local relation reads, are 0.
pub fn witness_row(a: &CircuitArtifact, values: &LayerValues, row: usize) -> WitnessRow {
    let committed = a
        .committed()
        .into_iter()
        .map(|address| values.base.get(address).expect("a column").get(row))
        .collect();
    let scratch = a
        .scratch
        .iter()
        .map(|slot| match slot.address {
            PolyAddress::Inner { layer, offset }
                if a.layer_vars(layer as usize) == a.trace_vars =>
            {
                values.layers[layer as usize - 1][offset as usize].get(row)
            }
            _ => Fr::ZERO,
        })
        .collect();
    WitnessRow {
        committed,
        row,
        scratch,
    }
}

/// Prove `values` and verify the proof, each on a fresh transcript bound to
/// the committed columns' witness digest as S13's harness binds a base, then
/// discharge every base claim against its column.
pub fn prove_and_verify(shard: &Shard, values: &LayerValues) -> Result<(), GkrError> {
    let digest = witness_digest(&committed(shard));
    let bound = || {
        let mut t = Transcript::new();
        absorb_witness_digest(&mut t, digest);
        t
    };
    let a = &shard.artifact;
    let proof = prove(a, values, &shard.challenges, &mut bound());
    let top = values.layers.last().expect("a top layer");
    let tables = a.outputs.iter().map(|out| match *out {
        PolyAddress::Inner { offset, .. } => top[offset as usize].clone(),
        other => panic!("an output is an inner address, not {other}"),
    });
    let outputs = OutputClaims {
        tables: tables.collect(),
    };
    let claims = verify(a, &proof, &outputs, &shard.challenges, &mut bound())?;
    for claim in claims {
        let column = shard.base.get(claim.address).expect("a committed column");
        let label = &shard.label;
        assert_eq!(
            column.evaluate(&claim.point),
            claim.value,
            "{label}: {}",
            claim.address
        );
    }
    Ok(())
}
