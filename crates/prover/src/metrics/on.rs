//! The metrics harness with the feature **on**: the collector, its data model
//! and its two reports.
//!
//! Nothing here is on the path of a default build — the module is not compiled
//! at all without `--features metrics` (`super`'s module docs). That is what
//! licenses the liberality: sizing a shard's forward pass walks every layer of
//! every column, which is work proportional to the trace, and it buys the one
//! number that explains a prover's memory profile.
//!
//! # No shared state
//!
//! Master anti-goal 7 bans global mutable state and the workspace has no
//! interior mutability, so the collector is threaded, not ambient. Each rayon
//! task builds its own [`Recorder::for_shard`], returns it beside its result,
//! and the caller [`Recorder::absorb`]s them **in statement order** — so a
//! block's metrics are as deterministic in their ordering as its proof is in
//! its bytes, and only the timings themselves vary.

use std::fmt;
use std::time::Instant;

use constraints::FamilyCircuit;
use gkr::{GkrProof, LayerValues};
use poly::{MultilinearPoly, PolyBacking};

use super::{ByteClass, ShardId, Stage, BYTE_CLASSES, STAGES};

// ---------------------------------------------------------------------------
// Sizing: the bytes a structure owns
// ---------------------------------------------------------------------------

/// The heap bytes one column owns, **as it is stored**: the small-type backings
/// are the point of `crates/poly`, and a `u1` column of `2^20` rows is 128 KiB
/// where the `Fr` backing of the same column would be 32 MiB. Counting the
/// lifted `Fr` value would hide exactly the saving the backing exists for.
pub fn poly_bytes(p: &MultilinearPoly) -> u64 {
    let b = match p.backing() {
        PolyBacking::U1(limbs, _) => limbs.len() * 8,
        PolyBacking::U8(v) => v.len(),
        PolyBacking::U16(v) => v.len() * 2,
        PolyBacking::U32(v) => v.len() * 4,
        PolyBacking::Fr(v) => v.len() * std::mem::size_of::<field::Fr>(),
    };
    b as u64
}

/// [`poly_bytes`] over a list.
pub fn polys_bytes(list: &[MultilinearPoly]) -> u64 {
    list.iter().map(poly_bytes).sum()
}

/// [`poly_bytes`] over a list of borrows.
pub fn poly_refs_bytes(list: &[&MultilinearPoly]) -> u64 {
    list.iter().copied().map(poly_bytes).sum()
}

/// [`poly_bytes`] over an addressed column list, as `shard_columns` returns
/// and `BaseLayer::new` takes.
pub fn columns_bytes(list: &[(constraints::PolyAddress, MultilinearPoly)]) -> u64 {
    list.iter().map(|(_, c)| poly_bytes(c)).sum()
}

/// **The forward pass's footprint**: every materialized layer of every column.
/// This is the prover's largest structure and what makes a shard's peak.
pub fn layer_values_bytes(values: &LayerValues) -> u64 {
    values.layers.iter().map(|l| polys_bytes(l)).sum()
}

/// A GKR proof's wire size, by its shape: four field elements a sumcheck round
/// and one per final evaluation.
pub fn gkr_proof_bytes(proof: &GkrProof) -> u64 {
    let fr = std::mem::size_of::<field::Fr>() as u64;
    proof
        .layers
        .iter()
        .map(|l| (l.rounds.len() as u64 * 4 + l.final_evals.len() as u64) * fr)
        .sum()
}

// ---------------------------------------------------------------------------
// The data model
// ---------------------------------------------------------------------------

/// The machine and build a run happened on. Every timing in a report is only
/// comparable with another taken here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    pub rayon_threads: usize,
    /// `true` in a `dev` build. A `dev`-profile proving run is roughly an
    /// order of magnitude slower and its timings say nothing about `release`.
    pub debug_assertions: bool,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub pointer_width: u32,
}

impl Environment {
    pub fn capture() -> Environment {
        Environment {
            rayon_threads: rayon::current_num_threads(),
            debug_assertions: cfg!(debug_assertions),
            target_os: std::env::consts::OS,
            target_arch: std::env::consts::ARCH,
            pointer_width: usize::BITS,
        }
    }
}

/// What was proven: the static descriptor and the execution's own shape. The
/// identity and the SRS digest are here so two reports can be told apart —
/// a timing table without them is a table about an unknown statement.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProgramShape {
    pub code_version: u32,
    pub entry_pc: u32,
    pub bytecode_size_words: u32,
    pub identity: String,
    pub srs_digest: String,
    /// `(family, height)`, the `VmConfig`'s order.
    pub families: Vec<(u32, u32)>,
    /// `(family, cycles)` from the archive's cycle profile.
    pub cycles: Vec<(u32, u64)>,
    pub total_cycles: u64,
    /// One per config family, the statement's order.
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
}

/// A registered family's circuit, by the numbers. This is a constant of the
/// family and its height, not of the execution, and it is what says whether a
/// slow shard is slow because of its circuit or because of its trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyShape {
    pub family: u32,
    pub height: u32,
    pub trace_vars: u32,
    pub memory_columns: usize,
    pub witness_columns: usize,
    pub setup_columns: usize,
    pub virtual_tables: usize,
    pub committed_columns: usize,
    /// Layers above the base: the GKR depth, and the number of sumchecks.
    pub layers: usize,
    pub relations: usize,
    pub lookups: usize,
    pub channels: usize,
    pub outputs: usize,
    pub scratch: usize,
    pub reads_generic_table: bool,
}

/// Read a family's shape off its compiled circuit.
pub fn family_shape(circuit: &FamilyCircuit, height: u32) -> FamilyShape {
    let a = &circuit.artifact;
    FamilyShape {
        family: circuit.family,
        height,
        trace_vars: a.trace_vars,
        memory_columns: a.memory.len(),
        witness_columns: a.witness.len(),
        setup_columns: a.setup.len(),
        virtual_tables: a.virtuals.len(),
        committed_columns: a.committed().len(),
        layers: a.depth(),
        relations: a.relations.len(),
        lookups: a.lookups.len(),
        channels: circuit.channels.len(),
        outputs: a.outputs.len(),
        scratch: a.scratch.len(),
        reads_generic_table: circuit.reads_generic_table(),
    }
}

/// One shard of one execution, by the numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardShape {
    pub shard: ShardId,
    pub height: u32,
    /// The claimed time window, `[start, end)`. `[0, 2^38)` for a family that
    /// owns no cycles.
    pub ts_window: [u64; 2],
    pub gkr_layers: usize,
    /// Sumcheck rounds summed over every layer: the shard's real GKR size.
    pub sumcheck_rounds: usize,
    pub final_evals: usize,
    pub witness_commitments: usize,
    pub proof_bytes: usize,
}

/// The block on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProofShape {
    pub block_bytes: usize,
    pub statement_bytes: usize,
    /// Per shard, in statement order.
    pub shard_bytes: Vec<(ShardId, usize)>,
}

/// One closed span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeSample {
    pub stage: Stage,
    pub shard: Option<ShardId>,
    pub wall_nanos: u64,
}

/// One sized structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSample {
    pub class: ByteClass,
    pub shard: Option<ShardId>,
    pub bytes: u64,
}

/// Everything one run recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvingMetrics {
    pub environment: Environment,
    pub program: ProgramShape,
    pub families: Vec<FamilyShape>,
    pub shards: Vec<ShardShape>,
    pub times: Vec<TimeSample>,
    pub bytes: Vec<ByteSample>,
    /// The trace archive's own five `PhaseTiming`s, which predate this harness
    /// and are part of the archive's frozen wire form: `(phase as u8, nanos)`.
    pub archive_phases: Vec<(u8, u64)>,
    pub proof: ProofShape,
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

impl ProvingMetrics {
    /// Total wall time in `stage`, over every sample of it.
    pub fn total(&self, stage: Stage) -> u64 {
        self.times
            .iter()
            .filter(|s| s.stage == stage)
            .map(|s| s.wall_nanos)
            .sum()
    }

    /// How many times `stage` was entered. **Read it against the shard count**:
    /// `ShardColumnsTotal` at twice the shard count is `advance` rebuilding
    /// every shard's columns for the opening phase after dropping them at the
    /// end of the GKR phase.
    pub fn count(&self, stage: Stage) -> usize {
        self.times.iter().filter(|s| s.stage == stage).count()
    }

    /// The slowest single sample of `stage`, which for a per-shard stage is
    /// the shard that paces the parallel region.
    pub fn slowest(&self, stage: Stage) -> Option<TimeSample> {
        self.times
            .iter()
            .filter(|s| s.stage == stage)
            .max_by_key(|s| s.wall_nanos)
            .copied()
    }

    /// Total wall time in `stage` for one shard.
    pub fn shard_total(&self, shard: ShardId, stage: Stage) -> u64 {
        self.times
            .iter()
            .filter(|s| s.stage == stage && s.shard == Some(shard))
            .map(|s| s.wall_nanos)
            .sum()
    }

    /// Bytes counted in `class`, over the whole run.
    pub fn class_bytes(&self, class: ByteClass) -> u64 {
        self.bytes
            .iter()
            .filter(|b| b.class == class)
            .map(|b| b.bytes)
            .sum()
    }

    /// **A shard's modelled peak**: the structures alive at the same moment
    /// inside `gkr_part` — its base layer and its forward pass. Every other
    /// class is smaller by orders of magnitude and is left out on purpose
    /// (`docs/spec/metrics.md` §4.2).
    pub fn shard_peak_bytes(&self, shard: ShardId) -> u64 {
        // **The largest sample of each class, never their sum.** `advance`
        // builds a shard's base layer twice — once for the GKR phase and once
        // for the opening phase, having dropped it in between — so two samples
        // of one class are one structure built twice, not two held at once.
        BYTE_CLASSES
            .iter()
            .filter(|c| c.resident_at_shard_peak())
            .map(|class| {
                self.bytes
                    .iter()
                    .filter(|b| b.shard == Some(shard) && b.class == *class)
                    .map(|b| b.bytes)
                    .max()
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Every shard's modelled peak, largest first.
    pub fn shard_peaks(&self) -> Vec<(ShardId, u64)> {
        let mut peaks: Vec<(ShardId, u64)> = self
            .shards
            .iter()
            .map(|s| (s.shard, self.shard_peak_bytes(s.shard)))
            .filter(|(_, b)| *b > 0)
            .collect();
        peaks.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        peaks
    }

    /// **The modelled block peak**: shard proving is the block's one parallel
    /// step, so at the worst moment `min(threads, shards)` shards hold a base
    /// layer and a forward pass at once. Summing the largest that many is the
    /// prediction, and it is the number that says what a thread count costs
    /// before the run is made (`docs/spec/block-proof.md` §5).
    ///
    /// It is a **lower bound on resident set size** and not an estimate of it:
    /// it counts the buffers the prover asks for and nothing else — no
    /// allocator slack, no fragmentation, no rayon stacks, no SRS, no archive.
    pub fn modelled_block_peak(&self) -> u64 {
        let peaks = self.shard_peaks();
        let concurrent = self.environment.rayon_threads.min(peaks.len());
        peaks.iter().take(concurrent).map(|(_, b)| b).sum()
    }

    /// The SRS and the archive are live for the whole run beside the shards;
    /// this is the modelled peak plus everything the statement holds across
    /// the parallel region.
    pub fn modelled_resident_floor(&self) -> u64 {
        self.modelled_block_peak() + self.class_bytes(ByteClass::MemoryColumns)
    }

    /// Work done divided by wall time in the GKR region: what the thread count
    /// actually bought. A number well below the thread count is the region
    /// waiting on its slowest shard, which [`ProvingMetrics::slowest`] names.
    ///
    /// The numerator is [`Stage::ShardGkrTask`], **one task's whole body**, and
    /// not `ShardGkrTotal`: the region also waits for each task to build its
    /// shard's columns, so measuring only `gkr_part` against the region's wall
    /// understates the speedup — on the S16 statement it read 0.84×, which is
    /// not a speedup at all.
    pub fn gkr_speedup(&self) -> Option<f64> {
        let wall = self.total(Stage::BlockGkrRegion);
        if wall == 0 {
            return None;
        }
        Some(self.total(Stage::ShardGkrTask) as f64 / wall as f64)
    }

    /// The same for the opening region.
    pub fn opening_speedup(&self) -> Option<f64> {
        let wall = self.total(Stage::BlockOpeningRegion);
        if wall == 0 {
            return None;
        }
        Some(self.total(Stage::ShardOpeningTask) as f64 / wall as f64)
    }

    /// **How full the shards are**: per family, the cycles it ran against the
    /// rows its shards hold. `(family, cycles, rows, fraction)`, families that
    /// ran no cycles left out.
    ///
    /// A cycle-owning family's shard cannot be smaller than `2^20` rows
    /// (`docs/spec/lookup.md` §3), so a family that just spills into a second
    /// shard pays for a whole one: the S20 demo runs 1,064,970 add/sub cycles
    /// over two `2^20` shards and is half empty. That is the cost of the
    /// height menu, and this is where it is visible.
    pub fn occupancy(&self) -> Vec<(u32, u64, u64, f64)> {
        let p = &self.program;
        p.cycles
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(family, cycles)| {
                let height = p
                    .families
                    .iter()
                    .find(|(f, _)| f == family)
                    .map(|(_, h)| *h as u64)
                    .unwrap_or(0);
                let shards = p
                    .families
                    .iter()
                    .position(|(f, _)| f == family)
                    .and_then(|i| p.shard_counts.get(i))
                    .copied()
                    .unwrap_or(0) as u64;
                let rows = height * shards;
                let fraction = if rows == 0 {
                    0.0
                } else {
                    *cycles as f64 / rows as f64
                };
                (*family, *cycles, rows, fraction)
            })
            .collect()
    }

    /// Wall-clock nanoseconds of `block_total` per executed cycle — the one
    /// number that compares two guests, two machines or two revisions without
    /// knowing anything about either statement's shape.
    pub fn nanos_per_cycle(&self) -> Option<f64> {
        let cycles = self.program.total_cycles;
        let total = self.total(Stage::BlockTotal);
        if cycles == 0 || total == 0 {
            return None;
        }
        Some(total as f64 / cycles as f64)
    }

    /// Wall time a root stage did not spend in any of its children — the
    /// unattributed remainder, and the first place to look when a total does
    /// not add up.
    pub fn unattributed(&self, root: Stage) -> i128 {
        let children: u64 = STAGES
            .iter()
            .filter(|s| s.parent() == Some(root))
            .map(|s| self.total(*s))
            .sum();
        self.total(root) as i128 - children as i128
    }
}

// ---------------------------------------------------------------------------
// The collector
// ---------------------------------------------------------------------------

/// An open span: the stage and the instant it opened at.
#[derive(Clone, Copy, Debug)]
pub struct Span {
    stage: Stage,
    at: Instant,
}

/// The collector. One per run, plus one per rayon task, merged by
/// [`Recorder::absorb`].
#[derive(Clone, Debug)]
pub struct Recorder {
    metrics: ProvingMetrics,
    /// Every sample this recorder takes is attributed here. `None` for the
    /// run's own recorder, `Some` inside a shard's task.
    shard: Option<ShardId>,
}

impl Default for Recorder {
    fn default() -> Recorder {
        Recorder::new()
    }
}

impl Recorder {
    pub fn new() -> Recorder {
        Recorder {
            metrics: ProvingMetrics {
                environment: Environment::capture(),
                program: ProgramShape::default(),
                families: Vec::new(),
                shards: Vec::new(),
                times: Vec::new(),
                bytes: Vec::new(),
                archive_phases: Vec::new(),
                proof: ProofShape::default(),
            },
            shard: None,
        }
    }

    /// One rayon task's own recorder: no shared state, and everything it
    /// records is attributed to `shard`.
    pub fn for_shard(shard: ShardId) -> Recorder {
        let mut rec = Recorder::new();
        rec.shard = Some(shard);
        rec
    }

    /// Open a span. Reading the clock here is the only cost timing has.
    pub fn start(&self, stage: Stage) -> Span {
        Span {
            stage,
            at: Instant::now(),
        }
    }

    /// Close a span and record it.
    pub fn end(&mut self, span: Span) {
        let wall_nanos = span.at.elapsed().as_nanos() as u64;
        self.metrics.times.push(TimeSample {
            stage: span.stage,
            shard: self.shard,
            wall_nanos,
        });
    }

    /// Merge a task's recorder. **Call this in statement order** — the caller
    /// collects the tasks' results in order already, and doing the same here
    /// is what makes two runs' reports differ only in their timings.
    pub fn absorb(&mut self, other: Recorder) {
        let ProvingMetrics {
            environment: _,
            program: _,
            families,
            shards,
            times,
            bytes,
            archive_phases,
            proof: _,
        } = other.metrics;
        self.metrics.families.extend(families);
        self.metrics.shards.extend(shards);
        self.metrics.times.extend(times);
        self.metrics.bytes.extend(bytes);
        self.metrics.archive_phases.extend(archive_phases);
    }

    /// Record a sized structure against this recorder's shard.
    pub fn bytes(&mut self, class: ByteClass, bytes: u64) {
        self.metrics.bytes.push(ByteSample {
            class,
            shard: self.shard,
            bytes,
        });
    }

    /// Record a sized structure against a named shard, whatever this
    /// recorder's own attribution.
    pub fn shard_bytes(&mut self, shard: ShardId, class: ByteClass, bytes: u64) {
        self.metrics.bytes.push(ByteSample {
            class,
            shard: Some(shard),
            bytes,
        });
    }

    pub fn note_program(&mut self, program: ProgramShape) {
        self.metrics.program = program;
    }

    pub fn note_family(&mut self, family: FamilyShape) {
        self.metrics.families.push(family);
    }

    pub fn note_shard(&mut self, shard: ShardShape) {
        self.metrics.shards.push(shard);
    }

    pub fn note_proof(&mut self, proof: ProofShape) {
        self.metrics.proof = proof;
    }

    pub fn note_archive_phase(&mut self, phase: u8, nanos: u64) {
        self.metrics.archive_phases.push((phase, nanos));
    }

    /// The run's metrics, with the per-shard lists put back into statement
    /// order so a report is stable.
    pub fn finish(self) -> ProvingMetrics {
        let mut m = self.metrics;
        // A shard notes its shape twice: once in `gkr_part`, which does not
        // have the proof yet, and once in `opening_part`, which does. Sort the
        // complete one first and keep it.
        m.shards.sort_by(|a, b| {
            a.shard
                .cmp(&b.shard)
                .then(b.proof_bytes.cmp(&a.proof_bytes))
        });
        m.shards.dedup_by_key(|s| s.shard);
        m.families.sort_by_key(|f| f.family);
        m.families.dedup_by_key(|f| f.family);
        m.archive_phases.sort_by_key(|p| p.0);
        m.archive_phases.dedup();
        m
    }

    /// A borrow of what has been recorded so far.
    pub fn peek(&self) -> &ProvingMetrics {
        &self.metrics
    }
}

// ---------------------------------------------------------------------------
// The reports
// ---------------------------------------------------------------------------

fn duration(nanos: u64) -> String {
    match nanos {
        0 => "-".to_string(),
        n if n < 1_000 => format!("{n} ns"),
        n if n < 1_000_000 => format!("{:.2} us", n as f64 / 1e3),
        n if n < 1_000_000_000 => format!("{:.2} ms", n as f64 / 1e6),
        n => format!("{:.3} s", n as f64 / 1e9),
    }
}

fn bytes_human(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    match b {
        0 => "-".to_string(),
        n if n < 1024 => format!("{n} B"),
        n if n < 1024 * 1024 => format!("{:.1} KiB", f / K),
        n if n < 1024 * 1024 * 1024 => format!("{:.1} MiB", f / (K * K)),
        _ => format!("{:.2} GiB", f / (K * K * K)),
    }
}

fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The identity and SRS digest as a report prints them.
pub fn digest_hex(bytes: [u8; 32]) -> String {
    hex32(bytes)
}

impl fmt::Display for ProvingMetrics {
    /// The human report: the environment, what was proven, the stage tree, the
    /// byte classes, the modelled peak and the per-shard table.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = &self.environment;
        writeln!(f, "prover metrics")?;
        writeln!(
            f,
            "  build            {} on {}/{} ({}-bit), rayon threads {}",
            if e.debug_assertions {
                "dev (timings are NOT release timings)"
            } else {
                "release"
            },
            e.target_os,
            e.target_arch,
            e.pointer_width,
            e.rayon_threads
        )?;
        let p = &self.program;
        if !p.identity.is_empty() {
            writeln!(f, "  identity         {}", p.identity)?;
            writeln!(f, "  srs digest       {}", p.srs_digest)?;
        }
        if !p.families.is_empty() {
            writeln!(
                f,
                "  config           {} families, bytecode {} words, entry pc {:#x}",
                p.families.len(),
                p.bytecode_size_words,
                p.entry_pc
            )?;
        }
        if p.total_cycles > 0 {
            writeln!(
                f,
                "  execution        {} cycles over {} shards",
                p.total_cycles,
                p.shard_counts.iter().sum::<u32>()
            )?;
        }

        writeln!(
            f,
            "\n  stage                      wall        n     slowest"
        )?;
        writeln!(
            f,
            "  ------------------------------------------------------"
        )?;
        for root in STAGES.iter().filter(|s| s.parent().is_none()) {
            if self.count(*root) == 0 {
                continue;
            }
            self.write_stage(f, *root, 0)?;
            for child in STAGES.iter().filter(|s| s.parent() == Some(*root)) {
                if self.count(*child) == 0 {
                    continue;
                }
                self.write_stage(f, *child, 1)?;
            }
            let rest = self.unattributed(*root);
            if rest > 0 && STAGES.iter().any(|s| s.parent() == Some(*root)) {
                writeln!(
                    f,
                    "    {:<24} {:>10}",
                    "(unattributed)",
                    duration(rest as u64)
                )?;
            }
        }

        if let Some(s) = self.gkr_speedup() {
            writeln!(
                f,
                "\n  gkr region       {:.2}x over {} threads ({:.0}% of them)",
                s,
                e.rayon_threads,
                100.0 * s / e.rayon_threads as f64
            )?;
        }
        if let Some(s) = self.opening_speedup() {
            writeln!(
                f,
                "  opening region   {:.2}x over {} threads ({:.0}% of them)",
                s,
                e.rayon_threads,
                100.0 * s / e.rayon_threads as f64
            )?;
        }

        if !self.bytes.is_empty() {
            writeln!(f, "\n  bytes the prover asked for")?;
            for class in BYTE_CLASSES {
                let b = self.class_bytes(class);
                if b > 0 {
                    writeln!(f, "    {:<20} {:>12}", class.name(), bytes_human(b))?;
                }
            }
            let peak = self.modelled_block_peak();
            if peak > 0 {
                let peaks = self.shard_peaks();
                let concurrent = e.rayon_threads.min(peaks.len());
                writeln!(
                    f,
                    "\n  modelled block peak  {:>12}  ({} of {} shards resident at once)",
                    bytes_human(peak),
                    concurrent,
                    peaks.len()
                )?;
                writeln!(
                    f,
                    "  modelled floor       {:>12}  (+ the statement's memory columns)",
                    bytes_human(self.modelled_resident_floor())
                )?;
                writeln!(
                    f,
                    "  a lower bound on RSS, not an estimate of it: docs/spec/metrics.md §4"
                )?;
            }
        }

        if !self.shards.is_empty() {
            writeln!(
                f,
                "\n  shard          rows   layers  rounds        gkr       open       peak     proof"
            )?;
            writeln!(
                f,
                "  ---------------------------------------------------------------------------------"
            )?;
            for s in &self.shards {
                writeln!(
                    f,
                    "  ({:>2},{:>2})  {:>10}  {:>6}  {:>6} {:>10} {:>10} {:>10} {:>9}",
                    s.shard.family,
                    s.shard.index,
                    s.height,
                    s.gkr_layers,
                    s.sumcheck_rounds,
                    duration(self.shard_total(s.shard, Stage::ShardGkrTotal)),
                    duration(self.shard_total(s.shard, Stage::ShardOpeningTotal)),
                    bytes_human(self.shard_peak_bytes(s.shard)),
                    s.proof_bytes
                )?;
            }
        }

        let occupancy = self.occupancy();
        if !occupancy.is_empty() {
            writeln!(f, "\n  family      cycles         rows   occupancy")?;
            writeln!(f, "  ------------------------------------------------")?;
            for (family, cycles, rows, fraction) in &occupancy {
                writeln!(
                    f,
                    "  {family:>6} {cycles:>11} {rows:>12}   {:>8.1}%",
                    100.0 * fraction
                )?;
            }
            if let Some(per) = self.nanos_per_cycle() {
                writeln!(
                    f,
                    "  {:.0} ns a cycle over {} cycles",
                    per, self.program.total_cycles
                )?;
            }
        }

        if !self.families.is_empty() {
            writeln!(
                f,
                "\n  family  height  vars   M    W    S  virt  layers  relations  lookups  chans"
            )?;
            writeln!(
                f,
                "  ------------------------------------------------------------------------------"
            )?;
            for c in &self.families {
                writeln!(
                    f,
                    "  {:>6}  {:>6}  {:>4} {:>3} {:>4} {:>4} {:>5} {:>7} {:>10} {:>8} {:>6}",
                    c.family,
                    c.height,
                    c.trace_vars,
                    c.memory_columns,
                    c.witness_columns,
                    c.setup_columns,
                    c.virtual_tables,
                    c.layers,
                    c.relations,
                    c.lookups,
                    c.channels
                )?;
            }
        }

        if self.proof.block_bytes > 0 {
            writeln!(
                f,
                "\n  block proof      {} bytes, statement {} over {} shards",
                self.proof.block_bytes,
                self.proof.statement_bytes,
                self.proof.shard_bytes.len()
            )?;
        }

        if !self.archive_phases.is_empty() {
            writeln!(f, "\n  archive phases (the trace archive's own timing)")?;
            for (phase, nanos) in &self.archive_phases {
                writeln!(f, "    phase {phase}  {:>12}", duration(*nanos))?;
            }
        }
        Ok(())
    }
}

impl ProvingMetrics {
    fn write_stage(&self, f: &mut fmt::Formatter<'_>, stage: Stage, depth: usize) -> fmt::Result {
        let n = self.count(stage);
        let slowest = self
            .slowest(stage)
            .filter(|_| n > 1)
            .map(|s| duration(s.wall_nanos))
            .unwrap_or_default();
        writeln!(
            f,
            "  {:indent$}{:<width$} {:>10} {:>8} {:>11}",
            "",
            stage.name(),
            duration(self.total(stage)),
            n,
            slowest,
            indent = depth * 2,
            width = 24usize.saturating_sub(depth * 2),
        )
    }

    /// The machine report: one JSON object, written by hand so the harness
    /// needs no serialization dependency it would otherwise not have. Stable
    /// enough to diff two runs and to feed a plot.
    pub fn to_json(&self) -> String {
        let mut s = String::from("{\n");
        let e = &self.environment;
        s.push_str(&format!(
            "  \"environment\": {{\"rayon_threads\": {}, \"debug_assertions\": {}, \"target_os\": \"{}\", \"target_arch\": \"{}\", \"pointer_width\": {}}},\n",
            e.rayon_threads, e.debug_assertions, e.target_os, e.target_arch, e.pointer_width
        ));
        let p = &self.program;
        s.push_str(&format!(
            "  \"program\": {{\"code_version\": {}, \"entry_pc\": {}, \"bytecode_size_words\": {}, \"identity\": \"{}\", \"srs_digest\": \"{}\", \"total_cycles\": {}, \"shard_counts\": {:?}, \"windows\": {:?}}},\n",
            p.code_version,
            p.entry_pc,
            p.bytecode_size_words,
            p.identity,
            p.srs_digest,
            p.total_cycles,
            p.shard_counts,
            p.windows
        ));
        s.push_str("  \"stages\": [\n");
        let used: Vec<Stage> = STAGES
            .iter()
            .copied()
            .filter(|x| self.count(*x) > 0)
            .collect();
        for (i, stage) in used.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"stage\": \"{}\", \"parent\": {}, \"wall_nanos\": {}, \"samples\": {}, \"slowest_nanos\": {}}}{}\n",
                stage.name(),
                match stage.parent() {
                    Some(p) => format!("\"{}\"", p.name()),
                    None => "null".to_string(),
                },
                self.total(*stage),
                self.count(*stage),
                self.slowest(*stage).map(|x| x.wall_nanos).unwrap_or(0),
                if i + 1 == used.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],\n  \"bytes\": [\n");
        let classes: Vec<ByteClass> = BYTE_CLASSES
            .iter()
            .copied()
            .filter(|c| self.class_bytes(*c) > 0)
            .collect();
        for (i, class) in classes.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"class\": \"{}\", \"bytes\": {}}}{}\n",
                class.name(),
                self.class_bytes(*class),
                if i + 1 == classes.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],\n  \"shards\": [\n");
        for (i, sh) in self.shards.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"family\": {}, \"index\": {}, \"height\": {}, \"ts_window\": [{}, {}], \"gkr_layers\": {}, \"sumcheck_rounds\": {}, \"gkr_nanos\": {}, \"opening_nanos\": {}, \"peak_bytes\": {}, \"proof_bytes\": {}}}{}\n",
                sh.shard.family,
                sh.shard.index,
                sh.height,
                sh.ts_window[0],
                sh.ts_window[1],
                sh.gkr_layers,
                sh.sumcheck_rounds,
                self.shard_total(sh.shard, Stage::ShardGkrTotal),
                self.shard_total(sh.shard, Stage::ShardOpeningTotal),
                self.shard_peak_bytes(sh.shard),
                sh.proof_bytes,
                if i + 1 == self.shards.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],\n");
        s.push_str("  \"occupancy\": [\n");
        let occ = self.occupancy();
        for (i, (family, cycles, rows, fraction)) in occ.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"family\": {family}, \"cycles\": {cycles}, \"rows\": {rows}, \"fraction\": {fraction:.6}}}{}\n",
                if i + 1 == occ.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],\n");
        s.push_str(&format!(
            "  \"modelled_block_peak_bytes\": {},\n  \"modelled_resident_floor_bytes\": {},\n  \"nanos_per_cycle\": {},\n",
            self.modelled_block_peak(),
            self.modelled_resident_floor(),
            match self.nanos_per_cycle() {
                Some(v) => format!("{v:.3}"),
                None => "null".to_string(),
            }
        ));
        s.push_str(&format!(
            "  \"proof\": {{\"block_bytes\": {}, \"statement_bytes\": {}}}\n",
            self.proof.block_bytes, self.proof.statement_bytes
        ));
        s.push('}');
        s
    }
}
