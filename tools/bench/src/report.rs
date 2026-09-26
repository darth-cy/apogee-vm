//! `BenchReport`: one proving job, as JSON and as a table.
//!
//! S25 freezes this schema. It is **one flat serde struct** — scalars and lists
//! of pairs, no nested report, no optional section whose absence changes the
//! shape — for the reason every wire format in this repository is flat: a
//! reader who has the type has the whole of it.
//!
//! # What it is for
//!
//! *"Its output mirrors what an ethproofs submission needs (block number/hash,
//! proving time, cost, hardware description)."* ethproofs' own `proofs` table
//! carries `proving_time` (ms), `proving_cycles`, `size_bytes` and a block
//! number, and derives a dollar cost from the hardware's hourly price:
//!
//! ```text
//!     cost_usd = hourly_price_usd × proving_time_ms / 3_600_000
//! ```
//!
//! which is their `num_gpus · hourly_price · proving_time_ms / 3_600_000` with
//! a CPU box's on-demand price in place of a GPU count times a GPU price. This
//! report carries both inputs, so **the cost is recomputable from the report**
//! — must-be-exact 7 — rather than being a number a reader must trust.
//!
//! # Where the timings come from
//!
//! Must-be-exact 5: *"read from the `TraceArchive` phase sections whose schemas
//! S16 froze, not from ad-hoc stopwatches sprinkled in the prover."* They are.
//! [`Phases`] below is `archive.timing(phase)` for each of S12's five sections,
//! and nothing here holds a stopwatch over anything inside the prover. Two
//! honest caveats, both reported rather than smoothed over:
//!
//! - The five phases do **not** sum to the proving wall-clock.
//!   `ProverSetup::new`, the plan check, `finish` and the block assembly sit
//!   outside every phase's span. The remainder is `unattributed_ms` and it is
//!   named rather than absorbed, which is the same discipline
//!   `docs/spec/metrics.md` §2 applies to its stage tree.
//! - The execution phase's number exists only because `host::prove` measures
//!   it. S12 froze the field and every caller in the repository passed zero.
//!
//! # No comparative claims
//!
//! Acceptance 6: *"No comparative or positioning claims appear anywhere in the
//! output."* There are none, and there is nowhere to put one: every field is a
//! measurement of this run on this machine, and the table prints the same
//! machine-dependence note `tools/bench`'s other routines do.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

/// The five `TraceArchive` phase timings, in milliseconds.
///
/// One field per `trace::Phase`, named as S12 named them. A phase that was
/// read back from an imported archive rather than computed carries the timing
/// of the run that computed it, which is why a bench run always proves from a
/// fresh archive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Phases {
    /// `emulator::trace_run`: the guest's whole execution.
    pub execution_ms: f64,
    /// The statement's columns, the global commit phase and its MSMs.
    pub commit_ms: f64,
    /// Every shard's GKR proof. A parallel region's **wall** time.
    pub gkr_ms: f64,
    /// Every shard's Mercury opening. A parallel region's wall time.
    pub opening_ms: f64,
    /// The statement's memory roots and the final section.
    pub final_ms: f64,
}

impl Phases {
    /// What the five phases account for.
    pub fn total_ms(&self) -> f64 {
        self.execution_ms + self.commit_ms + self.gkr_ms + self.opening_ms + self.final_ms
    }
}

/// The machine, in enough detail to recompute the cost and to know what was
/// measured.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Hardware {
    /// One line, for a human and for an ethproofs submission's hardware field.
    pub description: String,
    /// The CPU as the operating system names it.
    pub cpu: String,
    /// Logical processors.
    pub logical_cpus: usize,
    /// Physical memory in bytes, or 0 where it could not be read.
    pub memory_bytes: u64,
    /// `std::env::consts::OS`.
    pub os: String,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    /// Rayon's worker count for this run, which is what bounds the memory peak:
    /// shard proving is the block's one parallel step and its peak is one
    /// shard's forward pass per worker.
    pub rayon_threads: usize,
}

/// One proving job, measured.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchReport {
    // --- what was proven -------------------------------------------------
    /// The fixture's stem, as `crates/host/tests/vectors/` names it.
    pub fixture: String,
    /// `mini` or `stateless`.
    pub mode: String,
    /// The block.
    pub block_number: u64,
    /// Its header hash.
    pub block_hash: String,
    /// Transactions executed, which for a mini-block is a prefix of the block.
    pub txs: usize,
    /// Gas those transactions used.
    pub gas_used: u64,
    /// The program identity the proof is about, lowercase hex.
    pub program_identity: String,
    /// Which SRS the key was built over. A toy SRS gives the same timings and
    /// a different identity, and saying which is the difference between a
    /// measurement and a claim.
    pub srs: String,

    // --- the execution ---------------------------------------------------
    /// Cycles the guest ran, `CycleProfile::total()` — cycle-owning families
    /// only, so a delegation invocation is not double-counted.
    pub guest_cycles: u64,
    /// Guest cycles per unit of EVM gas. The workload's own ratio, on this
    /// block.
    pub cycles_per_gas: f64,

    // --- the proof -------------------------------------------------------
    /// Shards per family, by family name, in statement order.
    pub shards: Vec<(String, u32)>,
    /// Shards in the block.
    pub total_shards: u32,
    /// The `BlockProof`'s wire size.
    pub proof_bytes: usize,
    /// The statement's wire size, which a verifier needs beside the proof.
    pub statement_bytes: usize,

    // --- timing ----------------------------------------------------------
    /// `ProverSetup::new`: registry compilation, the setup MSMs, the key check.
    /// Outside every archive phase, and outside `proving_ms`.
    pub setup_ms: f64,
    /// The five archive phases.
    pub phases: Phases,
    /// The whole of `host::prove`: the executor, every phase, and the work
    /// between them.
    pub proving_ms: f64,
    /// `proving_ms` less what the phases account for — the plan check, the
    /// final assembly, and the archive bookkeeping between phases. Named
    /// rather than absorbed.
    pub unattributed_ms: f64,
    /// `verify_block` over the finished proof.
    pub verify_ms: f64,

    // --- memory ----------------------------------------------------------
    /// Peak resident set in bytes, where the platform reports one.
    pub peak_rss_bytes: Option<u64>,
    /// Where `peak_rss_bytes` came from, or why there is none.
    pub peak_rss_source: String,

    // --- cost ------------------------------------------------------------
    /// The hardware's on-demand price per hour, as given on the command line.
    pub hourly_price_usd: Option<f64>,
    /// `hourly_price_usd × proving_ms / 3_600_000`.
    pub cost_usd: Option<f64>,
    /// `cost_usd` per million gas, which is ethproofs' own unit.
    pub cost_per_mgas_usd: Option<f64>,
    /// How the cost was arrived at, or why there is none.
    pub cost_basis: String,

    // --- the machine -----------------------------------------------------
    pub hardware: Hardware,
}

impl BenchReport {
    /// Fill in the cost fields from an hourly price, or say why there are none.
    pub fn price(&mut self, hourly_usd: Option<f64>) {
        match hourly_usd {
            Some(hourly) => {
                let cost = hourly * self.proving_ms / 3_600_000.0;
                self.hourly_price_usd = Some(hourly);
                self.cost_usd = Some(cost);
                self.cost_per_mgas_usd = if self.gas_used == 0 {
                    None
                } else {
                    Some(cost / (self.gas_used as f64 / 1e6))
                };
                self.cost_basis = format!(
                    "hourly_price_usd * proving_ms / 3600000, ethproofs' own formula with a \
                     CPU instance's on-demand price in place of num_gpus * gpu_price; \
                     {hourly} USD/h was given on the command line"
                );
            }
            None => {
                self.cost_basis =
                    "no hourly price was given (--hourly-usd), so no cost was computed".to_string();
            }
        }
    }

    /// The machine-readable half.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a BenchReport encodes")
    }

    /// The human half.
    ///
    /// Plain rows, no comparisons, no thresholds, and the same
    /// machine-dependence note every other routine in this crate prints.
    pub fn to_table(&self) -> String {
        let mut out = String::new();
        let row = |out: &mut String, k: &str, v: String| {
            let _ = writeln!(out, "  {k:<24} {v}");
        };
        let _ = writeln!(out, "block");
        row(
            &mut out,
            "fixture",
            format!("{} ({})", self.fixture, self.mode),
        );
        row(&mut out, "number", self.block_number.to_string());
        row(&mut out, "hash", self.block_hash.clone());
        row(&mut out, "transactions", self.txs.to_string());
        row(&mut out, "gas used", self.gas_used.to_string());
        row(&mut out, "identity", self.program_identity.clone());
        row(&mut out, "srs", self.srs.clone());

        let _ = writeln!(out, "\nexecution");
        row(&mut out, "guest cycles", self.guest_cycles.to_string());
        row(
            &mut out,
            "cycles per gas",
            format!("{:.1}", self.cycles_per_gas),
        );

        let _ = writeln!(out, "\nproof");
        for (family, count) in &self.shards {
            row(&mut out, family, count.to_string());
        }
        row(&mut out, "shards", self.total_shards.to_string());
        row(&mut out, "proof bytes", self.proof_bytes.to_string());
        row(
            &mut out,
            "statement bytes",
            self.statement_bytes.to_string(),
        );

        let _ = writeln!(out, "\ntiming (ms)");
        row(&mut out, "setup", ms(self.setup_ms));
        row(&mut out, "phase: execution", ms(self.phases.execution_ms));
        row(&mut out, "phase: commit", ms(self.phases.commit_ms));
        row(&mut out, "phase: gkr", ms(self.phases.gkr_ms));
        row(&mut out, "phase: opening", ms(self.phases.opening_ms));
        row(&mut out, "phase: final", ms(self.phases.final_ms));
        row(&mut out, "phases total", ms(self.phases.total_ms()));
        row(&mut out, "unattributed", ms(self.unattributed_ms));
        row(&mut out, "proving (wall)", ms(self.proving_ms));
        row(&mut out, "verify", ms(self.verify_ms));

        let _ = writeln!(out, "\nmemory");
        match self.peak_rss_bytes {
            Some(bytes) => row(
                &mut out,
                "peak rss",
                format!(
                    "{:.2} GiB ({})",
                    bytes as f64 / (1 << 30) as f64,
                    self.peak_rss_source
                ),
            ),
            None => row(&mut out, "peak rss", self.peak_rss_source.clone()),
        }

        let _ = writeln!(out, "\ncost");
        match (self.hourly_price_usd, self.cost_usd) {
            (Some(hourly), Some(cost)) => {
                row(&mut out, "hourly price (USD)", format!("{hourly:.4}"));
                row(&mut out, "cost (USD)", format!("{cost:.4}"));
                if let Some(per) = self.cost_per_mgas_usd {
                    row(&mut out, "cost per Mgas (USD)", format!("{per:.4}"));
                }
            }
            _ => row(&mut out, "cost", "not computed".to_string()),
        }
        row(&mut out, "basis", self.cost_basis.clone());

        let _ = writeln!(out, "\nhardware");
        row(&mut out, "description", self.hardware.description.clone());
        row(&mut out, "cpu", self.hardware.cpu.clone());
        row(
            &mut out,
            "logical cpus",
            self.hardware.logical_cpus.to_string(),
        );
        row(
            &mut out,
            "memory",
            format!(
                "{:.1} GiB",
                self.hardware.memory_bytes as f64 / (1 << 30) as f64
            ),
        );
        row(
            &mut out,
            "os / arch",
            format!("{} / {}", self.hardware.os, self.hardware.arch),
        );
        row(
            &mut out,
            "rayon threads",
            self.hardware.rayon_threads.to_string(),
        );
        out
    }
}

fn ms(value: f64) -> String {
    format!("{value:.1}")
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

/// What this machine is, as far as `std` and one shell-out can say.
///
/// No new dependency and no `unsafe`. On Linux everything comes from `/proc`
/// through `std::fs`; on macOS there is no `/proc`, so the CPU and the memory
/// size come from `sysctl`, which `std::process::Command` spawns exactly as
/// this repository already spawns `cargo`, `qemu-riscv32` and `llvm-objdump`.
/// A field that cannot be read says so rather than guessing.
pub fn hardware() -> Hardware {
    let logical_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let (cpu, memory_bytes) = match std::env::consts::OS {
        "linux" => (linux_cpu(), linux_memory()),
        "macos" => (
            sysctl("machdep.cpu.brand_string").unwrap_or_else(|| "unknown".to_string()),
            sysctl("hw.memsize")
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0),
        ),
        _ => ("unknown".to_string(), 0),
    };
    let rayon_threads = rayon::current_num_threads();
    let description = format!(
        "{cpu}, {logical_cpus} logical cpus, {:.0} GiB, {} {}, rayon {rayon_threads}",
        memory_bytes as f64 / (1u64 << 30) as f64,
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    Hardware {
        description,
        cpu,
        logical_cpus,
        memory_bytes,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        rayon_threads,
    }
}

fn linux_cpu() -> String {
    field_of("/proc/cpuinfo", "model name")
        .or_else(|| field_of("/proc/cpuinfo", "Model"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn linux_memory() -> u64 {
    // `MemTotal:  263852264 kB`
    field_of("/proc/meminfo", "MemTotal")
        .and_then(|value| value.split_whitespace().next().map(str::to_string))
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

/// The first `key: value` line of a `/proc` file.
fn field_of(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim() == key {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn sysctl(name: &str) -> Option<String> {
    let out = std::process::Command::new("sysctl")
        .arg("-n")
        .arg(name)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Peak resident set, where the platform reports one without `unsafe`.
///
/// Linux's `/proc/self/status` carries `VmHWM`, the high-water mark, in plain
/// text. macOS has no equivalent short of a `libc` call or re-running the whole
/// job under `/usr/bin/time -l`, and master anti-goal 4 bans the `unsafe` the
/// first would need — so on macOS this is `None` and says so.
/// `docs/spec/metrics.md` §4.1 is the standing note that `/usr/bin/time` is
/// this repository's ground truth for RSS, and it remains the thing to wrap a
/// macOS run in.
pub fn peak_rss() -> (Option<u64>, String) {
    match field_of("/proc/self/status", "VmHWM") {
        // `VmHWM:  41234 kB`
        Some(value) => match value
            .split_whitespace()
            .next()
            .and_then(|kb| kb.parse::<u64>().ok())
        {
            Some(kb) => (Some(kb * 1024), "/proc/self/status VmHWM".to_string()),
            None => (
                None,
                format!("/proc/self/status VmHWM is not a size: {value}"),
            ),
        },
        None => (
            None,
            format!(
                "not measured: {} has no /proc/self/status, and reading peak RSS in-process \
                 otherwise needs unsafe, which master anti-goal 4 bans. Wrap the run in \
                 /usr/bin/time -l, which docs/spec/metrics.md §4.1 names as this \
                 repository's ground truth",
                std::env::consts::OS
            ),
        ),
    }
}
