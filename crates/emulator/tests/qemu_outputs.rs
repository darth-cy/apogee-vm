//! The emulator against `qemu-riscv32`, on what a guest **computes**: the exit
//! status it ends with, and the bytes it commits to fd 1.
//!
//! # What this suite does not do, and why
//!
//! It does not compare instruction counts, pcs, intermediate registers or
//! traces (owner's decision, S25). It did until S25 — S12 built this file as a
//! per-instruction register-file comparison, replayed from the emulator's own
//! `MemoryEventLog` — and that invariant is **withdrawn**, because it was never
//! the property the project needs and since S23 it is not even true:
//!
//! - This emulator is not a QEMU clone. It takes the execution path its trace
//!   generation needs, and the shape of that path is this VM's business.
//! - A **delegation** ecall proves it. `qemu-riscv32` has no circuit for a
//!   precompile number, answers `-ENOSYS`, and the shim's caller then computes
//!   the same value in software (`docs/spec/delegation.md` §2); this VM runs
//!   the delegation natively. Two instruction streams, one result, both
//!   correct. Since S25 that is the exit sequence of every guest that moves
//!   committed bytes, because publishing `io_digest` means Poseidon2
//!   (`docs/spec/memory.md` §10).
//!
//! So QEMU is an oracle for *what* a program computes and never for *how* this
//! emulator reaches it. What covers the trace is this VM's own semantics and
//! constraints, which is where a trace's correctness actually lives:
//! `crates/emulator/tests/trace.rs` (the frame, the four-slot clock, routing,
//! the halting sentinel, every ecall's answer), `crates/trace`'s log
//! self-check, `crates/checker/tests/multiset.rs` and `memory.rs` (the memory
//! argument over real guests' logs, forgeries refused by the gate that refuses
//! them), and each family's row suite over its fill.
//!
//! **`#[ignore]`d**, for the reason `crates/loader/tests/qemu.rs` gives:
//! user-mode QEMU is Linux-only, and a machine without it must not report a
//! pass. CI runs it by name:
//!
//! ```text
//! cargo test -p emulator --test qemu_outputs -- --include-ignored
//! ```
//!
//! `docs/guest-program-manual.md` section 7 has the Linux-container recipe
//! for macOS.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use common::{image, input_of, io, preprocess, qemu_binary};
use emulator::{run, trace_run, EmuError};

/// Every guest the comparison covers: the stage's required corpus —
/// `opcodes`, `rvc-dense`, `fib`, `heap` — `atomics`, the compiled AMOs,
/// `consistency` on its hazards workload, `addsub`, S16's guest, which exits
/// 42, `control`, S17's, which exits 16, and `alu` and `mem`.
///
/// `tests/consistency.rs` runs `guests/consistency`'s whole corpus, with the
/// host as a third leg; this file is one input per guest across the corpus
/// S12 required.
const SUITE: [&str; 10] = [
    "opcodes",
    "rvc-dense",
    "fib",
    "heap",
    "atomics",
    "consistency",
    "addsub",
    "control",
    "alu",
    "mem",
];

struct Qemu {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Run a committed guest under QEMU: `input` on fd 0, an empty hint on fd 3,
/// both regular files, and fd 1 captured to a file.
///
/// No `-d` flags. The register log this harness used to ask for is what made a
/// run cost 46 seconds and 15.5 GB once a guest delegated at exit, and nothing
/// reads it any more.
fn qemu(tag: &str, name: &str, input: &[u8]) -> Qemu {
    let dir = std::env::temp_dir().join(format!("apogee-qemu-outputs-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = |f: &str| dir.join(f);
    fs::write(path(name), common::elf(name)).unwrap();
    // QEMU's loader refuses a file with no execute bit, as the kernel would.
    fs::set_permissions(path(name), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(path("input"), input).unwrap();
    fs::write(path("hint"), b"").unwrap();

    // QEMU runs in the scratch directory with core dumps off: the ebreak case
    // ends on a trap signal, and a core file must never land in the tree —
    // cargo runs tests from the crate's own directory.
    let out = Command::new("sh")
        .current_dir(&dir)
        .arg("-c")
        .arg(r#"ulimit -c 0; exec 0<"$1" 1>"$2" 3<"$3"; shift 3; exec "$@""#)
        .arg("apogee-qemu-outputs")
        .arg(path("input"))
        .arg(path("stdout"))
        .arg(path("hint"))
        .arg(qemu_binary())
        .arg(path(name))
        .stderr(Stdio::piped())
        .output()
        .expect("spawning qemu");
    let run = Qemu {
        status: out.status.code(),
        stdout: fs::read(path("stdout")).unwrap_or_default(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    let _ = fs::remove_dir_all(&dir);
    run
}

/// What the emulator computes: the **traced** path's answer, because that is
/// the execution a proof is about. `tests/consistency.rs` holds `trace_run`
/// and `run` to each other over a corpus, so one of them here is both.
fn emulated(name: &str, input: &[u8]) -> emulator::Execution {
    let image = image(name);
    let (tables, config) = preprocess(&image);
    let (_, _, _, execution) = trace_run(&image, &io(input), &tables, &config).unwrap();
    execution
}

/// Acceptance 1: every guest of the suite computes the same thing under both
/// executors — the same exit status, and the same bytes on fd 1.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn the_suite_computes_the_same_thing_under_both_executors() {
    for name in SUITE {
        let input = input_of(name);
        let execution = emulated(name, &input);
        let q = qemu(name, name, &input);
        assert_eq!(
            q.status,
            Some(execution.exit_code),
            "{name}: exit status; QEMU said: {}",
            q.stderr
        );
        assert_eq!(
            q.stdout, execution.io.output,
            "{name}: fd 1, the committed public output"
        );
        println!(
            "{name}: exit {}, {} bytes on fd 1, under both",
            execution.exit_code,
            q.stdout.len()
        );
    }
}

/// Acceptance 2: the oracle can fail, and this is the shape of the failure
/// that matters — not a perturbed register but a different answer.
///
/// It is here because the way this comparison breaks silently is by comparing
/// nothing: a missing output file and an empty stream are equal, and so are
/// two runs of the same input. Giving the two executors **different** inputs
/// must produce different committed bytes, or the harness is not reading fd 1
/// at all.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn a_different_input_gives_a_different_answer() {
    let execution = emulated("fib", &24u32.to_le_bytes());
    let q = qemu("control", "fib", &12u32.to_le_bytes());
    assert_eq!(q.status, Some(execution.exit_code), "both still exit 0");
    assert!(
        !q.stdout.is_empty() && !execution.io.output.is_empty(),
        "both committed something"
    );
    assert_ne!(
        q.stdout, execution.io.output,
        "fib(12) and fib(24) must not commit the same bytes"
    );
}

/// `ebreak` stops both executors: QEMU on a trap signal, the emulator with the
/// named error. Where it stops them is not compared — that is a pc, and pcs
/// are this VM's business (the header).
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn ebreak_stops_both_executors() {
    let input = 1u32.to_le_bytes();
    let EmuError::Ebreak { pc: _ } = run(&image("opcodes"), &io(&input)).unwrap_err() else {
        panic!("mode 1 is an ebreak");
    };
    let q = qemu("ebreak", "opcodes", &input);
    assert_ne!(
        q.status,
        Some(0),
        "QEMU must not exit cleanly through an ebreak"
    );
}
