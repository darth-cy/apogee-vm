//! `qemu-riscv32` as an **output** oracle: what a guest computes, never how
//! this emulator computes it.
//!
//! The comparison is the guest's **exit status** and its **fd 1 bytes**, and
//! nothing below that — no register, no pc, no instruction count, no trace.
//! S12 compared the two register file by register file; S25 withdrew that
//! (`docs/handoff/S25-io-binding.md`). It was never the property this project
//! needs — this VM is not a clone of QEMU, and its internals exist for the
//! witness and the proof — and since S23 it is not even true: a delegation
//! ecall runs natively here and takes the `-ENOSYS` software fallback under
//! QEMU, so the two instruction streams differ *by design* and agree on the
//! answer.
//!
//! What holds a trace to *this* VM's semantics is `tests/trace.rs`,
//! `crates/trace`'s log self-check, and each family's row suite — all of
//! which run in `cargo test --workspace` with no emulator installed.
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
/// `consistency` on its hazards workload, and the four family guests, whose
/// exit statuses are their results: `addsub` (42), `control` (16), `alu` (96)
/// and `mem` (50). `tests/consistency.rs` runs the rest of `consistency`
/// against QEMU the same way, section by section.
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

/// What QEMU reports about a run: everything this oracle is allowed to read.
struct QemuRun {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Run a committed guest under QEMU: `input` on fd 0, an empty hint on fd 3,
/// both regular files, and fd 1 captured to a file.
fn qemu(tag: &str, name: &str, input: &[u8]) -> QemuRun {
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
    let run = QemuRun {
        status: out.status.code(),
        stdout: fs::read(path("stdout")).unwrap_or_default(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    let _ = fs::remove_dir_all(&dir);
    run
}

/// Trace `name` on `input` on this emulator, and report only what the oracle
/// compares: the exit status and the fd 1 bytes.
fn emulator(name: &str, input: &[u8]) -> (i32, Vec<u8>) {
    let image = image(name);
    let (tables, config) = preprocess(&image);
    let (_, _, _, execution) = trace_run(&image, &io(input), &tables, &config).unwrap();
    (execution.exit_code, execution.stdout)
}

/// The whole suite: both executors run the same committed bytes and agree on
/// the exit status and on fd 1.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn the_suite_agrees_with_qemu_on_the_outputs() {
    for name in SUITE {
        let input = input_of(name);
        let (exit_code, stdout) = emulator(name, &input);
        let q = qemu(name, name, &input);
        assert_eq!(
            q.status,
            Some(exit_code),
            "{name}: exit status; QEMU said: {}",
            q.stderr
        );
        assert_eq!(q.stdout, stdout, "{name}: fd 1");
        println!("{name}: exit {exit_code}, {} bytes on fd 1", stdout.len());
    }
}

/// The oracle can fail: the comparison discriminates.
///
/// `fib` on one input is the control and agrees; the same QEMU run against
/// the emulator's answer for a *different* input disagrees, on fd 1 or on the
/// exit status. Without this the suite above would pass just as happily if
/// either side's answer were ignored.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn the_oracle_can_fail() {
    let input = input_of("fib");
    let q = qemu("control", "fib", &input);

    let control = emulator("fib", &input);
    assert_eq!(q.status, Some(control.0), "the control's exit status");
    assert_eq!(q.stdout, control.1, "the control's fd 1");

    // A different `n`: the same program, a different answer.
    let mut other = input.clone();
    other[0] ^= 1;
    let perturbed = emulator("fib", &other);
    assert!(
        q.status != Some(perturbed.0) || q.stdout != perturbed.1,
        "the oracle accepted a different execution's outputs"
    );
}

/// `ebreak` stops both executors, neither cleanly: the emulator names the pc,
/// QEMU takes a trap signal. The pc itself is the emulator's own semantics
/// and is not compared.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn ebreak_stops_both_executors() {
    let input = 1u32.to_le_bytes();
    let EmuError::Ebreak { pc } = run(&image("opcodes"), &io(&input)).unwrap_err() else {
        panic!("mode 1 is an ebreak");
    };
    println!("the emulator stops at pc {pc:#010x}");
    let q = qemu("ebreak", "opcodes", &input);
    assert_ne!(
        q.status,
        Some(0),
        "QEMU must not exit cleanly through an ebreak"
    );
}
