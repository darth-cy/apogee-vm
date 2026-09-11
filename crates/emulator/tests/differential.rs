//! Acceptance 1 and 2: the emulator against `qemu-riscv32`, register file by
//! register file, instruction by instruction.
//!
//! The emulator's side is replayed from its `MemoryEventLog` by
//! `emulator::qemu::emulator_steps`, so what is held to QEMU is the trace a
//! proof would be about. The guests are the committed, digest-pinned ELFs, so
//! both executors run the same bytes.
//!
//! **`#[ignore]`d**, for the reason `crates/loader/tests/qemu.rs` gives:
//! user-mode QEMU is Linux-only, and a machine without it must not report a
//! pass. CI runs it by name:
//!
//! ```text
//! cargo test -p emulator --test differential -- --include-ignored
//! ```
//!
//! `docs/guest-program-manual.md` section 7 has the Linux-container recipe
//! for macOS.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use common::{image, input_of, io, preprocess};
use emulator::qemu::{compare, emulator_steps, parse_log, Agreement, Record, Step, QEMU_FLAGS};
use emulator::{run, trace_run, EmuError};

/// Every guest the comparison covers: the stage's required corpus —
/// `opcodes`, `rvc-dense`, `fib`, `heap` — and `atomics`, the compiled AMOs.
const SUITE: [&str; 5] = ["opcodes", "rvc-dense", "fib", "heap", "atomics"];

struct Qemu {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
    records: Vec<Record>,
}

/// Run a committed guest under QEMU with the frozen flags: `input` on fd 0,
/// an empty hint on fd 3, both regular files, and fd 1 captured to a file.
fn qemu(tag: &str, name: &str, input: &[u8]) -> Qemu {
    let dir = std::env::temp_dir().join(format!("apogee-differential-{tag}"));
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
        .arg("apogee-differential")
        .arg(path("input"))
        .arg(path("stdout"))
        .arg(path("hint"))
        .arg(qemu_binary())
        .args(QEMU_FLAGS)
        .arg("-D")
        .arg(path("log"))
        .arg(path(name))
        .stderr(Stdio::piped())
        .output()
        .expect("spawning qemu");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let log = fs::read_to_string(path("log")).unwrap_or_default();
    let records = parse_log(&log).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(
        !records.is_empty(),
        "{name}: QEMU logged no instruction (status {:?}): {stderr}",
        out.status.code()
    );
    let run = Qemu {
        status: out.status.code(),
        stdout: fs::read(path("stdout")).unwrap_or_default(),
        stderr,
        records,
    };
    let _ = fs::remove_dir_all(&dir);
    run
}

/// Trace `name` on `input` and replay the log into its register trace.
fn emulator(name: &str, input: &[u8]) -> (Vec<Step>, emulator::Execution) {
    let image = image(name);
    let (tables, config) = preprocess(&image);
    let (_, log, _, execution) = trace_run(&image, &io(input), &tables, &config).unwrap();
    (emulator_steps(&image, &log), execution)
}

fn agree(name: &str) -> Agreement {
    let input = input_of(name);
    let (steps, execution) = emulator(name, &input);
    let q = qemu(name, name, &input);
    assert_eq!(
        q.status,
        Some(execution.exit_code),
        "{name}: exit status; QEMU said: {}",
        q.stderr
    );
    assert_eq!(q.stdout, execution.io.output, "{name}: fd 1");
    compare(&steps, &q.records).unwrap_or_else(|m| panic!("{name}: {m}"))
}

/// Acceptance 1: the whole suite, every instruction, every register, under
/// the entry-state rule and the one-entry whitelist. `opcodes` holds the one
/// unpaired `sc.w`, so it is the one guest whose agreement uses the
/// whitelist, and it must use it exactly once.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn the_suite_agrees_with_qemu_instruction_by_instruction() {
    for name in SUITE {
        let agreement = agree(name);
        println!(
            "{name}: {} instructions agree, {} sc.w whitelisted",
            agreement.records, agreement.sc_w_whitelisted
        );
        let want = if name == "opcodes" { 1 } else { 0 };
        assert_eq!(agreement.sc_w_whitelisted, want, "{name}");
    }
}

/// Acceptance 2: the oracle can fail. One register of one instruction of the
/// emulator's trace, perturbed, is reported at exactly that instruction and
/// register; a perturbed pc likewise.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn a_perturbed_emulator_trace_is_caught_at_its_instruction() {
    let input = input_of("fib");
    let (steps, _) = emulator("fib", &input);
    let q = qemu("perturb", "fib", &input);
    compare(&steps, &q.records).expect("the unperturbed trace is the control");

    for k in [2, steps.len() / 2, steps.len() - 1] {
        for reg in [1usize, 10, 31] {
            let mut perturbed = steps.clone();
            perturbed[k].regs[reg] ^= 1;
            let m = compare(&perturbed, &q.records).unwrap_err();
            assert_eq!((m.index, m.pc, m.reg), (k, steps[k].pc, Some(reg)), "{m}");
        }
        let mut perturbed = steps.clone();
        perturbed[k].pc += 2;
        let m = compare(&perturbed, &q.records).unwrap_err();
        assert_eq!((m.index, m.reg), (k, None), "{m}");
    }
}

/// `ebreak` stops both executors at the same pc: QEMU on a trap signal with
/// the `ebreak` its last record, the emulator with the named error.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn ebreak_stops_both_executors_at_one_pc() {
    let input = 1u32.to_le_bytes();
    let EmuError::Ebreak { pc } = run(&image("opcodes"), &io(&input)).unwrap_err() else {
        panic!("mode 1 is an ebreak");
    };
    let q = qemu("ebreak", "opcodes", &input);
    assert_ne!(
        q.status,
        Some(0),
        "QEMU must not exit cleanly through an ebreak"
    );
    assert_eq!(q.records.last().map(|r| r.pc), Some(pc));
}

fn qemu_binary() -> String {
    for name in ["qemu-riscv32", "qemu-riscv32-static"] {
        if Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return name.to_string();
        }
    }
    panic!(
        "qemu-riscv32 is not on PATH, so the differential cannot run. User-mode \
         QEMU is Linux-only; docs/guest-program-manual.md section 7 has the \
         container recipe."
    )
}
