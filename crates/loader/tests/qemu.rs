//! The guests, executed.
//!
//! No zkVM emulator exists yet, so `qemu-riscv32` is the only executor this
//! stage has — which is the whole reason the ecall ABI uses Linux numbers over
//! Linux file descriptors. A guest runs here **unmodified**.
//!
//! Each test builds its guest from source rather than reading the committed
//! fixture, so behaviour is always checked against the current `guests/`. The
//! committed ELFs are loader-differential artifacts and nothing here depends on
//! them being fresh.
//!
//! # When QEMU is absent
//!
//! `qemu-riscv32` is user-mode emulation, which is built on Linux hosts only;
//! it does not exist on macOS. These tests print why and return on a machine
//! without it, the way `crates/srs`'s do without the ceremony file. CI runs on
//! `ubuntu-latest` with `qemu-user` installed, so they are not optional there.

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use field::Fr;
use test_support::to_hex;

/// Acceptance 3: fib reads `n` from fd 0 and writes `fib(n)` to fd 1.
#[test]
fn fib_computes_the_committed_value() {
    let Some(qemu) = qemu() else { return };

    let record = common::rows("fib_io.txt");
    let field = |key: &str| {
        record
            .iter()
            .find(|f| f[0] == key)
            .unwrap_or_else(|| panic!("fib_io.txt has no {key}"))[1]
            .clone()
    };
    let input = test_support::hex_to_bytes(&field("input")).expect("fib_io input is hex");
    let want = test_support::hex_to_bytes(&field("output")).expect("fib_io output is hex");

    let run = execute(&qemu, "fib-ok", "fib", &input, None);
    assert_eq!(
        run.status,
        Some(0),
        "fib exited {:?}: {}",
        run.status,
        run.stderr
    );
    assert_eq!(
        to_hex(&run.stdout),
        to_hex(&want),
        "fib({}) is wrong on fd 1",
        field("n")
    );
}

/// The panic handler: message and location to fd 2, and a nonzero exit.
///
/// fib asserts that fd 0 carried four bytes, so an empty input is the shortest
/// path to a real guest panic.
#[test]
fn a_panicking_guest_reports_and_exits_nonzero() {
    let Some(qemu) = qemu() else { return };

    let run = execute(&qemu, "fib-panic", "fib", &[], None);
    assert!(
        run.status.is_some_and(|c| c != 0),
        "a panicking guest must exit nonzero, got {:?}",
        run.status
    );
    assert!(
        run.stderr.contains("guest panicked at") && run.stderr.contains("src/main.rs:"),
        "the panic handler must write the message and the location to fd 2, got: {}",
        run.stderr
    );
    assert!(
        run.stdout.is_empty(),
        "a panic must not commit anything to fd 1"
    );
}

/// Acceptance 8: `read_input`, `commit` and `hint` over fds 0, 1 and 3, and a
/// precompile number that answers `-ENOSYS` and falls back.
#[test]
fn echo_exercises_every_shim() {
    let Some(qemu) = qemu() else { return };

    // 100 bytes: more than one 64-byte read, and not a multiple of it, so both
    // the full-buffer and the short-read paths run.
    let input: Vec<u8> = (0..100u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let hint = b"private-advice".to_vec();

    let run = execute(&qemu, "echo", "echo", &input, Some(&hint));
    assert_eq!(
        run.status,
        Some(0),
        "echo exited {:?}: {}",
        run.status,
        run.stderr
    );

    // fd 1 is the public journal: exactly the input, and nothing else.
    assert_eq!(
        to_hex(&run.stdout),
        to_hex(&input),
        "fd 1 is not a byte-for-byte echo of fd 0"
    );

    // fd 3 reached the guest, and stayed off fd 1.
    assert!(
        run.stderr.contains("hint=private-advice"),
        "the hint channel did not reach the guest: {}",
        run.stderr
    );

    // The precompile number is in range, unimplemented, and the guest took its
    // software path.
    assert!(
        run.stderr.contains("precompile=software"),
        "the precompile shim did not fall back: {}",
        run.stderr
    );

    // ... and that path really computed the permutation, not a placeholder.
    let mut state = [Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];
    transcript::poseidon2_permute(&mut state);
    assert!(
        run.stderr
            .contains(&format!("state0={}", to_hex(&state[0].to_bytes()))),
        "the software fallback did not produce the S02 permutation: {}",
        run.stderr
    );
}

/// The RVC-dense fixture is real, runnable code: its compressed routine and its
/// uncompressed twin agree, and the paired regions are the sizes the loader
/// tests read them at.
#[test]
fn the_rvc_fixture_runs() {
    let Some(qemu) = qemu() else { return };

    let run = execute(&qemu, "rvc", "rvc-dense", &7u32.to_le_bytes(), None);
    assert_eq!(
        run.status,
        Some(0),
        "rvc-dense exited {:?} -- the compressed and uncompressed routines \
         disagree, or an address moved: {}",
        run.status,
        run.stderr
    );
    assert_eq!(run.stdout.len(), 12, "three committed u32s");

    let word = |i: usize| u32::from_le_bytes(run.stdout[4 * i..4 * i + 4].try_into().unwrap());
    // rvc_exec(7): a1 = (7 + 1) << 2 = 32, a0 = 7 + 32 = 39, nonzero so + 7,
    // masked to a byte = 46.
    assert_eq!(word(0), 46, "the executed routine returned the wrong value");
    let (rvc_len, norvc_len) = (word(1), word(2));
    assert_eq!(
        norvc_len,
        2 * rvc_len,
        "the uncompressed region must be exactly twice the compressed one"
    );
    assert!(
        rvc_len >= 80,
        "the compressed region holds too few instructions"
    );
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

struct Run {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Build `name`, then run it under QEMU with `stdin` on fd 0 and, if given,
/// `hint` on fd 3.
///
/// `tag` names this call's scratch directory. Tests in one binary run on
/// several threads, so two runs of the same guest must not share one.
///
/// fd 3 is opened by `sh` rather than by this process: passing an extra
/// descriptor to a child otherwise needs `pre_exec`, which is `unsafe`, and the
/// shell already knows how.
fn execute(qemu: &str, tag: &str, name: &str, stdin: &[u8], hint: Option<&[u8]>) -> Run {
    let dir = std::env::temp_dir().join(format!("apogee-qemu-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("creating the run directory");
    let elf = dir.join(name);
    fs::write(&elf, common::build(name, &format!("qemu-{tag}"))).expect("writing the guest");
    // QEMU opens the file itself rather than exec'ing it, but a guest binary
    // that is not executable is a confusing thing to hand a debugger.
    fs::set_permissions(&elf, fs::Permissions::from_mode(0o755)).expect("marking the guest");

    let mut command = match hint {
        None => {
            let mut c = Command::new(qemu);
            c.arg(&elf);
            c
        }
        Some(bytes) => {
            let hint_path = dir.join("hint");
            fs::write(&hint_path, bytes).expect("writing the hint file");
            let mut c = Command::new("sh");
            c.arg("-c")
                .arg(r#"exec 3<"$1"; exec "$2" "$3""#)
                .arg("apogee-qemu")
                .arg(&hint_path)
                .arg(qemu)
                .arg(&elf);
            c
        }
    };

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning qemu");
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(stdin)
        .expect("writing the guest's public input");
    let out = child.wait_with_output().expect("waiting for qemu");

    let _ = fs::remove_dir_all(&dir);
    Run {
        status: out.status.code(),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `qemu-riscv32`, if this machine has it.
fn qemu() -> Option<String> {
    for name in ["qemu-riscv32", "qemu-riscv32-static"] {
        if Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return Some(name.to_string());
        }
    }
    println!(
        "qemu-riscv32 is not on PATH, so the guests were not executed. \
         User-mode QEMU is Linux-only; CI installs qemu-user and runs these. \
         (Looked in {:?}.)",
        std::env::var("PATH").unwrap_or_default()
    );
    None
}
