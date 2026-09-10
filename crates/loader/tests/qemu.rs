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
//! # Why every test here is `#[ignore]`d
//!
//! `qemu-riscv32` is *user-mode* emulation: it translates Linux syscalls for a
//! foreign architecture, so it is built for Linux hosts only and no macOS build
//! of it exists -- Homebrew's `qemu` ships the system emulators and no
//! `linux-user` targets at all. There is therefore no arrangement under which
//! these run on a macOS developer machine, and a suite that silently passes by
//! doing nothing is worse than one that is visibly not run: it reads as
//! coverage in the summary line. So they are `#[ignore]`d, and [`qemu`] panics
//! rather than returning when the emulator is missing -- running them is now an
//! explicit request, and a request that cannot be honoured should say so.
//!
//! ```text
//! cargo test -p loader --test qemu -- --ignored    # a Linux host with qemu-user
//! ```
//!
//! **What still covers this ground without an emulator.** `tests/layout.rs`
//! checks the property whose absence broke these four tests in CI -- that the
//! image a host program loader is handed is one it can actually map and run --
//! by reading the program headers directly. That runs everywhere. What is left
//! uncovered here is execution itself: that fib computes the value it commits,
//! that the shims move bytes over the right descriptors, and that the panic
//! handler reports and exits nonzero. Nothing but an executor can witness those,
//! and until S12 builds one, QEMU is it.

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use field::Fr;
use test_support::to_hex;

/// Acceptance 3: fib reads `n` from fd 0 and writes `fib(n)` to fd 1.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn fib_computes_the_committed_value() {
    let qemu = qemu();

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
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn a_panicking_guest_reports_and_exits_nonzero() {
    let qemu = qemu();

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
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn echo_exercises_every_shim() {
    let qemu = qemu();

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
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn the_rvc_fixture_runs() {
    let qemu = qemu();

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

/// The user-mode emulator to run the guests under.
///
/// Panics when it is absent. These tests are `#[ignore]`d, so reaching this
/// function at all means someone asked for them by name; answering that request
/// with a silent pass would report coverage that did not happen.
fn qemu() -> String {
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
        "qemu-riscv32 is not on PATH, so the guests cannot be executed. \
         User-mode QEMU is Linux-only -- on macOS there is no build of it to \
         install. Run these on a Linux host with qemu-user, or rely on \
         tests/layout.rs, which checks host loadability without an emulator. \
         (Looked in {:?}.)",
        std::env::var("PATH").unwrap_or_default()
    )
}
