//! The guests, executed.
//!
//! `qemu-riscv32` runs every guest here **unmodified** — which is the whole
//! reason the ecall ABI uses Linux numbers over Linux file descriptors. It was
//! the only executor before S12; since then `crates/emulator` runs the guests
//! too, and `crates/emulator/tests/qemu_outputs.rs` holds the two executors to
//! one **exit status** and one **fd 1** — what a guest computes, never how this
//! emulator computes it. This file stays what it was: the guests' behaviour,
//! under the executor with a decade of maintenance behind it.
//!
//! Each test builds its guest from source rather than reading the committed
//! fixture, so behaviour is always checked against the current `guests/`. The
//! committed ELFs are loader-differential artifacts and nothing here depends on
//! them being fresh.
//!
//! # Why every test here is `#[ignore]`d
//!
//! `qemu-riscv32` is *user-mode* emulation: it does not emulate a machine, it
//! runs one Linux userspace binary by translating each syscall it makes into a
//! syscall on the host. That is Linux-on-Linux with a CPU translated in
//! between -- QEMU's own tree calls the mode `linux-user`, and it reimplements
//! Linux's `mmap` flags, signal frames, `futex` and errno numbering by calling
//! through to a Linux kernel underneath. So it builds for Linux hosts only and
//! no native macOS build exists; Homebrew's `qemu` ships the system emulators
//! and no `linux-user` targets at all.
//!
//! A machine with no emulator must not report silent coverage -- a suite that
//! passes by doing nothing reads as green in the summary line. So these are
//! `#[ignore]`d and [`qemu`] panics rather than returning when the emulator is
//! missing: running them is an explicit request, and a request that cannot be
//! honoured should say so.
//!
//! ```text
//! cargo test -p loader --test qemu -- --include-ignored   # a Linux host, qemu-user
//! ```
//!
//! **`#[ignore]`d is not unrunnable, and on macOS it is not even inconvenient.**
//! Apple Silicon runs a Linux VM at native speed, so only the innermost hop is
//! emulated. `docs/guest-program-manual.md` section 7 has the recipe; it is
//! about four minutes of setup, and CI gates on this suite on every pull
//! request.
//!
//! A guest built inside such a container is not the same bytes as one built on
//! the host: rustc embeds absolute paths in `core`'s panic-location strings, so
//! the ELFs differ in size as well as content. It does not matter here, because
//! every test below builds its guest from source -- what is checked is the
//! behaviour of the current `guests/` tree, not of a fixture.
//!
//! **What covers this ground without an emulator.** `tests/layout.rs` checks
//! the property whose absence broke these tests in CI -- that the image a host
//! program loader is handed is one it can actually map and run -- by reading
//! the program headers directly, and it runs everywhere. What only an executor
//! can witness is execution itself: that fib computes the value it commits,
//! that the shims move bytes over the right descriptors, that a 256-bit
//! `mul_div` and a 254-bit `Fr::pow` give the same answers on a 32-bit machine
//! as on the host, and that the panic handler reports and exits nonzero. Before
//! S12 QEMU was the only thing that could; now the emulator runs the same
//! guests, and `tests/qemu_outputs.rs` compares what the two of them compute.

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use field::Fr;
use test_support::to_hex;

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
    let profile = common::profile();
    fs::write(
        &elf,
        common::build_profile(name, &format!("qemu-{tag}"), &profile),
    )
    .expect("writing the guest");
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
         User-mode QEMU is Linux-only -- on macOS there is no native build \
         of it, but a Linux container is enough and takes minutes: see \
         docs/guest-program-manual.md section 7. Otherwise rely on \
         tests/layout.rs, which checks host loadability without an emulator. \
         (Looked in {:?}.)",
        std::env::var("PATH").unwrap_or_default()
    )
}

/// `guests/keccak-test` and `guests/keccak-unused`: S21's acceptance 5, the
/// **software-fallback half**.
///
/// The delegation ecall `0x501` is a precompile number `qemu-riscv32` knows
/// nothing about, so its `ecall` returns `-ENOSYS` and `guest_sdk::keccak256`
/// takes its in-guest software path — the same frozen signature, the same
/// bytes out (`docs/spec/delegation.md` §2). The guest checks its own six
/// digests and exits 6 either way, which is the property: one binary, two
/// executors, bit-identical answers. The emulator's half of the same
/// acceptance is `crates/emulator/tests/guests.rs`, where the ecall performs
/// the permutation instead, and the digests themselves are re-derived from
/// `tiny-keccak` there so neither path can agree on a stale literal.
///
/// `keccak-unused` links the shim and never calls it. Under QEMU that is
/// indistinguishable from any other guest — nothing about detachment is
/// visible at run time; it is the *image* that declares the family, and
/// `crates/program/tests/delegation.rs` is what reads that. What this run adds
/// is that linking the shim costs the guest nothing at run time: it still
/// exits 7.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn keccak_falls_back_to_software_and_agrees() {
    let qemu = qemu();

    for (name, status) in [("keccak-test", 6), ("keccak-unused", 7)] {
        let run = execute(&qemu, name, name, &[], None);
        assert_eq!(
            run.status,
            Some(status),
            "{name} exited {:?} rather than {status}, so a digest disagreed \
             between the delegation path and the software one: {}",
            run.status,
            run.stderr
        );
        assert!(
            run.stdout.is_empty(),
            "{name} commits nothing to fd 1: an ecall other than EXIT and the \
             delegation call would make the fixture unprovable"
        );
    }
}

/// `guests/recursion-ops` and `guests/recursion-unused`: S23's acceptances 1,
/// 2 and 9, the **software-fallback half**, and the sharper version of the
/// test above it.
///
/// S21's shim was one the guest called by name. S23's two are not: a guest
/// writes ordinary `field::Fr` arithmetic and calls
/// `transcript::poseidon2_permute`, and the backends inside those two crates
/// route them through `guest_sdk::recursion` under `#[cfg(target_arch =
/// "riscv32")]` (`docs/spec/delegation.md` §13.4). So what "the same binary on
/// two executors" means here is stronger than at S21 — the *fallback is the
/// same source*, one branch below the ecall, and not a second implementation.
/// `qemu-riscv32` knows neither `0x500` nor `0x502`, answers `-ENOSYS` to
/// both, and every operation takes `field`'s and `transcript`'s own software
/// path.
///
/// `recursion-ops` checks its own answers in-guest — the Fr round trips and
/// the three permutation known-answers — and exits 9 either way, which is the
/// property: 33,164 proven cycles under the emulator against 2,865,234 of
/// software here, bit-identical results. The emulator's half is
/// `crates/emulator/tests/guests.rs`, where the same run makes 2 `POSEIDON2`
/// and 29 `FR_ARITH` invocations.
///
/// `recursion-unused` links both backends behind a `black_box` the optimiser
/// cannot fold and reaches neither, so it exits 11 on either executor. As with
/// `keccak-unused`, detachment is invisible at run time — it is the *image*
/// that declares a family — and what this adds is that linking two backends
/// costs a guest that calls neither nothing at all.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn the_recursion_guests_fall_back_to_software_and_agree() {
    let qemu = qemu();

    for (name, status) in [
        ("recursion-ops", 9),
        ("recursion-unused", 11),
        // S26's fixture, and the same story one family further: under QEMU the
        // `MOD_MUL` ecall answers `-ENOSYS`, so the guest's own `u128` path
        // answers its ABI checks and `guests/vendor/k256`'s own `mul_inner`
        // answers its curve checks — both against the same literals, so the
        // status is the same. This test is the fallback half; the delegated half
        // is `crates/emulator/tests/guests.rs`'.
        ("mod-mul-ops", 12),
    ] {
        let run = execute(&qemu, name, name, &[], None);
        assert_eq!(
            run.status,
            Some(status),
            "{name} exited {:?} rather than {status}, so an answer disagreed \
             between the delegated path and the software one: {}",
            run.status,
            run.stderr
        );
        assert!(
            run.stdout.is_empty(),
            "{name} commits nothing to fd 1: an ecall other than EXIT and the \
             delegation calls would make the fixture unprovable"
        );
    }
}
