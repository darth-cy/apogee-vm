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
//! as on the host, and that the panic handler reports and exits nonzero. Until
//! S12 builds a zkVM executor, QEMU is the only thing that can.

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

/// `amm` prices one swap against a seeded pool, and the numbers are checkable.
///
/// A constant-product pool of a million against a million, seeded with no
/// shares so the guest mints `sqrt(x*y)` for itself, and a single 1000-unit swap
/// at thirty basis points. Every figure below is arithmetic anyone can redo:
///
/// ```text
/// fee   = 1000 * 30 / 10_000                    = 3
/// net   = 1000 - 3                              = 997
/// new_x = 1_000_000 + 997                       = 1_000_997
/// out   = floor(1_000_000 * 997 / 1_000_997)    = 996
/// new_y = 1_000_000 - 996                       = 999_004
/// k     = 1_000_997 * 999_004 = 1_000_000_006_988 >= 1_000_000_000_000
/// ```
///
/// The point is not the arithmetic, which `guests/amm` gets right or wrong on
/// the host too. It is that the exact 256-bit `mul_div` and `sqrt` underneath it
/// run correctly on a 32-bit machine, where a `u128` is four registers and every
/// multiply is a sequence LLVM writes out itself.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn amm_prices_a_swap() {
    let qemu = qemu();

    let mut input = Vec::new();
    input.extend_from_slice(&1_000_000u128.to_le_bytes()); // reserve_x
    input.extend_from_slice(&1_000_000u128.to_le_bytes()); // reserve_y
    input.extend_from_slice(&0u128.to_le_bytes()); // total_shares: an unclaimed seed
    input.extend_from_slice(&30u32.to_le_bytes()); // fee_bps
    input.extend_from_slice(&1u32.to_le_bytes()); // n_ops
    input.extend_from_slice(&0u32.to_le_bytes()); // kind: SwapXForY
    input.extend_from_slice(&1_000u128.to_le_bytes()); // amount
    input.extend_from_slice(&0u128.to_le_bytes()); // limit: no floor
    assert_eq!(input.len(), 56 + 36, "the batch is a header and one record");

    let run = execute(&qemu, "amm", "amm", &input, None);
    assert_eq!(
        run.status,
        Some(0),
        "amm exited {:?}: {}",
        run.status,
        run.stderr
    );
    assert_eq!(run.stdout.len(), 104, "six u128 totals and two u32 tallies");

    let word = |i: usize| u128::from_le_bytes(run.stdout[16 * i..16 * i + 16].try_into().unwrap());
    let tally =
        |i: usize| u32::from_le_bytes(run.stdout[96 + 4 * i..100 + 4 * i].try_into().unwrap());
    assert_eq!(word(0), 1_000_997, "reserve_x");
    assert_eq!(word(1), 999_004, "reserve_y");
    assert_eq!(
        word(2),
        1_000_000,
        "total_shares: sqrt(10^12) against the seed"
    );
    assert_eq!(word(3), 3, "fees_x");
    assert_eq!(word(4), 0, "fees_y");
    assert_eq!(word(5), 0, "last_quote: the batch has no Quote in it");
    assert_eq!(tally(0), 1, "applied");
    assert_eq!(tally(1), 0, "rejected");
}

/// `orderbook` commits the same bytes whether the prover's advice was good.
///
/// This is the fd 3 rule, executed. The guest is run three times over one batch
/// — once with the permutation that really does sort it, once with a
/// transposition of that permutation, and once with nothing on fd 3 at all —
/// and **fd 1 must be identical in all three**. It is the strongest statement
/// this repository can make about prover advice without a prover: a hint that
/// changed a committed byte would be a statement the prover chose, and here the
/// three runs cannot be told apart from the outside.
///
/// fd 2 is where they do differ, and the test insists on that too: three runs
/// that agreed on the diagnostics as well would more likely mean the advice
/// never reached the guest than that it was correctly ignored.
///
/// The batch, and the permutation `key` puts it in — bids best-price-first,
/// then asks best-price-first, index breaking ties:
///
/// ```text
/// 0  bid  100 x 10        bids: 0 (100), 2 (95)
/// 1  ask   90 x  6        asks: 1 (90),  3 (100)
/// 2  bid   95 x  5
/// 3  ask  100 x  3        so the sorting permutation is [0, 2, 1, 3]
/// ```
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn orderbook_ignores_advice_it_cannot_verify() {
    let qemu = qemu();

    let mut input = 4u32.to_le_bytes().to_vec();
    for (side, price, qty) in [(0u32, 100u64, 10u64), (1, 90, 6), (0, 95, 5), (1, 100, 3)] {
        input.extend_from_slice(&side.to_le_bytes());
        input.extend_from_slice(&price.to_le_bytes());
        input.extend_from_slice(&qty.to_le_bytes());
    }
    assert_eq!(input.len(), 4 + 4 * 20, "a count and four 20-byte records");

    let advice = |perm: &[u32]| {
        let mut bytes = (perm.len() as u32).to_le_bytes().to_vec();
        for i in perm {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        bytes
    };
    let sorted = advice(&[0, 2, 1, 3]);
    // A permutation still, and still in range, so only the third check can
    // refuse it: the ask at 100 cannot precede the ask at 90.
    let transposed = advice(&[0, 2, 3, 1]);

    let good = execute(&qemu, "ob-good", "orderbook", &input, Some(&sorted));
    let bad = execute(&qemu, "ob-bad", "orderbook", &input, Some(&transposed));
    // An empty file rather than no fd 3 at all: a `read` on a closed descriptor
    // answers -EBADF, which the SDK treats as an executor fault and exits on,
    // and that would be testing the shell rather than the guest.
    let none = execute(&qemu, "ob-none", "orderbook", &input, Some(&[]));

    for (tag, run) in [("good", &good), ("bad", &bad), ("none", &none)] {
        assert_eq!(
            run.status,
            Some(0),
            "orderbook/{tag} exited {:?}: {}",
            run.status,
            run.stderr
        );
        assert_eq!(run.stdout.len(), 28, "orderbook/{tag}: one 28-byte record");
    }

    assert_eq!(
        to_hex(&good.stdout),
        to_hex(&bad.stdout),
        "a transposed permutation changed the committed output, so fd 3 is \
         binding something it must not"
    );
    assert_eq!(
        to_hex(&good.stdout),
        to_hex(&none.stdout),
        "the presence of advice changed the committed output"
    );

    assert!(
        good.stderr.contains("advice=verified"),
        "the sorting permutation was not accepted: {}",
        good.stderr
    );
    assert!(
        bad.stderr.contains("advice=rejected"),
        "a transposed permutation was accepted: {}",
        bad.stderr
    );
    assert!(
        none.stderr.contains("advice=rejected"),
        "an empty fd 3 was treated as advice: {}",
        none.stderr
    );
}

/// `vault` verifies a Merkle path, moves the root, and refuses a bad one.
///
/// Two withdrawals against a depth-1 tree, in one batch and in this order: the
/// first opens correctly against the header root, the second presents a proof
/// against a root that is no longer current. So the guest must accept one,
/// reject one, and leave the root where the accepted one put it — which also
/// says the rejection cost nothing, since a rejected withdrawal that had moved
/// the root would show up in the final value.
///
/// The expected values are computed here with `transcript::poseidon2_permute`
/// and `field::Fr`, which is the same permutation the guest falls back to. That
/// makes this an independent implementation of the *Merkle and share
/// arithmetic* and not an independent oracle for Poseidon2 — `crates/transcript`
/// has its own vectors for that. What it witnesses is that a 254-bit `Fr::pow`,
/// a field inversion and a tree walk all give the same answers inside a 32-bit
/// guest as they do on the host.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --ignored"]
fn vault_settles_a_merkle_withdrawal() {
    let qemu = qemu();

    /// The guest's `hash2`: lanes `[a, b, 0]`, permuted, first lane out.
    fn hash2(a: Fr, b: Fr) -> Fr {
        let mut state = [a, b, Fr::ZERO];
        transcript::poseidon2_permute(&mut state);
        state[0]
    }

    let account = Fr::from_u64(7);
    let balance = Fr::from_u64(100);
    let amount = Fr::from_u64(10);
    let sibling = Fr::from_u64(0xabc);
    let total_assets = Fr::from_u64(1_000);
    let total_shares = Fr::from_u64(1_000);

    // Depth 1, path bit clear: the leaf is the left child, so the root is
    // hash2(leaf, sibling).
    let root = hash2(hash2(account, balance), sibling);
    let settled = hash2(hash2(account, balance - amount), sibling);

    let record = |bal: Fr| {
        let mut r = Vec::new();
        r.extend_from_slice(&account.to_bytes());
        r.extend_from_slice(&bal.to_bytes());
        r.extend_from_slice(&amount.to_bytes());
        r.extend_from_slice(&0u32.to_le_bytes()); // path_bits: left child
        r.extend_from_slice(&sibling.to_bytes());
        r
    };

    let mut input = Vec::new();
    input.extend_from_slice(&root.to_bytes());
    input.extend_from_slice(&total_assets.to_bytes());
    input.extend_from_slice(&total_shares.to_bytes());
    input.extend_from_slice(&1u32.to_le_bytes()); // depth
    input.extend_from_slice(&2u32.to_le_bytes()); // count
    input.extend_from_slice(&record(balance));
    // The same leaf again. The first withdrawal already moved the root, so this
    // one opens against a root that is gone.
    input.extend_from_slice(&record(balance));
    assert_eq!(
        input.len(),
        104 + 2 * 132,
        "a header and two depth-1 records"
    );

    let run = execute(&qemu, "vault", "vault", &input, None);
    assert_eq!(
        run.status,
        Some(0),
        "vault exited {:?}: {}",
        run.status,
        run.stderr
    );
    assert_eq!(
        run.stdout.len(),
        104,
        "three field elements and two tallies"
    );

    let element = |i: usize| to_hex(&run.stdout[32 * i..32 * i + 32]);
    let tally =
        |i: usize| u32::from_le_bytes(run.stdout[96 + 4 * i..100 + 4 * i].try_into().unwrap());

    assert_eq!(
        element(0),
        to_hex(&settled.to_bytes()),
        "the final root is not the one the accepted withdrawal produced"
    );
    assert_eq!(element(1), to_hex(&amount.to_bytes()), "total_withdrawn");
    // shares = amount * total_shares / total_assets, and the two are equal here,
    // so the share price is one and the shares burned are the amount.
    assert_eq!(element(2), to_hex(&amount.to_bytes()), "shares_burned");
    assert_eq!(tally(0), 1, "accepted");
    assert_eq!(
        tally(1),
        1,
        "rejected: the second proof is against a stale root"
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
         User-mode QEMU is Linux-only -- on macOS there is no native build \
         of it, but a Linux container is enough and takes minutes: see \
         docs/guest-program-manual.md section 7. Otherwise rely on \
         tests/layout.rs, which checks host loadability without an emulator. \
         (Looked in {:?}.)",
        std::env::var("PATH").unwrap_or_default()
    )
}
