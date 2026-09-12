//! The three-way consistency suite: `guests/consistency` run on the host,
//! under `qemu-riscv32` and on the zkVM's emulator, over one set of inputs,
//! and held to one answer.
//!
//! `guests/consistency` is a library of ordinary `no_std + alloc` Rust —
//! numerics, collections, text, traits and closures, a codec, hashes and the
//! repository's own field and permutation, allocation patterns — and a thin
//! guest `main`. The host calls the library directly. The guest is built from
//! that same source here, at test time, so the legs are always one program: the
//! committed `consistency.elf` is the loader's fixture and the
//! instruction-by-instruction differential's, and a stale one would have this
//! suite comparing two programs.
//!
//! Which legs disagree says what broke:
//!
//! | host | QEMU | emulator | reading |
//! | --- | --- | --- | --- |
//! | a | a | a | consistent, on this input |
//! | a | b | b | the host differs from both RV32 executors: Rust's target, the SDK, or 32-bit behaviour |
//! | a | a | b | the emulator differs from real RV32 and from the host: an emulator bug |
//! | a | b | a | QEMU differs from both: the harness, or QEMU's environment |
//! | a | b | c | all three differ |
//!
//! Compared: the exit status; fd 1 byte for byte, split into its sections so a
//! mismatch names the workload that wrote it; and for a panic, its message,
//! line and column. The host is excused from the sections
//! [`consistency::hazards::PLATFORM_DEPENDENT`] declares — values Rust itself
//! defines per target — and the two RV32 executors are not. On a 64-bit host
//! the pointer-width ones must actually differ, so the list cannot go stale by
//! quietly becoming false.
//!
//! The host leg runs with overflow checks on, as both guest profiles do, and on
//! a thread with a 64 MiB stack: a test thread's 2 MiB would make deep
//! recursion a difference between the legs for no reason worth finding.
//!
//! Without QEMU the suite compares the host and the emulator, which says *that*
//! they differ but not which is wrong. The QEMU leg is `#[ignore]`d for the
//! reason `tests/differential.rs` gives, and CI asks for it by name:
//!
//! ```text
//! cargo test -p emulator --test consistency -- --include-ignored
//! ```
//!
//! `APOGEE_GUEST_PROFILE=release` builds the guest at `--release` instead,
//! which must change nothing any leg can see.

mod common;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::panic;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Once, OnceLock};
use std::thread;

use common::{instr_at, io};
use consistency::hazards::{Divergence, Platform, PLATFORM_DEPENDENT};
use consistency::hazards::{TAG_SIZE_OF, TAG_USIZE_CAST, TAG_USIZE_OVERFLOW};
use consistency::{
    sections, Input, HEADER_LEN, MAX_SCALE, MODE_HEAP_CEILING, MODE_HEAP_UNDER_DEEP_STACK,
    TAG_BAD_INPUT, WORKLOADS,
};
use constants::family;
use emulator::{run, trace_run};
use loader::{load_elf, ProgramImage};
use test_support::{to_hex, Rng};

/// guest-sdk's `EXIT_PANIC`: what its panic handler exits with, and what a
/// panic on the host is scored as.
const PANIC_EXIT: i32 = 101;

/// guest-sdk's `EXIT_OUT_OF_MEMORY`.
const OUT_OF_MEMORY: i32 = 71;

/// Seeded inputs beyond the fixed corpus.
const RANDOM_CASES: usize = 32;

/// The heap probes, and the line each commits before the allocator must
/// refuse it with [`OUT_OF_MEMORY`].
const HEAP_PROBES: [(u8, &[u8]); 2] = [
    (MODE_HEAP_CEILING, b"reached the ceiling\n"),
    (
        MODE_HEAP_UNDER_DEEP_STACK,
        b"granted a block below the live stack\n",
    ),
];

/// A payload with the Unicode a text workload should trip over: a character
/// whose uppercase is two, one whose lowercase is two, a ligature, CJK, an
/// emoji, and a combining mark.
const TEXT: &str = "Consistent? naïve café — Straße, İstanbul, ﬃ, 日本語, 🦀, and e\u{301}.";

// ---------------------------------------------------------------------------
// The legs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Panic {
    /// The location's last component only. The directory differs between the
    /// legs — the host compiles the library from the root workspace and the
    /// guest from `guests/` — but the file itself does not, and dropping it
    /// entirely would let a panic that moved to another module compare equal.
    file: String,
    line: u32,
    column: u32,
    message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// The program exited with `code`, having written `output` to fd 1.
    Exit {
        code: i32,
        output: Vec<u8>,
        panic: Option<Panic>,
    },
    /// The executor stopped it: a fatal guest error, or a signal.
    Stopped(String),
}

/// `panicked at FILE:LINE:COL:\nMESSAGE`: the `Display` of core's `PanicInfo`,
/// which guest-sdk's panic handler prints to fd 2, and of std's
/// `PanicHookInfo`. The file is left out — the host and the guest compile the
/// library from different working directories — and the line and column say
/// where regardless.
fn parse_panic(text: &str) -> Option<Panic> {
    let rest = text.split_once("panicked at ")?.1;
    let (location, message) = rest.split_once(":\n").unwrap_or((rest.trim_end(), ""));
    let mut fields = location.trim_end_matches(':').rsplitn(3, ':');
    let column = fields.next()?.parse().ok()?;
    let line = fields.next()?.parse().ok()?;
    let file = fields.next()?.rsplit('/').next()?.to_string();
    Some(Panic {
        file,
        line,
        column,
        message: message.trim_end_matches('\n').to_string(),
    })
}

const HOST_THREAD: &str = "consistency-host";

thread_local! {
    static HOST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Route panics on the host leg's threads into [`HOST_PANIC`] rather than to
/// stderr. Every other thread keeps the default hook, so a failing assertion
/// still says why.
fn capture_host_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let default = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if thread::current().name() == Some(HOST_THREAD) {
                HOST_PANIC.with(|p| *p.borrow_mut() = Some(info.to_string()));
            } else {
                default(info);
            }
        }));
    });
}

/// Run `f` on a host-leg thread.
fn on_host_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    capture_host_panics();
    thread::Builder::new()
        .name(HOST_THREAD.into())
        .stack_size(64 << 20)
        .spawn(f)
        .expect("spawning a host-leg thread")
        .join()
        .expect("a host-leg thread died outside catch_unwind")
}

/// The host leg: `consistency::run`, called.
fn host(input: &[u8]) -> Outcome {
    static CHECKS_OVERFLOW: OnceLock<bool> = OnceLock::new();
    let checks = *CHECKS_OVERFLOW.get_or_init(|| {
        on_host_thread(|| panic::catch_unwind(|| black_box(black_box(u8::MAX) + 1)).is_err())
    });
    assert!(
        checks,
        "the host leg is built without overflow checks, and both guest profiles \
         are pinned with them on, so every overflow would be a difference \
         between the legs. `cargo test --release` does this; run the suite in \
         the dev profile."
    );

    let input = input.to_vec();
    on_host_thread(move || {
        let mut output = Vec::new();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            consistency::run(&input, &mut |section: &[u8]| {
                output.extend_from_slice(section)
            })
        }));
        match result {
            Ok(()) => Outcome::Exit {
                code: 0,
                output,
                panic: None,
            },
            Err(_) => {
                let text = HOST_PANIC
                    .with(|p| p.borrow_mut().take())
                    .unwrap_or_default();
                let panic = parse_panic(&text).unwrap_or(Panic {
                    file: String::new(),
                    line: 0,
                    column: 0,
                    message: text,
                });
                Outcome::Exit {
                    code: PANIC_EXIT,
                    output,
                    panic: Some(panic),
                }
            }
        }
    })
}

/// The emulator leg: `emulator::run` over the guest built from source.
fn emulate(image: &ProgramImage, input: &[u8]) -> Outcome {
    match run(image, &io(input)) {
        Ok(e) => Outcome::Exit {
            code: e.exit_code,
            output: e.io.output,
            panic: parse_panic(&String::from_utf8_lossy(&e.stderr)),
        },
        Err(e) => Outcome::Stopped(format!("the emulator stopped it: {e}")),
    }
}

/// The QEMU leg: the same ELF under `qemu-riscv32`, `input` on fd 0.
fn qemu(elf: &[u8], input: &[u8]) -> Outcome {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "apogee-consistency-{}-{}",
        std::process::id(),
        RUNS.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("creating the run directory");
    let path = dir.join("consistency");
    fs::write(&path, elf).expect("writing the guest");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("marking the guest");

    // In the scratch directory, so a core file from a guest that dies on a
    // signal never lands in the tree.
    let mut child = Command::new(common::qemu_binary())
        .arg(&path)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning qemu");
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(input)
        .expect("writing fd 0");
    let out = child.wait_with_output().expect("waiting for qemu");
    let _ = fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(code) => Outcome::Exit {
            code,
            output: out.stdout,
            panic: parse_panic(&stderr),
        },
        None => Outcome::Stopped(format!("QEMU ended on a signal: {stderr}")),
    }
}

struct Guest {
    elf: Vec<u8>,
    image: ProgramImage,
}

/// `guests/consistency`, built once per test binary.
fn guest() -> &'static Guest {
    static GUEST: OnceLock<Guest> = OnceLock::new();
    GUEST.get_or_init(|| {
        let elf = common::build_guest("consistency", &common::guest_profile());
        let image = load_elf(&elf).unwrap_or_else(|e| panic!("consistency: {e:?}"));
        Guest { elf, image }
    })
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

fn platform(tag: u8) -> Option<&'static Platform> {
    PLATFORM_DEPENDENT.iter().find(|p| p.tag == tag)
}

/// Whether this host produces RISC-V's quiet NaN, which AArch64 does and
/// x86-64 does not.
fn host_nan_is_rv32s() -> bool {
    static BITS: OnceLock<u64> = OnceLock::new();
    *BITS.get_or_init(|| (black_box(0.0f64) / black_box(-0.0f64)).to_bits())
        == 0x7ff8_0000_0000_0000
}

/// Whether the host leg is excused from `tag`.
///
/// The pointer-width sections always. The NaN section only on a host whose own
/// convention differs: excusing it everywhere would throw away a real emulator
/// divergence on a host that agrees with RISC-V, which is every AArch64 one.
fn excused(tag: u8) -> bool {
    match platform(tag).map(|p| p.kind) {
        None => false,
        Some(Divergence::PointerWidth) => true,
        Some(Divergence::NanBits) => !host_nan_is_rv32s(),
    }
}

/// The workload that owns `tag`.
fn owner(tag: u8) -> &'static str {
    if tag == TAG_BAD_INPUT {
        return "the input check";
    }
    WORKLOADS
        .iter()
        .find(|w| (w.tags.0..=w.tags.1).contains(&tag))
        .map_or("no workload", |w| w.name)
}

/// Bytes for a failure message: as text when they are text, else hex, and
/// either way not the whole of a long section.
fn show(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if !text.chars().any(|c| c.is_control() && c != '\n') {
            let head: String = text.chars().take(160).collect();
            return if head.len() < text.len() {
                format!("{head:?}... ({} bytes)", bytes.len())
            } else {
                format!("{head:?}")
            };
        }
    }
    if bytes.len() <= 48 {
        to_hex(bytes)
    } else {
        format!("{}... ({} bytes)", to_hex(&bytes[..48]), bytes.len())
    }
}

fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Exit {
            code,
            output,
            panic,
        } => format!(
            "exit {code}, {} bytes on fd 1, panic {panic:?}",
            output.len()
        ),
        Outcome::Stopped(why) => why.clone(),
    }
}

/// The first difference between two legs, or `None`.
///
/// `excuse_host` is set when `a` is the host: the platform-dependent sections
/// are then left out, after checking that the pointer-width ones do differ on
/// a 64-bit host.
fn difference(a: &Outcome, b: &Outcome, excuse_host: bool) -> Option<String> {
    let (
        Outcome::Exit {
            code: code_a,
            output: out_a,
            panic: panic_a,
        },
        Outcome::Exit {
            code: code_b,
            output: out_b,
            panic: panic_b,
        },
    ) = (a, b)
    else {
        let both_stopped = matches!((a, b), (Outcome::Stopped(_), Outcome::Stopped(_)));
        return (excuse_host || !both_stopped)
            .then(|| format!("{} against {}", describe(a), describe(b)));
    };
    if code_a != code_b {
        return Some(format!("exit status {code_a} against {code_b}"));
    }
    if panic_a != panic_b {
        return Some(format!("panic {panic_a:?} against {panic_b:?}"));
    }
    let (Some(sections_a), Some(sections_b)) = (sections(out_a), sections(out_b)) else {
        return (out_a != out_b).then(|| {
            format!(
                "fd 1 does not split into sections: {} bytes against {}",
                out_a.len(),
                out_b.len()
            )
        });
    };

    if excuse_host && cfg!(target_pointer_width = "64") {
        let pointer_width = PLATFORM_DEPENDENT
            .iter()
            .filter(|p| p.kind == Divergence::PointerWidth);
        for p in pointer_width {
            let x = sections_a.iter().find(|(tag, _)| *tag == p.tag);
            let y = sections_b.iter().find(|(tag, _)| *tag == p.tag);
            if let (Some(x), Some(y)) = (x, y) {
                if x == y {
                    return Some(format!(
                        "section {:#04x} is declared pointer-width dependent -- {} -- and \
                         is the same on this 64-bit host, so the declaration is stale",
                        p.tag, p.what
                    ));
                }
            }
        }
    }

    let keep = |s: Vec<(u8, &[u8])>| -> Vec<(u8, Vec<u8>)> {
        s.into_iter()
            .filter(|(tag, _)| !excuse_host || !excused(*tag))
            .map(|(tag, body)| (tag, body.to_vec()))
            .collect()
    };
    let (kept_a, kept_b) = (keep(sections_a), keep(sections_b));
    let first = kept_a
        .iter()
        .zip(&kept_b)
        .enumerate()
        .find(|(_, (x, y))| x != y);
    if let Some((i, (x, y))) = first {
        return Some(if x.0 != y.0 {
            format!(
                "section {i} is tag {:#04x}, from {}, against {:#04x}, from {}",
                x.0,
                owner(x.0),
                y.0,
                owner(y.0)
            )
        } else {
            format!(
                "section {i}, tag {:#04x}, from {}: {} against {}",
                x.0,
                owner(x.0),
                show(&x.1),
                show(&y.1)
            )
        });
    }
    (kept_a.len() != kept_b.len())
        .then(|| format!("{} sections against {}", kept_a.len(), kept_b.len()))
}

/// The verdict on one input, read off the table in the module docs.
fn judge(host: &Outcome, qemu: Option<&Outcome>, emulator: &Outcome) -> Result<(), String> {
    let he = difference(host, emulator, true);
    let Some(qemu) = qemu else {
        return match he {
            None => Ok(()),
            Some(d) => Err(format!(
                "the host and the emulator differ -- {d}. Run the QEMU leg \
                 (--include-ignored) to say which is wrong."
            )),
        };
    };
    // Both executors stopping is its own answer: they may have stopped for
    // different reasons, and "they agree" would blame the host for it.
    if let (Outcome::Stopped(q), Outcome::Stopped(e)) = (qemu, emulator) {
        return Err(format!(
            "both RV32 executors stopped -- QEMU: {q}; the emulator: {e}"
        ));
    }
    let hq = difference(host, qemu, true);
    let qe = difference(qemu, emulator, false);
    match (hq, qe, he) {
        (None, None, None) => Ok(()),
        (Some(d), None, _) => Err(format!(
            "the host differs from both RV32 executors, which agree: Rust's \
             target, the SDK or 32-bit behaviour -- {d}"
        )),
        (None, Some(d), Some(_)) => Err(format!(
            "the emulator differs from QEMU and the host, which agree: an \
             emulator semantics bug -- {d}"
        )),
        (None, Some(d), None) => Err(format!(
            "the two RV32 executors differ on a section the host is excused \
             from -- {d}"
        )),
        (Some(_), Some(d), None) => Err(format!(
            "QEMU differs from the host and the emulator, which agree: the \
             harness or QEMU's environment -- {d}"
        )),
        (Some(a), Some(b), Some(_)) => Err(format!(
            "all three differ -- host against QEMU: {a}; QEMU against the \
             emulator: {b}"
        )),
        (None, None, Some(d)) => Err(format!(
            "the host and the emulator differ although each agrees with QEMU \
             -- {d}"
        )),
    }
}

// ---------------------------------------------------------------------------
// The inputs
// ---------------------------------------------------------------------------

struct Case {
    name: String,
    input: Vec<u8>,
}

/// One ordinary input, encoded as the fd 0 the guest and the host both read.
fn fd0(seed: u64, scale: u32, workloads: u32, fault: u8, payload: &[u8]) -> Vec<u8> {
    Input {
        seed,
        scale,
        workloads,
        fault,
        payload,
    }
    .encode()
}

/// The input that asks workload `index` for fault `code`.
fn fault_input(index: usize, code: u8) -> Vec<u8> {
    fd0(
        0x100 + u64::from(code),
        3,
        1 << index,
        code,
        TEXT.as_bytes(),
    )
}

/// fd 0s that are not inputs: each gets one `TAG_BAD_INPUT` section.
fn bad_inputs() -> [(&'static str, Vec<u8>); 3] {
    let mut unknown_mode = fd0(5, 0, 0, 0, b"");
    unknown_mode[0] = 0x7f;
    [
        ("an empty fd 0", Vec::new()),
        (
            "a header one byte short",
            fd0(4, 0, 0, 0, b"")[..HEADER_LEN - 1].to_vec(),
        ),
        ("an unknown mode", unknown_mode),
    ]
}

/// Text drawn from characters that exercise the Unicode paths.
fn random_text(rng: &mut Rng, len: usize) -> Vec<u8> {
    const POOL: [char; 16] = [
        'a', 'Z', '7', ' ', '\n', ',', 'é', 'ß', 'Ω', 'ж', 'İ', 'ﬃ', '日', '本', '🦀', '\u{301}',
    ];
    let mut text = String::new();
    while text.len() < len {
        text.push(POOL[(rng.next_u64() % POOL.len() as u64) as usize]);
    }
    text.into_bytes()
}

fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |name: String, input: Vec<u8>| cases.push(Case { name, input });

    add(
        "every workload, scale 0, no payload".into(),
        fd0(1, 0, 0, 0, b""),
    );
    add(
        "every workload, MAX_SCALE, the text payload".into(),
        fd0(2, MAX_SCALE, 0, 0, TEXT.as_bytes()),
    );
    add(
        "every workload, a scale past MAX_SCALE".into(),
        fd0(3, u32::MAX, 0, 0, b"clamped"),
    );
    for (i, w) in WORKLOADS.iter().enumerate() {
        add(
            format!("{} alone, scale 5", w.name),
            fd0(10 + i as u64, 5, 1 << i, 0, TEXT.as_bytes()),
        );
    }
    let payloads: [(&str, Vec<u8>); 6] = [
        (
            "ASCII",
            b"The quick brown fox jumps over the lazy dog, 0123456789.".to_vec(),
        ),
        (
            "invalid UTF-8",
            vec![
                b'o', b'k', 0xc3, 0x28, 0xff, 0xed, 0xa0, 0x80, 0xf0, 0x9f, 0xa6,
            ],
        ),
        ("64 x 0xff", vec![0xff; 64]),
        ("64 x 0x00", vec![0; 64]),
        ("4 KiB random", Rng::new(0x5041_594c).next_bytes(4096)),
        ("one byte", vec![b'{']),
    ];
    for (k, (what, payload)) in payloads.iter().enumerate() {
        add(
            format!("every workload, scale 2, {what} payload"),
            fd0(20 + k as u64, 2, 0, 0, payload),
        );
    }
    for (what, input) in bad_inputs() {
        add(what.into(), input);
    }
    for (i, w) in WORKLOADS.iter().enumerate() {
        for f in w.faults {
            add(
                format!("{} fault {:#04x}: {}", w.name, f.code, f.what),
                fault_input(i, f.code),
            );
        }
    }

    let mut rng = Rng::new(0x7031_7277_6179);
    for k in 0..RANDOM_CASES {
        let seed = rng.next_u64();
        // Drawn twice, so small scales are commoner than large ones: every
        // scale still appears, and the corpus does not spend most of its time
        // at MAX_SCALE, where the crypto workload alone is 169M guest cycles.
        let ceiling = rng.next_u64() % (u64::from(MAX_SCALE) + 1);
        let scale = (rng.next_u64() % (ceiling + 1)) as u32;
        let workloads = if rng.next_u64().is_multiple_of(3) {
            0
        } else {
            rng.next_u64() as u32 & ((1 << WORKLOADS.len()) - 1)
        };
        let len = (rng.next_u64() % 600) as usize;
        let payload = if rng.next_u64().is_multiple_of(2) {
            rng.next_bytes(len)
        } else {
            random_text(&mut rng, len)
        };
        add(
            format!("random {k}: seed {seed:#x}, scale {scale}, workloads {workloads:#x}"),
            fd0(seed, scale, workloads, 0, &payload),
        );
    }
    // A corpus that shrank would let both agreement tests pass by having
    // nothing left to disagree about.
    assert!(cases.len() >= 80, "the corpus is {} inputs", cases.len());
    cases
}

fn failure(case: &Case, why: &str) -> String {
    format!("{}: {why}\n    fd 0: {}", case.name, show(&case.input))
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

/// Every tag belongs to one workload, every fault code to one fault, and every
/// declared divergence to the hazards workload.
#[test]
fn the_registry_is_consistent() {
    assert!(WORKLOADS.len() <= 32, "fd 0's workload mask is a u32");
    let mut names = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut codes = BTreeSet::new();
    for w in &WORKLOADS {
        assert!(names.insert(w.name), "two workloads are called {}", w.name);
        assert!(w.tags.0 <= w.tags.1, "{}'s tag range is empty", w.name);
        for tag in w.tags.0..=w.tags.1 {
            assert_ne!(tag, TAG_BAD_INPUT, "{} claims the bad-input tag", w.name);
            assert!(tags.insert(tag), "tag {tag:#04x} is claimed twice");
        }
        for f in w.faults {
            assert_ne!(f.code, 0, "fault code 0 means no fault");
            assert!(
                codes.insert(f.code),
                "fault {:#04x} is claimed twice",
                f.code
            );
        }
    }
    let mut declared = BTreeSet::new();
    for p in &PLATFORM_DEPENDENT {
        assert_eq!(owner(p.tag), "hazards", "{:#04x}", p.tag);
        assert!(declared.insert(p.tag), "{:#04x} is declared twice", p.tag);
    }
}

/// The suite's claim, on every input in the corpus: the host and the emulator
/// commit the same bytes, exit the same way, and panic at the same line.
#[test]
fn the_host_and_the_emulator_agree_on_every_input() {
    let guest = guest();
    let cases = corpus();
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let verdict = judge(
                &host(&case.input),
                None,
                &emulate(&guest.image, &case.input),
            );
            verdict.err().map(|why| failure(case, &why))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} inputs disagree:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

/// The corpus exercises what it claims to: every workload writes at
/// `MAX_SCALE`, every declared divergence is written, every fault panics on
/// both legs, and every bad input takes the error path.
#[test]
fn every_workload_fault_and_bad_input_is_exercised() {
    let guest = guest();
    let full = emulate(&guest.image, &fd0(2, MAX_SCALE, 0, 0, TEXT.as_bytes()));
    let Outcome::Exit {
        code: 0, output, ..
    } = &full
    else {
        panic!("the full run: {}", describe(&full));
    };
    let written: BTreeSet<u8> = sections(output)
        .expect("fd 1 splits into sections")
        .iter()
        .map(|(tag, _)| *tag)
        .collect();
    for w in &WORKLOADS {
        assert!(
            written.iter().any(|t| (w.tags.0..=w.tags.1).contains(t)),
            "{} writes no section at MAX_SCALE",
            w.name
        );
    }
    for p in &PLATFORM_DEPENDENT {
        assert!(
            written.contains(&p.tag),
            "{:#04x} is declared and never written",
            p.tag
        );
    }

    // The host is excused from the hazards sections, so in a run without QEMU
    // nothing else compares them at all — the emulator could corrupt one and
    // the suite would stay green. Three of them are constants of the target
    // rather than of the input, so the emulator's own bytes are pinned here.
    let body = |tag: u8| {
        sections(output)
            .expect("fd 1 splits into sections")
            .into_iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, body)| body.to_vec())
            .unwrap_or_else(|| panic!("{tag:#04x} is not written"))
    };
    assert_eq!(
        body(TAG_SIZE_OF),
        // usize, Box<u8>, &[u8], (u8, usize), Option<Box<u64>> on RV32.
        [4, 4, 8, 8, 4],
        "the guest's pointer-holding types are not RV32's sizes"
    );
    assert_eq!(
        body(TAG_USIZE_OVERFLOW),
        u64::MAX.to_le_bytes(),
        "the guest's 32-bit `usize` must overflow where the host's does not"
    );
    assert_eq!(
        body(TAG_USIZE_CAST)[8..],
        [32u64.to_le_bytes(), u64::from(u32::MAX).to_le_bytes()].concat(),
        "the guest's `usize` is 32 bits wide"
    );

    for (i, w) in WORKLOADS.iter().enumerate() {
        for f in w.faults {
            let input = fault_input(i, f.code);
            for (leg, outcome) in [
                ("host", host(&input)),
                ("emulator", emulate(&guest.image, &input)),
            ] {
                let Outcome::Exit {
                    code: PANIC_EXIT,
                    panic: Some(p),
                    ..
                } = &outcome
                else {
                    panic!(
                        "{} fault {:#04x} ({}) did not panic on the {leg}: {}",
                        w.name,
                        f.code,
                        f.what,
                        describe(&outcome)
                    );
                };
                // What the legs are compared on, so it has to be there to
                // compare: `parse_panic` answers `None` for a message it
                // cannot read, and two `None`s agree.
                assert!(
                    p.line > 0 && p.column > 0 && !p.message.is_empty() && !p.file.is_empty(),
                    "{} fault {:#04x} on the {leg} parsed to {p:?}",
                    w.name,
                    f.code
                );
            }
        }
    }

    for (what, input) in bad_inputs() {
        let outcome = emulate(&guest.image, &input);
        let Outcome::Exit {
            code: 0,
            output,
            panic: None,
        } = &outcome
        else {
            panic!("{what}: {}", describe(&outcome));
        };
        let written = sections(output).expect("fd 1 splits into sections");
        assert!(
            written.len() == 1 && written[0].0 == TAG_BAD_INPUT,
            "{what} must write the one bad-input section, and wrote {written:?}"
        );
    }
}

/// `trace_run` over the guest is the same execution as `run`, and the memory
/// log it leaves balances. The full run at scale 0 also carries the coverage
/// claim at instruction level: every instruction family but init/teardown has
/// rows, and all eight M-extension instructions execute.
#[test]
fn a_traced_run_is_the_same_execution_and_its_memory_balances() {
    let guest = guest();
    let (tables, config) = common::preprocess(&guest.image);
    // Two workloads rather than all of them: a traced run holds every query of
    // every cycle in memory, and the whole guest at scale 0 is tens of millions
    // of cycles. These two carry the coverage claim below — `numeric` the M
    // instructions, `structures` the atomics its `Arc` compiles to — and the
    // rest of the guest is the same instructions in a different order.
    let traced = WORKLOADS
        .iter()
        .enumerate()
        .filter(|(_, w)| w.name == "numeric" || w.name == "structures")
        .fold(0, |mask, (i, _)| mask | 1 << i);
    let mut inputs = vec![
        fd0(1, 0, traced, 0, TEXT.as_bytes()),
        bad_inputs()[0].1.clone(),
    ];
    if let Some((i, f)) = WORKLOADS
        .iter()
        .enumerate()
        .find_map(|(i, w)| w.faults.first().map(|f| (i, f)))
    {
        inputs.push(fault_input(i, f.code));
    }
    for (k, input) in inputs.iter().enumerate() {
        let (traces, log, _, execution) = trace_run(&guest.image, &io(input), &tables, &config)
            .unwrap_or_else(|e| panic!("input {k}: {e}"));
        let plain = run(&guest.image, &io(input)).expect("run");
        assert_eq!(plain, execution, "input {k}: run and trace_run");
        log.self_check(&guest.image)
            .unwrap_or_else(|e| panic!("input {k}: the memory log does not balance: {e:?}"));

        if k == 0 {
            for trace in &traces.families {
                assert!(
                    trace.family == family::INIT_TEARDOWN || !trace.cycle.is_empty(),
                    "family {} never runs",
                    program::family_name(trace.family)
                );
            }
            let executed: BTreeSet<&str> = traces
                .families
                .iter()
                .flat_map(|t| t.pc.iter())
                .map(|pc| instr_at(&guest.image, *pc).mnemonic())
                .collect();
            // The committed guest is a debug build and executes all eight. At
            // `opt-level = 3` LLVM computes a remainder as `a - (a / b) * b`,
            // so `rem` and `remu` are never emitted and the release build is
            // held to what survives that rewrite.
            let wanted: &[&str] = if common::guest_profile() == "debug" {
                &[
                    "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
                ]
            } else {
                &["mul", "mulh", "mulhsu", "mulhu", "div", "divu"]
            };
            let missing: Vec<&str> = wanted
                .iter()
                .copied()
                .filter(|m| !executed.contains(m))
                .collect();
            assert!(
                missing.is_empty(),
                "the traced run never executes {missing:?}"
            );
        }
    }
}

/// guest-sdk's allocator refuses a block that reaches the stack, in both halves
/// of its rule. Before S12's fix the ceiling was `__stack_top` itself: the
/// first probe committed its second line and exited 0, and the second was
/// handed a block covering its own frame.
#[test]
fn the_heap_stops_below_the_stack() {
    let guest = guest();
    for (mode, committed) in HEAP_PROBES {
        let outcome = emulate(&guest.image, &[mode]);
        let Outcome::Exit { code, output, .. } = &outcome else {
            panic!("heap probe {mode}: {}", describe(&outcome));
        };
        assert_eq!(
            (*code, show(output)),
            (OUT_OF_MEMORY, show(committed)),
            "heap probe {mode}"
        );
    }
}

/// The oracle can fail, and says where. A byte flipped in any workload's
/// section is reported against that workload; with the emulator standing in
/// for QEMU, the same flip in each leg is read off the table as the leg that
/// broke; and a pointer-width section the host agrees on is a stale
/// declaration.
#[test]
fn a_perturbed_leg_is_caught_and_classified() {
    let guest = guest();
    let input = fd0(7, 2, 0, 0, TEXT.as_bytes());
    let (h, e) = (host(&input), emulate(&guest.image, &input));
    judge(&h, None, &e).expect("the unperturbed legs are the control");
    judge(&h, Some(&e), &e).expect("and agree three ways with the emulator as QEMU");

    let Outcome::Exit {
        code,
        output,
        panic,
    } = &e
    else {
        panic!("{}", describe(&e));
    };
    let mut flipped_in = BTreeSet::new();
    let mut at = 0;
    for (tag, body) in sections(output).expect("fd 1 splits into sections") {
        let body_at = at + 5;
        at = body_at + body.len();
        if body.is_empty() || platform(tag).is_some() || !flipped_in.insert(owner(tag)) {
            continue;
        }
        let mut flipped = output.clone();
        flipped[body_at + body.len() / 2] ^= 0x10;
        let bad = Outcome::Exit {
            code: *code,
            output: flipped,
            panic: panic.clone(),
        };
        let why = judge(&h, None, &bad).expect_err("a flipped byte is caught");
        assert!(
            // The attribution, not the section's rendered content, which could
            // hold the workload's name by coincidence.
            why.contains(&format!("from {}", owner(tag))),
            "a flip in {}'s section read: {why}",
            owner(tag)
        );
        for (verdict, reading) in [
            (judge(&h, Some(&e), &bad), "an emulator semantics bug"),
            (judge(&bad, Some(&e), &e), "the host differs from both"),
            (judge(&h, Some(&bad), &e), "QEMU differs"),
        ] {
            let why = verdict.expect_err("a flipped leg is caught");
            assert!(why.contains(reading), "expected {reading:?}, read: {why}");
        }
    }
    assert_eq!(
        flipped_in.len(),
        WORKLOADS.len() - 1,
        "a flip landed in every workload but hazards: {flipped_in:?}"
    );

    // The two RV32 executors are never excused from a hazards section, even
    // though the host is: the verdict for one of those is its own arm.
    let mut at = 0;
    let platform_section = sections(output)
        .expect("fd 1 splits into sections")
        .into_iter()
        .find_map(|(tag, body)| {
            let body_at = at + 5;
            at = body_at + body.len();
            (platform(tag).is_some() && !body.is_empty()).then_some((tag, body_at, body.len()))
        });
    let (tag, body_at, len) = platform_section.expect("a platform-dependent section with a body");
    let mut flipped = output.clone();
    flipped[body_at + len / 2] ^= 0x10;
    let bad = Outcome::Exit {
        code: *code,
        output: flipped,
        panic: panic.clone(),
    };
    let why = judge(&h, Some(&e), &bad).expect_err("the RV32 executors are never excused");
    assert!(why.contains("host is excused"), "{tag:#04x}: {why}");

    // A leg that stops one section short, which only the trailing count
    // catches: the sections it did write all match. The section dropped is the
    // last one the host is *not* excused from — dropping a hazards section,
    // which is what the run ends with, would be invisible in this comparison.
    let all = sections(output).expect("fd 1 splits into sections");
    let drop_at = all
        .iter()
        .rposition(|(tag, _)| !excused(*tag))
        .expect("a section the host is compared on");
    let mut rebuilt = Vec::with_capacity(output.len());
    for (i, (tag, body)) in all.iter().enumerate() {
        if i == drop_at {
            continue;
        }
        rebuilt.push(*tag);
        rebuilt.extend_from_slice(&(body.len() as u32).to_le_bytes());
        rebuilt.extend_from_slice(body);
    }
    let short = Outcome::Exit {
        code: *code,
        output: rebuilt,
        panic: panic.clone(),
    };
    let why = judge(&h, None, &short).expect_err("a leg one section short is caught");
    assert!(why.contains("sections against"), "{why}");

    let wrong_exit = Outcome::Exit {
        code: 1,
        output: output.clone(),
        panic: panic.clone(),
    };
    assert!(judge(&h, None, &wrong_exit)
        .unwrap_err()
        .contains("exit status"));
    if cfg!(target_pointer_width = "64") {
        let why = judge(&e, None, &e).expect_err("the guest's hazards as the host's");
        assert!(why.contains("stale"), "{why}");
    }
}

/// The suite's claim with QEMU in the loop: every input, three ways, read off
/// the table; and the heap probes, where the host has no such heap, two ways.
#[test]
#[ignore = "needs a Linux host with qemu-user; run with --include-ignored"]
fn the_host_qemu_and_the_emulator_agree_on_every_input() {
    let guest = guest();
    let cases = corpus();
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let (h, q, e) = (
                host(&case.input),
                qemu(&guest.elf, &case.input),
                emulate(&guest.image, &case.input),
            );
            judge(&h, Some(&q), &e).err().map(|why| failure(case, &why))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} inputs disagree:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );

    for (mode, committed) in HEAP_PROBES {
        let want = Outcome::Exit {
            code: OUT_OF_MEMORY,
            output: committed.to_vec(),
            panic: None,
        };
        assert_eq!(
            qemu(&guest.elf, &[mode]),
            want,
            "heap probe {mode} under QEMU"
        );
        assert_eq!(emulate(&guest.image, &[mode]), want, "heap probe {mode}");
    }
}

/// What each workload costs the guest, at scale 0 and at `MAX_SCALE`. A
/// report for whoever tunes a workload, not a check.
#[test]
#[ignore = "a report: --ignored --nocapture"]
fn workload_costs() {
    let guest = guest();
    println!(
        "{:<16} {:>14} {:>14} {:>12}",
        "workload", "cycles, 0", "cycles, max", "fd 1, max"
    );
    for (i, w) in WORKLOADS.iter().enumerate() {
        let cost = |scale| {
            let e = run(
                &guest.image,
                &io(&fd0(1, scale, 1 << i, 0, TEXT.as_bytes())),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", w.name));
            (e.cycle_count, e.io.output.len())
        };
        let ((small, _), (large, bytes)) = (cost(0), cost(MAX_SCALE));
        println!("{:<16} {small:>14} {large:>14} {bytes:>12}", w.name);
    }
}
