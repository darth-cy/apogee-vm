//! Shared plumbing for the emulator's suites.
//!
//! Every guest here is the committed ELF under `crates/loader/tests/vectors`,
//! pinned by digest in `crates/loader/tests/common/mod.rs` — the same bytes
//! QEMU runs in `tests/differential.rs`.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use constants::family;
use emulator::{trace_run, Execution, GuestIo};
use isa::{decode, Instr};
use loader::{load_elf, ProgramImage, Slot};
use program::{decode_program, DecodedTables, ProgramParams, VmConfig};
use trace::{CycleProfile, FamilyTraces, MemoryEventLog};

pub fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../loader/tests/vectors")
}

pub fn elf(name: &str) -> Vec<u8> {
    let path = vectors().join(format!("{name}.elf"));
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn image(name: &str) -> ProgramImage {
    load_elf(&elf(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"))
}

pub fn io(input: &[u8]) -> GuestIo {
    GuestIo {
        input: input.to_vec(),
        hint: Vec::new(),
    }
}

/// Every family at the smallest height: every committed guest's code fits,
/// and a table costs 2^16 rows rather than 2^22.
pub fn smallest() -> ProgramParams {
    uniform(1 << 16)
}

/// Every family at `height`.
pub fn uniform(height: u32) -> ProgramParams {
    ProgramParams {
        heights: [height; family::COUNT as usize],
        ..ProgramParams::defaults()
    }
}

/// Decoded tables at the smallest menu height the guest's code fits.
///
/// 2^16 rows for every committed guest but `portability`, whose code is large
/// enough to need a taller table: a table's rows are absolute pcs, one per
/// halfword, so a family's height has to reach past the last instruction.
pub fn preprocess(image: &ProgramImage) -> (DecodedTables, VmConfig) {
    let mut refused = None;
    for &height in &family::HEIGHT_MENU {
        match decode_program(image, &uniform(height)) {
            Ok(decoded) => return decoded,
            Err(e) => refused = Some(e),
        }
    }
    panic!("{}", refused.expect("the height menu is not empty"))
}

/// The instruction at `pc`.
pub fn instr_at(image: &ProgramImage, pc: u32) -> Instr {
    match image.slot_at(pc) {
        Some(Slot::Instruction { word, .. }) => decode(word).expect("a traced pc decodes"),
        other => panic!("{pc:#010x} is {other:?}"),
    }
}

/// fib's committed public-I/O record: `(input, output)`.
pub fn fib_record() -> (Vec<u8>, Vec<u8>) {
    let text = fs::read_to_string(vectors().join("fib_io.txt")).expect("reading fib_io.txt");
    let field = |key: &str| {
        let line = text
            .lines()
            .find(|l| l.split_whitespace().next() == Some(key))
            .unwrap_or_else(|| panic!("fib_io.txt has no {key}"));
        let value = line.split_whitespace().nth(1).expect("a key has a value");
        test_support::hex_to_bytes(value).expect("fib_io.txt values are hex")
    };
    (field("input"), field("output"))
}

/// `opcodes` in mode 0, with the six payload bytes `cover_ecall` reads.
pub fn opcodes_input() -> Vec<u8> {
    vec![0, 0, 0, 0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]
}

/// The input each traced guest runs on here.
pub fn input_of(name: &str) -> Vec<u8> {
    match name {
        "fib" => fib_record().0,
        "opcodes" => opcodes_input(),
        "heap" => 40u32.to_le_bytes().to_vec(),
        "atomics" => 37u32.to_le_bytes().to_vec(),
        "rvc-dense" => 7u32.to_le_bytes().to_vec(),
        // The hazards workload alone, at scale 0: 25,945 instructions, which is
        // all of a guest this size that an instruction-by-instruction log can
        // afford. `tests/portability.rs` is where the rest of it runs.
        "portability" => portability::Input {
            seed: 1,
            scale: 0,
            workloads: 1
                << portability::WORKLOADS
                    .iter()
                    .position(|w| w.name == "hazards")
                    .expect("the hazards workload"),
            fault: 0,
            payload: &[],
        }
        .encode(),
        other => panic!("no input chosen for {other}"),
    }
}

/// One guest, preprocessed and traced.
pub struct Traced {
    pub image: ProgramImage,
    pub tables: DecodedTables,
    pub config: VmConfig,
    pub traces: FamilyTraces,
    pub log: MemoryEventLog,
    pub profile: CycleProfile,
    pub execution: Execution,
}

pub fn traced(name: &str) -> Traced {
    let image = image(name);
    let (tables, config) = preprocess(&image);
    let (traces, log, profile, execution) =
        trace_run(&image, &io(&input_of(name)), &tables, &config)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        execution.exit_code, 0,
        "{name} exited {}",
        execution.exit_code
    );
    Traced {
        image,
        tables,
        config,
        traces,
        log,
        profile,
        execution,
    }
}

/// The guests the trace suites run.
pub const TRACED: [&str; 5] = ["fib", "heap", "atomics", "opcodes", "rvc-dense"];

/// The profile a from-source guest is built at: `debug`, unless
/// `APOGEE_GUEST_PROFILE` names another — the variable
/// `crates/loader/tests/qemu.rs` reads.
pub fn guest_profile() -> String {
    std::env::var("APOGEE_GUEST_PROFILE").unwrap_or_else(|_| "debug".into())
}

/// Build `guests/<name>` from source at `profile`, into a fresh target
/// directory, and return the ELF bytes.
///
/// The command is the manual's: `cargo build --target
/// riscv32imac-unknown-none-elf` from the guest's own directory, with the
/// target, the runner and the linker flags coming from
/// `guests/.cargo/config.toml`, and nothing from the ambient environment that
/// could reach rustc.
pub fn build_guest(name: &str, profile: &str) -> Vec<u8> {
    assert!(
        matches!(profile, "debug" | "release"),
        "unknown guest profile {profile:?}: expected \"debug\" or \"release\""
    );
    let guest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests")
        .join(name);
    let target_dir = std::env::temp_dir().join(format!(
        "apogee-emulator-{name}-{profile}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&target_dir);

    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args(["build", "--target", "riscv32imac-unknown-none-elf"])
        .env("CARGO_TARGET_DIR", &target_dir);
    if profile == "release" {
        command.arg("--release");
    }
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(key);
    }
    let out = command.output().expect("running cargo for a guest");
    assert!(
        out.status.success(),
        "{name}: guest build failed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let elf = target_dir
        .join("riscv32imac-unknown-none-elf")
        .join(profile)
        .join(name);
    let bytes = fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = fs::remove_dir_all(&target_dir);
    bytes
}

/// The user-mode emulator the QEMU legs run under.
///
/// Panics when it is absent: those tests are `#[ignore]`d, so reaching here
/// means someone asked for them by name, and a silent pass would report
/// coverage that did not happen.
pub fn qemu_binary() -> String {
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
        "qemu-riscv32 is not on PATH, so the QEMU leg cannot run. User-mode \
         QEMU is Linux-only; docs/guest-program-manual.md section 7 has the \
         container recipe."
    )
}
