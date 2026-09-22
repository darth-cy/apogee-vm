//! S22: the `ECRECOVER` delegation, from three directions.
//!
//! 1. the frame transform the ecall performs, against the committed corpus
//!    `libsecp256k1` answered;
//! 2. `guests/ecrecover-test`'s in-guest vectors, read **out of the guest's
//!    source** and held to that same corpus, so a stale literal cannot pass;
//! 3. the two fixture guests executed on the emulator, where the delegation
//!    ecall runs the circuit's function.
//!
//! The fallback half — the same guests under `qemu-riscv32`, where the ecall
//! answers `-ENOSYS` and the SDK's software recovery runs — is
//! `crates/loader/tests/qemu.rs`, which needs an emulator this suite
//! deliberately does not.

mod common;

use common::{image, io};
use constants::ecrecover as e;
use emulator::run;
use program::secp256k1 as s2;
use test_support::to_hex;

/// One line of `crates/program/tests/vectors/ecrecover.txt`.
struct Case {
    name: String,
    hash: [u8; 32],
    v: u32,
    r: [u8; 32],
    s: [u8; 32],
    key: Option<([u8; 32], [u8; 32])>,
    address: Option<[u8; 20]>,
}

/// The committed corpus, parsed.
fn corpus() -> Vec<Case> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../program/tests/vectors/ecrecover.txt");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 9, "a corpus line is nine fields: {line}");
        let hex32 = |s: &str| test_support::hex_to_32(s).expect("32 bytes of hex");
        let (key, address) = if f[5] == "ok" {
            let bytes = test_support::hex_to_bytes(f[8]).expect("the address");
            let mut address = [0u8; 20];
            address.copy_from_slice(&bytes);
            (Some((hex32(f[6]), hex32(f[7]))), Some(address))
        } else {
            (None, None)
        };
        out.push(Case {
            name: f[0].to_string(),
            hash: hex32(f[2]),
            v: f[1].parse().expect("v"),
            r: hex32(f[3]),
            s: hex32(f[4]),
            key,
            address,
        });
    }
    assert!(out.len() >= 20, "the corpus is not vacuous");
    out
}

/// The frame transform the ecall performs — `program::secp256k1::apply_frame`,
/// which `emulator`'s `delegated` calls and which the circuit proves — against
/// the whole corpus.
///
/// This is the answer the two guests below are checked against, fixed by an
/// outside oracle rather than by either path to it.
#[test]
fn the_frame_transform_matches_the_committed_corpus() {
    let mut ok = 0;
    let mut failed = 0;
    for case in corpus() {
        let hash = s2::from_be_bytes(&case.hash);
        let r = s2::from_be_bytes(&case.r);
        let s = s2::from_be_bytes(&case.s);
        let mut frame = s2::frame_of(&hash, case.v, &r, &s).to_vec();
        let before = frame.clone();
        s2::apply_frame(&mut frame);

        // Whatever the outcome, the input words come back unchanged: the frame
        // is read and written in place and only its outputs move
        // (`docs/spec/ecrecover.md` §2.1).
        assert_eq!(
            frame[..e::OFF_PUBKEY_X],
            before[..e::OFF_PUBKEY_X],
            "{}: an input word moved",
            case.name
        );

        match case.key {
            Some((x, y)) => {
                ok += 1;
                assert_eq!(frame[e::OFF_SUCCESS], 1, "{}: success", case.name);
                let got_x = s2::from_frame_words(&frame[e::OFF_PUBKEY_X..e::OFF_PUBKEY_Y]);
                let got_y = s2::from_frame_words(&frame[e::OFF_PUBKEY_Y..e::OFF_SUCCESS]);
                assert_eq!(
                    to_hex(&s2::to_be_bytes(&got_x)),
                    to_hex(&x),
                    "{}",
                    case.name
                );
                assert_eq!(
                    to_hex(&s2::to_be_bytes(&got_y)),
                    to_hex(&y),
                    "{}",
                    case.name
                );
            }
            None => {
                failed += 1;
                // Must-be-exact 2: on failure **every** output word is zero,
                // the flag included, so a forged "failure with a live pubkey"
                // has nothing to be.
                assert!(
                    frame[e::OFF_PUBKEY_X..].iter().all(|w| *w == 0),
                    "{}: a failing call left an output word set",
                    case.name
                );
            }
        }
    }
    assert!(ok >= 10 && failed >= 6, "the corpus covers both outcomes");
}

/// One `Case` literal as the guest's source spells it, before it is matched
/// against a corpus line.
struct GuestCase {
    hash: Vec<u8>,
    v: u32,
    r: Vec<u8>,
    s: Vec<u8>,
    address: Vec<u8>,
}

/// The `[Case; 4]` literal in `guests/ecrecover-test/src/main.rs`, read out of
/// the source file.
///
/// Reading the guest's source rather than restating its table is the whole
/// point, and is `the_keccak_corpus_digests_are_the_references`' rule: a table
/// restated in a test is a second literal, and two stale literals agree.
fn guest_cases() -> Vec<GuestCase> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests/ecrecover-test/src/main.rs");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
    let head = "const CASES: [Case; 4] = [";
    let start = text.find(head).expect("ecrecover-test declares CASES") + head.len();
    let body = &text[start..start + text[start..].find("\n];").expect("CASES ends")];

    let mut out = Vec::new();
    for block in body.split("    Case {").skip(1) {
        let field = |name: &str| -> Vec<u8> {
            let at = block
                .find(&format!("{name}: ["))
                .unwrap_or_else(|| panic!("a Case has a `{name}` field"));
            let rest = &block[at..];
            let inner = &rest[rest.find('[').expect("[") + 1..rest.find(']').expect("]")];
            inner
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(|t| u8::from_str_radix(t.trim_start_matches("0x"), 16).expect("a hex byte"))
                .collect()
        };
        let v_at = block.find("v: ").expect("a Case has a `v` field") + 3;
        let v: u32 = block[v_at..block[v_at..].find(',').expect(",") + v_at]
            .trim()
            .parse()
            .expect("v");
        out.push(GuestCase {
            hash: field("hash"),
            v,
            r: field("r"),
            s: field("s"),
            address: field("address"),
        });
    }
    assert_eq!(out.len(), 4, "four cases");
    out
}

/// Every vector `guests/ecrecover-test` checks itself against is a line of the
/// committed corpus, matched by all five fields.
///
/// The guest compares in-guest and exits 4, so a wrong literal makes the guest
/// fail — but only if the emulator's recovery and the SDK's shim were both
/// right. This test fixes the **answer**; the two below fix the paths to it.
#[test]
fn the_guests_vectors_are_the_corpus() {
    let corpus = corpus();
    let mut covered_v = [false; 2];
    let mut covered_high_s = false;
    for guest in guest_cases() {
        let case = corpus
            .iter()
            .find(|c| {
                c.hash[..] == guest.hash[..]
                    && c.v == guest.v
                    && c.r[..] == guest.r[..]
                    && c.s[..] == guest.s[..]
            })
            .unwrap_or_else(|| {
                panic!(
                    "a guest vector is on no corpus line: v={} r={}",
                    guest.v,
                    to_hex(&guest.r)
                )
            });
        let want = case.address.unwrap_or_else(|| {
            panic!("{}: the guest expects a key from a failing line", case.name)
        });
        assert_eq!(
            to_hex(&guest.address),
            to_hex(&want),
            "{}: the guest's address is stale",
            case.name
        );
        covered_v[(guest.v - e::V_MIN) as usize] = true;
        covered_high_s |= case.name.starts_with("high_s_");
    }
    // Acceptance 3's coverage, asserted rather than assumed.
    assert!(
        covered_v[0] && covered_v[1],
        "the guest covers v = 27 and 28"
    );
    assert!(covered_high_s, "the guest covers an accepted s > n/2");
}

/// The delegated path: `guests/ecrecover-test` runs on the emulator, whose
/// ecall performs the recovery, and exits **4** — one per corpus entry.
///
/// A wrong address exits `200 + i` and a spurious `None` exits `210 + i`, so a
/// failure names which vector and which way it went wrong.
#[test]
fn the_test_guest_recovers_on_the_delegated_path() {
    let execution = run(&image("ecrecover-test"), &io(&[])).unwrap();
    assert_eq!(
        execution.exit_code, 4,
        "ecrecover-test: 4 is every vector passed; 200+i is a wrong address and 210+i a \
         refusal where the corpus says a key"
    );
}

/// Acceptance 5's fixture: a call whose `r` is on no curve point is a
/// **provable failure**, not an unprovable execution. The shim answers `None`,
/// the guest runs on, and it exits 5.
#[test]
fn the_failure_guest_answers_none_and_exits_cleanly() {
    let execution = run(&image("ecrecover-fail"), &io(&[])).unwrap();
    assert_eq!(
        execution.exit_code, 5,
        "ecrecover-fail: 5 is the shim answering None; 200 is it answering a key"
    );
}

/// The frame's two rules (`docs/spec/delegation.md` §4) are this family's
/// unchanged, and the emulator checks them over **this** frame's width: 42
/// words, not keccak's 50.
#[test]
fn the_frame_is_forty_two_words_and_the_registry_says_so() {
    assert_eq!(e::FRAME_WORDS, 42);
    assert_eq!(
        program::delegation_frame_words(constants::family::ECRECOVER),
        Some(e::FRAME_WORDS),
        "the registry's width is the frame's"
    );
    // The layout the shim and the circuit both read.
    assert_eq!(e::OFF_HASH, 0);
    assert_eq!(e::OFF_V, 8);
    assert_eq!(e::OFF_R, 9);
    assert_eq!(e::OFF_S, 17);
    assert_eq!(e::OFF_PUBKEY_X, 25);
    assert_eq!(e::OFF_PUBKEY_Y, 33);
    assert_eq!(e::OFF_SUCCESS, 41);
}
