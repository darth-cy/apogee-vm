//! S16 acceptance 10's CLI half: the `verifier` binary verifies the dumped
//! proof files against the dumped key and statement, given the program's
//! identity from outside, and refuses a bit-flipped copy of any of them — the
//! same `verify_shard` every test calls, reached from files. It also refuses a
//! proof list that is not the statement's shards, each once: a statement is
//! proven only by all of them.
//!
//! `#[ignore]`d with the rest of S16's proving suites: it proves the statement
//! first, which peaks at 8.6 GB.

#[path = "../../prover/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use trace::Phase;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(args: &[&Path], identity: &str) -> (i32, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_verifier"));
    command.arg(args[0]).arg(identity);
    for a in &args[1..] {
        command.arg(a);
    }
    let out = command.output().expect("running the verifier");
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().expect("an exit code"), text)
}

#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn the_cli_verifies_the_dumped_files_and_refuses_a_flipped_bit() {
    let setup = common::setup();
    let mut archive = common::archive(&setup.program);
    prover::advance(&setup, &mut archive, Phase::Final).unwrap();
    let (public, proofs) = prover::finish(&archive).unwrap();

    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s16-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let key = write("addsub.vk", &setup.vk.to_bytes());
    let statement = write("addsub.public", &public.to_bytes());
    let files: Vec<PathBuf> = proofs
        .iter()
        .map(|p| {
            write(
                &format!("shard-{}-{}.proof", p.family, p.shard_index),
                &p.to_bytes(),
            )
        })
        .collect();
    let identity = hex(&setup.vk.identity.to_bytes());

    let mut args: Vec<&Path> = vec![&key, &statement];
    args.extend(files.iter().map(|p| p.as_path()));
    let (code, text) = run(&args, &identity);
    assert_eq!(code, 0, "{text}");
    assert_eq!(text.matches(" verifies").count(), 3, "{text}");
    assert!(text.contains("the statement verifies: 2 shards"), "{text}");

    // Another identity than the key's: refused before any proof is read.
    let mut other = setup.vk.identity.to_bytes();
    other[0] ^= 1;
    let (code, text) = run(&args, &hex(&other));
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("not the one given"), "{text}");

    // A flipped bit in each proof, at several places, in the statement and in
    // the key: each refused, never accepted.
    let flip = |path: &Path, at: usize| -> PathBuf {
        let mut bytes = std::fs::read(path).unwrap();
        let at = at % bytes.len();
        bytes[at] ^= 0x10;
        let flipped = dir.join(format!(
            "{}.flipped-{at}",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&flipped, bytes).unwrap();
        flipped
    };
    for proof in &files {
        let len = std::fs::metadata(proof).unwrap().len() as usize;
        for at in [0, 30, 100, len / 2, len - 1] {
            let bad = flip(proof, at);
            let (code, text) = run(&[&key, &statement, &bad], &identity);
            assert_eq!(code, 1, "{} flipped at {at}: {text}", proof.display());
        }
    }
    for at in [0, 11, 100, 3000] {
        let bad = flip(&statement, at);
        let (code, text) = run(&[&key, &bad, &files[1]], &identity);
        assert_eq!(code, 1, "the statement flipped at {at}: {text}");
    }
    for at in [4, 50, 5000] {
        let bad = flip(&key, at);
        let (code, text) = run(&[&bad, &statement, &files[1]], &identity);
        assert_eq!(code, 1, "the key flipped at {at}: {text}");
    }
    // Each proof verifies alone, but a statement is proven only by all of its
    // shards, each once: one missing, or one given twice in place of another,
    // is refused.
    for (i, one) in files.iter().enumerate() {
        let (code, text) = run(&[&key, &statement, one], &identity);
        assert_eq!(code, 1, "only proof {i}: {text}");
        assert!(text.contains(" verifies"), "{text}");
        assert!(text.contains("not the statement's 2 shards"), "{text}");
        let (code, text) = run(&[&key, &statement, one, one], &identity);
        assert_eq!(code, 1, "proof {i} twice: {text}");
        assert!(text.contains("not the statement's 2 shards"), "{text}");
    }
    let mut reversed = args.clone();
    reversed[2..].reverse();
    let (code, text) = run(&reversed, &identity);
    assert_eq!(code, 0, "any order: {text}");

    // A usage error is 2.
    let out = Command::new(env!("CARGO_BIN_EXE_verifier"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    std::fs::remove_dir_all(&dir).ok();
}
