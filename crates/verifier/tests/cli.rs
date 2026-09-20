//! S16 acceptance 10's CLI half: the `verifier` binary verifies the dumped
//! proof files against the dumped key and statement, given the program's
//! identity from outside, and refuses a bit-flipped copy of any of them — the
//! same `verify_shard` every test calls, reached from files. It also refuses a
//! proof list that is not the statement's shards, each once: a statement is
//! proven only by all of them.
//!
//! Since S20 it also covers the `block` verb over a `BlockProof` file, which
//! is `verify_block` reached from files: one proof carrying its whole shard
//! set, so no list of shards can be short.
//!
//! `#[ignore]`d with the rest of the proving suites: it proves the statement
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
    invoke(&[], args, identity)
}

/// `verifier [verb] <key> <identity> <rest>...`.
fn invoke(verb: &[&str], args: &[&Path], identity: &str) -> (i32, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_verifier"));
    for v in verb {
        command.arg(v);
    }
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

/// S20: the `block` verb over a `BlockProof` file, end to end — the same
/// statement, proved as a block instead of as loose shards.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.6 GB"]
fn the_cli_verifies_a_block_file() {
    use verifier_core::BlockProof;

    let setup = common::setup();
    let mut archive = common::archive(&setup.program);
    let plan = trace::plan_shards(archive.cycle_profile(), &setup.program.config);
    let block = prover::prove_block(&setup, &mut archive, &plan).expect("the block proves");

    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s20-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let key = write("addsub.vk", &setup.vk.to_bytes());
    let statement = write("addsub.public", &block.statement().to_bytes());
    let file = write("addsub.block", &block.to_bytes());
    let identity = hex(&setup.vk.identity.to_bytes());

    let (code, text) = invoke(&["block"], &[&key, &statement, &file], &identity);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("the block verifies: 2 shards"), "{text}");

    // Another identity, a statement that is not the block's, and a flipped bit
    // anywhere in the block are each refused.
    let mut other = setup.vk.identity.to_bytes();
    other[0] ^= 1;
    let (code, text) = invoke(&["block"], &[&key, &statement, &file], &hex(&other));
    assert_eq!(code, 1, "{text}");

    let mut elsewhere = block.statement().clone();
    elsewhere.exit_status += 1;
    let other_statement = write("other.public", &elsewhere.to_bytes());
    let (code, text) = invoke(&["block"], &[&key, &other_statement, &file], &identity);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("the block's statement is not the one given"),
        "{text}"
    );

    let bytes = std::fs::read(&file).unwrap();
    for at in [0, 40, bytes.len() / 2, bytes.len() - 1] {
        let mut flipped = bytes.clone();
        flipped[at] ^= 0x10;
        let bad = write(&format!("addsub.block.flipped-{at}"), &flipped);
        let (code, text) = invoke(&["block"], &[&key, &statement, &bad], &identity);
        assert_eq!(code, 1, "the block flipped at {at}: {text}");
    }

    // A block file given to the shard form, and a shard file to the block
    // form, are each refused as the wrong encoding rather than accepted.
    let (code, _) = run(&[&key, &statement, &file], &identity);
    assert_eq!(code, 1);
    let shard = write("shard.proof", &block.shard_proofs()[0].to_bytes());
    let (code, _) = invoke(&["block"], &[&key, &statement, &shard], &identity);
    assert_eq!(code, 1);

    // `block` with the wrong number of arguments is a usage error.
    let out = Command::new(env!("CARGO_BIN_EXE_verifier"))
        .arg("block")
        .arg(&key)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    assert_eq!(BlockProof::from_bytes(&bytes).unwrap(), block);
    std::fs::remove_dir_all(&dir).ok();
}
