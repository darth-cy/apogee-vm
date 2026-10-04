//! Local probe: prove two small leaves over an archived base block, verify
//! them, run the internal node over them natively and in the guest, and
//! (with `prove`) prove it.
use std::path::Path;
use std::time::Instant;

use emulator::GuestIo;
use verifier_core::node::{journal, node_image, BaseKey, Kind, ProgramKey};

fn program(elf: &[u8], params: program::ProgramParams) -> prover::Program {
    let image = loader::load_elf(elf).unwrap();
    let (tables, config) = program::decode_program(&image, &params).unwrap();
    prover::Program {
        image,
        tables,
        config,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (base_vk, _, _, block) =
        host::proof_archive::read_proof(Path::new(&args[1]), &args[2]).unwrap();
    let in_flight: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(1);
    let prove_node = args.get(4).map(String::as_str) == Some("prove");

    let t = Instant::now();
    let cache = std::env::temp_dir().join("apogee-ceremony-24.srs");
    let srs = match srs::Srs::load(&cache) {
        Ok(s) => s,
        Err(_) => {
            let s = srs::Srs::from_ptau(Path::new("assets/ptau/ppot_0080_24.ptau"), 24).unwrap();
            s.save(&cache).unwrap();
            s
        }
    };
    println!("srs in {:?}", t.elapsed());
    let leaf_elf = host::fixture::build_guest("recursion", "leaf").unwrap();
    let node_elf = host::fixture::build_guest("recursion", "node").unwrap();

    let t = Instant::now();
    let leaf_setup = prover::ProverSetup::new(
        program(&leaf_elf, host::recursion::leaf_params()),
        srs.clone(),
    )
    .unwrap();
    println!("leaf setup in {:?}", t.elapsed());
    let words = host::recursion::leaf_image(&base_vk);
    let mut leaves = vec![];
    for range in [0..2, 2..4] {
        let run = host::recursion::leaf(&base_vk, &words, &block, range.clone()).unwrap();
        let t = Instant::now();
        let (proof, _) = prover::prove_block_streaming(
            &leaf_setup,
            &GuestIo {
                input: vec![],
                advice: run.advice,
            },
            in_flight,
        )
        .unwrap();
        println!(
            "leaf {range:?}: {} shards proved in {:?}",
            proof.shard_proofs().len(),
            t.elapsed()
        );
        verifier::verify_block(&leaf_setup.vk, &proof, proof.statement()).unwrap();
        let native: Vec<u8> = run.journal.iter().flat_map(|v| v.to_bytes()).collect();
        assert_eq!(
            proof.statement().output,
            native,
            "the proved journal is the native one"
        );
        println!("  verified, its journal the native one");
        leaves.push(proof);
    }

    let t = Instant::now();
    let node_setup =
        prover::ProverSetup::new(program(&node_elf, host::recursion::node_params()), srs).unwrap();
    println!("node setup in {:?}", t.elapsed());
    let keys = host::recursion::program_keys(&leaf_elf, &node_elf).unwrap();
    let committed =
        ProgramKey::list_from_bytes(&std::fs::read("guests/recursion/programs.key").unwrap())
            .unwrap();
    assert_eq!(keys, committed, "programs.key is the two ELFs'");
    let node_words = node_image(Kind::Internal, &BaseKey::of(&base_vk), &keys);
    let identities = [leaf_setup.vk.identity.0, node_setup.vk.identity.0];
    let children: Vec<host::recursion::Child> = leaves
        .iter()
        .map(|b| host::recursion::Child {
            vk: &leaf_setup.vk,
            block: b,
            program: 0,
        })
        .collect();
    let t = Instant::now();
    let run = host::recursion::internal(&node_words, &children, identities).unwrap();
    println!(
        "node natively in {:?}: covers {:?}..{:?}",
        t.elapsed(),
        run.journal[journal::FROM],
        run.journal[journal::TO]
    );
    let image = loader::load_elf(&node_elf).unwrap();
    let out = emulator::run(
        &image,
        &GuestIo {
            input: vec![],
            advice: run.advice.clone(),
        },
    )
    .unwrap();
    let native: Vec<u8> = run.journal.iter().flat_map(|v| v.to_bytes()).collect();
    println!(
        "node in the guest: exit {}, {} cycles, journal the native one: {}",
        out.exit_code,
        out.cycle_count,
        out.io.output == native
    );
    if prove_node {
        let t = Instant::now();
        let (proof, _) = prover::prove_block_streaming(
            &node_setup,
            &GuestIo {
                input: vec![],
                advice: run.advice,
            },
            in_flight,
        )
        .unwrap();
        println!(
            "node: {} shards proved in {:?}",
            proof.shard_proofs().len(),
            t.elapsed()
        );
        verifier::verify_block(&node_setup.vk, &proof, proof.statement()).unwrap();
        println!("  verified");
    }
}
