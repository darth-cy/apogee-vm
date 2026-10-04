//! Local probe, not committed: the CURRENT internal node guest over a tree
//! run's child proofs, profiled by family and by function.
use std::path::Path;
use verifier_core::node::{node_image, BaseKey, Kind};
use verifier_core::{BlockProof, VerifyingKey};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, stem, out) = (Path::new(&args[1]), &args[2], Path::new(&args[3]));
    let kids: Vec<usize> = args[4..].iter().map(|s| s.parse().unwrap()).collect();
    let (base_vk, _, _, _) = host::proof_archive::read_proof(dir, stem).unwrap();
    let vk = |n: &str| {
        VerifyingKey::from_bytes(&std::fs::read(out.join(format!("{n}.vk"))).unwrap()).unwrap()
    };
    let (leaf_vk, node_vk) = (vk("leaf"), vk("node"));
    let leaf_elf = host::fixture::build_guest("recursion", "leaf").unwrap();
    let node_elf = host::fixture::build_guest("recursion", "node").unwrap();
    let keys = host::recursion::program_keys(&leaf_elf, &node_elf).unwrap();
    let words = node_image(Kind::Internal, &BaseKey::of(&base_vk), &keys);
    let blocks: Vec<BlockProof> = kids
        .iter()
        .map(|c| {
            BlockProof::from_bytes(&std::fs::read(out.join(format!("{c}.block"))).unwrap()).unwrap()
        })
        .collect();
    let children: Vec<host::recursion::Child> = blocks
        .iter()
        .map(|b| host::recursion::Child {
            vk: &leaf_vk,
            block: b,
            program: 0,
        })
        .collect();
    let t = std::time::Instant::now();
    let run =
        host::recursion::internal(&words, &children, [leaf_vk.identity.0, node_vk.identity.0])
            .unwrap();
    println!(
        "advice {} bytes in {:.1} s",
        run.advice.len(),
        t.elapsed().as_secs_f64()
    );
    let native: Vec<u8> = run.journal.iter().flat_map(|v| v.to_bytes()).collect();
    let io = emulator::GuestIo {
        input: vec![],
        advice: run.advice,
    };
    let image = loader::load_elf(&node_elf).unwrap();
    let (tables, config) =
        program::decode_program(&image, &host::recursion::node_params()).unwrap();
    let p = profiler::profile(&node_elf, &image, &io, &tables, &config).unwrap();
    println!(
        "exit {:?}, journal equal to native: {}",
        p.execution.exit_code,
        p.execution.io.output == native
    );
    println!(
        "exit {:?} cycles {} ram windows {}",
        p.execution.exit_code, p.cycles, p.ram_windows
    );
    for (f, n) in &p.profile.counts {
        if *n > 0 {
            println!("{:>12} {}", n, program::family_name(*f));
        }
    }
    let mut funcs = p.funcs.clone();
    funcs.sort_by_key(|f| std::cmp::Reverse(f.cycles));
    for f in funcs.iter().take(25) {
        println!("{:>10} {:>8} {}", f.cycles, f.calls, f.path);
    }
    for (m, n) in p.mnemonics.iter().take(20) {
        print!("{m} {n}, ");
    }
    println!();
}
