//! Local probe: each family's shard tape, and its runs before and after scheduling.
use std::path::Path;
use verifier_core::tape::{encode, schedule, shard_tape};
fn runs(body: &[u32]) -> usize {
    let (mut n, mut at) = (0, 0);
    while at < body.len() {
        let width = if body[at] == constants::ecall::PRECOMPILE_P2_FIELD {
            5
        } else {
            4
        };
        at += 2 + width * body[at + 1] as usize;
        n += 1;
    }
    n
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (vk, _, _, _) = host::proof_archive::read_proof(Path::new(&args[1]), &args[2]).unwrap();
    for (fi, (family, height)) in vk.config.families.iter().enumerate() {
        let circuit = &vk.circuits[fi];
        let mut setup = vk.setup_commitments[fi].len();
        if circuit.reads_generic_table() {
            setup += 3;
        }
        let tape = shard_tape(&vk.config, circuit, setup, 3);
        let (before, after) = (
            runs(&encode(&tape.ops).body),
            runs(&encode(&schedule(&tape.ops)).body),
        );
        println!(
            "{:20} 2^{:2} ops {:6} runs {before:5} -> {after:4}",
            program::family_name(*family),
            height.trailing_zeros(),
            tape.ops.len()
        );
    }
}
