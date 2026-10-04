//! Local probe: the leaf guest's journal against the native one.
use std::path::Path;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (vk, _, _, block) = host::proof_archive::read_proof(Path::new(&args[1]), &args[2]).unwrap();
    let elf = host::fixture::build_guest("recursion", "leaf").unwrap();
    let image = loader::load_elf(&elf).unwrap();
    let words = host::recursion::leaf_image(&vk);
    let range: Vec<usize> = args[3].split("..").map(|x| x.parse().unwrap()).collect();
    let leaf = host::recursion::leaf(&vk, &words, &block, range[0]..range[1]).unwrap();
    let out = emulator::run(
        &image,
        &emulator::GuestIo {
            input: vec![],
            advice: leaf.advice,
        },
    )
    .unwrap();
    let native: Vec<u8> = leaf.journal.iter().flat_map(|v| v.to_bytes()).collect();
    println!(
        "exit {:?}, journal {} bytes, equal to native: {}",
        out.exit_code,
        out.io.output.len(),
        out.io.output == native
    );
}
