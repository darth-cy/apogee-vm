//! Local probe: the recursion guest's own families' tapes, in the recursion format.
use verifier_core::tape::{encode, shard_tape};
fn main() {
    let elf =
        std::fs::read("guests/target/riscv32imac-unknown-none-elf/release/recursion").unwrap();
    let image = loader::load_elf(&elf).unwrap();
    let mut params = program::ProgramParams::defaults();
    for f in 0..7 {
        params.heights[f] = 1 << 20;
    }
    let (_, config) = program::decode_program(&image, &params).unwrap();
    println!("recursion format: {}", config.is_recursion());
    let mut total = 0;
    for (family, height) in &config.families {
        let circuit = config.circuit(*family, height.trailing_zeros()).unwrap();
        let setup = circuit.artifact.setup.len();
        let tape = shard_tape(&config, &circuit, setup, 3);
        let e = encode(&tape.ops);
        println!(
            "{:20} h 2^{:2}  ops {:6}  words {:7}  imports {:5}  σ {}",
            program::family_name(*family),
            height.trailing_zeros(),
            tape.ops.len(),
            e.body.len(),
            e.imports.len(),
            config.stack_vars(&circuit.artifact)
        );
        total += e.body.len() + e.imports.len();
    }
    println!("total words {total} = {} KiB", total * 4 / 1024);
}
