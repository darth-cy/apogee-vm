//! Local probe: the points a node program proof's deferred checks carry, by
//! family, for one shard a family or, given a root's block, for its shards.
fn main() {
    let bytes = std::fs::read("guests/recursion/programs.key").unwrap();
    let keys = verifier_core::node::ProgramKey::list_from_bytes(&bytes).unwrap();
    let node = &keys[1];
    let shards: Option<Vec<u32>> = std::env::args().nth(1).map(|p| {
        let block = verifier_core::BlockProof::from_bytes(&std::fs::read(p).unwrap()).unwrap();
        block.shard_proofs().iter().map(|s| s.family).collect()
    });
    let (mut total, mut setups) = (0, 0);
    for ((f, h), s) in node.config.families.iter().zip(&node.setups) {
        let circuit = node.config.circuit(*f, h.trailing_zeros()).unwrap();
        let sigma = node.config.stack_vars(&circuit.artifact);
        let m = verifier_core::stack_count(circuit.artifact.memory.len(), sigma);
        let w = verifier_core::stack_count(circuit.artifact.witness.len(), sigma);
        let generic = if circuit.reads_generic_table() { 3 } else { 0 };
        let count = shards
            .as_ref()
            .map_or(1, |v| v.iter().filter(|g| *g == f).count());
        let points = count * (12 + m + w);
        println!(
            "{:18} x{count:2} σ {sigma}  M {m:2} W {w:2} S {:2}  points {points}",
            program::family_name(*f),
            s + generic
        );
        total += points;
        if count > 0 {
            setups += s + generic;
        }
    }
    println!("{total} proof points, {setups} setup points");
}
