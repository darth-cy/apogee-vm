//! Local probe: a node proof's shards by family.
fn main() {
    for path in std::env::args().skip(1) {
        let block = verifier_core::BlockProof::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        let mut counts = std::collections::BTreeMap::new();
        for s in block.shard_proofs() {
            *counts.entry(program::family_name(s.family)).or_insert(0) += 1;
        }
        println!("{path}: {} shards {:?}", block.shard_proofs().len(), counts);
    }
}
