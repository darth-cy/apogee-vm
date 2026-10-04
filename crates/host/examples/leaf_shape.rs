//! Local probe: per shard of a slice, how many points its fold owes.
use std::path::Path;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    let (vk, _, _, block) = host::proof_archive::read_proof(dir, &args[2]).unwrap();
    let public = block.statement();
    let (mut m, mut w, mut s) = (0, 0, 0);
    let mut fams = std::collections::BTreeMap::new();
    for (i, p) in block.shard_proofs().iter().enumerate().take(32) {
        let fi = vk
            .config
            .families
            .iter()
            .position(|(f, _)| *f == p.family)
            .unwrap();
        let mut setup = vk.setup_commitments[fi].len();
        if vk.circuits[fi].reads_generic_table() {
            setup += 3;
        }
        let (mi, wi) = (
            public.memory_commitments[i].len(),
            p.witness_commitments.len(),
        );
        println!(
            "{i:3} {:20} M {mi:3} W {wi:3} S {setup:3}",
            program::family_name(p.family)
        );
        m += mi;
        w += wi;
        s += setup;
        *fams.entry(p.family).or_insert(0) += 1;
    }
    let distinct_setup: usize = fams
        .keys()
        .map(|f| {
            let fi = vk.config.families.iter().position(|(g, _)| g == f).unwrap();
            vk.setup_commitments[fi].len()
                + if vk.circuits[fi].reads_generic_table() {
                    3
                } else {
                    0
                }
        })
        .sum();
    println!(
        "total M {m} W {w} S {s}; distinct S {distinct_setup}; families {}; shards {}",
        fams.len(),
        block.shard_proofs().len()
    );
}
