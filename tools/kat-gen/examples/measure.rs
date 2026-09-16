use constraints::CircuitArtifact;
use field::Fr;
use gkr::{forward, prove, BaseLayer, ExternalChallenges};
use poly::{MultilinearPoly, PolyBacking};
use std::time::Instant;
use transcript::Transcript;

fn main() {
    let bytes = std::fs::read("crates/constraints/tests/vectors/lookup_toy.bin").unwrap();
    let a = CircuitArtifact::from_bytes(&bytes).unwrap();
    let rows = 1usize << a.trace_vars;
    let mut cells = 0usize;
    for k in 1..=a.depth() {
        cells += (a.layer_width(k) as usize) << a.layer_vars(k);
    }
    println!(
        "depth {} trace_vars {} widths {:?} inner cells {cells} ({:.2} GB)",
        a.depth(),
        a.trace_vars,
        (0..=4.min(a.depth()))
            .map(|k| a.layer_width(k))
            .collect::<Vec<_>>(),
        cells as f64 * 32.0 / 1e9
    );
    let columns: Vec<_> = a
        .committed()
        .into_iter()
        .enumerate()
        .map(|(i, addr)| {
            let v: Vec<u32> = (0..rows)
                .map(|y| (y as u32).wrapping_add(i as u32) | 1)
                .collect();
            (addr, MultilinearPoly::new(PolyBacking::U32(v)))
        })
        .collect();
    let base = BaseLayer::new(columns);
    let mut ch = ExternalChallenges::new();
    for slot in 0..constants::challenge_slot::NAMES.len() as u32 {
        ch.insert(slot, Fr::from_u64(slot as u64 * 7 + 3));
    }
    let t0 = Instant::now();
    let values = forward(&a, &base, &ch);
    println!("forward {:?}", t0.elapsed());
    let t1 = Instant::now();
    let mut tr = Transcript::new();
    let p = prove(&a, &values, &ch, &mut tr);
    println!("prove {:?} ({} layers)", t1.elapsed(), p.layers.len());
}
