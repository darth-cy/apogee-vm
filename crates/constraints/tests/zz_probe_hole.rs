//! TEMPORARY probe — delete after running.
use constants::{family, lookup_channel};
use constraints::lookup::check_discharge;
use constraints::memory::{frame_queries, frame_with_channels_artifact, Extras};
use constraints::{Coeff, GateDef, LookupExpr, PolyAddress};
use field::Fr;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

#[test]
fn probe_lookups_with_no_channels_builds() {
    // frame witness for JUMP_BRANCH_SLT: one `<q>_gap_hi` per query (4) + 3 x0
    let word_hi = PolyAddress::Witness(4 + 3);
    let boolean = GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), word_hi)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), word_hi, word_hi)],
    };
    let e = Extras {
        witness: vec!["word_hi".to_string()],
        setup: Vec::new(),
        virtuals: Vec::new(),
        enforcing: vec![("word_hi_boolean".to_string(), boolean)],
        lookups: vec![LookupExpr {
            name: "word_hi_range".to_string(),
            channel: lookup_channel::RANGE16,
            selector: word_hi,
            tuple: vec![GateDef::Linear {
                terms: vec![(lit(1), word_hi)],
                constant: lit(0),
            }],
        }],
        channels: Vec::new(),
    };
    let a = frame_with_channels_artifact(frame_queries(family::JUMP_BRANCH_SLT), 20, e);
    println!("BUILT OK");
    println!("validate      = {:?}", a.validate());
    println!(
        "check_memory  = {:?}",
        constraints::memory::check_memory(&a)
    );
    println!("outputs       = {}", a.outputs.len());
    println!("lookups       = {}", a.lookups.len());
    println!(
        "lookup names  = {:?}",
        a.lookups
            .iter()
            .map(|l| l.name.as_str())
            .collect::<Vec<_>>()
    );
    println!("discharge []  = {:?}", check_discharge(&a, &[]));
}
