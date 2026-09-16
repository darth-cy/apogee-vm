//! TEMPORARY PROBE — delete after running.
use checker::check_lookup_discharge;
use constants::lookup_channel;
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;

const TOY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/lookup_toy.bin"
);

fn toy() -> CircuitArtifact {
    let bytes = std::fs::read(TOY).expect("reading the toy");
    CircuitArtifact::from_bytes(&bytes).expect("decodes")
}

fn at(a: &CircuitArtifact, name: &str) -> PolyAddress {
    let named = |list: &[String], make: fn(u32) -> PolyAddress| {
        list.iter().position(|n| n == name).map(|i| make(i as u32))
    };
    named(&a.memory, PolyAddress::Memory)
        .or_else(|| named(&a.witness, PolyAddress::Witness))
        .or_else(|| named(&a.setup, PolyAddress::Setup))
        .unwrap_or_else(|| panic!("no column `{name}`"))
}

fn toy_specs(a: &CircuitArtifact) -> Vec<ChannelSpec> {
    let table = |names: &[&str]| -> Vec<PolyAddress> { names.iter().map(|n| at(a, n)).collect() };
    let mult = |c: u32| at(a, &format!("mult_{}", lookup_channel::NAMES[c as usize]));
    vec![
        ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
            multiplicity: mult(lookup_channel::TIMESTAMP),
        },
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: mult(lookup_channel::RANGE16),
        },
        ChannelSpec {
            channel: lookup_channel::GENERIC,
            table: table(&["generic_key", "generic_v1", "generic_v2"]),
            multiplicity: mult(lookup_channel::GENERIC),
        },
        ChannelSpec {
            channel: lookup_channel::DECODER,
            table: table(&[
                "table_pc",
                "table_next_pc",
                "table_rs1",
                "table_rs2",
                "table_rd",
                "table_imm",
                "table_extra_mask",
            ]),
            multiplicity: mult(lookup_channel::DECODER),
        },
    ]
}

#[test]
fn zeroing_a_leaf_numerator() {
    let a = toy();
    let specs = toy_specs(&a);
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(constraints::memory::check_memory(&a), Ok(()));
    assert_eq!(check_discharge(&a, &specs), Ok(()));
    assert_eq!(check_lookup_discharge(&a, &specs), Ok(()));

    // find the numerator leaf named gap_hi_pc_num
    let idx = a
        .scratch
        .iter()
        .position(|s| s.name == "gap_hi_pc_num")
        .expect("the toy has gap_hi_pc_num");
    println!(
        "scratch idx {idx}, gate = {:?}",
        a.layers[0].producing[idx].gate
    );

    let mut t = a.clone();
    let zero = GateDef::Linear {
        terms: Vec::new(),
        constant: Coeff::Literal(Fr::ZERO),
    };
    let rel = t.layers[0].producing[idx].relation as usize;
    println!("relation {rel} name {}", t.relations[rel].name);
    t.layers[0].producing[idx].gate = zero.clone();
    t.relations[rel].gate = zero;

    println!("validate       -> {:?}", t.validate());
    println!(
        "check_memory   -> {:?}",
        constraints::memory::check_memory(&t)
    );
    println!("check_discharge-> {:?}", check_discharge(&t, &specs));
    println!("checker disch  -> {:?}", check_lookup_discharge(&t, &specs));

    // and through the wire form
    let bytes = t.to_bytes();
    let back = CircuitArtifact::from_bytes(&bytes).expect("round trips");
    println!("roundtrip validate -> {:?}", back.validate());
    println!("roundtrip discharge-> {:?}", check_discharge(&back, &specs));
    panic!("probe output above");
}
