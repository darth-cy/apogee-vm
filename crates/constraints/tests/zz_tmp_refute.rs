use constants::{family, lookup_channel};
use constraints::lookup::check_discharge;
use constraints::memory::{frame_artifact, frame_queries, frame_with_channels_artifact, Extras};
use constraints::{Coeff, GateDef, LookupExpr, PolyAddress};
use field::Fr;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn booleanity(x: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![(lit(1), x)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), x, x)],
    }
}

#[test]
fn scenario() {
    // S14's frozen frame, no extras at all: does it already carry undischarged
    // obligations?
    let plain = frame_artifact(frame_queries(family::JUMP_BRANCH_SLT), 20);
    println!("frame_artifact lookups = {}", plain.lookups.len());
    println!(
        "frame_artifact check_discharge(&[]) = {:?}",
        check_discharge(&plain, &[])
    );

    // The claim's scenario.
    let word_hi = PolyAddress::Witness(7);
    let a = frame_with_channels_artifact(
        frame_queries(family::JUMP_BRANCH_SLT),
        20,
        Extras {
            witness: vec!["word_hi".into()],
            enforcing: vec![("word_hi_boolean".into(), booleanity(word_hi))],
            lookups: vec![LookupExpr {
                name: "word_hi_range".into(),
                channel: lookup_channel::RANGE16,
                selector: PolyAddress::Memory(1),
                tuple: vec![GateDef::Linear {
                    terms: vec![(lit(1), word_hi)],
                    constant: lit(0),
                }],
            }],
            channels: vec![],
            ..Default::default()
        },
    );
    println!("scenario built: lookups = {}", a.lookups.len());
    println!("scenario validate = {:?}", a.validate());
    println!(
        "scenario check_discharge(&[]) = {:?}",
        check_discharge(&a, &[])
    );
}
