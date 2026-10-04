//! The recursion format's registry (`docs/spec/recursion.md` §1.2): its
//! families build, pass every construction rule, and live in it alone; and the
//! base registry's `ADD_SUB` is still the base format's.

use constants::family;
use constraints::{family_circuit, recursion_circuit};

const RECURSION: [u32; 5] = [
    family::FIELD_WINDOWS,
    family::FR_OP,
    family::P2_FIELD,
    family::FIELD_IO,
    family::FQ_OP,
];

/// Each family builds at its default height — which runs `validate`,
/// `check_memory` and the discharge rule — and the base registry refuses it,
/// so a base key cannot name one.
#[test]
fn the_recursion_families_build_in_the_recursion_registry_alone() {
    for f in RECURSION {
        let vars = family::DEFAULT_HEIGHTS[f as usize].trailing_zeros();
        let c = recursion_circuit(f, vars).unwrap_or_else(|| panic!("family {f} at 2^{vars}"));
        assert_eq!(c.family, f);
        assert!(
            c.artifact.padding.zero_row_valid,
            "family {f}: the all-zero row pads"
        );
        assert!(
            family_circuit(f, vars).is_none(),
            "family {f} is in the base registry"
        );
    }
}

/// Every family the base registry holds, the recursion registry holds
/// identically — but `ADD_SUB`, which knows the recursion types besides.
#[test]
fn the_registries_differ_in_add_sub_alone() {
    for f in 0..family::COUNT {
        if RECURSION.contains(&f) {
            continue;
        }
        let vars = family::DEFAULT_HEIGHTS[f as usize].trailing_zeros();
        let (base, rec) = (family_circuit(f, vars), recursion_circuit(f, vars));
        let (base, rec) = match (base, rec) {
            (Some(b), Some(r)) => (b, r),
            (None, None) => continue,
            _ => panic!("family {f} is in one registry and not the other"),
        };
        let same = base.artifact == rec.artifact;
        assert_eq!(same, f != family::ADD_SUB_LUI_AUIPC, "family {f}");
    }
    let base = constraints::add_sub::artifact(20);
    let rec = constraints::add_sub::recursion_artifact(20);
    let extra = constants::delegation::TYPES.len() - constants::delegation::BASE_TYPES;
    assert_eq!(rec.witness.len(), base.witness.len() + extra);
}
