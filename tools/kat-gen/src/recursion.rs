//! The `recursion` group: the recursion format's circuits (S-RECURSION,
//! `docs/spec/recursion.md`), pinned by **digest**, as the delegation group
//! pins its six and for its reason — what a fixture buys is a regeneration
//! CI can diff, and a digest buys that at a line a circuit.
//!
//! The five families only the recursion registry holds, each at its default
//! height, and the one family whose circuit the two registries both hold
//! and differ in: `ADD_SUB_LUI_AUIPC`, whose recursion form knows the four
//! recursion delegation types and holds a recursion request's `a0` to the
//! end of its frame (§1.4). Every other family's recursion circuit is its
//! base circuit, byte for byte, which `crates/constraints/tests/recursion.rs`
//! asserts.

use constants::family;
use constraints::{recursion_circuit, CircuitArtifact};
use test_support::{sha256, to_hex};

use crate::write_vectors;

const PATH: &str = "crates/constraints/tests/vectors/recursion.txt";

/// The circuits pinned: the five recursion families, then `ADD_SUB`.
const FAMILIES: [u32; 6] = [
    family::FIELD_WINDOWS,
    family::FR_OP,
    family::P2_FIELD,
    family::FIELD_IO,
    family::FQ_OP,
    family::ADD_SUB_LUI_AUIPC,
];

fn line(artifact: &CircuitArtifact, name: &str) -> String {
    let bytes = artifact.to_bytes();
    let inner: usize = artifact.layers.iter().map(|l| l.width as usize).sum();
    format!(
        "{name} {n} {memory} {witness} {layers} {inner} {relations} {outputs} {len} {digest}\n",
        n = artifact.trace_vars,
        memory = artifact.memory.len(),
        witness = artifact.witness.len(),
        layers = artifact.layers.len(),
        relations = artifact.relations.len(),
        outputs = artifact.outputs.len(),
        len = bytes.len(),
        digest = to_hex(&sha256(&bytes)),
    )
}

pub fn generate() {
    let mut text = String::from(
        "# the recursion format's circuits, by SHA-256 of `recursion_circuit(family, n).artifact.to_bytes()`\n\
         # docs/spec/recursion.md is normative; the five recursion families at their default heights,\n\
         # then ADD_SUB_LUI_AUIPC, the one family whose recursion circuit is not its base circuit\n\
         # family n memory witness layers inner relations outputs bytes sha256\n",
    );
    for f in FAMILIES {
        let height = family::DEFAULT_HEIGHTS[f as usize];
        let vars = match f {
            // The recursion programs run it at 2^20, as the base block does.
            family::ADD_SUB_LUI_AUIPC => 20,
            _ => height.trailing_zeros(),
        };
        let circuit = recursion_circuit(f, vars).expect("a recursion family builds");
        text.push_str(&line(&circuit.artifact, program::family_name(f)));
    }
    write_vectors(PATH, &text);
}
