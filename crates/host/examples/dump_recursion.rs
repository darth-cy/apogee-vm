//! Local probe: the recursion circuits' artifacts as files, for `checker dump`.
fn main() {
    let out = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    for (f, vars) in [
        (18u32, 20u32),
        (19, 20),
        (20, 18),
        (21, 18),
        (22, 20),
        (0, 20),
    ] {
        let c = constraints::recursion_circuit(f, vars).unwrap();
        let name = program::family_name(f).to_lowercase();
        std::fs::write(out.join(format!("{name}.bin")), c.artifact.to_bytes()).unwrap();
        println!("{name}: {} bytes", c.artifact.to_bytes().len());
    }
}
