use loader::load_elf;
fn main() {
    let a = load_elf(&std::fs::read("/tmp/fib_old.elf").unwrap()).unwrap();
    let b = load_elf(&std::fs::read("crates/loader/tests/vectors/fib.elf").unwrap()).unwrap();
    println!("entry {} == {}", a.entry, b.entry);
    println!("slot_base {} == {}", a.slot_base, b.slot_base);
    println!("slots equal: {}", a.slots == b.slots);
    println!("segments equal: {}", a.segments == b.segments);
    println!("image equal: {}", a == b);
}
