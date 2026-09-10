#![no_std]
#![no_main]

guest_sdk::entry!(main);

fn main() {
    let mut n = [0u8; 4];
    assert_eq!(
        guest_sdk::read_input(&mut n),
        4,
        "fib: public input is one u32"
    );
    let n = u32::from_le_bytes(n);

    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    guest_sdk::commit(&a.to_le_bytes());
}
