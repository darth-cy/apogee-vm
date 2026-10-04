//! Local probe, not committed: which functions execute MUL_DIV and MEM_SUBWORD.
use std::collections::BTreeMap;
use std::path::Path;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (vk, _, _, block) = host::proof_archive::read_proof(Path::new(&args[1]), &args[2]).unwrap();
    let range: Vec<usize> = args[3].split("..").map(|x| x.parse().unwrap()).collect();
    let elf = host::fixture::build_guest("recursion", "leaf").unwrap();
    let words = host::recursion::leaf_image(&vk);
    let leaf = host::recursion::leaf(&vk, &words, &block, range[0]..range[1]).unwrap();
    let native: Vec<u8> = leaf.journal.iter().flat_map(|v| v.to_bytes()).collect();
    let io = emulator::GuestIo {
        input: vec![],
        advice: leaf.advice,
    };
    let image = loader::load_elf(&elf).unwrap();
    let (tables, config) =
        program::decode_program(&image, &host::recursion::leaf_params()).unwrap();
    let p = profiler::profile(&elf, &image, &io, &tables, &config).unwrap();
    println!(
        "exit {:?}, journal equal to native: {}",
        p.execution.exit_code,
        p.execution.io.output == native
    );
    println!("cycles {} profile {:?}", p.cycles, p.profile);
    let wanted = [constants::family::MUL_DIV, constants::family::MEM_SUBWORD];
    let mut by: BTreeMap<(u32, String, String), u64> = BTreeMap::new();
    for (i, &n) in p.hist.iter().enumerate() {
        if n == 0 {
            continue;
        }
        let loader::Slot::Instruction { word, .. } = image.slots[i] else {
            continue;
        };
        let instr = isa::decode(word).unwrap();
        let (family, _) = program::row_kind(&instr);
        if !wanted.contains(&family) {
            continue;
        }
        let pc = p.slot_base + 2 * i as u32;
        let func = p
            .funcs
            .iter()
            .find(|f| f.addr <= pc && pc < f.addr + f.size.max(1))
            .map(|f| f.path.clone())
            .unwrap_or_else(|| "?".into());
        let m = format!("{instr:?}")
            .split([' ', '{', '('])
            .next()
            .unwrap()
            .to_string();
        *by.entry((family, func, m)).or_default() += n;
    }
    let mut rows: Vec<_> = by.into_iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    for ((family, func, m), n) in rows.iter().take(60) {
        println!(
            "{:>10} {:<12} {:<8} {}",
            n,
            program::family_name(*family),
            m,
            func
        );
    }
    let mut funcs = p.funcs.clone();
    funcs.sort_by_key(|f| std::cmp::Reverse(f.cycles));
    println!("top functions");
    for f in funcs.iter().take(25) {
        println!("{:>10} {:>8} {}", f.cycles, f.calls, f.path);
    }
}
