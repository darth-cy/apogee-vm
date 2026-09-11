//! Acceptance 1: the decoder against llvm-objdump.
//!
//! Every instruction of the committed listings — `fib`, `rvc-dense` and `amm`
//! from S10, and the hand-encoded corpus of every RV32IMA mnemonic — is decoded
//! here and **rendered in the disassembler's own syntax**, and the two strings
//! must be equal. That compares the mnemonic, every register and every
//! immediate at once, with the disassembler's reading as the authority.
//!
//! A compressed instruction reaches the decoder as the loader's 32-bit
//! expansion, while llvm-objdump prints the 16-bit form it read. So for those
//! lines the disassembler's `c.*` text is rewritten into the base instruction
//! it abbreviates — `c.lwsp ra, 44(sp)` is `lw ra, 44(sp)` — from the RVC
//! chapter's definitions, and compared with the decode of the expansion. That
//! checks the loader's expansion and this decoder together against LLVM's
//! reading of the original halfword.

mod common;

use std::collections::BTreeSet;

use isa::{decode, Instr};
use loader::{load_elf, Slot};

/// The integer register file's ABI names, as llvm-objdump prints them.
const ABI: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// A decoded instruction, spelled the way `llvm-objdump -M no-aliases
/// --no-print-imm-hex` spells it, with `pc` resolving branch and jump targets.
fn render(pc: u32, instr: &Instr) -> String {
    let x = |r: Option<u8>| ABI[r.expect("the form has this register") as usize];
    let mn = instr.mnemonic();
    let f = instr.fields();
    let target = || {
        format!(
            "0x{:x}",
            pc.wrapping_add(f.imm.expect("a displacement") as u32)
        )
    };
    let suffix = |(aq, rl)| match (aq, rl) {
        (false, false) => "",
        (true, false) => ".aq",
        (false, true) => ".rl",
        (true, true) => ".aqrl",
    };
    match *instr {
        Instr::Ecall | Instr::Ebreak => mn.to_string(),
        Instr::Fence { fm, pred, succ } => {
            if fm == 0b1000 && pred == 0b0011 && succ == 0b0011 {
                return "fence.tso".to_string();
            }
            assert_eq!(fm, 0, "llvm-objdump spells no other fence mode");
            let set = |bits: u8| {
                let s: String = [(8, 'i'), (4, 'o'), (2, 'r'), (1, 'w')]
                    .iter()
                    .filter(|(bit, _)| bits & bit != 0)
                    .map(|(_, c)| *c)
                    .collect();
                if s.is_empty() {
                    "0".to_string()
                } else {
                    s
                }
            };
            format!("fence {}, {}", set(pred), set(succ))
        }
        Instr::Lui { .. } | Instr::Auipc { .. } => {
            format!("{mn} {}, {}", x(f.rd), (f.imm.expect("upper") as u32) >> 12)
        }
        Instr::Jal { .. } => format!("jal {}, {}", x(f.rd), target()),
        Instr::LrW { aq, rl, .. } => {
            format!("lr.w{} {}, ({})", suffix((aq, rl)), x(f.rd), x(f.rs1))
        }
        _ if instr.aq_rl().is_some() => format!(
            "{mn}{} {}, {}, ({})",
            suffix(instr.aq_rl().expect("an atomic")),
            x(f.rd),
            x(f.rs2),
            x(f.rs1)
        ),
        _ => match (f.rd, f.rs1, f.rs2, f.imm) {
            (Some(_), Some(_), Some(_), None) => {
                format!("{mn} {}, {}, {}", x(f.rd), x(f.rs1), x(f.rs2))
            }
            (None, Some(_), Some(_), Some(_)) if mn.starts_with('b') => {
                format!("{mn} {}, {}, {}", x(f.rs1), x(f.rs2), target())
            }
            (None, Some(_), Some(_), Some(imm)) => {
                format!("{mn} {}, {imm}({})", x(f.rs2), x(f.rs1))
            }
            (Some(_), Some(_), None, Some(imm)) if mn.starts_with('l') || mn == "jalr" => {
                format!("{mn} {}, {imm}({})", x(f.rd), x(f.rs1))
            }
            (Some(_), Some(_), None, Some(imm)) => format!("{mn} {}, {}, {imm}", x(f.rd), x(f.rs1)),
            other => panic!("{mn}: no rendering for the field shape {other:?}"),
        },
    }
}

/// llvm-objdump's text for a compressed instruction, rewritten as the base
/// instruction it abbreviates, per the RVC chapter. `None` for `c.unimp`,
/// which abbreviates nothing and which the loader records as not code.
fn uncompress(text: &str) -> Option<String> {
    let (mn, rest) = text.split_once(' ').unwrap_or((text, ""));
    let o: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(", ").collect()
    };
    Some(match mn {
        "c.unimp" => return None,
        "c.nop" if o.is_empty() => "addi zero, zero, 0".to_string(),
        "c.nop" => format!("addi zero, zero, {}", o[0]),
        "c.addi" => format!("addi {0}, {0}, {1}", o[0], o[1]),
        "c.li" => format!("addi {}, zero, {}", o[0], o[1]),
        "c.addi16sp" => format!("addi sp, sp, {}", o[1]),
        "c.addi4spn" => format!("addi {}, sp, {}", o[0], o[2]),
        "c.lui" => format!("lui {}, {}", o[0], o[1]),
        "c.mv" => format!("add {}, zero, {}", o[0], o[1]),
        "c.add" => format!("add {0}, {0}, {1}", o[0], o[1]),
        "c.sub" | "c.xor" | "c.or" | "c.and" => format!("{} {1}, {1}, {2}", &mn[2..], o[0], o[1]),
        "c.andi" | "c.slli" | "c.srli" | "c.srai" => {
            format!("{} {1}, {1}, {2}", &mn[2..], o[0], o[1])
        }
        "c.lw" | "c.lwsp" => format!("lw {}, {}", o[0], o[1]),
        "c.sw" | "c.swsp" => format!("sw {}, {}", o[0], o[1]),
        "c.j" => format!("jal zero, {}", o[0]),
        "c.jal" => format!("jal ra, {}", o[0]),
        "c.jr" => format!("jalr zero, 0({})", o[0]),
        "c.jalr" => format!("jalr ra, 0({})", o[0]),
        "c.beqz" => format!("beq {}, zero, {}", o[0], o[1]),
        "c.bnez" => format!("bne {}, zero, {}", o[0], o[1]),
        "c.ebreak" => "ebreak".to_string(),
        other => panic!("no RVC rewrite for {other}: add one from the RVC chapter"),
    })
}

/// One listing line: address, raw encoding width, the encoding, and the text
/// with any trailing `<symbol+offset>` annotation removed.
fn parse(line: &str) -> (u32, usize, u32, String) {
    let mut f = line.splitn(3, ' ');
    let addr = u32::from_str_radix(f.next().expect("address"), 16).expect("hex address");
    let enc = f.next().expect("encoding");
    let text = f.next().expect("disassembly");
    let text = text.split(" <").next().expect("text").trim().to_string();
    (
        addr,
        enc.len() / 2,
        u32::from_str_radix(enc, 16).expect("hex encoding"),
        text,
    )
}

/// Decode every line of one listing and compare. Returns the mnemonics seen.
fn check_listing(elf: &[u8], listing: &[u8], name: &str) -> (usize, BTreeSet<&'static str>) {
    let image = load_elf(elf).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let mut seen = BTreeSet::new();
    let mut checked = 0usize;
    for line in common::lines(listing) {
        let (pc, width, encoding, text) = parse(&line);
        let (word, expected) = if width == 4 {
            (encoding, text)
        } else {
            let Some(base) = uncompress(&text) else {
                continue;
            };
            match image.slot_at(pc) {
                Some(Slot::Instruction {
                    word,
                    compressed: true,
                }) => (word, base),
                other => panic!("{name}: {pc:#010x} is {other:?}, not a compressed instruction"),
            }
        };
        let instr = decode(word).unwrap_or_else(|e| {
            panic!(
                "{name}: {pc:#010x} `{text_or}` does not decode: {e:?}",
                text_or = line
            )
        });
        assert_eq!(
            render(pc, &instr),
            expected,
            "{name}: at {pc:#010x}, word {word:#010x} decodes to {instr:?}"
        );
        if let Some(funct3) = instr.fields().funct3 {
            assert_eq!(
                funct3 as u32,
                (word >> 12) & 0b111,
                "{name}: at {pc:#010x} the funct3 accessor is not the encoding's funct3"
            );
        }
        seen.insert(instr.mnemonic());
        checked += 1;
    }
    (checked, seen)
}

#[test]
fn decode_agrees_with_objdump_on_the_guest_corpus() {
    for name in ["fib", "rvc-dense", "amm"] {
        let (checked, _) = check_listing(
            &common::loader(&format!("{name}.elf")),
            &common::loader(&format!("{name}.objdump.txt")),
            name,
        );
        assert!(
            checked > 2000,
            "{name}: only {checked} instructions compared"
        );
    }
}

#[test]
fn decode_agrees_with_objdump_on_every_mnemonic() {
    let listing = common::own("isa_corpus.objdump.txt");
    let (checked, seen) = check_listing(&common::own("isa_corpus.elf"), &listing, "isa_corpus");
    let want: BTreeSet<&str> = common::MNEMONICS.iter().copied().collect();
    assert_eq!(
        seen, want,
        "the corpus decodes to exactly the 59 RV32IMA mnemonics"
    );

    // The same coverage from the disassembler's side, so a decoder that
    // mislabelled one mnemonic as another could not supply it.
    let spelled: BTreeSet<String> = common::lines(&listing)
        .iter()
        .map(|l| {
            let (_, _, _, text) = parse(l);
            let mn = text.split(' ').next().expect("mnemonic").to_string();
            let mn = mn
                .trim_end_matches(".aqrl")
                .trim_end_matches(".aq")
                .trim_end_matches(".rl")
                .to_string();
            if mn == "fence.tso" {
                "fence".to_string()
            } else {
                mn
            }
        })
        .collect();
    assert_eq!(
        spelled.len(),
        59,
        "llvm-objdump names 59 mnemonics in the corpus"
    );
    assert!(checked >= 300, "only {checked} corpus words compared");
}

/// The negative control: a word one bit away from the one listed must fail
/// the comparison, or the two tests above prove nothing.
#[test]
fn a_perturbed_word_disagrees_with_the_listing() {
    let listing = common::own("isa_corpus.objdump.txt");
    let mut caught = 0usize;
    for line in common::lines(&listing).iter().take(64) {
        let (pc, _, word, text) = parse(line);
        // Flip the low bit of rd, rs1 or rs2 -- whichever the form has -- or
        // failing that the lowest immediate bit.
        for bit in [7, 15, 20, 21, 25] {
            if let Ok(instr) = decode(word ^ (1 << bit)) {
                if render(pc, &instr) != text {
                    caught += 1;
                    break;
                }
            }
        }
    }
    assert!(
        caught >= 60,
        "only {caught} of 64 perturbations were caught"
    );
}

#[test]
fn committed_fixtures_match_their_pins() {
    for (name, want) in common::PINS {
        assert_eq!(
            common::digest(&common::own(name)),
            want,
            "{name} has changed. If that was deliberate, rerun `cargo run -p kat-gen -- isa` \
             and update the digest in tests/common/mod.rs."
        );
    }
}
