//! Acceptance 2: words that are not RV32IMAC instructions are refused.

mod common;

use std::collections::BTreeSet;

use isa::decode;

fn corpus() -> Vec<(u32, String, String)> {
    common::lines(&common::own("isa_negative.txt"))
        .iter()
        .map(|l| {
            let mut f = l.splitn(3, ' ');
            let word = u32::from_str_radix(f.next().expect("word"), 16).expect("hex word");
            let format = f.next().expect("format").to_string();
            (word, format, f.next().expect("reason").to_string())
        })
        .collect()
}

#[test]
fn every_negative_word_is_refused() {
    let corpus = corpus();
    assert!(
        corpus.len() >= 40,
        "the negative corpus has only {}",
        corpus.len()
    );
    for (word, format, why) in &corpus {
        match decode(*word) {
            Err(e) => assert_eq!(e.word, *word, "the error names the word it refused"),
            Ok(instr) => panic!("{word:#010x} ({format}: {why}) decoded to {instr:?}"),
        }
    }

    // At least one near miss per format with a fixed field, plus the foreign
    // opcodes and the compressed shapes.
    let formats: BTreeSet<&str> = corpus.iter().map(|(_, f, _)| f.as_str()).collect();
    let want: BTreeSet<&str> = [
        "R",
        "I",
        "S",
        "B",
        "AMO",
        "SYSTEM",
        "MISC-MEM",
        "extension",
        "opcode",
        "compressed",
    ]
    .into_iter()
    .collect();
    assert_eq!(formats, want, "the corpus covers every refusable format");
}

/// Each near miss really is near: one field away from a word that decodes.
/// Without this a corpus of words that are wrong everywhere would pass the
/// test above and prove nothing about the edges.
#[test]
fn every_near_miss_is_one_field_from_an_instruction() {
    // The fields a near miss may have wrong: funct7, funct3, rs2 (lr.w), rd
    // and rs1 (ecall, ebreak), and funct5.
    let repairs: [(u32, u32); 5] = [
        (0xfe00_0000, 25), // funct7
        (0x0000_7000, 12), // funct3
        (0x01f0_0000, 20), // rs2
        (0x0000_0f80, 7),  // rd
        (0x000f_8000, 15), // rs1
    ];
    for (word, format, why) in corpus() {
        if matches!(format.as_str(), "extension" | "opcode" | "compressed") {
            continue;
        }
        let near = repairs.iter().any(|(mask, shift)| {
            (0..=(mask >> shift)).any(|v| decode((word & !mask) | (v << shift)).is_ok())
        });
        assert!(
            near,
            "{word:#010x} ({format}: {why}) is not one field from any instruction"
        );
    }
}

/// The positive control for the harness above: the corpus the disassembler
/// read all decodes, so `decode` is not passing the negative test by refusing
/// everything.
#[test]
fn the_positive_corpus_decodes() {
    let elf = common::own("isa_corpus.elf");
    let image = loader::load_elf(&elf).expect("the corpus loads");
    let mut words = 0usize;
    for slot in &image.slots {
        if let loader::Slot::Instruction { word, .. } = slot {
            decode(*word).unwrap_or_else(|e| panic!("{word:#010x}: {e:?}"));
            words += 1;
        }
    }
    assert!(words >= 300);
}
