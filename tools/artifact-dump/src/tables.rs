//! The decoded tables of a guest ELF, printed: every instruction's pc,
//! mnemonic, decoded fields and owning family, the derived `VmConfig`, and the
//! program identity.
//!
//! The listing is read **out of the tables** — the columns program identity
//! commits to — and not re-derived from the image, so the page shows the thing
//! that is committed. The one exception is the mnemonic: a table stores a
//! one-hot kind bit, not a name, so the name comes from decoding the slot's
//! word, which is what put the bit there. `tests/tables.rs` parses the listing
//! back and holds it to the tables row for row.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use loader::{load_elf, Slot};
use program::{
    decode_program, family_name, field_mask, program_identity, DecodedTables, ProgramParams,
    RowField,
};
use srs::Srs;
use test_support::{sha256, to_hex};

/// The printed tables of `elf`, or the named loader or decoder error that
/// stopped them. With `srs`, the identity is computed over it; without, the
/// page says what is needed.
pub fn render(
    elf: &[u8],
    source_label: &str,
    params: &ProgramParams,
    srs: Option<&Srs>,
) -> Result<String, String> {
    let image =
        load_elf(elf).map_err(|e| format!("{source_label}: the loader refused it: {e:?}"))?;
    let (tables, config) =
        decode_program(&image, params).map_err(|e| format!("{source_label}: {e}"))?;
    let identity = match srs {
        Some(srs) => to_hex(&program_identity(&tables, &config, srs).to_bytes()),
        None => "not computed: pass --ptau <ppot_0080_24.ptau>, the PSE ceremony file".to_string(),
    };

    let mut out = String::new();
    let _ = write!(
        out,
        "apogee-vm decoded tables\n\
         ========================\n\
         \n\
         source ELF        {source_label}\n\
         source sha256     {}\n\
         code version      {}\n\
         bytecode ceiling  {} words\n\
         program identity  {identity}\n\
         \n\
         The identity is one Fr, canonical little-endian: the Mercury commitments to\n\
         every column below, with the VmConfig, digested by the recipe in\n\
         crates/program/CLAUDE.md. It is a function of the decoded instructions and\n\
         the parameters only -- not of the ELF's bytes, its symbols, .rodata, .data\n\
         or its entry point, none of which S11's identity binds yet.\n",
        to_hex(&sha256(elf)),
        tables.code_version,
        config.bytecode_size_words,
    );

    let _ = write!(
        out,
        "\nVmConfig\n\
         --------\n\
         \x20 id  family              height     live rows  columns\n"
    );
    for table in &tables.families {
        let live = (0..table.height as usize)
            .filter(|r| table.is_live(*r))
            .count();
        let columns: Vec<&str> = table.columns.iter().map(|(f, _)| field_name(*f)).collect();
        let _ = writeln!(
            out,
            "  {:>2}  {:<18}  {:>9}  {:>9}  {} (mask {:#010b})",
            table.family,
            family_name(table.family),
            table.height,
            live,
            if columns.is_empty() {
                "none: claims no pc".to_string()
            } else {
                columns.join(" ")
            },
            field_mask(table.family),
        );
    }

    listing(&mut out, &image, &tables);
    Ok(out)
}

/// Every instruction, in address order, read from its family's table.
fn listing(out: &mut String, image: &loader::ProgramImage, tables: &DecodedTables) {
    let _ = write!(
        out,
        "\nlisting\n\
         -------\n\
         One line per instruction. Fields not in the owning family's lookup tuple\n\
         are `-`. `imm` is the two's-complement word the instruction uses, or on a\n\
         system row the system code (0 ecall, 1 ebreak, 2 fence). `kind` is the\n\
         one-hot extra mask, written as its bit number. Every row the listing does\n\
         not show is padding: Fr::MINUS_ONE in every field.\n\
         \n\
         pc          next_pc     family              mnemonic   rs1 rs2  rd  imm         kind\n"
    );
    let mut kinds: BTreeMap<(u32, u32), &'static str> = BTreeMap::new();
    for (i, slot) in image.slots.iter().enumerate() {
        let Slot::Instruction { word, .. } = *slot else {
            continue;
        };
        let row = (image.slot_base / 2) as usize + i;
        let table = tables
            .families
            .iter()
            .find(|t| t.is_live(row))
            .expect("the partition gives every instruction one family");
        let field = |f: RowField| {
            table
                .columns
                .iter()
                .position(|(c, _)| *c == f)
                .map(|c| table.get(c, row).expect("a live row"))
        };
        let show = |v: Option<u32>, width: usize| match v {
            Some(v) => format!("{v:>width$}"),
            None => format!("{:>width$}", "-"),
        };
        let mnemonic = isa::decode(word)
            .expect("a live row decoded to put it there")
            .mnemonic();
        let kind = field(RowField::ExtraMask).map(|m| m.trailing_zeros());
        if let Some(bit) = kind {
            kinds.insert((table.family, bit), mnemonic);
        }
        let _ = writeln!(
            out,
            "{:#010x}  {:#010x}  {:<18}  {mnemonic:<9}  {} {} {}  {}  {}",
            field(RowField::Pc).expect("pc is in every tuple"),
            field(RowField::NextPc).expect("next_pc is in every tuple"),
            family_name(table.family),
            show(field(RowField::Rs1), 3),
            show(field(RowField::Rs2), 3),
            show(field(RowField::Rd), 3),
            match field(RowField::Imm) {
                Some(v) => format!("{v:#010x}"),
                None => format!("{:>10}", "-"),
            },
            show(kind, 4),
        );
    }

    let _ = write!(
        out,
        "\nkinds\n\
         -----\n\
         The extra-mask bits this program uses, and the mnemonic each names. The\n\
         bit positions are frozen in constants::extra_mask.\n"
    );
    for ((family, bit), mnemonic) in &kinds {
        let name = if *family == constants::family::ADD_SUB_LUI_AUIPC
            && *bit == constants::extra_mask::add_sub_lui_auipc::SYSTEM
        {
            "system (ecall, ebreak, fence)"
        } else {
            mnemonic
        };
        let _ = writeln!(out, "  {:<18}  bit {bit:>2}  {name}", family_name(*family));
    }
}

fn field_name(field: RowField) -> &'static str {
    match field {
        RowField::Pc => "pc",
        RowField::NextPc => "next_pc",
        RowField::Rs1 => "rs1",
        RowField::Rs2 => "rs2",
        RowField::Rd => "rd",
        RowField::Imm => "imm",
        RowField::Funct3 => "funct3",
        RowField::ExtraMask => "extra_mask",
    }
}
