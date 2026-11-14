/* The guest memory map, which `docs/spec/ecall-abi.md` §5 documents, symbols
   included.

   The symbol names __init_array_start, __init_array_end, __bss_start,
   __bss_end, __heap_start and __stack_top are referenced by name: crt0 in
   src/lib.rs zeroes the bss range, then calls each initializer in the array,
   and the bump allocator lives between the last two.

   The input sections are the ones Rust and Clang emit for RV64, the small-data
   `.srodata`, `.sdata` and `.sbss` included: Clang puts a global of eight bytes
   or less there unless its small-data limit is 0, which differs by release. An
   unlisted writable section is an orphan the linker places after `.bss`, past
   the reservation that runs to the top of RAM, where it does not fit.

   Every writable byte the guest can touch is declared as one loadable segment
   that runs to the top of RAM. The zkVM executor does not need that -- it makes
   the whole of RAM addressable by construction -- but an image whose stack
   and heap are in no PT_LOAD is an image whose program headers are a lie about
   its own memory, and any loader that believes them leaves the first push
   pointing at nothing. The headers say what the image needs, whoever reads
   them; the segment is NOBITS, so the file does not grow.
   crates/loader/tests/layout.rs reads the headers and pins this. */
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
ENTRY(_start)
SECTIONS {
  /* Every segment starts on its own page. A loader that maps each PT_LOAD
     independently maps the page containing p_vaddr, so two segments sharing a
     page means the second mapping's permissions win for the whole page: an
     unaligned .rodata would strip execute from the tail of .text, and an
     unaligned .bss would put zero-fill on a read-only page, which is refused
     outright. The zkVM executor is indifferent -- it has no pages -- so this
     costs three pages of address space to keep one ELF running under both. */
  .text   : ALIGN(4096) { *(.text._start) *(.text*) } > RAM
  .rodata : ALIGN(4096) { *(.rodata*) *(.srodata*) } > RAM
  .data   : ALIGN(4096) {
    *(.data*)
    *(.sdata*)
    /* C++ dynamic initializers and constructor functions: one function
       pointer each, prioritised ones first, in priority order. crt0 calls them
       in this order before main. Inside .data, so they add no segment. */
    . = ALIGN(8);
    __init_array_start = .;
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    __init_array_end = .;
  } > RAM
  .bss    : ALIGN(4096) {
    __bss_start = .;
    *(.sbss*)
    *(.bss*)
    *(COMMON)
    __bss_end = .;
    . = ALIGN(16);
    __heap_start = .;
    /* The heap grows up from here and the stack down from __stack_top; the
       reservation between them is what makes both addressable. crt0 zeroes
       only __bss_start..__bss_end, so this costs no startup cycles. */
    . = ORIGIN(RAM) + LENGTH(RAM);
  } > RAM
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
