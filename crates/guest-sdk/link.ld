/* The guest memory map, frozen at S10. `prompts/S10-toolchain.md` pins this
   script; `docs/spec/ecall-abi.md` section 7 documents the symbols.

   The symbol names __bss_start, __bss_end, __heap_start and __stack_top are
   frozen: crt0 in src/lib.rs zeroes the first range and the bump allocator
   lives between the last two.

   Every writable byte the guest can touch is declared as one loadable segment
   that runs to the top of RAM. The zkVM executor does not need that -- it makes
   the whole RAM window addressable by construction -- but a host loader such as
   qemu-riscv32 maps exactly what the program headers declare and nothing else,
   so an undeclared stack or heap is unmapped memory and the first push faults.
   Declaring it keeps the two executors agreeing on the memory map, which is the
   property that matters; the segment is NOBITS, so the file does not grow. */
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
ENTRY(_start)
SECTIONS {
  /* Every segment starts on its own page. A host loader mmaps each PT_LOAD
     independently at the page containing p_vaddr, so two segments sharing a
     page means the second mapping's permissions win for the whole page: an
     unaligned .rodata would strip execute from the tail of .text, and an
     unaligned .bss would put zero-fill on a read-only page, which is refused
     outright. The zkVM executor is indifferent -- it has no pages -- so this
     costs three pages of address space to keep one ELF running under both. */
  .text   : ALIGN(4096) { *(.text._start) *(.text*) } > RAM
  .rodata : ALIGN(4096) { *(.rodata*) } > RAM
  .data   : ALIGN(4096) { *(.data*) } > RAM
  .bss    : ALIGN(4096) {
    __bss_start = .;
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
