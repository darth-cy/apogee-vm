/* The guest memory map, frozen at S10. `prompts/S10-toolchain.md` pins this
   script; `docs/spec/ecall-abi.md` section 7 documents the symbols.

   The symbol names __bss_start, __bss_end, __heap_start and __stack_top are
   frozen: crt0 in src/lib.rs zeroes the first range and the bump allocator
   lives between the last two. */
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x0FFF0000 }
ENTRY(_start)
SECTIONS {
  .text   : { *(.text._start) *(.text*) } > RAM
  .rodata : { *(.rodata*) } > RAM
  .data   : { *(.data*) } > RAM
  .bss    : { __bss_start = .; *(.bss*) *(COMMON); __bss_end = .; } > RAM
  . = ALIGN(16);
  __heap_start = .;
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
