/* The guest memory map, which `docs/spec/ecall-abi.md` §5 documents, symbols
   included.

   The symbol names __init_array_start, __init_array_end, __fini_array_start,
   __fini_array_end, __bss_start, __bss_end, __heap_start, __stack_top and
   __apogee_main are referenced by name: crt0 in src/lib.rs zeroes the bss
   range and calls the init array's functions, then __apogee_main, which runs
   the fini array's in reverse when it is not main itself; the bump allocator
   lives between __heap_start and __stack_top.

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
   them; the reservation is NOBITS, so the file does not grow.
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
  .text   : ALIGN(4096) {
    *(.text._start)
    /* __cxa_atexit alone, between two symbols the teardown's selection below
       compares. */
    __apogee_cxa_atexit_start = .;
    *(.text.apogee.cxa_atexit)
    __apogee_cxa_atexit_end = .;
    *(.text*)
  } > RAM
  .rodata : ALIGN(4096) {
    *(.rodata*)
    *(.srodata*)
    /* Unwind tables, which both compilers emit without exceptions. Unlisted,
       they are an orphan, and once --gc-sections leaves .rodata empty the
       linker puts that orphan straight after .text, a read-only segment on
       .text's page. */
    *(.eh_frame_hdr)
    *(.eh_frame)
    *(.gcc_except_table*)
  } > RAM
  /* The delegation declarations (docs/spec/precompiles.md §1): one u32 per
     precompile shim the guest links, its ecall number, each an input section
     of its own that --gc-sections keeps exactly where the shim is. An output
     section of their own, which the loader reads by name and nothing else
     declares; empty, it is dropped. Never on .text's last page: when
     --gc-sections leaves .rodata empty, the address skips to the next page. */
  .apogee.delegations MAX(ALIGN(4), ALIGN(ADDR(.text) + SIZEOF(.text), 4096)) : {
    *(.apogee.delegations.*)
  } > RAM
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
    /* C's destructor functions, laid out the same way and called in reverse
       after main. */
    __fini_array_start = .;
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    __fini_array_end = .;
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

/* What crt0 calls: the guest's main, or, for a guest with destructors, main
   followed by them: those C++ registers through __cxa_atexit, which it calls
   for each static object that has one, then C's destructor functions. The
   library's __cxa_atexit is an archive member of its own (crates/guest-sdk/cxa),
   which a linker takes only for a reference, and keeps under --gc-sections only
   for a reference from live code; so it is in the image exactly when this guest
   can register a destructor, and a guest with no destructor has crt0 call main
   itself and runs no teardown at all. A PROVIDE, so that a guest which is its
   own _start, with no crt0 and no main, links. */
PROVIDE(__apogee_main = (__apogee_cxa_atexit_end != __apogee_cxa_atexit_start
                         || __fini_array_end != __fini_array_start)
  ? __apogee_main_then_destructors : main);
