# guest-sdk

The guest runtime: crt0 and `entry!`, the linker script, the allocator, the three memory regions and `exit`, the precompile shims and `U256`; built as a static library, the C/C++ SDK with `include/apogee_guest.h` and `cmake/apogee-rv64.cmake`; `cxa/` is `__cxa_atexit`, an archive member of its own. Guest-only, outside the workspace.

Specified in [ecall-abi.md](../../docs/spec/ecall-abi.md), [public-values.md](../../docs/spec/public-values.md), [precompiles.md](../../docs/spec/precompiles.md) §5, [guest-program-manual.md](../../docs/guest-program-manual.md).
