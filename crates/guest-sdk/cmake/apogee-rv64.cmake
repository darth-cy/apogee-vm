# The Apogee guest toolchain: RV64IMAC, LP64, bare metal, standard Clang and
# LLD. Configure a C or C++ project with
#
#     cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<sdk>/cmake/apogee-rv64.cmake
#
# and every executable it builds is a static `guest.elf` Apogee runs and
# proves: compiled for rv64imac/lp64, linked by `apogee.ld` against
# `libapogee_guest.a`, which provides startup and `apogee_guest.h`'s ABI
# (docs/guest-program-manual.md §11).
#
# The SDK's layout, relative to this file: `../include/apogee_guest.h`,
# `../lib/libapogee_guest.a`, `../lib/apogee.ld`. Each is a cache variable,
# so a build from a source tree points them elsewhere.

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)
# A bare-metal compiler cannot link a test executable on its own.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

get_filename_component(APOGEE_SDK "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(APOGEE_INCLUDE_DIR "${APOGEE_SDK}/include" CACHE PATH "apogee_guest.h's directory")
set(APOGEE_GUEST_LIB "${APOGEE_SDK}/lib/libapogee_guest.a" CACHE FILEPATH "libapogee_guest.a")
set(APOGEE_LINKER_SCRIPT "${APOGEE_SDK}/lib/apogee.ld" CACHE FILEPATH "apogee.ld")

# Standard Clang and LLD, any recent release, from PATH — after Homebrew's
# keg-only LLVM, because Apple's clang has no RISC-V backend.
set(_apogee_hints /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
    /opt/homebrew/opt/lld/bin /usr/local/opt/lld/bin)
find_program(APOGEE_CLANG NAMES clang HINTS ${_apogee_hints} REQUIRED)
find_program(APOGEE_CLANGXX NAMES clang++ HINTS ${_apogee_hints} REQUIRED)
find_program(APOGEE_LLD NAMES ld.lld HINTS ${_apogee_hints} REQUIRED)

set(CMAKE_C_COMPILER "${APOGEE_CLANG}")
set(CMAKE_CXX_COMPILER "${APOGEE_CLANGXX}")
set(CMAKE_ASM_COMPILER "${APOGEE_CLANG}")
foreach(lang C CXX ASM)
  set(CMAKE_${lang}_COMPILER_TARGET riscv64-unknown-elf)
endforeach()

# -mcmodel=medany: code and data anywhere below 2^31, the whole guest map.
# No exceptions, no RTTI, no C++ standard library headers: a guest is
# freestanding, and the compiler's own C headers (stdint.h, stddef.h) are
# what it includes.
set(_apogee_flags "-march=rv64imac -mabi=lp64 -mcmodel=medany -ffreestanding -fno-pic -isystem ${APOGEE_INCLUDE_DIR}")
set(CMAKE_C_FLAGS_INIT "${_apogee_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_apogee_flags} -nostdinc++ -fno-exceptions -fno-rtti -fno-threadsafe-statics")
set(CMAKE_ASM_FLAGS_INIT "${_apogee_flags}")
# --no-relax: relaxation moves addresses, and the program identity is a
# function of them.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-nostdlib -static -fuse-ld=lld --ld-path=${APOGEE_LLD} -Wl,-T,${APOGEE_LINKER_SCRIPT} -Wl,--no-relax")
set(CMAKE_C_STANDARD_LIBRARIES "${APOGEE_GUEST_LIB}")
set(CMAKE_CXX_STANDARD_LIBRARIES "${APOGEE_GUEST_LIB}")
