/* The Apogee guest ABI for C and C++: what `libapogee_guest.a` implements.
 *
 * Link a program against `libapogee_guest.a` and the `apogee.ld` memory map
 * (`cmake/apogee-rv64.cmake` does both) and define `int main(void)`: the
 * library's startup zeroes `.bss`, runs the static initializers (C++ dynamic
 * initialization and constructor functions), calls `main`, and exits with
 * what it returns. A global whose type has a non-trivial destructor does not
 * link: the library has no `__cxa_atexit`.
 *
 * An Apogee guest has no files and no streams. Its public input, advice and
 * journal are memory the proof binds — or, for advice, does not — and these
 * four calls are the whole of reaching them (docs/guest-program-manual.md §11,
 * docs/spec/public-values.md).
 *
 * The library also provides `memcpy`, `memmove`, `memset` and `memcmp`, and
 * the 128-bit integer helpers a compiler calls. It has no allocator, no
 * `printf` and no C++ standard library: a guest is freestanding. */
#ifndef APOGEE_GUEST_H
#define APOGEE_GUEST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The public input: the verifier-known bytes this execution is about. Returns
 * their address and, where `len` is not null, stores their length. */
const uint8_t *apogee_public_input(size_t *len);

/* The advice: prover-supplied bytes, bound by nothing, which a guest checks
 * against something public before relying on them. Calling it on a run given
 * no advice is a fatal error. */
const uint8_t *apogee_advice(size_t *len);

/* Append `len` bytes to the journal, the execution's public output. Exits 70
 * rather than overflow the journal's 16,380 bytes. */
void apogee_commit(const void *bytes, size_t len);

/* End the execution with `code`; nonzero is a failed execution, still
 * provable. Returning `code` from `main` is the same. */
__attribute__((noreturn)) void apogee_exit(int32_t code);

/* The guest's entry, which the library's startup calls. Declared here with C
 * linkage because a freestanding C++ compiler does not give `main` any: a
 * C++ guest's `int main()` then defines the symbol startup links to. */
int main(void);

#ifdef __cplusplus
}
#endif

#endif /* APOGEE_GUEST_H */
