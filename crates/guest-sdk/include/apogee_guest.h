/* The Apogee guest ABI for C and C++: what `libapogee_guest.a` implements.
 *
 * Link a program against `libapogee_guest.a` and the `apogee.ld` memory map
 * (`cmake/apogee-rv64.cmake` does both) and define `int main(void)`: the
 * library's startup zeroes `.bss`, runs the static initializers (C++ dynamic
 * initialization and constructor functions), calls `main`, runs the static
 * objects' destructors, the latest constructed first, then the destructor
 * functions, and exits with what `main` returned.
 *
 * An Apogee guest has no files and no streams. Its public input, advice and
 * journal are memory the proof binds — or, for advice, does not — and these
 * four calls are the whole of reaching them (docs/guest-program-manual.md §11,
 * docs/spec/public-values.md). The last seven calls are precompiles, each
 * a circuit of its own (docs/spec/precompiles.md).
 *
 * The library also provides `memcpy`, `memmove`, `memset` and `memcmp`, the
 * 128-bit integer helpers a compiler calls, and `__cxa_atexit`, which C++
 * registers a static object's destructor with. It has no allocator, no
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
 * provable. Unlike returning `code` from `main`, it runs no destructor: it is
 * C's `_Exit`. */
__attribute__((noreturn)) void apogee_exit(int32_t code);

/* The Poseidon2-A64-C5 permutation of the 16 lanes at `state`, in place, by
 * the precompile: each lane read mod p = 2^64 - 59 and written below it.
 * `state` is 8-aligned and below the advice region: copy advice in before
 * hashing it. */
void apogee_poseidon2_permute(uint64_t state[16]);

/* q = floor(a*b/d) and r = a*b mod d over the full 512-bit product, by the
 * precompile; each value four little-endian 64-bit limbs. Returns 0, or 1 and
 * writes nothing when d = 0 or the quotient is not below 2^256. */
int32_t apogee_mul_div_u256(const uint64_t a[4], const uint64_t b[4], const uint64_t d[4],
                            uint64_t q[4], uint64_t r[4]);

/* The root of the Merkle path from the 8 lanes at `leaf` at `slot` up `depth`
 * siblings at `siblings`, 64 bytes each, level 0's first, by the precompile,
 * written to `root`. Level L's node is apogee_poseidon2_permute of the node
 * below and its sibling, the node below first where bit L of `slot` is 0,
 * truncated to its first 8 lanes. The siblings may be anywhere, the advice
 * included, each lane read mod p. Returns 0, or 1 and writes nothing when
 * depth is outside 16..32, slot is not below 2^depth, a leaf lane is not below
 * p, or `siblings` is not 4-aligned. */
int32_t apogee_merkle_root(uint32_t slot, uint32_t depth, const uint64_t leaf[8],
                           const uint8_t *siblings, uint64_t root[8]);

/* ||s1||^2 by the precompile, s1 = (c - s2*h) mod (q, x^512 + 1), q = 12289,
 * each coefficient centered to [-6144, 6144] and every coefficient of h, s2
 * and c read mod q: Falcon-512 verification's lattice check. Below 2^35.
 * Each array is 512 coefficients, coefficient i at index i, and must be
 * 4-aligned: a uint16_t array is 2-aligned unless declared `_Alignas(4)` (C)
 * or `alignas(4)` (C++). The three must not overlap; each may be anywhere,
 * the advice included. Anything else exits 101, a panic. */
uint64_t apogee_falcon512_s1_norm(const uint16_t h[512], const uint16_t s2[512],
                                  const uint16_t c[512]);

/* HashToPoint's sampler by the precompile: each of the 8 lanes at `lanes`, x,
 * rewritten in place as its four base-q digits floor(x / q^j) mod q, j < 4,
 * d0 + 2^16*d1 + 2^32*d2 + 2^48*d3, so lane l is coefficients 4l to 4l + 3 of
 * the 32 uint16_t its bytes are. `lanes` is 8-aligned and below the advice
 * region. A lane at or above 808*q^4, the largest multiple of q^4 below p,
 * exits 101, a panic. */
void apogee_falcon512_sample(uint64_t lanes[8]);

/* Falcon-512's decoder by the precompile: in `mode` 0 a public key's h at
 * `src`, its 896 bytes, 512 fields of 14 bits, each below q (the key's v1.2
 * encoding without its header 0x09); in `mode` 1 a signature's compressed s2
 * at `src`, 40 bytes into its advised form, after the salt: 512
 * coefficients, none -0, none above 2047 in size, within 5,000 bits, and the
 * bits after the last in its word zeros. The coefficients are written to
 * `dst`, s2's each s mod q. Returns ||s2||^2, 0 for a key, and stores the
 * stream's end through `end` where not null: the bit after the last
 * coefficient, counted from `src`'s first, its bytes MSB first, a key's 7168.
 * `src` and `dst` are 4-aligned and apart; `src` is read a word at a time
 * through the word holding the stream's last bit, and may be anywhere a load
 * reaches, the advice included. Anything else, and any stream that is not
 * one of these, the call refuses: the execution fails. */
uint32_t apogee_falcon512_decode(uint32_t mode, const uint8_t *src, uint16_t dst[512],
                                 uint32_t *end);

/* The value of the op program of `n` ops at `ops`, by the precompile, written
 * to `root`: op i is (info, arg) at ops[2i] and ops[2i + 1], run in order over
 * a value of 8 lanes, zero to start, each lane written below p. An info word
 * is kind + 4*park + 8*left + 16*d, d < 512. A LOAD (kind 0) makes the value
 * the block at `arg`; a SIB (1) or a JOIN (2) makes it apogee_poseidon2_permute
 * of the value and the other child, the other first where `left` is set,
 * truncated to its first 8 lanes, with d + 1 added to lane 0 mod p: a crit-bit
 * trie's branch at bit d. A SIB's other child is the block at `arg`; a JOIN's
 * is the value op `arg`, an earlier op with its park bit set, started from. A
 * block is 16 words, 8 little-endian lanes, each read mod p; the ops and the
 * blocks may be anywhere a load reaches, the advice included. Returns 0, or 1
 * and writes nothing when n is 0 or above 2^20 or `ops` is not 4-aligned. The
 * call refuses any other program -- an info word that does not decode, a block
 * not 4-aligned, a JOIN of no earlier park, a park taken by no JOIN or by two,
 * a word read twice across the ops and the blocks -- and the execution fails. */
int32_t apogee_mpt_eval(const uint32_t *ops, uint32_t n, uint64_t root[8]);

/* The guest's entry, which the library's startup calls. Declared here with C
 * linkage because a freestanding C++ compiler does not give `main` any: a
 * C++ guest's `int main()` then defines the symbol startup links to. */
int main(void);

#ifdef __cplusplus
}
#endif

#endif /* APOGEE_GUEST_H */
