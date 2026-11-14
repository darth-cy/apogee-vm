// cpp-primes: deterministic Miller-Rabin over 64-bit integers, in C++.
//
// The first C++ guest, and a 64-bit workload: Montgomery multiplication is a
// `mul` and a `mulhu` of full registers, and the bases below decide every
// 64-bit integer exactly, so the answer is a function of the input alone.
//
// Its state is ordinary C++ globals, which the SDK places, initializes and
// tears down (docs/guest-program-manual.md §11). The integers are read by a
// global's constructor, a dynamic initializer the startup runs before `main`.
// The tally, four bytes, is in `.sbss` or `.bss` as Clang's small-data limit
// has it, and the verdicts are in `.bss`. The journal is written by a static
// object's destructor once `main` returns, as a C++ program's buffered output
// is flushed at exit.
//
// # The public input
//
//     0..8k     k unsigned 64-bit integers, little-endian
//
// # The journal
//
//     0..4      k, u32 LE
//     4..8      how many of the k are prime, u32 LE
//     8..8+k    one byte per integer, 1 if it is prime and 0 if it is not
//
// # The advice
//
// Unused.
#include <apogee_guest.h>

namespace {

using u64 = uint64_t;
using u128 = unsigned __int128;

// Arithmetic modulo an odd n in Montgomery form, R = 2^64.
class Montgomery {
  public:
    explicit Montgomery(u64 n) : n_(n), inv_(n) {
        // Newton's iteration doubles the correct low bits of n^-1 mod 2^64.
        for (int i = 0; i < 6; ++i) {
            inv_ *= 2 - n_ * inv_;
        }
        // R mod n, then R^2 mod n by doubling it 64 times.
        u64 r = -n_ % n_;
        r2_ = r;
        for (int i = 0; i < 64; ++i) {
            r2_ = double_mod(r2_);
        }
    }

    u64 to(u64 a) const { return mul(a % n_, r2_); }
    u64 one() const { return to(1); }

    // a·b·R^-1 mod n.
    u64 mul(u64 a, u64 b) const {
        u128 t = static_cast<u128>(a) * b;
        u64 m = static_cast<u64>(t) * -inv_;
        u128 s = (t >> 64) + ((static_cast<u128>(m) * n_) >> 64) +
                 (static_cast<u64>(t) != 0);
        u64 r = static_cast<u64>(s);
        return (s >> 64 || r >= n_) ? r - n_ : r;
    }

    u64 pow(u64 a, u64 e) const {
        u64 acc = one();
        for (; e != 0; e >>= 1) {
            if (e & 1) {
                acc = mul(acc, a);
            }
            a = mul(a, a);
        }
        return acc;
    }

  private:
    u64 double_mod(u64 x) const {
        u64 d = x << 1;
        return (x >> 63 || d >= n_) ? d - n_ : d;
    }

    u64 n_;
    u64 inv_;
    u64 r2_;
};

// The first twelve primes decide primality for every n below 2^64.
constexpr u64 kBases[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};

bool is_prime(u64 n) {
    if (n < 2) {
        return false;
    }
    for (u64 p : kBases) {
        if (n % p == 0) {
            return n == p;
        }
    }
    u64 d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }
    const Montgomery m(n);
    const u64 one = m.one();
    const u64 minus_one = m.to(n - 1);
    for (u64 a : kBases) {
        u64 x = m.pow(m.to(a), d);
        if (x == one || x == minus_one) {
            continue;
        }
        bool witness = true;
        for (int i = 1; i < s && witness; ++i) {
            x = m.mul(x, x);
            witness = x != minus_one;
        }
        if (witness) {
            return false;
        }
    }
    return true;
}

template <typename T>
T read_le(const uint8_t *bytes) {
    T v = 0;
    for (unsigned i = 0; i < sizeof(T); ++i) {
        v |= static_cast<T>(bytes[i]) << (8 * i);
    }
    return v;
}

template <typename T>
void commit_le(T v) {
    uint8_t bytes[sizeof(T)];
    for (unsigned i = 0; i < sizeof(T); ++i) {
        bytes[i] = static_cast<uint8_t>(v >> (8 * i));
    }
    apogee_commit(bytes, sizeof(T));
}

// The public input as integers.
class Integers {
  public:
    Integers() : bytes_(apogee_public_input(&len_)) {}

    bool whole() const { return len_ % 8 == 0; }
    uint32_t size() const { return static_cast<uint32_t>(len_ / 8); }
    u64 operator[](uint32_t i) const { return read_le<u64>(bytes_ + 8 * i); }

  private:
    size_t len_ = 0;
    const uint8_t *bytes_;
};

const Integers integers;

}  // namespace

// External, so the optimizer keeps them globals rather than locals of `main`.
uint32_t k;
uint32_t primes;
uint8_t verdicts[2048];

// The journal, committed when `main` returns.
struct Journal {
    ~Journal() {
        commit_le(k);
        commit_le(primes);
        apogee_commit(verdicts, k);
    }
};
Journal journal;

int main() {
    if (!integers.whole()) {
        // Ends the run before any destructor, so nothing is committed.
        apogee_exit(2);
    }
    k = integers.size();
    for (uint32_t i = 0; i < k; ++i) {
        verdicts[i] = is_prime(integers[i]);
        primes += verdicts[i];
    }
    return 0;
}
