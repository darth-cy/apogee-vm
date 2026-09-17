//! The byte layouts of `docs/spec/shard-proof.md` §9: little-endian integers,
//! canonical `Fr`s, opaque 64-byte `G1`s, `u32`-length-prefixed byte strings
//! and lists.
//!
//! Public because the prover's phase snapshots (`docs/spec/shard-proof.md`
//! §10) are written in the same primitives, and one set of them is enough.
//!
//! The reader is total: every refusal is an `Err`, and it reserves nothing an
//! untrusted count asks for — a count is refused unless the bytes left could
//! hold that many items of the smallest size an item can have.

use alloc::vec::Vec;

use field::Fr;

/// An encoder: bytes appended in order.
pub struct Writer {
    pub bytes: Vec<u8>,
}

// A `Default` would be a second name for `new` with no caller.
#[allow(clippy::new_without_default)]
impl Writer {
    pub fn new() -> Writer {
        Writer { bytes: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) {
        self.bytes.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    pub fn fr(&mut self, v: &Fr) {
        self.bytes.extend_from_slice(&v.to_bytes());
    }

    /// Bytes with no length: a fixed-size field.
    pub fn raw(&mut self, b: &[u8]) {
        self.bytes.extend_from_slice(b);
    }

    /// A list's or a byte string's `u32` count. Panics above `u32::MAX`, which
    /// no value this crate writes can reach.
    pub fn count(&mut self, n: usize) {
        self.u32(u32::try_from(n).expect("a wire count fits a u32"));
    }

    /// A `u32` length, then the bytes.
    pub fn bytes(&mut self, b: &[u8]) {
        self.count(b.len());
        self.raw(b);
    }
}

/// A decoder over one byte string.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

pub type Read<T> = Result<T, &'static str>;

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, at: 0 }
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Read<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("truncated")?;
        let out = self.bytes.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        Ok(out)
    }

    fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    pub fn u8(&mut self) -> Read<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Read<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Read<u64> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    /// A canonical field element; a value at or above the modulus is refused,
    /// never reduced.
    pub fn fr(&mut self) -> Read<Fr> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Fr::from_bytes(&b).ok_or("a field element is not canonical")
    }

    /// A 64-byte `G1` encoding, not validated: that is the curve's decoder's.
    pub fn g1(&mut self) -> Read<[u8; 64]> {
        let mut b = [0u8; 64];
        b.copy_from_slice(self.take(64)?);
        Ok(b)
    }

    /// A count of items of at least `item_bytes` bytes each, refused unless
    /// the bytes left could hold that many.
    pub fn count(&mut self, item_bytes: usize) -> Read<usize> {
        let n = self.u32()? as usize;
        if n.checked_mul(item_bytes.max(1))
            .is_none_or(|need| need > self.left())
        {
            return Err("a count is longer than the bytes left");
        }
        Ok(n)
    }

    /// A `u32`-length-prefixed byte string.
    pub fn bytes(&mut self) -> Read<&'a [u8]> {
        let n = self.count(1)?;
        self.take(n)
    }

    /// A list of `u32`s.
    pub fn u32s(&mut self) -> Read<Vec<u32>> {
        let n = self.count(4)?;
        (0..n).map(|_| self.u32()).collect()
    }

    /// A list of field elements.
    pub fn frs(&mut self) -> Read<Vec<Fr>> {
        let n = self.count(32)?;
        (0..n).map(|_| self.fr()).collect()
    }

    /// A list of `G1` encodings.
    pub fn g1s(&mut self) -> Read<Vec<[u8; 64]>> {
        let n = self.count(64)?;
        (0..n).map(|_| self.g1()).collect()
    }

    /// Refuse bytes after the value.
    pub fn finish(&self) -> Read<()> {
        match self.left() {
            0 => Ok(()),
            _ => Err("bytes follow the value"),
        }
    }
}

impl Writer {
    pub fn u32s(&mut self, xs: &[u32]) {
        self.count(xs.len());
        for x in xs {
            self.u32(*x);
        }
    }

    pub fn frs(&mut self, xs: &[Fr]) {
        self.count(xs.len());
        for x in xs {
            self.fr(x);
        }
    }

    pub fn g1s(&mut self, xs: &[[u8; 64]]) {
        self.count(xs.len());
        for x in xs {
            self.raw(x);
        }
    }
}
