//! The artifact's wire form, `docs/spec/gkr.md` §4.1: `postcard` over a
//! tuple per type, hand-written, like every serde impl in this workspace.
//!
//! The workspace's serde has no `alloc` feature, so `Vec` and `String` have no
//! impls of their own. Writing needs none — a slice and a `str` serialize in
//! `core` — and reading needs exactly two visitors, [`Seq`] and [`Name`]; every
//! type then reads as a tuple of things that already deserialize and is
//! rebuilt, shape-checked, from it. An enum is a fixed tuple with a tag, so no
//! serde enum machinery is involved.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, Error as _, SeqAccess, Visitor};
use serde::{Serialize, Serializer};

use field::Fr;

use crate::{
    CachedEntry, CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, LookupExpr, Padding,
    PolyAddress, ProducingEntry, Relation, ScratchSlot, VirtualKind, FORMAT_VERSION,
};

pub(crate) fn to_bytes(a: &CircuitArtifact) -> Vec<u8> {
    postcard::to_extend(a, Vec::new())
        .unwrap_or_else(|e| panic!("encoding a circuit artifact into memory failed: {e}"))
}

pub(crate) fn from_bytes(bytes: &[u8]) -> Result<CircuitArtifact, String> {
    // The layout after the first word is the version's, so no other version is
    // decoded at all.
    let (version, _) = postcard::take_from_bytes::<u32>(bytes)
        .map_err(|e| format!("malformed circuit artifact: {e}"))?;
    if version != FORMAT_VERSION {
        return Err(format!(
            "malformed circuit artifact: format version {version}, but this reader reads \
             {FORMAT_VERSION} only"
        ));
    }
    let a: CircuitArtifact =
        postcard::from_bytes(bytes).map_err(|e| format!("malformed circuit artifact: {e}"))?;
    // `postcard` reads overlong varints and ignores trailing bytes; one
    // artifact is one byte string.
    if to_bytes(&a) != bytes {
        return Err(String::from(
            "malformed circuit artifact: not the canonical encoding of what it decodes to",
        ));
    }
    Ok(a)
}

// ---------------------------------------------------------------------------
// The two visitors
// ---------------------------------------------------------------------------

/// A `Vec<T>` read back from a sequence.
struct Seq<T>(Vec<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Seq<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Seq<T>, D::Error> {
        d.deserialize_seq(SeqVisitor(PhantomData))
    }
}

struct SeqVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for SeqVisitor<T> {
    type Value = Seq<T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a sequence")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Seq<T>, A::Error> {
        // The declared length is untrusted, so it reserves nothing: the vector
        // grows only as elements actually decode.
        let mut out = Vec::new();
        while let Some(x) = seq.next_element()? {
            out.push(x);
        }
        Ok(Seq(out))
    }
}

/// A `String` read back from a `str`.
struct Name(String);

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Name, D::Error> {
        d.deserialize_str(NameVisitor)
    }
}

struct NameVisitor;

impl Visitor<'_> for NameVisitor {
    type Value = Name;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a name")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Name, E> {
        Ok(Name(String::from(v)))
    }
}

/// A `&[String]` written as a sequence of `str`.
struct Names<'a>(&'a [String]);

impl Serialize for Names<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter().map(String::as_str))
    }
}

// ---------------------------------------------------------------------------
// Addresses and coefficients
// ---------------------------------------------------------------------------

impl Serialize for VirtualKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            VirtualKind::RowIndex => 0u32.serialize(s),
            VirtualKind::RamLive => 1u32.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for VirtualKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<VirtualKind, D::Error> {
        match u32::deserialize(d)? {
            0 => Ok(VirtualKind::RowIndex),
            1 => Ok(VirtualKind::RamLive),
            _ => Err(D::Error::custom("unknown virtual table kind")),
        }
    }
}

impl Serialize for PolyAddress {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (tag, a, b): (u8, u32, u32) = match *self {
            PolyAddress::Memory(i) => (0, i, 0),
            PolyAddress::Witness(i) => (1, i, 0),
            PolyAddress::Setup(i) => (2, i, 0),
            PolyAddress::Virtual(VirtualKind::RowIndex) => (3, 0, 0),
            PolyAddress::Virtual(VirtualKind::RamLive) => (3, 1, 0),
            PolyAddress::Inner { layer, offset } => (4, layer, offset),
            PolyAddress::Scratch(i) => (5, i, 0),
            PolyAddress::Cached { layer, offset } => (6, layer, offset),
        };
        (tag, a, b).serialize(s)
    }
}

impl<'de> Deserialize<'de> for PolyAddress {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<PolyAddress, D::Error> {
        match <(u8, u32, u32)>::deserialize(d)? {
            (0, i, 0) => Ok(PolyAddress::Memory(i)),
            (1, i, 0) => Ok(PolyAddress::Witness(i)),
            (2, i, 0) => Ok(PolyAddress::Setup(i)),
            (3, 0, 0) => Ok(PolyAddress::Virtual(VirtualKind::RowIndex)),
            (3, 1, 0) => Ok(PolyAddress::Virtual(VirtualKind::RamLive)),
            (4, layer, offset) => Ok(PolyAddress::Inner { layer, offset }),
            (5, i, 0) => Ok(PolyAddress::Scratch(i)),
            (6, layer, offset) => Ok(PolyAddress::Cached { layer, offset }),
            _ => Err(D::Error::custom(
                "malformed poly address: unknown tag, or a nonzero unused field",
            )),
        }
    }
}

impl Serialize for Coeff {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match *self {
            Coeff::Literal(v) => (0u8, 0u32, v).serialize(s),
            Coeff::Challenge(slot) => (1u8, slot, Fr::ZERO).serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Coeff {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Coeff, D::Error> {
        match <(u8, u32, Fr)>::deserialize(d)? {
            (0, 0, v) => Ok(Coeff::Literal(v)),
            (1, slot, v) if v == Fr::ZERO => Ok(Coeff::Challenge(slot)),
            _ => Err(D::Error::custom(
                "malformed coefficient: unknown tag, or a nonzero unused field",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

impl Serialize for GateDef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (tag, split): (u8, u32) = match self {
            GateDef::Linear { .. } => (0, 0),
            GateDef::Product { .. } => (1, 0),
            GateDef::MaskIntoIdentity { .. } => (2, 0),
            GateDef::AffineProduct { left, .. } => (3, left.len() as u32),
            GateDef::TreeProduct { .. } => (4, 0),
            GateDef::Quadratic { linear, .. } => (5, linear.len() as u32),
        };
        (
            tag,
            split,
            self.coefficients().as_slice(),
            self.operands().as_slice(),
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for GateDef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<GateDef, D::Error> {
        let (tag, split, Seq(c), Seq(o)) =
            <(u8, u32, Seq<Coeff>, Seq<PolyAddress>)>::deserialize(d)?;
        let shape = |ok: bool| {
            if ok {
                Ok(())
            } else {
                Err(D::Error::custom(
                    "malformed gate: a coefficient or operand count its shape does not have",
                ))
            }
        };
        match tag {
            0 => {
                shape(split == 0 && c.len() == o.len() + 1)?;
                Ok(GateDef::Linear {
                    terms: c.iter().copied().zip(o.iter().copied()).collect(),
                    constant: c[o.len()],
                })
            }
            1 => {
                shape(split == 0 && c.len() == 1 && o.len() == 2)?;
                Ok(GateDef::Product {
                    coeff: c[0],
                    left: o[0],
                    right: o[1],
                })
            }
            2 => {
                shape(split == 0 && c.is_empty() && o.len() == 2)?;
                Ok(GateDef::MaskIntoIdentity {
                    input: o[0],
                    mask: o[1],
                })
            }
            3 => {
                let t = split as usize;
                shape(t <= o.len() && c.len() == o.len() + 2)?;
                Ok(GateDef::AffineProduct {
                    left: c[..t].iter().copied().zip(o[..t].iter().copied()).collect(),
                    left_constant: c[t],
                    right: c[t + 1..]
                        .iter()
                        .copied()
                        .zip(o[t..].iter().copied())
                        .collect(),
                    right_constant: c[c.len() - 1],
                })
            }
            4 => {
                shape(split == 0 && c.is_empty() && o.len() == 1)?;
                Ok(GateDef::TreeProduct { input: o[0] })
            }
            5 => {
                // `t` linear operands, then two per product, one coefficient
                // each, after the constant. `t <= o.len()` is checked first,
                // so the subtractions below cannot wrap.
                let t = split as usize;
                shape(
                    t <= o.len()
                        && (o.len() - t).is_multiple_of(2)
                        && c.len() == 1 + t + (o.len() - t) / 2,
                )?;
                Ok(GateDef::Quadratic {
                    constant: c[0],
                    linear: c[1..=t]
                        .iter()
                        .copied()
                        .zip(o[..t].iter().copied())
                        .collect(),
                    products: c[1 + t..]
                        .iter()
                        .zip(o[t..].chunks_exact(2))
                        .map(|(b, yz)| (*b, yz[0], yz[1]))
                        .collect(),
                })
            }
            _ => Err(D::Error::custom("malformed gate: unknown shape tag")),
        }
    }
}

// ---------------------------------------------------------------------------
// The structures
// ---------------------------------------------------------------------------

impl Serialize for CachedEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.name.as_str(), self.address, &self.gate).serialize(s)
    }
}

impl<'de> Deserialize<'de> for CachedEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<CachedEntry, D::Error> {
        let (Name(name), address, gate) = <(Name, PolyAddress, GateDef)>::deserialize(d)?;
        Ok(CachedEntry {
            name,
            address,
            gate,
        })
    }
}

impl Serialize for ProducingEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.relation, self.output, &self.gate).serialize(s)
    }
}

impl<'de> Deserialize<'de> for ProducingEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<ProducingEntry, D::Error> {
        let (relation, output, gate) = <(u32, PolyAddress, GateDef)>::deserialize(d)?;
        Ok(ProducingEntry {
            relation,
            output,
            gate,
        })
    }
}

impl Serialize for EnforcingEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.relation, &self.gate).serialize(s)
    }
}

impl<'de> Deserialize<'de> for EnforcingEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<EnforcingEntry, D::Error> {
        let (relation, gate) = <(u32, GateDef)>::deserialize(d)?;
        Ok(EnforcingEntry { relation, gate })
    }
}

impl Serialize for LayerSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (
            self.halving,
            self.num_vars,
            self.width,
            self.cached.as_slice(),
            self.producing.as_slice(),
            self.enforcing.as_slice(),
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for LayerSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<LayerSpec, D::Error> {
        let (halving, num_vars, width, Seq(cached), Seq(producing), Seq(enforcing)) =
            <(
                bool,
                u32,
                u32,
                Seq<CachedEntry>,
                Seq<ProducingEntry>,
                Seq<EnforcingEntry>,
            )>::deserialize(d)?;
        Ok(LayerSpec {
            halving,
            num_vars,
            width,
            cached,
            producing,
            enforcing,
        })
    }
}

impl Serialize for Relation {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.name.as_str(), self.output, &self.gate).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Relation {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Relation, D::Error> {
        let (Name(name), output, gate) = <(Name, Option<u32>, GateDef)>::deserialize(d)?;
        Ok(Relation { name, output, gate })
    }
}

impl Serialize for LookupExpr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (
            self.name.as_str(),
            self.channel,
            self.selector,
            self.tuple.as_slice(),
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for LookupExpr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<LookupExpr, D::Error> {
        let (Name(name), channel, selector, Seq(tuple)) =
            <(Name, u32, PolyAddress, Seq<GateDef>)>::deserialize(d)?;
        Ok(LookupExpr {
            name,
            channel,
            selector,
            tuple,
        })
    }
}

impl Serialize for ScratchSlot {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.name.as_str(), self.address).serialize(s)
    }
}

impl<'de> Deserialize<'de> for ScratchSlot {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<ScratchSlot, D::Error> {
        let (Name(name), address) = <(Name, PolyAddress)>::deserialize(d)?;
        Ok(ScratchSlot { name, address })
    }
}

/// A `&[(VirtualKind, String)]` written as a sequence of `(kind, str)`.
struct Virtuals<'a>(&'a [(VirtualKind, String)]);

impl Serialize for Virtuals<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter().map(|(kind, name)| (*kind, name.as_str())))
    }
}

impl Serialize for CircuitArtifact {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (
            self.format_version,
            self.coefficient_encoding,
            self.trace_vars,
            Names(&self.memory),
            Names(&self.witness),
            Names(&self.setup),
            Virtuals(&self.virtuals),
            self.layers.as_slice(),
            self.relations.as_slice(),
            self.lookups.as_slice(),
            self.scratch.as_slice(),
            self.outputs.as_slice(),
            (self.padding.row.as_slice(), self.padding.zero_row_valid),
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for CircuitArtifact {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<CircuitArtifact, D::Error> {
        #[allow(clippy::type_complexity)]
        let (
            format_version,
            coefficient_encoding,
            trace_vars,
            Seq(memory),
            Seq(witness),
            Seq(setup),
            Seq(virtuals),
            Seq(layers),
            Seq(relations),
            Seq(lookups),
            Seq(scratch),
            Seq(outputs),
            (Seq(row), zero_row_valid),
        ) = <(
            u32,
            u32,
            u32,
            Seq<Name>,
            Seq<Name>,
            Seq<Name>,
            Seq<(VirtualKind, Name)>,
            Seq<LayerSpec>,
            Seq<Relation>,
            Seq<LookupExpr>,
            Seq<ScratchSlot>,
            Seq<PolyAddress>,
            (Seq<Fr>, bool),
        )>::deserialize(d)?;
        let names = |v: Vec<Name>| v.into_iter().map(|Name(n)| n).collect();
        Ok(CircuitArtifact {
            format_version,
            coefficient_encoding,
            trace_vars,
            memory: names(memory),
            witness: names(witness),
            setup: names(setup),
            virtuals: virtuals.into_iter().map(|(k, Name(n))| (k, n)).collect(),
            layers,
            relations,
            lookups,
            scratch,
            outputs,
            padding: Padding {
                row,
                zero_row_valid,
            },
        })
    }
}
