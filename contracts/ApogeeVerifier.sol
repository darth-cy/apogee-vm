// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// The recursion tree's last check: a Groth16 proof that the tree's root
/// verifies — every shard of it, its transcript and its memory argument, over
/// a journal covering a whole base statement — and the one pairing check the
/// tree's folded openings come down to.
///
/// The circuit folds nothing. It binds each point the root's proof and journal
/// owe a pairing, and the scalar it derived for it, to the values this
/// contract holds, which does the two multi-scalar multiplications itself.
///
/// **The key is a development key**: its trapdoors come from a seed, so a
/// proof it checks is worth what that seed's secrecy is.
contract ApogeeVerifier {
    /// BN254's scalar field and base field.
    uint256 private constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 private constant Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    /// The Groth16 key — `alpha` in G1, `beta`, `gamma`, `delta`, `eta` in G2,
    /// the three public wires' points — at words 0 to 23; the ceremony's
    /// `[1]_2` and `[x]_2` at 24 and 28; the leaf program's and the node
    /// program's identities at 32 and 33. A G2 point is `x.c1, x.c0, y.c1,
    /// y.c0`, as the pairing precompile reads it.
    uint256[34] public key;
    /// How many points pair with `[1]_2`, and how many with `[x]_2`.
    uint256 public immutable sideA;
    uint256 public immutable sideB;

    constructor(uint256[34] memory key_, uint256 sideA_, uint256 sideB_) {
        key = key_;
        sideA = sideA_;
        sideB = sideB_;
    }

    /// Whether the base program ran to `exitStatus` over public values whose
    /// digest is `ioDigest`. `proof` is `A`, `B`, `C` and the bound wires'
    /// commitment `D`; `points` are side A's then side B's, three words each:
    /// `x`, `y` and the point's scalar. A point off the curve reverts.
    function verify(uint256 ioDigest, uint256 exitStatus, uint256[10] calldata proof, uint256[] calldata points)
        external
        view
        returns (bool)
    {
        require(points.length == 3 * (sideA + sideB), "points");
        uint256[34] memory k = key;
        (uint256 c, uint256 v) = bind([proof[8], proof[9], k[32], k[33], ioDigest, exitStatus], points);

        // The Groth16 check: e(A, B) = e(alpha, beta) e(IC, gamma) e(C, delta) e(D, eta).
        uint256[30] memory g;
        (g[12], g[13]) = mul(k[20], k[21], c);
        (c, v) = mul(k[22], k[23], v);
        (g[12], g[13]) = add(g[12], g[13], c, v);
        (g[12], g[13]) = add(g[12], g[13], k[18], k[19]);
        (g[0], g[1]) = (proof[0], negate(proof[1]));
        (g[6], g[7]) = (k[0], k[1]);
        (g[18], g[19]) = (proof[6], proof[7]);
        (g[24], g[25]) = (proof[8], proof[9]);
        for (uint256 i = 0; i < 4; i++) {
            g[2 + i] = proof[2 + i];
            g[8 + i] = k[2 + i];
            g[14 + i] = k[6 + i];
            g[20 + i] = k[10 + i];
            g[26 + i] = k[14 + i];
        }
        if (!pairing(g, 30)) return false;

        // The accumulator: e(A, [1]_2) = e(B, [x]_2).
        (g[0], g[1]) = msm(points, 0, sideA);
        (g[6], g[7]) = msm(points, sideA, sideA + sideB);
        g[7] = negate(g[7]);
        for (uint256 i = 0; i < 4; i++) {
            g[2 + i] = k[24 + i];
            g[8 + i] = k[28 + i];
        }
        return pairing(g, 12);
    }

    /// The binding challenge, and the bound wires' polynomial at it. The
    /// wires hold `head` past its first two words, which are `D`, and five
    /// values a point: its coordinates' low and high 128 bits, which are what
    /// the root's transcript absorbed, and its scalar. The challenge is the
    /// hash of all of it, so `D` is fixed before the challenge is.
    function bind(uint256[6] memory head, uint256[] calldata points) private view returns (uint256 c, uint256 v) {
        uint256[] memory bound = new uint256[](6 + 5 * (points.length / 3));
        for (uint256 i = 0; i < 6; i++) {
            bound[i] = head[i];
        }
        assembly {
            let out := add(bound, 0xe0)
            let p := points.offset
            for { let end := add(p, mul(points.length, 0x20)) } lt(p, end) { p := add(p, 0x60) } {
                let x := calldataload(p)
                let y := calldataload(add(p, 0x20))
                switch or(x, y)
                case 0 {
                    // Infinity is four sentinels no limb can be.
                    mstore(out, shl(128, 1))
                    mstore(add(out, 0x20), shl(128, 1))
                    mstore(add(out, 0x40), shl(128, 1))
                    mstore(add(out, 0x60), shl(128, 1))
                }
                default {
                    mstore(out, and(x, 0xffffffffffffffffffffffffffffffff))
                    mstore(add(out, 0x20), shr(128, x))
                    mstore(add(out, 0x40), and(y, 0xffffffffffffffffffffffffffffffff))
                    mstore(add(out, 0x60), shr(128, y))
                }
                mstore(add(out, 0x80), calldataload(add(p, 0x40)))
                out := add(out, 0xa0)
            }
            if iszero(staticcall(gas(), 2, add(bound, 0x20), sub(out, add(bound, 0x20)), 0, 0x20)) { revert(0, 0) }
            c := mod(mload(0), R)
            for { let at := add(bound, 0x60) } lt(at, out) { at := add(at, 0x20) } {
                v := mulmod(addmod(v, mload(at), R), c, R)
            }
        }
    }

    function negate(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : Q - y;
    }

    function mul(uint256 x, uint256 y, uint256 s) private view returns (uint256 rx, uint256 ry) {
        assembly {
            let m := mload(0x40)
            mstore(m, x)
            mstore(add(m, 0x20), y)
            mstore(add(m, 0x40), s)
            if iszero(staticcall(gas(), 7, m, 0x60, m, 0x40)) { revert(0, 0) }
            rx := mload(m)
            ry := mload(add(m, 0x20))
        }
    }

    function add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) private view returns (uint256 rx, uint256 ry) {
        assembly {
            let m := mload(0x40)
            mstore(m, x0)
            mstore(add(m, 0x20), y0)
            mstore(add(m, 0x40), x1)
            mstore(add(m, 0x60), y1)
            if iszero(staticcall(gas(), 6, m, 0x80, m, 0x40)) { revert(0, 0) }
            rx := mload(m)
            ry := mload(add(m, 0x20))
        }
    }

    /// The sum of each point of `from..to` times its scalar.
    function msm(uint256[] calldata points, uint256 from, uint256 to) private view returns (uint256 x, uint256 y) {
        assembly {
            // The sum at `m`; behind it a point and its scalar, then their product.
            let m := mload(0x40)
            mstore(m, 0)
            mstore(add(m, 0x20), 0)
            for { let i := from } lt(i, to) { i := add(i, 1) } {
                calldatacopy(add(m, 0x40), add(points.offset, mul(i, 0x60)), 0x60)
                if iszero(staticcall(gas(), 7, add(m, 0x40), 0x60, add(m, 0x40), 0x40)) { revert(0, 0) }
                if iszero(staticcall(gas(), 6, m, 0x80, m, 0x40)) { revert(0, 0) }
            }
            x := mload(m)
            y := mload(add(m, 0x20))
        }
    }

    /// Whether the product of the pairings of `words / 6` pairs is 1.
    function pairing(uint256[30] memory pairs, uint256 words) private view returns (bool ok) {
        assembly {
            if iszero(staticcall(gas(), 8, pairs, mul(words, 0x20), 0, 0x20)) { revert(0, 0) }
            ok := mload(0)
        }
    }
}
