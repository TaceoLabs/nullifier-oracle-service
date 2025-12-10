// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title BabyJubJub Elliptic Curve Operations
/// @notice A helper contract for performing operations on the BabyJubJub elliptic curve. At the moment limited to point addition and curve membership check.
contract BabyJubJub {
    // BN254 scalar field = BabyJubJub base field
    uint256 public constant Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // BabyJubJub scalar field
    uint256 public constant R = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    // BabyJubJub curve parameters
    uint256 public constant A = 168700;
    uint256 public constant D = 168696;

    /// @notice Returns the bits of the characteristic of the scalarfield in big-endian order.
    function characteristic_bits() private pure returns (uint8[251] memory) {
        return [
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            1,
            0,
            0,
            1,
            1,
            1,
            0,
            0,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            0,
            1,
            1,
            0,
            1,
            1,
            0,
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            1,
            1,
            0,
            1,
            0,
            1,
            0,
            1,
            1,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            0,
            1,
            1,
            1,
            0,
            1,
            1,
            0,
            1,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            0,
            1,
            1,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            1,
            0,
            1,
            0,
            0,
            1,
            0,
            1,
            1,
            1,
            1,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            1
        ];
    }

    /// @notice Points are represented in Affine (x, y) coordinates.
    /// This method expects that the point is on the curve and in the correct subgroup. Additionally, the method expects that the coordinates are reduced mod Q. The outputs are also reduced mod Q.
    ///
    /// @param x1 The x-coordinate of the first point reduced mod Q
    /// @param y1 The y-coordinate of the first point reduced mod Q
    /// @param x2 the x-coordinate of the second point reduced mod Q
    /// @param y2 the y-coordinate of the second point reduced mod Q
    /// @return x3 the x-coordinate of the resulting point reduced mod Q
    /// @return y3 the y-coordinate of the resulting point reduced mod Q
    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) public pure returns (uint256 x3, uint256 y3) {
        // Handle identity cases
        if (x1 == 0 && y1 == 1) return (x2, y2);
        if (x2 == 0 && y2 == 1) return (x1, y1);

        uint256 x1x2 = mulmod(x1, x2, Q);
        uint256 y1y2 = mulmod(y1, y2, Q);
        uint256 dx1x2y1y2 = mulmod(D, mulmod(x1x2, y1y2, Q), Q);

        // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
        // SAFETY: can add without mod because Q is 254 bits
        uint256 x3Num = mulmod(x1, y2, Q) + mulmod(y1, x2, Q);
        // SAFETY: can add without mod because Q is 254 bits
        uint256 x3Den = 1 + dx1x2y1y2;

        // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
        uint256 y3Num = submod(y1y2, mulmod(A, x1x2, Q), Q);
        uint256 y3Den = submod(1, dx1x2y1y2, Q);

        x3 = mulmod(x3Num, modInverse(x3Den, Q), Q);
        y3 = mulmod(y3Num, modInverse(y3Den, Q), Q);
    }

    /// @notice Checks if a point in affine form is on curve: a*x^2 + y^2 = 1 + d*x^2*y^2 and its coordinates are in the basefield (smaller than Q).
    ///
    /// @param x The x-coordinate of the point
    /// @param y The y-coordinate of the point
    /// @return True if the point is on the BabyJubJub curve, false otherwise.
    function isOnCurve(uint256 x, uint256 y) public pure returns (bool) {
        if (x == 0 && y == 1) return true;
        if (x >= Q || y >= Q) return false;

        uint256 xx = mulmod(x, x, Q);
        uint256 yy = mulmod(y, y, Q);
        uint256 axx = mulmod(A, xx, Q);
        uint256 dxxyy = mulmod(D, mulmod(xx, yy, Q), Q);

        return addmod(axx, yy, Q) == addmod(1, dxxyy, Q);
    }

    /// @notice Checks if a point in affine form is in the sub-group with the same order as the scalarfield. This method assumes that the point is on the curve and the coordinates are reduced mod Q.
    ///
    /// @param x The x-coordinate of the point
    /// @param y The y-coordinate of the point
    /// @return True if the point is in the correct sub-subgroup, false otherwise.
    function isInCorrectSubgroupAssumingOnCurve(uint256 x, uint256 y) public pure returns (bool) {
        (uint256 x1, uint256 y1, uint256 z1) = _scalarMulInner(characteristic_bits(), 0, x, y);
        return x1 == 0 && y1 == z1 && y != 0;
    }

    /// @notice Computes the lagrange coefficients for the provided party IDs (starting at zero) and the threshold of the secret-sharing. We expect callsite to check that. Importantly, this method will always return an array with length numPeers, where lagrange coefficient of party ID is on index in the array (with zero for not participating nodes). We need this because the nodes will access this array with their partyID.
    /// This method will revert if either of those cases occurs:
    ///    * the length of ids != numPeers
    ///    * the ids are not distinct
    ///    * the ids are not unique
    ///
    ///  All of those checks must be enforced at callsite. It is considered a bug if this method revert for either of that reasons, therefore we also don't revert with a meaningful error.
    /// @param ids The party IDs (coefficients of the polynomial) of the participating parties (starting with ID 0)
    /// @param threshold The degree of the polynomial + 1
    /// @return lagrange The requested lagrange coefficients
    function computeLagrangeCoefficiants(uint256[] memory ids, uint256 threshold, uint256 numPeers)
        public
        pure
        returns (uint256[] memory lagrange)
    {
        // should be checked at callsite
        require(ids.length == threshold);
        // check that all ids are distinct and smaller than numPeers
        for (uint256 i = 0; i < threshold; ++i) {
            require(ids[i] < numPeers);
            for (uint256 j = i + 1; j < threshold; ++j) {
                require(ids[i] != ids[j]);
            }
        }
        lagrange = new uint256[](numPeers);
        for (uint256 i = 0; i < threshold; ++i) {
            uint256 num = 1;
            uint256 den = 1;
            uint256 currentId = ids[i] + 1;
            for (uint256 j = 0; j < threshold; ++j) {
                uint256 otherId = ids[j] + 1;
                if (currentId != otherId) {
                    num = mulmod(num, otherId, R);
                    den = mulmod(den, submod(otherId, currentId, R), R);
                }
            }
            lagrange[ids[i]] = mulmod(num, modInverse(den, R), R);
        }
        return lagrange;
    }

    /// @notice Computes xP, where x is an element of the scalarfield of BabyJubJub and P is an affine point on the BabyJubJub curve represented as x and y. This method reverts if scalar doesn't fit into BabyJubJub's scalarfield.
    ///
    /// This method expects that the point is on the curve and in the correct subgroup. Additionally, the method expects that the coordinates are reduced mod Q. The outputs are also reduced mod Q.
    ///
    /// @param scalar The scalar for the multiplication.
    /// @param x The x-coordinate of the affine point reduced mod Q.
    /// @param y The y-coordinate of the affine point reduced mod Q.
    /// @return The (x,y)-coordinates of xP
    function scalarMul(uint256 scalar, uint256 x, uint256 y) public pure returns (uint256, uint256) {
        require(scalar < R);
        if (scalar == 0) {
            return (0, 1);
        }
        (uint8[251] memory bits, uint256 highBit) = getBits(scalar);
        (uint256 x1, uint256 y1, uint256 z1) = _scalarMulInner(bits, highBit, x, y);
        return toAffine(x1, y1, z1);
    }

    /// @notice Internal helper function for scalar point multiplication. Performs the actual double-and-add scalar-multiplication. The highBit parameter allows to skip the leading zeroes.
    ///
    /// @param bits The scalar in big-endian order. *Attention* does NO alias checking as this is used internally.
    /// @param highBit The index of the "first" 1. Used to skip the leading zeroes.
    /// @param x The x-coordinate of the affine point reduced mod Q
    /// @param y The y-coordinate of the affine point reduced mod Q
    ///
    /// This method expects that the point is on the curve and in the correct subgroup. Additionally, the method expects that the coordinates are reduced mod Q. The outputs are also reduced mod Q.
    function _scalarMulInner(uint8[251] memory bits, uint256 highBit, uint256 x, uint256 y)
        private
        pure
        returns (uint256 x_res, uint256 y_res, uint256 z_res)
    {
        x_res = 0;
        y_res = 1;
        uint256 t_res = 0;
        z_res = 1;
        // skip leading zeros
        for (uint256 i = highBit; i < 251; ++i) {
            (x_res, y_res, t_res, z_res) = doubleTwistedEdwards(x_res, y_res, z_res);
            if (bits[i] == 1) {
                (x_res, y_res, t_res, z_res) = addProjective(x_res, y_res, t_res, z_res, x, y);
            }
        }
        return (x_res, y_res, z_res);
    }

    /// @notice A+B, where A and B are points on the BabyJubJub curve with the difference that A represented with projective coordinates and B with affine coordinates. Returns A+B in projective form.
    /// This method expects that the point is on the curve and in the correct subgroup. Additionally, the method expects that the coordinates are reduced mod Q. The outputs are also reduced mod Q.
    ///
    /// @param x1 The x-coordinate of the projective point reduced mod Q.
    /// @param y1 The y-coordinate of the projective point reduced mod Q.
    /// @param t1 The t-coordinate of the projective point reduced mod Q.
    /// @param z1 The z-coordinate of the projective point reduced mod Q.
    /// @param x2 The x-coordinate of the affine point reduced mod Q.
    /// @param y2 The y-coordinate of the affine point reduced mod Q.
    ///
    /// @return x_res The x-coordinate of A+B reduced mod Q.
    /// @return y_res The y-coordinate of A+B reduced mod Q.
    /// @return t_res The t-coordinate of A+B reduced mod Q.
    /// @return z_res The z-coordinate of A+B reduced mod Q.
    function addProjective(uint256 x1, uint256 y1, uint256 t1, uint256 z1, uint256 x2, uint256 y2)
        public
        pure
        returns (uint256 x_res, uint256 y_res, uint256 t_res, uint256 z_res)
    {
        // See "Twisted Edwards Curves Revisited"
        // Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson
        // 3.1 Unified Addition in E^e
        // Source: https://www.hyperelliptic.org/EFD/g1p/data/twisted/extended/addition/madd-2008-hwcd

        // A = X1*X2
        uint256 a = mulmod(x1, x2, Q);
        // B = Y1*Y2
        uint256 b = mulmod(y1, y2, Q);
        // C = T1*d*X2*Y2
        uint256 c = mulmod(mulmod(mulmod(D, t1, Q), x2, Q), y2, Q);
        // D = Z1
        uint256 d = z1;
        // E = (X1+Y1)*(X2+Y2)-A-B
        // SAFETY: can add without mod because Q is 254 bits and we expect point to be on the curve
        uint256 x1y1 = x1 + y1;
        // SAFETY: can add without mod because Q is 254 bits and we expect point to be on the curve
        uint256 x2y2 = x2 + y2;
        uint256 e = submod(submod(mulmod(x1y1, x2y2, Q), a, Q), b, Q);
        // F = D-C
        uint256 f = submod(d, c, Q);
        // G = D+C
        // SAFETY: can add without mod because Q is 254 bits and we expect point to be on the curve
        uint256 g = d + c;
        // H = B-a*A
        uint256 h = submod(b, mulmod(A, a, Q), Q);
        // X3 = E*F
        x_res = mulmod(e, f, Q);
        // Y3 = G*H
        y_res = mulmod(g, h, Q);
        // T3 = E*H
        t_res = mulmod(e, h, Q);
        // Z3 = F*G
        z_res = mulmod(f, g, Q);
    }

    /// @notice Converts a point P on the BabyJubJub curve in projective form to its affine form.
    /// This method will not check whether the points are on the curve nor if they are in the correct subgroup.
    ///
    /// @param x1 The x-coordinate of the projective point.
    /// @param y1 The y-coordinate of the projective point.
    /// @param z1 The z-coordinate of the projective point.
    ///
    /// @return x_res The x-coordinate of the affine point.
    /// @return y_res The y-coordinate of the affine point.
    function toAffine(uint256 x1, uint256 y1, uint256 z1) public pure returns (uint256 x_res, uint256 y_res) {
        // The projective point X, Y, Z is represented in the affine coordinates as X/Z, Y/Z.
        if (x1 == 0 && y1 == z1 && y1 != 1) {
            x_res = 0;
            y_res = 1;
        } else if (z1 == 1) {
            // If Z is one, the point is already normalized.
            x_res = x1;
            y_res = y1;
        } else {
            // Z is nonzero, so it must have an inverse in a field.
            uint256 z_inv = modInverse(z1, Q);
            x_res = mulmod(x1, z_inv, Q);
            y_res = mulmod(y1, z_inv, Q);
        }
    }

    ///Helper function for scalarMul(scalar, x, y). Bit-decomposes the provided value in big-endian form and returns the index of the highest bit (to skip leading zeros). Ignores highest five bits as this should only be used for scalar mul and the scalarfield only has 251 bits.
    function getBits(uint256 value) private pure returns (uint8[251] memory bits, uint256 highBit) {
        // set high bit to 256 -> cannot happen as we only go up to 251 bits and if all zeroes, will return 256.
        highBit = 256;
        value <<= 5;
        for (uint256 i = 0; i < 251; i++) {
            uint256 shift = 255 - i;
            bits[i] = uint8((value >> shift) & 1);
            if (bits[i] == 1 && highBit == 256) {
                highBit = i;
            }
        }
    }

    /// @notice Performs point-doubling of a BabyJubJub projective point in twisted-edwards form.
    /// This method expects that the point is on the curve and in the correct subgroup. Additionally, the method expects that the coordinates are reduced mod Q. The outputs are also reduced mod Q.
    ///
    /// @param x The x-coordinate of the projective point reduced mod Q.
    /// @param y The y-coordinate of the projective point reduced mod Q.
    /// @param z The z-coordinate of the projective point reduced mod Q.
    ///
    /// @param x3 The x-coordinate of the doubled point reduced mod Q.
    /// @param y3 The y-coordinate of the doubled point reduced mod Q.
    /// @param t3 The t-coordinate of the doubled point reduced mod Q.
    /// @param z3 The z-coordinate of the doubled point reduced mod Q.
    function doubleTwistedEdwards(uint256 x, uint256 y, uint256 z)
        public
        pure
        returns (uint256 x3, uint256 y3, uint256 t3, uint256 z3)
    {
        // See "Twisted Edwards Curves Revisited"
        // Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson
        // 3.3 Doubling in E^e
        // Source: https://www.hyperelliptic.org/EFD/g1p/data/twisted/extended/doubling/dbl-2008-hwcd

        // A = X1^2
        uint256 a = mulmod(x, x, Q);
        // B = Y1^2
        uint256 b = mulmod(y, y, Q);
        // C = 2 * Z1^2
        // SAFETY: can write the 2 * z without mod because Q is 254 bits and we expect a valid point here.
        uint256 c = mulmod(2 * z, z, Q);
        // D = a * A
        uint256 d = mulmod(a, A, Q);
        // E = (X1 + Y1)^2 - A - B
        // SAFETY: can add without mod because Q is 254 bits
        uint256 x1y1 = x + y;
        uint256 x1y12 = mulmod(x1y1, x1y1, Q);
        uint256 e = submod(submod(x1y12, a, Q), b, Q);
        // G = D + B
        // SAFETY: can add without mod because Q is 254 bits
        uint256 g = d + b;
        // F = G - C
        uint256 f = submod(g, c, Q);
        // H = D - B
        uint256 h = submod(d, b, Q);
        // X3 = E * F
        x3 = mulmod(e, f, Q);
        // Y3 = G * H
        y3 = mulmod(g, h, Q);
        // T3 = E * H
        t3 = mulmod(e, h, Q);
        // Z3 = F * G
        z3 = mulmod(f, g, Q);
    }

    function submod(uint256 a, uint256 b, uint256 m) private pure returns (uint256) {
        return (a >= b) ? (a - b) : m - (b - a);
    }

    function modInverse(uint256 a, uint256 P) private pure returns (uint256) {
        return expmod(a, P - 2, P);
    }

    function expmod(uint256 base, uint256 e, uint256 m) private pure returns (uint256 result) {
        result = 1;
        base = base % m;
        while (e > 0) {
            if (e & 1 == 1) {
                result = mulmod(result, base, m);
            }
            base = mulmod(base, base, m);
            e = e >> 1;
        }
    }
}
