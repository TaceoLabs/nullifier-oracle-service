// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title BabyJubJub Elliptic Curve Operations
/// @notice A helper contract for performing operations on the BabyJubJub elliptic curve. At the moment limited to point addition and curve membership check.
contract BabyJubJub {
    // BN254 scalar field = BabyJubJub base field
    uint256 public constant Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // BabyJubJub curve parameters
    uint256 public constant A = 168700;
    uint256 public constant D = 168696;

    /// @notice Points are represented in Affine (x, y) coordinates. A prerequisite is that both points are on the curve. This can be checked with isOnCurve function.
    /// @param x1 The x-coordinate of the first point
    /// @param y1 The y-coordinate of the first point
    /// @param x2 the x-coordinate of the second point
    /// @param y2 the y-coordinate of the second point
    /// @return x3 the x-coordinate of the resulting point
    /// @return y3 the y-coordinate of the resulting point
    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) public pure returns (uint256 x3, uint256 y3) {
        // Handle identity cases
        if (x1 == 0 && y1 == 1) return (x2, y2);
        if (x2 == 0 && y2 == 1) return (x1, y1);

        uint256 x1x2 = mulmod(x1, x2, Q);
        uint256 y1y2 = mulmod(y1, y2, Q);
        uint256 dx1x2y1y2 = mulmod(D, mulmod(x1x2, y1y2, Q), Q);

        // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
        uint256 x3Num = addmod(mulmod(x1, y2, Q), mulmod(y1, x2, Q), Q);
        uint256 x3Den = addmod(1, dx1x2y1y2, Q);

        // y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
        uint256 y3Num = submod(y1y2, mulmod(A, x1x2, Q), Q);
        uint256 y3Den = submod(1, dx1x2y1y2, Q);

        x3 = mulmod(x3Num, modInverse(x3Den), Q);
        y3 = mulmod(y3Num, modInverse(y3Den), Q);
    }

    /// @notice Check if point is on curve: a*x^2 + y^2 = 1 + d*x^2*y^2
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

    function submod(uint256 a, uint256 b, uint256 m) private pure returns (uint256) {
        return (a >= b) ? (a - b) : m - (b - a);
    }

    function modInverse(uint256 a) private pure returns (uint256) {
        return expmod(a, Q - 2, Q);
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
