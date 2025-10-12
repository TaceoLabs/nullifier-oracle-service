// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/BabyJubjub.sol";

contract BabyJubjubTest is Test {
    BabyJubjub public babyJubjub;

    uint256 constant GEN_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 constant GEN_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    function setUp() public {
        babyJubjub = new BabyJubjub();
    }

    function testIdentityPoint() public {
        assertTrue(babyJubjub.isOnCurve(0, 1));
    }

    function testGeneratorOnCurve() public {
        assertTrue(babyJubjub.isOnCurve(GEN_X, GEN_Y));
    }

    function testAddIdentity() public {
        (uint256 x, uint256 y) = babyJubjub.add(0, 1, GEN_X, GEN_Y);
        assertEq(x, GEN_X);
        assertEq(y, GEN_Y);
    }

    function testAddGeneratorToItself() public {
        (uint256 x, uint256 y) = babyJubjub.add(GEN_X, GEN_Y, GEN_X, GEN_Y);
        assertTrue(babyJubjub.isOnCurve(x, y));
    }

    function testThreeTimes() public {
        // 2*Generator by adding generator to itself
        (uint256 2Gx, uint256 2Gy) = babyJubjub.add(GEN_X, GEN_Y, GEN_X, GEN_Y);
        assertTrue(babyJubjub.isOnCurve(2Gx, 2Gy));

        // Add generator + 2*generator to get 3*generator
        (uint256 3Gx, uint256 3Gy) = babyJubjub.add(GEN_X, GEN_Y, 2Gx, 2Gy);

        assertTrue(babyJubjub.isOnCurve(3Gx, 3Gy));

        // Result should be different from both G and 2G
        assertTrue(3Gx != GEN_X || 3Gy != GEN_Y);
        assertTrue(3Gx != 2Gx || 3Gy != 2Gy);
    }
}
