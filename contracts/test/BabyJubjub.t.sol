// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/BabyJubjub.sol";

contract BabyJubjubTest is Test {
    BabyJubjub public babyJubjub;

    uint256 constant GEN_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 constant GEN_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Known values from circomlib/reference implementations
    // 2G (generator doubled) - from circomlib test vectors
    uint256 constant TWO_G_X = 17324563846726889236817837922625232543153115346355010501047597319863650987830;
    uint256 constant TWO_G_Y = 20022170825455209233733649024450576091402881793145646502279487074566492066831;

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
        assertEq(x, TWO_G_X);
        assertEq(y, TWO_G_Y);
    }

    function testThreeTimes() public {
        // 2*Generator by adding generator to itself
        (uint256 twoGx, uint256 twoGy) = babyJubjub.add(GEN_X, GEN_Y, GEN_X, GEN_Y);
        assertTrue(babyJubjub.isOnCurve(twoGx, twoGy));

        // Add generator + 2*generator to get 3*generator
        (uint256 threeGx, uint256 threeGy) = babyJubjub.add(GEN_X, GEN_Y, twoGx, twoGy);

        assertTrue(babyJubjub.isOnCurve(threeGx, threeGy));

        // Result should be different from both G and 2G
        assertTrue(threeGx != GEN_X || threeGy != GEN_Y);
        assertTrue(threeGx != twoGx || threeGy != twoGy);
    }
}
