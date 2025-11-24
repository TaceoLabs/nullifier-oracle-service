// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../src/Groth16VerifierKeyGen13.sol";
import {Types} from "../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {aliceRound2Contribution, bobRound2Contribution, carolRound2Contribution} from "./RpRegistry.t.sol";

/**
 *
 *
 * @title RpRegistryV2Mock
 *
 *
 * @notice Mock V2 implementation for testing upgrades
 *
 *
 */
contract RpRegistryV2Mock is RpRegistry {
    // Add a new state variable to test storage layout preservation

    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract RpRegistryUpgradeTest is Test {
    using Types for Types.BabyJubJubElement;

    uint256 public constant THRESHOLD = 2;
    uint256 public constant MAX_PEERS = 3;

    RpRegistry public rpRegistry;
    BabyJubJub public accumulator;
    Groth16VerifierKeyGen13 public verifierKeyGen;
    ERC1967Proxy public proxy;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);
    address taceoAdmin = address(0x4);

    uint256 privateKeyAlice = 0x3bc78294cae1fe9e441b3c6a97fc4f7844b016ec9deb28787b2ec8a63812834;
    uint256 privateKeyBob = 0xb5aaa322223b7015e0ab2690ddad24a3e553bbea711dcdd0f30e2ea2ca6fdc;
    uint256 privateKeyCarol = 0x379ca5cd47470da7bcefb954d86cf4d409d25dd2d65c4e2280aa2bcfc4f1f4d;

    Types.BabyJubJubElement publicKeyAlice = Types.BabyJubJubElement({
        x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
        y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
    });

    Types.BabyJubJubElement publicKeyBob = Types.BabyJubJubElement({
        x: 0x35ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
        y: 0xa9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368
    });

    Types.BabyJubJubElement publicKeyCarol = Types.BabyJubJubElement({
        x: 0x3bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
        y: 0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37
    });

    uint256 commCoeffsAlice = 0x6fc7aa21491e4b6878290f06958efa50de23e427d7b4f17b49b8da6191ad41f;

    uint256 commCoeffsBob = 0x84292791fef8a2de0d2617e877fe8769bf81df0848ac54c1a02ea84289a2d0c;

    uint256 commCoeffsCarol = 0x1cf1e6e4f9f4aa29430a9b08d51584f3194571178c0dde3f8d2edfef28cc2dac;

    Types.BabyJubJubElement commShareAlice = Types.BabyJubJubElement({
        x: 0x1713acbc11e0f0fdaebbcedceed52e57abf30f2b8c435f013ce0756e4377f097,
        y: 0x28145c47c630ed060a7f10ea3d727b9bc0d249796172c2bcb58b836d1e3d4bd4
    });

    Types.BabyJubJubElement commShareBob = Types.BabyJubJubElement({
        x: 0x23c80416edd379bde086351fc0169cfa69adff2c0f0ab04ca9622b099e597489,
        y: 0x130cf58590a10bdf2b75d0533cb5911d0fe86cfd27187eb77e42cc5719cb7124
    });

    Types.BabyJubJubElement commShareCarol = Types.BabyJubJubElement({
        x: 0x278da9b32323bf8afa691001d5d20e2c5f96db21b18a2e22f28e5d5742992232,
        y: 0x2cf9744859cdd3d29fd15057b7e3ebd2197a1af0bae650e5e40bfcd437dfd299
    });

    Types.EcDsaPubkeyCompressed ecdsaPubKey = Types.EcDsaPubkeyCompressed({x: bytes32(0), yParity: 2});

    function setUp() public {
        accumulator = new BabyJubJub();
        verifierKeyGen = new Groth16VerifierKeyGen13();
        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData =
            abi.encodeWithSelector(RpRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator);
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        rpRegistry = RpRegistry(address(proxy));

        // register participants for runs later
        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;

        //TODO: Set these smart accounts when writing tests later...
        address[] memory smartAccounts = new address[](peerAddresses.length);

        rpRegistry.registerOprfPeers(peerAddresses, smartAccounts);
    }

    function testUpgrade() public {
        // start key generation process for rpId 42
        // see testE2E in RpRegistry.t.sol for the full process
        uint128 rpId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(rpId, THRESHOLD);
        rpRegistry.initKeyGen(rpId, ecdsaPubKey);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        rpRegistry.addRound1Contribution(
            rpId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        rpRegistry.addRound1Contribution(
            rpId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound2(rpId);
        rpRegistry.addRound1Contribution(
            rpId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        rpRegistry.addRound2Contribution(rpId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        rpRegistry.addRound2Contribution(rpId, aliceRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound3(rpId);
        vm.prank(carol);
        rpRegistry.addRound2Contribution(rpId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        rpRegistry.addRound3Contribution(rpId);
        vm.stopPrank();

        vm.prank(bob);
        rpRegistry.addRound3Contribution(rpId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenFinalize(rpId);
        vm.prank(carol);
        rpRegistry.addRound3Contribution(rpId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        Types.RpMaterial memory material = rpRegistry.getRpMaterial(rpId);
        assertEq(material.nullifierKey.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738);
        assertEq(material.nullifierKey.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329);
        assertEq(material.ecdsaKey.x, bytes32(0));
        assertEq(material.ecdsaKey.yParity, 2);

        // Now perform upgrade
        RpRegistryV2Mock implementationV2 = new RpRegistryV2Mock();
        // upgrade as owner
        RpRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
        // Wrap proxy with V2 interface
        RpRegistryV2Mock rpRegistryV2 = RpRegistryV2Mock(address(proxy));

        // Verify storage was preserved
        Types.RpMaterial memory materialv2 = rpRegistryV2.getRpMaterial(rpId);
        assertEq(
            materialv2.nullifierKey.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738
        );
        assertEq(
            materialv2.nullifierKey.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329
        );
        assertEq(materialv2.ecdsaKey.x, bytes32(0));
        assertEq(materialv2.ecdsaKey.yParity, 2);

        // Verify new functionality works
        assertEq(rpRegistryV2.version(), "V2");
        rpRegistryV2.setNewFeature(42);
        assertEq(rpRegistryV2.newFeature(), 42);

        // Verify old functionality still works
        uint128 newRpId = 43;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(newRpId, 2);
        rpRegistry.initKeyGen(newRpId, ecdsaPubKey);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        rpRegistry.addRound1Contribution(
            newRpId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        rpRegistry.addRound1Contribution(
            newRpId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound2(newRpId);
        rpRegistry.addRound1Contribution(
            newRpId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        rpRegistry.addRound2Contribution(newRpId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        rpRegistry.addRound2Contribution(newRpId, aliceRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound3(newRpId);
        vm.prank(carol);
        rpRegistry.addRound2Contribution(newRpId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        rpRegistry.addRound3Contribution(newRpId);
        vm.stopPrank();

        vm.prank(bob);
        rpRegistry.addRound3Contribution(newRpId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenFinalize(newRpId);
        vm.prank(carol);
        rpRegistry.addRound3Contribution(newRpId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        Types.RpMaterial memory materialnew = rpRegistry.getRpMaterial(newRpId);
        assertEq(
            materialnew.nullifierKey.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738
        );
        assertEq(
            materialnew.nullifierKey.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329
        );
        assertEq(materialnew.ecdsaKey.x, bytes32(0));
        assertEq(materialnew.ecdsaKey.yParity, 2);
    }
}

