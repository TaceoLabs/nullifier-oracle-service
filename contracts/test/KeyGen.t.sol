// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract KeyGenTest is Test {
    KeyGen public gen;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);

    function setUp() public {
        address [] memory participants = new address[](3);
        participants[0] = alice;
        participants[1] = bob;
        participants[2] = carol;

        bytes memory peerKeys = hex"deadbeef"; // dummy peer keys

        gen = new KeyGen(participants, 1, peerKeys);
    }

    function testInitKeyGenEmitsRound1() public {
        bytes memory ecdsaPubKey = hex"1234";

        vm.expectEmit(true, true, true, true);
        emit KeyGen.SecretGenRound1(1, 1);

        gen.initKeyGen(1, ecdsaPubKey);
    }

    function testRound1ThenRound2Flow() public {
        uint128 sessionId = 1;
        bytes memory pubKey = hex"1111";
        gen.initKeyGen(sessionId, pubKey);

        // Each participant submits round1
        vm.startPrank(alice);
        gen.addRound1Contribution(sessionId, hex"aaa1");
        vm.stopPrank();

        vm.startPrank(bob);
        gen.addRound1Contribution(sessionId, hex"aaa2");
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit KeyGen.SecretGenRound2(sessionId, hex"deadbeef");

        vm.startPrank(carol);
        gen.addRound1Contribution(sessionId, hex"aaa3");
        vm.stopPrank();
    }

    function testRound2ThenFinalizeFlow() public {
        uint128 sessionId = 2;
        bytes memory pubKey = hex"2222";
        gen.initKeyGen(sessionId, pubKey);

        // All round1 first
        vm.prank(alice); gen.addRound1Contribution(sessionId, hex"aaa1");
        vm.prank(bob);   gen.addRound1Contribution(sessionId, hex"aaa2");
        vm.prank(carol); gen.addRound1Contribution(sessionId, hex"aaa3");

        // Two round2 contributions already submitted
        vm.prank(alice); gen.addRound2Contribution(sessionId, hex"bbb1");
        vm.prank(bob);   gen.addRound2Contribution(sessionId, hex"bbb2");

        // Build expected array exactly as contract will have it
        KeyGen.RpSecretGenCiphertexts[] memory expected = 
            new KeyGen.RpSecretGenCiphertexts[](3);

        expected[0] = KeyGen.RpSecretGenCiphertexts({ data: hex"bbb1" });
        expected[1] = KeyGen.RpSecretGenCiphertexts({ data: hex"bbb2" });
        expected[2] = KeyGen.RpSecretGenCiphertexts({ data: hex"bbb3" });

        // Expect the Finalize event — check indexed rpId (topic1) and full data (last boolean = true)
        vm.expectEmit(true, false, false, true);
        emit KeyGen.SecretGenFinalize(sessionId, pubKey, expected);

        // Trigger final submission (this call should emit the Finalize event)
        vm.prank(carol);
        gen.addRound2Contribution(sessionId, hex"bbb3");
    }
}
