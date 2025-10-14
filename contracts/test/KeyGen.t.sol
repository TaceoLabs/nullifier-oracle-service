// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {KeyGen} from "../src/KeyGen.sol";
import {BabyJubjub} from "../src/BabyJubjub.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

contract KeyGenTest is Test {
    KeyGen public gen;
    BabyJubjub public accumulator;
    Groth16Verifier public verifier;


    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);

        function getValidProof() internal pure returns (KeyGen.Groth16Proof memory) {
            return KeyGen.Groth16Proof({
                pA: [
                    0x215ff06bdcaa01703b7586bac6b4c7df6d0f8db30e193b25ead4d9ef24e4a2ee,
                    0x07b5a5f3cebf93fea7424e917ce240b6b6ae4d497d4bd5fc754fe9505a589892
                ],
                pB: [
                    [
                        0x22909aa5f3fa70f1b3ea4294387d190d4bb6deae9ff2697e7fff5a70df446b72,
                        0x17455378cfd2b5ff1d5be41512abf32511cdf490a26405a0fef06b0e8e9ca203
                    ],
                    [
                        0x20f2fb3c3275362a8332e353a3dbcfc445b96700fe44afaf909926418b5a6ce1,
                        0x22b69ff116889c21dcd4256721b981838510cb4768c60d00a4054630ce3b06d4
                    ]
                ],
                pC: [
                    0x1d3190dcbfcf398dd72b0acbf46e325e56c20f7bf10d7137e7e81c225a188dcc,
                    0x0ef89d9f5f17706c737e6eee18311b6db37054c94bdc72965419a4b7026b4229
                ],
                pubSignals: [
                    0x1b1e9a6aeccca69f22cebb80c7c3eafaa0fbcdf987667bc227fdd00321b4a0c3,
                    0x14769465a224eda0f355d1f09580fb4a89474cdb9b4d874dc3c21c384503c553,
                    0x15f6d9f8b0c58a5ec2c6cd12dc1c9144eece2654ac541f199ff3e7de5d8f7ad9,
                    0x290502ecd06e093b98e7dc07312074e8bf1c9267f9d5e94719727463c4b6a306,
                    0x220138336a128ebf9a1465b7c6107061343cba68d626bd92dea42667cf47c5a4,
                    0x1fa3d8d7dbfb2cda8dbc6457fcd0ee696a1428496d95371d15395cfa9b3437d0,
                    0x2a3ac9425130ddd6a62d8f48eab49b704b903ede07de2b8cd5bb62d2d7d407c4,
                    0x1dbb8e88cbe7c38e766eb05fcd488ebddbc9276ee7c016e5658ed20e0e385a45,
                    0x15f6d9f8b0c58a5ec2c6cd12dc1c9144eece2654ac541f199ff3e7de5d8f7ad9,
                    0x290502ecd06e093b98e7dc07312074e8bf1c9267f9d5e94719727463c4b6a306,
                    0x15f6d9f8b0c58a5ec2c6cd12dc1c9144eece2654ac541f199ff3e7de5d8f7ad9,
                    0x290502ecd06e093b98e7dc07312074e8bf1c9267f9d5e94719727463c4b6a306,
                    0x15f6d9f8b0c58a5ec2c6cd12dc1c9144eece2654ac541f199ff3e7de5d8f7ad9,
                    0x290502ecd06e093b98e7dc07312074e8bf1c9267f9d5e94719727463c4b6a306,
                    0x0000000000000000000000000000000000000000000000000000000000000001,
                    0x043dd6222cc5c980000000000000000000000000000000000000000000000000,
                    0x281af7cd8cd56a00000000000000000000000000000000000000000000000000,
                    0x2a2b283a22a60200000000000000000000000000000000000000000000000000,
                    0x1cdd273c07571a00000000000000000000000000000000000000000000000000,
                    0x2a6bc12aef73d800000000000000000000000000000000000000000000000000,
                    0x0a77b905b6e70e80000000000000000000000000000000000000000000000000,
                    0x2989c7c598742e00000000000000000000000000000000000000000000000000,
                    0x04f5106948b99300000000000000000000000000000000000000000000000000,
                    0x0d96f9a57d4e0c00000000000000000000000000000000000000000000000000                ]
            });
    }

    function setUp() public {
        address [] memory participants = new address[](3);
        participants[0] = alice;
        participants[1] = bob;
        participants[2] = carol;

        bytes memory peerKeys = hex"deadbeef"; // dummy peer keys

        accumulator = new BabyJubjub();
        verifier = new Groth16Verifier();
        gen = new KeyGen(address(verifier), address(accumulator), participants, 1, peerKeys);
    }

    function testProof() public {
        KeyGen.Groth16Proof memory proof = getValidProof();
        assert(verifier.verifyProof(proof.pA, proof.pB, proof.pC, proof.pubSignals));
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
        KeyGen.BabyJubjubElement memory testElement = KeyGen.BabyJubjubElement(
            5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203
        );
        KeyGen.Round1Data memory testRound1Data = KeyGen.Round1Data(
            testElement,
            123
        );

        // Each participant submits round1
        vm.startPrank(alice);
        gen.addRound1Contribution(sessionId, testRound1Data);
        vm.stopPrank();

        vm.startPrank(bob);
        gen.addRound1Contribution(sessionId, testRound1Data);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit KeyGen.SecretGenRound2(sessionId, hex"deadbeef");

        vm.startPrank(carol);
        gen.addRound1Contribution(sessionId, testRound1Data);
        vm.stopPrank();
    }

    function testRound2ThenFinalizeFlow() public {
        uint128 sessionId = 2;
        bytes memory pubKey = hex"2222";
        KeyGen.Groth16Proof memory proof = getValidProof();
        KeyGen.BabyJubjubElement memory testElement = KeyGen.BabyJubjubElement(
            5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203
        );
        KeyGen.Round1Data memory testRound1Data = KeyGen.Round1Data(
            testElement,
            0
        );
        gen.initKeyGen(sessionId, pubKey);

        // All round1 first
        vm.prank(alice); gen.addRound1Contribution(sessionId, testRound1Data);
        vm.prank(bob);   gen.addRound1Contribution(sessionId, testRound1Data);
        vm.prank(carol); gen.addRound1Contribution(sessionId, testRound1Data);

        // Two round2 contributions already submitted
        vm.prank(alice); gen.addRound2Contribution(sessionId, hex"bbb1", proof);
        vm.prank(bob);   gen.addRound2Contribution(sessionId, hex"bbb2", proof);

        // Build expected array exactly as contract will have it
        KeyGen.Round1Data[] memory expectedRound1 = 
            new KeyGen.Round1Data[](3);
        expectedRound1[0] = testRound1Data;
        expectedRound1[1] = testRound1Data;
        expectedRound1[2] = testRound1Data;

        KeyGen.RpSecretGenCiphertexts[] memory expectedRound2 = 
            new KeyGen.RpSecretGenCiphertexts[](3);
        expectedRound2[0] = KeyGen.RpSecretGenCiphertexts({ data: hex"bbb1" });
        expectedRound2[1] = KeyGen.RpSecretGenCiphertexts({ data: hex"bbb2" });
        expectedRound2[2] = KeyGen.RpSecretGenCiphertexts({ data: hex"bbb3" });

        // Expect the Finalize event — check indexed rpId (topic1) and full data (last boolean = true)
        vm.expectEmit(true, false, false, true);
        emit KeyGen.SecretGenFinalize(sessionId, pubKey, expectedRound1, expectedRound2);

        // Trigger final submission (this call should emit the Finalize event)
        vm.prank(carol);
        gen.addRound2Contribution(sessionId, hex"bbb3", proof);
    }
}
