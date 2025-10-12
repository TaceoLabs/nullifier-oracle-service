// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract KeyGenTest is Test {
    KeyGen public gen;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);
    address verifier = address(0x999);

        function getValidProof() internal pure returns (KeyGen.Groth16Proof memory) {
            return KeyGen.Groth16Proof({
                pA: [
                    uint256(11468312949660864720429384337059670254676757541106984351883106197231676331091),
                    uint256(21560358938855909614179660361638410317406061096686392551110873609152313723109)
                ],
                pB: [
                    [
                        uint256(13980735654856460516138664573684586245924121068887112274291276365337539666387),
                        uint256(1397686996180224672356736405336363147127650825259727108741836519542724073549)
                    ],
                    [
                        uint256(15968577707534258110766194616852883078287268231758202275139689991817632376051),
                        uint256(469385223440505726293960417901985434579356989079082282124441130782779936314)
                    ]
                ],
                pC: [
                    uint256(3828322601558746243527055852380149288514094431838454636266089925907567679932),
                    uint256(17157137033268191615882850272980802574559493710030675183074422207142524601595)
                ],
                pubSignals: [
                    uint256(12266518075321185797589213532529011619734935414538300173788220522564798423235),
                    uint256(9255769123798898149953956649378827479482860591468882466861237176479881872723),
                    uint256(8877462399555945640480352492384831296250368331849204127836387507013104108526),
                    uint256(12631578230906775280794624255429491101400272482084813319607964027266411768781),
                    uint256(10205653472383472488460086772914067351086846265958759657301844448460926571680),
                    uint256(12516440285411826786488393729181852955056729344716724525960091951044647653599),
                    uint256(16975626554934773333990238653479791437475071502682450338677582176538684668386),
                    uint256(10992448926546190201408689558740052308140915979466990124400156321727043134834),
                    uint256(20367068389700016202738591873020896263520259691531819894712948288043834304716),
                    uint256(659148035290194116254646018585218061530651957523574443961880551765821062297),
                    uint256(2921312310036426493358859436494592988052601788337886029974845598317363250844),
                    uint256(10978475984719372499905328185911196421720951744571240239767067517059248071653),
                    uint256(5774906195600420545408082827191749158707796026354858181412974772508107763669),
                    uint256(16500991884686672355460614453662597856273297492358612952380955536381842267525),
                    uint256(1),
                    uint256(1918506960356052592250645643564153987471142747759193561574073802325049212928),
                    uint256(18140162239983131849346838246485360180462820807127348324812097711560806367232),
                    uint256(19073391701462346724876164917900366752759475209209991802186600260493388021760),
                    uint256(13055503748124824218507870140538419803140480795435834229229760919434237575168),
                    uint256(19187525471008459097508586080877286328315161835320367150266572407467403116544),
                    uint256(4734660263677069481471877790974401255879730803634753754107037821651474448384),
                    uint256(18788263614476327212261984658076727094194233323277639391448847593238983344128),
                    uint256(2242242191598544219883711217843414152398659753497348717266486535244044304384),
                    uint256(6146817087726914709223289044796148798688490938256583422678060326361342410752)
                ]
            });
    }

    function setUp() public {
        address [] memory participants = new address[](3);
        participants[0] = alice;
        participants[1] = bob;
        participants[2] = carol;

        bytes memory peerKeys = hex"deadbeef"; // dummy peer keys

        gen = new KeyGen(verifier, participants, 1, peerKeys);
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
        KeyGen.Groth16Proof memory proof = getValidProof();
        gen.initKeyGen(sessionId, pubKey);

        // All round1 first
        vm.prank(alice); gen.addRound1Contribution(sessionId, hex"aaa1");
        vm.prank(bob);   gen.addRound1Contribution(sessionId, hex"aaa2");
        vm.prank(carol); gen.addRound1Contribution(sessionId, hex"aaa3");

        // Two round2 contributions already submitted
        vm.prank(alice); gen.addRound2Contribution(sessionId, hex"bbb1", proof);
        vm.prank(bob);   gen.addRound2Contribution(sessionId, hex"bbb2", proof);

        // Build expected array exactly as contract will have it
        KeyGen.RpSecretGenCommitment[] memory expectedRound1 = 
            new KeyGen.RpSecretGenCommitment[](3);
        expectedRound1[0] = KeyGen.RpSecretGenCommitment({ data: hex"aaa1" });
        expectedRound1[1] = KeyGen.RpSecretGenCommitment({ data: hex"aaa2" });
        expectedRound1[2] = KeyGen.RpSecretGenCommitment({ data: hex"aaa3" });

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
