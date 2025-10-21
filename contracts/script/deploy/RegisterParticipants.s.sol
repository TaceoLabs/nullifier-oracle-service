// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../../src/KeyGen.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../../src/Groth16VerifierKeyGen13.sol";
import {Groth16Verifier as Groth16VerifierNullifier} from "../../src/Groth16VerifierNullifier.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";

contract RegisterParticipantScript is Script {
    using Types for Types.BabyJubJubElement;

    KeyGen public gen;

    function setUp() public {
        address keyGenAddress = vm.envAddress("KEY_GEN_ADDRESS");
        console.log("register Participants for KeyGen contract at:", keyGenAddress);
        gen = KeyGen(keyGenAddress);
    }

    function run() public {
        vm.startBroadcast();

        uint256 aliceX = vm.envUint("ALICE_PK_X");
        uint256 aliceY = vm.envUint("ALICE_PK_Y");

        uint256 bobX = vm.envUint("BOB_PK_X");
        uint256 bobY = vm.envUint("BOB_PK_Y");

        uint256 carolX = vm.envUint("CAROL_PK_X");
        uint256 carolY = vm.envUint("CAROL_PK_Y");

        address aliceAddress = vm.envAddress("ALICE_ADDRESS");
        address bobAddress = vm.envAddress("BOB_ADDRESS");
        address carolAddress = vm.envAddress("CAROL_ADDRESS");

        Types.BabyJubJubElement memory publicKeyAlice = Types.BabyJubJubElement({x: aliceX, y: aliceY});

        Types.BabyJubJubElement memory publicKeyBob = Types.BabyJubJubElement({x: bobX, y: bobY});

        Types.BabyJubJubElement memory publicKeyCarol = Types.BabyJubJubElement({x: carolX, y: carolY});

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = aliceAddress;
        peerAddresses[1] = bobAddress;
        peerAddresses[2] = carolAddress;
        Types.BabyJubJubElement[] memory peerPublicKeys = new Types.BabyJubJubElement[](3);
        peerPublicKeys[0] = publicKeyAlice;
        peerPublicKeys[1] = publicKeyBob;
        peerPublicKeys[2] = publicKeyCarol;

        console.log("alice address:", aliceAddress);
        console.log("bob address:", bobAddress);
        console.log("carol address:", carolAddress);

        gen.registerOprfPeers(peerAddresses, peerPublicKeys);

        // check that contract is ready
        assert(gen.isContractReady());
        vm.stopBroadcast();
        console.log("Contract is ready!");
    }
}
