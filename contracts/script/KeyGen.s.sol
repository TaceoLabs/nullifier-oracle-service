// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract KeyGenScript is Script {
    KeyGen public gen;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address accumulatorAddress = vm.envAddress("ACCUMULATOR_ADDRESS");
        address keyGenVerifierAddress = vm.envAddress("VERIFIER_ADDRESS_KEYGEN");
        address nullifierVerifierAddress = vm.envAddress("VERIFIER_ADDRESS_NULLIFIER");
        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");
        uint256 threshold = vm.envUint("THRESHOLD");
        uint256 numPeers = vm.envUint("NUM_PEERS");

        gen = new KeyGen(
            taceoAdminAddress, keyGenVerifierAddress, nullifierVerifierAddress, accumulatorAddress, threshold, numPeers
        );

        vm.stopBroadcast();
        console.log("KeyGen deployed to:", address(gen));
    }
}
