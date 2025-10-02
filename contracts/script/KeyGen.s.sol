// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract KeyGenScript is Script {
    KeyGen public gen;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Example participants (hardcoded here, but you could read from env vars or input)
        address [] memory participants = new address[](3);
        participants[0] = address(0x111);
        participants[1] = address(0x222);
        participants[2] = address(0x333);

        bytes memory peerKeys = hex"deadbeef"; // some dummy peer keys

        gen = new KeyGen(participants, peerKeys);

        vm.stopBroadcast();
    }
}
