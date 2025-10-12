// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract KeyGenScript is Script {
    KeyGen public gen;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Example participants (hardcoded here, but you could read from env vars or input)
        address [] memory participants = new address[](3);
        participants[0] = address(0x14dC79964da2C08b23698B3D3cc7Ca32193d9955);
        participants[1] = address(0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f);
        participants[2] = address(0xa0Ee7A142d267C1f36714E4a8F75612F20a79720);
        address verifier = address(0x999);


        string memory filePath = "script/script-data/pubkey-list.hex";
        bytes memory peerKeys = vm.parseBytes(vm.readFile(filePath));

        gen = new KeyGen(verifier, participants, 1, peerKeys);

        vm.stopBroadcast();
        console.log("Contract deployed at:", address(gen));
    }
}
