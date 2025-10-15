// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract KeyGenScript is Script {
    KeyGen public gen;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address accumulator = address(0x998);
        address verifier = address(0x999);
        address taceoAdmin = address(0x4);

        gen = new KeyGen(verifier, accumulator, 1, taceoAdmin);

        vm.stopBroadcast();
        console.log("Contract deployed at:", address(gen));
    }
}
