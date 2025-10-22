// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../../src/KeyGen.sol";
import {Types} from "../../src/Types.sol";

contract InitKeyGenScript is Script {
    using Types for Types.EcDsaPubkeyCompressed;

    KeyGen public keyGenContract;

    function setUp() public {
        keyGenContract = KeyGen(vm.envAddress("KEY_GEN_ADDRESS"));
    }

    function run() external {
        vm.startBroadcast();
        address taceoAdmin = keyGenContract.taceoAdmin();
        vm.stopBroadcast();

        console.log("TACEO admin is", taceoAdmin);
    }
}
