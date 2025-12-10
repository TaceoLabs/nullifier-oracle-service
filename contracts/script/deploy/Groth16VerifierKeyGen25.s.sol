// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Verifier} from "../../src/VerifierKeyGen25.sol";

contract Groth16VerifierScript is Script {
    Verifier public verifier;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        verifier = new Verifier();
        vm.stopBroadcast();
        console.log("Groth16Verifier deployed to:", address(verifier));
    }
}
