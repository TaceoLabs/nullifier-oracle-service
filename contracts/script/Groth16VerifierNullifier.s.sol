// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Groth16Verifier} from "../src/Groth16VerifierNullifier.sol";

contract Groth16VerifierScript is Script {
    Groth16Verifier public verifier;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        verifier = new Groth16Verifier();
        vm.stopBroadcast();
        console.log("Groth16Verifier deployed to:", address(verifier));
    }
}
