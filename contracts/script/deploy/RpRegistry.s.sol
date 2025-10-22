// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../../src/KeyGen.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../../src/Groth16VerifierKeyGen13.sol";
import {Groth16Verifier as Groth16VerifierNullifier} from "../../src/Groth16VerifierNullifier.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";

contract DeployRpRegistryScript is Script {
    using Types for Types.BabyJubJubElement;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");

        address accumulatorAddress = vm.envAddress("ACCUMULATOR_ADDRESS");
        address keyGenVerifierAddress = vm.envAddress("KEY_GEN_VERIFIER_ADDRESS");
        address nullifierVerifierAddress = vm.envAddress("NULLIFIER_VERIFIER_ADDRESS");

        console.log("using TACEO address:", taceoAdminAddress);
        console.log("using accumulator address:", accumulatorAddress);
        console.log("using key-gen verifier address:", keyGenVerifierAddress);
        console.log("using nullifier verifier address:", nullifierVerifierAddress);

        KeyGen gen =
            new KeyGen(taceoAdminAddress, keyGenVerifierAddress, nullifierVerifierAddress, accumulatorAddress, 3, 2);

        vm.stopBroadcast();
        console.log("RpRegistry deployed to:", address(gen));
    }
}
