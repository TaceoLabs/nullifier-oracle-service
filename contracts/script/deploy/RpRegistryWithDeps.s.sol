// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../../src/Groth16VerifierKeyGen13.sol";
import {Groth16Verifier as Groth16VerifierNullifier} from "../../src/Groth16VerifierNullifier.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";

contract DeployRpRegistryWithDepsScript is Script {
    using Types for Types.BabyJubJubElement;

    RpRegistry public rpRegistry;

    function setUp() public {}

    function deployGroth16VerifierKeyGen() public returns (address) {
        Groth16VerifierKeyGen13 verifier = new Groth16VerifierKeyGen13();
        console.log("Groth16VerifierKeyGen13 deployed to:", address(verifier));
        return address(verifier);
    }

    function deployGroth16VerifierNullifier() public returns (address) {
        Groth16VerifierNullifier verifier = new Groth16VerifierNullifier();
        console.log("Groth16VerifierNullifier deployed to:", address(verifier));
        return address(verifier);
    }

    function deployAccumulator() public returns (address) {
        BabyJubJub acc = new BabyJubJub();
        console.log("Accumulator deployed to:", address(acc));
        return address(acc);
    }

    function run() public {
        vm.startBroadcast();

        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");

        address accumulatorAddress = deployAccumulator();
        address keyGenVerifierAddress = deployGroth16VerifierKeyGen();
        address nullifierVerifierAddress = deployGroth16VerifierNullifier();
        rpRegistry =
            new RpRegistry(taceoAdminAddress, keyGenVerifierAddress, nullifierVerifierAddress, accumulatorAddress, 2, 3);

        console.log("RpRegistry deployed to:", address(rpRegistry));
    }
}
