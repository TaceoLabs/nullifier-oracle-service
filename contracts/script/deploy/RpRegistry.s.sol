// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
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

        RpRegistry rpRegistry = new RpRegistry(
            taceoAdminAddress, keyGenVerifierAddress, nullifierVerifierAddress, accumulatorAddress, 2, 3
        );

        vm.stopBroadcast();
        console.log("RpRegistry deployed to:", address(rpRegistry));
    }
}
