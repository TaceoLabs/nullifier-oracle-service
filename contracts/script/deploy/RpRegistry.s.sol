// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployRpRegistryScript is Script {
    using Types for Types.BabyJubJubElement;
    RpRegistry public rpRegistry;
    ERC1967Proxy public proxy;

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

        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector,
            taceoAdminAddress,
            keyGenVerifierAddress,
            nullifierVerifierAddress,
            accumulatorAddress
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        rpRegistry = RpRegistry(address(proxy));

        vm.stopBroadcast();
        console.log("RpRegistry implementation deployed to:", address(implementation));
        console.log("RpRegistry deployed to:", address(rpRegistry));
    }
}
