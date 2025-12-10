// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployOprfKeyRegistryScript is Script {
    using Types for Types.BabyJubJubElement;
    OprfKeyRegistry public oprfKeyRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");
        address accumulatorAddress = vm.envAddress("ACCUMULATOR_ADDRESS");
        address keyGenVerifierAddress = vm.envAddress("KEY_GEN_VERIFIER_ADDRESS");
        uint256 threshold = vm.envUint("THRESHOLD");
        uint256 numPeers = vm.envUint("NUM_PEERS");

        console.log("using TACEO address:", taceoAdminAddress);
        console.log("using accumulator address:", accumulatorAddress);
        console.log("using key-gen verifier address:", keyGenVerifierAddress);
        console.log("using threshold:", threshold);
        console.log("using numPeers:", numPeers);

        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector,
            taceoAdminAddress,
            keyGenVerifierAddress,
            accumulatorAddress,
            threshold,
            numPeers
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        oprfKeyRegistry = OprfKeyRegistry(address(proxy));

        vm.stopBroadcast();
        console.log("OprfKeyRegistry implementation deployed to:", address(implementation));
        console.log("OprfKeyRegistry deployed to:", address(oprfKeyRegistry));
    }
}
