// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Types} from "../../src/Types.sol";

contract ReadKeyGenAdminScript is Script {
    using Types for Types.EcDsaPubkeyCompressed;

    RpRegistry public rpRegistry;

    function setUp() public {
        rpRegistry = RpRegistry(vm.envAddress("RP_REGISTRY_PROXY"));
    }

    function run() external {
        vm.startBroadcast();
        address keygenAdmin = rpRegistry.keygenAdmin();
        vm.stopBroadcast();

        console.log("KeyGen admin is", keygenAdmin);
    }
}
