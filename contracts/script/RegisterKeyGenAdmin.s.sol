// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../src/RpRegistry.sol";

contract RevokeKeyGenAdminScript is Script {
    RpRegistry public rpRegistry;

    function setUp() public {
        rpRegistry = RpRegistry(vm.envAddress("RP_REGISTRY_PROXY"));
    }

    function run() public {
        address admin = vm.envAddress("ADMIN_ADDRESS_REGISTER");
        vm.startBroadcast();
        rpRegistry.addKeyGenAdmin(admin);
        vm.stopBroadcast();
        console.log("Added new admin:", admin, "at: ", address(rpRegistry));
    }
}
