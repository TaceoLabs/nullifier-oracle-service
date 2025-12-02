// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";

contract RevokeKeyGenAdminScript is Script {
    OprfKeyRegistry public oprfKeyRegistry;

    function setUp() public {
        oprfKeyRegistry = OprfKeyRegistry(vm.envAddress("OPRF_KEY_REGISTRY_PROXY"));
    }

    function run() public {
        address admin = vm.envAddress("ADMIN_ADDRESS_REGISTER");
        vm.startBroadcast();
        oprfKeyRegistry.addKeyGenAdmin(admin);
        vm.stopBroadcast();
        console.log("Added new admin:", admin, "at: ", address(oprfKeyRegistry));
    }
}
