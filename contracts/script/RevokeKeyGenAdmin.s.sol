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
        address admin = vm.envAddress("ADMIN_ADDRESS_REVOKE");
        vm.startBroadcast();
        rpRegistry.revokeKeyGenAdmin(admin);
        vm.stopBroadcast();
        console.log("Revoked", admin, "as admin at: ", address(rpRegistry));
    }
}
