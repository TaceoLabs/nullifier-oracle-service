// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";

contract DeleteRpMaterialScript is Script {
    RpRegistry public rpRegistry;

    function setUp() public {
        rpRegistry = RpRegistry(vm.envAddress("RP_REGISTRY_PROXY"));
    }

    function run() public {
        uint128 rpId = uint128(vm.envUint("RP_ID"));
        vm.startBroadcast();
        rpRegistry.deleteRpMaterial(rpId);
        vm.stopBroadcast();

        console.log("Deleted RpId", rpId, "from RpRegistry at: ", address(rpRegistry));
    }
}
