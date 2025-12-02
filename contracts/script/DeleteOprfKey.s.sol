// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";

contract DeleteOprfKeyScript is Script {
    OprfKeyRegistry public oprfKeyRegistry;

    function setUp() public {
        oprfKeyRegistry = OprfKeyRegistry(vm.envAddress("OPRF_KEY_REGISTRY_PROXY"));
    }

    function run() public {
        uint160 oprfKeyId = uint160(vm.envUint("OPRF_KEY_ID"));
        vm.startBroadcast();
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopBroadcast();

        console.log("Deleted OPRF public-key", oprfKeyId, "from OprfKeyRegistry at: ", address(oprfKeyRegistry));
    }
}
