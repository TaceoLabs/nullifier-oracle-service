// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";

contract InitReshareScript is Script {
    OprfKeyRegistry public oprfKeyRegistry;

    function setUp() public {
        oprfKeyRegistry = OprfKeyRegistry(vm.envAddress("OPRF_KEY_REGISTRY_PROXY"));
    }

    function run() external {
        uint160 keyId = uint160(vm.envUint("OPRF_KEY_ID"));

        vm.startBroadcast();
        oprfKeyRegistry.initReshare(keyId);
        vm.stopBroadcast();

        console.log("Initialized reshare session with ID:", keyId);
    }
}
