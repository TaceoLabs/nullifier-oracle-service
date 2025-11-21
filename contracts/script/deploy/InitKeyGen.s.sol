// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";

contract InitKeyGenScript is Script {
    OprfKeyRegistry public oprfKeyRegistry;

    function setUp() public {
        oprfKeyRegistry = OprfKeyRegistry(vm.envAddress("OPRF_KEY_REGISTRY_PROXY"));
    }

    function run() external {
        uint160 keyId = uint160(vm.envUint("OPRF_KEY_ID"));

        vm.startBroadcast();
        oprfKeyRegistry.initKeyGen(keyId);
        vm.stopBroadcast();

        console.log("Initialized new key gen session with ID:", keyId);
    }
}
