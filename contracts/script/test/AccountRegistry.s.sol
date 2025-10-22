// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccountRegistry} from "world-id-protocol/src/AccountRegistry.sol";

contract AccountRegistryDeployScript is Script {
    AccountRegistry public accountRegistry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        accountRegistry = new AccountRegistry(30);
        vm.stopBroadcast();

        console.log("AccountRegistry deployed to:", address(accountRegistry));
    }
}
