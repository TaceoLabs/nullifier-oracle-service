pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

contract DeployEntryPoint is Script {
    function run() external returns (address) {
        vm.startBroadcast();

        EntryPoint entryPoint = new EntryPoint();
        console.log("EntryPoint deployed at:", address(entryPoint));

        vm.stopBroadcast();

        return address(entryPoint);
    }
}
