// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";

contract BabyJubJubScript is Script {
    BabyJubJub public babyJubJub;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        babyJubJub = new BabyJubJub();
        vm.stopBroadcast();
        console.log("BabyJubJub deployed to:", address(babyJubJub));
    }
}
