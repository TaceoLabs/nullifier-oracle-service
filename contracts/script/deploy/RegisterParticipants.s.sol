// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Types} from "../../src/Types.sol";

contract RegisterParticipantScript is Script {
    using Types for Types.BabyJubJubElement;

    RpRegistry public rpRegistry;

    function setUp() public {
        address rpRegistryAddress = vm.envAddress("RP_REGISTRY_PROXY");
        console.log("register Participants for RpRegistry Proxy contract at:", rpRegistryAddress);

        rpRegistry = RpRegistry(rpRegistryAddress);
    }

    function run() public {
        vm.startBroadcast();

        address aliceAddress = vm.envAddress("ALICE_ADDRESS");
        address bobAddress = vm.envAddress("BOB_ADDRESS");
        address carolAddress = vm.envAddress("CAROL_ADDRESS");

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = aliceAddress;
        peerAddresses[1] = bobAddress;
        peerAddresses[2] = carolAddress;

        console.log("alice address:", aliceAddress);
        console.log("bob address:", bobAddress);
        console.log("carol address:", carolAddress);

        //TODO: Change to add some participants
        address[] memory smartAccounts = new address[](peerAddresses.length);

        rpRegistry.registerOprfPeers(peerAddresses, smartAccounts);

        // check that contract is ready
        assert(rpRegistry.isContractReady());
        vm.stopBroadcast();
        console.log("Contract is ready!");
    }
}
