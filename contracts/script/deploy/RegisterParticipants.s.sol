// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";
import {Types} from "../../src/Types.sol";

contract RegisterParticipantScript is Script {
    using Types for Types.BabyJubJubElement;

    OprfKeyRegistry public oprfKeyRegistry;

    function setUp() public {
        address oprfKeyRegistryAddress = vm.envAddress("OPRF_KEY_REGISTRY_PROXY");
        console.log("register Participants for OprfKeyRegistry Proxy contract at:", oprfKeyRegistryAddress);

        oprfKeyRegistry = OprfKeyRegistry(oprfKeyRegistryAddress);
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

        oprfKeyRegistry.registerOprfPeers(peerAddresses);

        // check that contract is ready
        assert(oprfKeyRegistry.isContractReady());
        vm.stopBroadcast();
        console.log("Contract is ready!");
    }
}
