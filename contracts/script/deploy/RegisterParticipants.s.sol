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

        address[] memory participants = vm.envAddress("PARTICIPANT_ADDRESSES", ",");
        for (uint256 i = 0; i < participants.length; i++) {
            console.log("Registering participant address:", participants[i]);
        }

        oprfKeyRegistry.registerOprfPeers(participants);

        // check that contract is ready
        assert(oprfKeyRegistry.isContractReady());
        vm.stopBroadcast();
        console.log("Contract is ready!");
    }
}
