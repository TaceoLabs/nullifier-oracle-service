// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Types} from "../../src/Types.sol";

contract RegisterParticipantScript is Script {
    using Types for Types.BabyJubJubElement;

    RpRegistry public rpRegistry;

    function setUp() public {
        address rpRegistryAddress = vm.envAddress("RP_REGISTRY_ADDRESS");
        console.log("register Participants for RpRegistry contract at:", rpRegistryAddress);
        rpRegistry = RpRegistry(rpRegistryAddress);
    }

    function run() public {
        vm.startBroadcast();

        uint256 aliceX = vm.envUint("ALICE_PK_X");
        uint256 aliceY = vm.envUint("ALICE_PK_Y");

        uint256 bobX = vm.envUint("BOB_PK_X");
        uint256 bobY = vm.envUint("BOB_PK_Y");

        uint256 carolX = vm.envUint("CAROL_PK_X");
        uint256 carolY = vm.envUint("CAROL_PK_Y");

        address aliceAddress = vm.envAddress("ALICE_ADDRESS");
        address bobAddress = vm.envAddress("BOB_ADDRESS");
        address carolAddress = vm.envAddress("CAROL_ADDRESS");

        Types.BabyJubJubElement memory publicKeyAlice = Types.BabyJubJubElement({x: aliceX, y: aliceY});

        Types.BabyJubJubElement memory publicKeyBob = Types.BabyJubJubElement({x: bobX, y: bobY});

        Types.BabyJubJubElement memory publicKeyCarol = Types.BabyJubJubElement({x: carolX, y: carolY});

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = aliceAddress;
        peerAddresses[1] = bobAddress;
        peerAddresses[2] = carolAddress;
        Types.BabyJubJubElement[] memory peerPublicKeys = new Types.BabyJubJubElement[](3);
        peerPublicKeys[0] = publicKeyAlice;
        peerPublicKeys[1] = publicKeyBob;
        peerPublicKeys[2] = publicKeyCarol;

        console.log("alice address:", aliceAddress);
        console.log("bob address:", bobAddress);
        console.log("carol address:", carolAddress);

        rpRegistry.registerOprfPeers(peerAddresses, peerPublicKeys);

        // check that contract is ready
        assert(rpRegistry.isContractReady());
        vm.stopBroadcast();
        console.log("Contract is ready!");
    }
}
