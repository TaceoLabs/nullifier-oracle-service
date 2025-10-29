// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccountRegistry} from "world-id-protocol/src/AccountRegistry.sol";

contract InsertAuthenticatorScript is Script {
    AccountRegistry public accountRegistry;

    function setUp() public {
        accountRegistry = AccountRegistry(vm.envAddress("ACCOUNT_REGISTRY"));
    }

    function run() public {
        vm.startBroadcast();

        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(uint160(uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)))));
        uint256[] memory accountPubKeys = new uint256[](1);
        accountPubKeys[0] = 5379110988641622236343601253334548597861310598935430213851596230561241835800;

        accountRegistry.createAccount(address(0xABCD), authenticatorAddresses, accountPubKeys, 123456789);

        console.log("created with authenticatorAddresses", authenticatorAddresses[0]);

        vm.stopBroadcast();
    }
}
