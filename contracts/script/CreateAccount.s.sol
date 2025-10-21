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
        authenticatorAddresses[0] = address(uint160(0x001a642f0e3c3af545e7acbd38b07251b3990914f1));
        uint256[] memory accountPubKeys = new uint256[](1);
        accountPubKeys[0] = 5379110988641622236343601253334548597861310598935430213851596230561241835800;

        accountRegistry.createAccount(address(0xABCD), authenticatorAddresses, accountPubKeys, 123456789);

        vm.stopBroadcast();
    }
}
