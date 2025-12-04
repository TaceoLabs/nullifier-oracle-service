// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";
import {Verifier as VerifierKeyGen13} from "../../src/VerifierKeyGen13.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract TestSetupScript is Script {
    using Types for Types.BabyJubJubElement;

    OprfKeyRegistry public oprfKeyRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function deployGroth16VerifierKeyGen() public returns (address) {
        VerifierKeyGen13 verifier = new VerifierKeyGen13();
        console.log("VerifierKeyGen13 deployed to:", address(verifier));
        return address(verifier);
    }

    function deployAccumulator() public returns (address) {
        BabyJubJub acc = new BabyJubJub();
        console.log("Accumulator deployed to:", address(acc));
        return address(acc);
    }

    function run() public {
        vm.startBroadcast();

        address accumulatorAddress = deployAccumulator();
        address keyGenVerifierAddress = deployGroth16VerifierKeyGen();
        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");

        address aliceAddress = vm.envAddress("ALICE_ADDRESS");
        address bobAddress = vm.envAddress("BOB_ADDRESS");
        address carolAddress = vm.envAddress("CAROL_ADDRESS");

        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdminAddress, keyGenVerifierAddress, accumulatorAddress
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        oprfKeyRegistry = OprfKeyRegistry(address(proxy));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = aliceAddress;
        peerAddresses[1] = bobAddress;
        peerAddresses[2] = carolAddress;

        oprfKeyRegistry.registerOprfPeers(peerAddresses);

        // check that contract is ready
        assert(oprfKeyRegistry.isContractReady());
        vm.stopBroadcast();

        console.log("OprfKeyRegistry deployed to:", address(oprfKeyRegistry));
    }
}
