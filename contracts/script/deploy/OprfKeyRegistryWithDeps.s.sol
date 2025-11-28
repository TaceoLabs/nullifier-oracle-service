// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../../src/Groth16VerifierKeyGen13.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployOprfKeyRegistryWithDepsScript is Script {
    using Types for Types.BabyJubJubElement;

    OprfKeyRegistry public oprfKeyRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function deployGroth16VerifierKeyGen() public returns (address) {
        Groth16VerifierKeyGen13 verifier = new Groth16VerifierKeyGen13();
        console.log("Groth16VerifierKeyGen13 deployed to:", address(verifier));
        return address(verifier);
    }

    function deployAccumulator() public returns (address) {
        BabyJubJub acc = new BabyJubJub();
        console.log("Accumulator deployed to:", address(acc));
        return address(acc);
    }

    function run() public {
        vm.startBroadcast();

        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");

        address accumulatorAddress = deployAccumulator();
        address keyGenVerifierAddress = deployGroth16VerifierKeyGen();
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdminAddress, keyGenVerifierAddress, accumulatorAddress
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        oprfKeyRegistry = OprfKeyRegistry(address(proxy));

        console.log("OprfKeyRegistry implementation deployed to:", address(implementation));
        console.log("OprfKeyRegistry deployed to:", address(oprfKeyRegistry));
    }
}
