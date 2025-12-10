// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";
import {Verifier as VerifierKeyGen13} from "../../src/VerifierKeyGen13.sol";
import {Verifier as VerifierKeyGen25} from "../../src/VerifierKeyGen25.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployOprfKeyRegistryWithDepsScript is Script {
    using Types for Types.BabyJubJubElement;

    OprfKeyRegistry public oprfKeyRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function deployGroth16VerifierKeyGen(uint256 threshold, uint256 numPeers) public returns (address) {
        if (threshold == 2 && numPeers == 3) {
            VerifierKeyGen13 verifier = new VerifierKeyGen13();
            console.log("VerifierKeyGen deployed to:", address(verifier));
            return address(verifier);
        } else if (threshold == 3 && numPeers == 5) {
            VerifierKeyGen25 verifier = new VerifierKeyGen25();
            console.log("VerifierKeyGen deployed to:", address(verifier));
            return address(verifier);
        } else {
            revert("Unsupported threshold and numPeers combination");
        }
    }

    function deployAccumulator() public returns (address) {
        BabyJubJub acc = new BabyJubJub();
        console.log("Accumulator deployed to:", address(acc));
        return address(acc);
    }

    function run() public {
        vm.startBroadcast();

        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");
        uint256 threshold = vm.envUint("THRESHOLD");
        uint256 numPeers = vm.envUint("NUM_PEERS");

        address accumulatorAddress = deployAccumulator();
        address keyGenVerifierAddress = deployGroth16VerifierKeyGen(threshold, numPeers);
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector,
            taceoAdminAddress,
            keyGenVerifierAddress,
            accumulatorAddress,
            threshold,
            numPeers
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        oprfKeyRegistry = OprfKeyRegistry(address(proxy));

        console.log("OprfKeyRegistry implementation deployed to:", address(implementation));
        console.log("OprfKeyRegistry deployed to:", address(oprfKeyRegistry));
    }
}
