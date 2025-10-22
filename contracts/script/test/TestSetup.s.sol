// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../../src/Groth16VerifierKeyGen13.sol";
import {Groth16Verifier as Groth16VerifierNullifier} from "../../src/Groth16VerifierNullifier.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract TestSetupScript is Script {
    using Types for Types.BabyJubJubElement;

    RpRegistry public rpRegistry;
    ERC1967Proxy public proxy;

    function setUp() public {}

    function deployGroth16VerifierKeyGen() public returns (address) {
        Groth16VerifierKeyGen13 verifier = new Groth16VerifierKeyGen13();
        console.log("Groth16VerifierKeyGen13 deployed to:", address(verifier));
        return address(verifier);
    }

    function deployGroth16VerifierNullifier() public returns (address) {
        Groth16VerifierNullifier verifier = new Groth16VerifierNullifier();
        console.log("Groth16VerifierNullifier deployed to:", address(verifier));
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
        address nullifierVerifierAddress = deployGroth16VerifierNullifier();
        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");
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

        // Deploy implementation
        RpRegistry implementation = new RpRegistry{salt: bytes32(uint256(0))}();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector,
            taceoAdminAddress,
            keyGenVerifierAddress,
            nullifierVerifierAddress,
            accumulatorAddress,
            2,
            3
        );
        // Deploy proxy
        proxy = new ERC1967Proxy{salt: bytes32(uint256(0))}(address(implementation), initData);
        rpRegistry = RpRegistry(address(proxy));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = aliceAddress;
        peerAddresses[1] = bobAddress;
        peerAddresses[2] = carolAddress;
        Types.BabyJubJubElement[] memory peerPublicKeys = new Types.BabyJubJubElement[](3);
        peerPublicKeys[0] = publicKeyAlice;
        peerPublicKeys[1] = publicKeyBob;
        peerPublicKeys[2] = publicKeyCarol;

        rpRegistry.registerOprfPeers(peerAddresses, peerPublicKeys);

        // check that contract is ready
        assert(rpRegistry.isContractReady());
        vm.stopBroadcast();

        console.log("RpRegistry deployed to:", address(rpRegistry));
    }
}
