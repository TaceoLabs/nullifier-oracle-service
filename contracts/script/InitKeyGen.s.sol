// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../src/KeyGen.sol";

contract InitKeyGenScript is Script {
    KeyGen public keyGenContract;

    function setUp() public {
        keyGenContract = KeyGen(vm.envAddress("KEYGEN_CONTRACT"));
    }

    function run() external {

        // --- Replace with your deployed contract address ---

        // Example: new session ID and ECDSA public key
        uint128 sessionId = uint128(uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender))
        ));

        bytes memory ecdsaPubKey = hex"deadbeef";

        vm.startBroadcast();
        keyGenContract.initKeyGen(sessionId, ecdsaPubKey);
        vm.stopBroadcast();



        console.log("Initialized new key gen session with ID:", sessionId);

    }
}
