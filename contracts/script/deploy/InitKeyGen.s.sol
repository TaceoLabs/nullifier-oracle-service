// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {KeyGen} from "../../src/KeyGen.sol";
import {Types} from "../../src/Types.sol";

contract InitKeyGenScript is Script {
    using Types for Types.EcDsaPubkeyCompressed;

    KeyGen public keyGenContract;

    function setUp() public {
        keyGenContract = KeyGen(vm.envAddress("KEYGEN_CONTRACT"));
    }

    function run() external {
        uint128 sessionId = uint128(vm.envUint("SESSION_ID"));
        uint256 ecdsaKeyX = vm.envUint("ECDSA_X");
        uint256 ecdsaKeyYParity = vm.envUint("ECDSA_Y_PARITY");

        Types.EcDsaPubkeyCompressed memory ecdsaPubKey =
            Types.EcDsaPubkeyCompressed({x: bytes32(ecdsaKeyX), yParity: ecdsaKeyYParity});

        vm.startBroadcast();
        keyGenContract.initKeyGen(sessionId, ecdsaPubKey);
        vm.stopBroadcast();

        console.log("Initialized new key gen session with ID:", sessionId);
    }
}
