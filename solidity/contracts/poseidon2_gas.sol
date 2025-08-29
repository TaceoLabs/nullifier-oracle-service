// SPDX-License-Identifier: MIT

pragma solidity >=0.8.8;

import {Poseidon2T2} from "./poseidon2_t2.sol";
import {Poseidon2T2opt} from "./poseidon2_t2_opt.sol";
import {Poseidon2T2Inline} from "./poseidon2_t2_inline.sol";

contract Poseidon2 {
    uint256 constant HASH_COUNT = 100;

    uint256 public result;
    uint256 public gas_used;

    function compress(uint256[2] memory inputs) public {
        uint256 res;
        uint256 start_gas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            res = Poseidon2T2.compress(inputs);
        }
        uint256 end_gas = gasleft();
        gas_used = (start_gas - end_gas) / HASH_COUNT;
        result = res;
    }

    function compress_opt(uint256[2] memory inputs) public {
        uint256 res;
        uint256 start_gas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            res = Poseidon2T2opt.compress(inputs);
        }
        uint256 end_gas = gasleft();
        gas_used = (start_gas - end_gas) / HASH_COUNT;
        result = res;
    }

    function compress_inline(uint256[2] memory inputs) public {
        uint256 res;
        uint256 start_gas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            res = Poseidon2T2Inline.compress(inputs);
        }
        uint256 end_gas = gasleft();
        gas_used = (start_gas - end_gas) / HASH_COUNT;
        result = res;
    }
}
