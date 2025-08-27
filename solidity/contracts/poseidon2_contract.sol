// SPDX-License-Identifier: MIT

pragma solidity >=0.8.8;

import {Poseidon2T2} from "./poseidon2_t2.sol";
import {Poseidon2T2opt} from "./poseidon2_t2_opt.sol";

contract Poseidon2 {
    function compress(uint256[2] memory inputs) public pure returns (uint256) {
        return Poseidon2T2.compress(inputs);
    }

    function compress_opt(
        uint256[2] memory inputs
    ) public pure returns (uint256) {
        return Poseidon2T2opt.compress(inputs);
    }
}
