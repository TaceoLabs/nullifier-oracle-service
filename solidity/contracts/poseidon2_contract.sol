// SPDX-License-Identifier: MIT

pragma solidity >=0.8.8;

import {Poseidon2T2} from "./poseidon2_t2.sol";
import {Poseidon2T2opt} from "./poseidon2_t2_opt.sol";
import {Poseidon2T2Inline} from "./poseidon2_t2_inline.sol";

contract Poseidon2 {
    uint256 public result;

    function compress(uint256[2] memory inputs) public {
        result = Poseidon2T2.compress(inputs);
    }

    function compress_opt(uint256[2] memory inputs) public {
        result = Poseidon2T2opt.compress(inputs);
    }

    function compress_inline(uint256[2] memory inputs) public {
        result = Poseidon2T2Inline.compress(inputs);
    }
}
