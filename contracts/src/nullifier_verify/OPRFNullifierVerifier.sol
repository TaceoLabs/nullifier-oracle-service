// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Groth16Verifier} from "./OPRFNullifierProofVerifier.sol";
import {KeyGen} from "../KeyGen.sol";
import {CredentialSchemaIssuerRegistry} from "@world-id-protocol/contracts/CredentialSchemaIssuerRegistry.sol";

contract OPRFNullifierVerifier is Ownable {
    Groth16Verifier public verifier;

    constructor(address _verifierAddress) {
        verifier = Groth16Verifier(_verifierAddress);
    }

    struct Groth16Proof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
    }

    function verifyNullifierProof(
        uint256 calldata nullifier,
        uint256 calldata nullifier_action
        uint128 calldata rp_id,
        uint256 calldata identity_commitment,
        uint256 calldata nonce,
        uint256 calldata signal_hash,
        uint256 calldata authenticator_merkle_root,
        uint256 calldata proof_timestamp
        uint8 calldata authenticator_merkle_tree_depth,
        CredentialSchemaIssuerRegistry.PubKey calldata credential_public_key,
        Groth16Proof calldata proof
    ) external view returns (bool) {


        // do not allow proofs from the future
        if proof_timestamp > block.timestamp {
            // TODO better error types
            return false;
        }
        // do not allow proofs older than 5 hours
        if proof_timestamp + 5 hours < block.timestamp {
            // TODO better error types
            return false;
        }

        // for this specific proof, we have 13 public signals
        // [0]: credential public key x coordinate
        // [1]: credential public key y coordinate
        // [2]: current time stamp
        // [3]: Authenticator merkle tree root hash
        // [4]: Current depth of the Authenticator merkle tree
        // [5]: RP ID
        // [6]: Nullifier action
        // [7]: RP OPRF public key x coordinate
        // [8]: RP OPRF public key y coordinate
        // [9]: signal hash
        // [10]: nonce for the RP signature
        // [11]: identity commitment
        // [12]: nullifier
        // use calldata since we set it once
        uint256[13] pubSignals;

        pubSignals[0] = credential_public_key.x;
        pubSignals[1] = credential_public_key.y;
        pubSignals[2] = proof_timestamp;
        pubSignals[3] = authenticator_merkle_root; 
        pubSignals[4] = uint256(authenticator_merkle_tree_depth);
        pubSignals[5] = uint128(rp_id);
        pubSignals[6] = nullifier_action; 
        pubSignals[7] = 0; // RP OPRF public key x coordinate
        pubSignals[8] = 0; // RP OPRF public key y coordinate
        pubSignals[9] = signal_hash;
        pubSignals[10] = nonce;
        pubSignals[11] = identity_commitment;
        pubSignals[12] = nullifier;

        return verifier.verifyProof(proof.pA, proof.pB, proof.pC, pubSignals);
    }

    function updateGroth16Verifier(address _verifier) external onlyOwner {
        verifier = AccountRegistry(_verifier);
    }
}
