// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Types Library
/// @notice Defines common structs, enums, and constants for the project
library Types {
    struct OprfPeer {
        bool isParticipant;
        uint256 partyId;
    }

    struct Round1Contribution {
        BabyJubJubElement commShare;
        // Hash of the polynomial created by participant
        uint256 commCoeffs;
        // ephemeral public key for this round
        BabyJubJubElement ephPubKey;
    }

    struct Round2Contribution {
        Groth16Proof proof;
        // Hash of the polynomial created by participant
        SecretGenCiphertext[] ciphers;
    }

    struct SecretGenCiphertext {
        uint256 nonce;
        uint256 cipher;
        BabyJubJubElement commitment;
    }

    struct RpNullifierGenState {
        EcDsaPubkeyCompressed ecdsaPubKey;
        Round1Contribution[] round1;
        SecretGenCiphertext[][] round2;
        BabyJubJubElement keyAggregate;
        bool[] round2Done;
        bool[] round3Done;
        bool round2EventEmitted;
        bool round3EventEmitted;
        bool finalizeEventEmitted;
        bool exists;
        bool deleted;
    }

    struct Groth16Proof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
    }

    struct BabyJubJubElement {
        uint256 x;
        uint256 y;
    }

    struct EcDsaPubkeyCompressed {
        bytes32 x;
        uint256 yParity; // 0 or 1
    }

    struct RpMaterial {
        EcDsaPubkeyCompressed ecdsaKey;
        BabyJubJubElement nullifierKey;
    }

    // events for key-gen
    event SecretGenRound1(uint128 indexed rpId, uint256 threshold);
    event SecretGenRound2(uint128 indexed rpId);
    event SecretGenRound3(uint128 indexed rpId);
    event SecretGenFinalize(uint128 indexed rpId);
    // event to delete created key
    event KeyDeletion(uint128 indexed rpId);
}
