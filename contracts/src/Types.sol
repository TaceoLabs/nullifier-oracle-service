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
        uint256[4] compressedProof;
        // Hash of the polynomial created by participant
        SecretGenCiphertext[] ciphers;
    }

    struct SecretGenCiphertext {
        uint256 nonce;
        uint256 cipher;
        BabyJubJubElement commitment;
    }

    struct OprfKeyGenState {
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

    // events for key-gen
    event SecretGenRound1(uint160 indexed oprfKeyId, uint256 threshold);
    event SecretGenRound2(uint160 indexed oprfKeyId);
    event SecretGenRound3(uint160 indexed oprfKeyId);
    event SecretGenFinalize(uint160 indexed oprfKeyId);
    // event to delete created key
    event KeyDeletion(uint160 indexed oprfKeyId);
    // admin events
    event KeyGenAdminRevoked(address indexed admin);
    event KeyGenAdminRegistered(address indexed admin);
}
