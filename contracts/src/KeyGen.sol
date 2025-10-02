// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";

contract KeyGen {
    address[] public participants;
    mapping(address => uint256) public participantIndex; // participant -> index
    mapping(uint128 => RpNullifierGenState) internal states;
    mapping(uint128 => RpSecretGenCommitment[]) internal key_storage;
    uint128[] public activeIds;

    bytes public peer_keys;
    uint16 public degree;

    struct RpSecretGenCommitment { bytes data; }
    struct RpSecretGenCiphertexts { bytes data; }

    struct RpNullifierGenState {
        bytes ecdsaPubKey; // session key
        RpSecretGenCommitment[] round1; 
        RpSecretGenCiphertexts[] round2;
        bool[] finalizeDone;
        bool round2EventEmitted;
        bool finalizeEventEmitted;
        bool storedNullifier;
    }

    // Events
    event SecretGenRound1(uint128 indexed rpId, uint16 degree);
    event SecretGenRound2(uint128 indexed rpId, bytes peerPublicKeyList);
    event SecretGenFinalize(uint128 indexed rpId, bytes rpPublicKey, RpSecretGenCiphertexts[] round2Contributions);

    constructor(address[] memory _participants, uint16 _degree, bytes memory _peer_keys) {
        require(_participants.length > 0, "Need participants");
        participants = _participants;
        for (uint i = 0; i < _participants.length; i++) participantIndex[_participants[i]] = i;
        peer_keys = _peer_keys;
        degree = _degree;
    }

    function getMyId() external view returns (uint256) {
        uint256 idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");
        return idx;
    }

    function getRpNullifierKey(uint128 id) external view returns (RpSecretGenCommitment[] memory) {
        return key_storage[id];
    }

    // Initialize a new session
    function initKeyGen(uint128 id, bytes calldata ecdsaPubKey) external {
        RpNullifierGenState storage st = states[id];
        require(st.ecdsaPubKey.length == 0, "Session exists");

        st.ecdsaPubKey = ecdsaPubKey;

        uint n = participants.length;
        delete st.round1;
        delete st.round2;
        delete st.finalizeDone;
        for (uint i = 0;i<n;i++) {
            st.round1.push(RpSecretGenCommitment({ data: "" }));
            st.round2.push(RpSecretGenCiphertexts({ data: "" }));
            st.finalizeDone.push(false);
        }

        st.round2EventEmitted = false;
        st.finalizeEventEmitted = false;
        activeIds.push(id);

        // Emit Round1 event for everyone
        emit SecretGenRound1(id, degree);
    }

    // Round1 submission
    function addRound1Contribution(uint128 id, bytes calldata commitment) external {
        uint idx = participantIndex[msg.sender];
        console.log(msg.sender, "has idx:", idx);
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[id];
        require(st.ecdsaPubKey.length != 0, "Session not initialized");
        require(st.round1[idx].data.length == 0, "Already submitted");

        st.round1[idx] = RpSecretGenCommitment(commitment);

        // If all round1 submitted, emit Round2 event for everyone
        if (allRound1Submitted(st) && !st.round2EventEmitted) {
            console.log("I will emit secret gen round2");
            st.round2EventEmitted = true;
            emit SecretGenRound2(id, peer_keys);
        }
    }

    // Round2 submission
    function addRound2Contribution(uint128 id, bytes calldata ciphertext) external {
        uint idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[id];
        require(allRound1Submitted(st), "Round1 not complete");
        require(st.round2[idx].data.length == 0, "Already submitted");

        st.round2[idx] = RpSecretGenCiphertexts(ciphertext);

        // If all round2 submitted, emit Finalize event for everyone
        if (allRound2Submitted(st) && !st.finalizeEventEmitted) {
            st.finalizeEventEmitted = true;
            emit SecretGenFinalize(id, st.ecdsaPubKey, st.round2);
        }
    }

    // Finalize submission
    function addFinalizeContribtion(uint128 id) external {
        uint idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[id];
        require(allRound2Submitted(st), "Round2 not complete");
        require(!st.finalizeDone[idx], "Already submitted");

        st.finalizeDone[idx] = true;
        // If all round2 submitted, emit Finalize event for everyone
        if (allFinalizeSubmitted(st) && !st.storedNullifier) {
            st.storedNullifier = true;
            key_storage[id] = st.round1;
            console.log("created nullifier key uwu");
        }
    }


    // --- Helpers ---
    function allRound1Submitted(RpNullifierGenState storage st) internal view returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (st.round1[i].data.length == 0) return false;
        }
        return true;
    }

    function allRound2Submitted(RpNullifierGenState storage st) internal view returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (st.round2[i].data.length == 0) return false;
        }
        return true;
    }

    function allFinalizeSubmitted(RpNullifierGenState storage st) internal view returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (!st.finalizeDone[i]) return false;
        }
        return true;
    }

}
