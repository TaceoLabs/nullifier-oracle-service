// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";

contract KeyGen {
    address[] public participants;

    mapping(address => uint256) public participantIndex; // participant -> index

    // The the keygen state for each RP
    mapping(uint128 => RpNullifierGenState) internal states;

    // Mapping between each rpId and the corresponding nullifier
    mapping(uint128 => RpSecretGenCommitment[]) internal keyStorage;

    uint128[] public activeIds;

    bytes public peerKeys;
    uint16 public threshold;

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
    event SecretGenRound1(uint128 indexed rpId, uint16 threshold);
    event SecretGenRound2(uint128 indexed rpId, bytes peerPublicKeyList);
    event SecretGenFinalize(uint128 indexed rpId, bytes rpPublicKey, RpSecretGenCiphertexts[] round2Contributions);
    event SecretGenNullifierKeyCreated(uint128 indexed rpId, bytes rpNullifierKey);

    constructor(address[] memory _participants, uint16 _threshold, bytes memory _peerKeys) {
        require(_participants.length > 0, "Need participants");
        participants = _participants;
        for (uint i = 0; i < _participants.length; i++) participantIndex[_participants[i]] = i;
        peerKeys = _peerKeys;
        threshold = _threshold;
    }

    function getMyId() external view returns (uint256) {
        uint256 idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");
        return idx;
    }

    function getPeerKeys() external view returns (bytes memory) {
        return peerKeys;
    }

    function getRpNullifierKey(uint128 rpId) external view returns (RpSecretGenCommitment[] memory) {
        return keyStorage[id];
    }

    // Initialize a new session
    // TODO: Who can initiate the keygen? Just one of the parties??
    // TODO: Can the person have the ecdsaPubKey be empty and then delete rounds
    // i.e. initKeyGen(1, realpubkey) then later initKeyGen(1, emptypubkey)
    // Dont we need to ensure that the ecdsaPubKey they provide isnt empty?
    function initKeyGen(uint128 rpId, bytes calldata ecdsaPubKey) external {
        uint idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");

        // If this check is not in then someone can rerun the same round over and over again
        require(ecdsaPubKey.length != 0, "submitting faulty empty ECDSA key");

        RpNullifierGenState storage st = states[rpId];
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
        activeIds.push(rpId);

        // Emit Round1 event for everyone
        emit SecretGenRound1(rpId, threshold);
    }

    // Round1 submission
    function addRound1Contribution(uint128 rpId, bytes calldata commitment) external {
        uint idx = participantIndex[msg.sender];
        console.log(msg.sender, "has idx:", idx);
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[rpId];
        require(st.ecdsaPubKey.length != 0, "Session not initialized");
        require(st.round1[idx].data.length == 0, "Already submitted");

        //TODO: Add BabyJubJub Points together and keep running total
        // Here is just a single commitment...
        st.round1[idx] = RpSecretGenCommitment(commitment);


        _tryEmitRound2Event(rpId, st);
    }

    // Round2 submission
    function addRound2Contribution(uint128 rpId, bytes calldata ciphertext) external {
        uint idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[rpId];
        require(allRound1Submitted(st), "Round1 not complete");
        require(ciphertext.length != 0, "Submitted empty ciphertext");
        // TODO: Check if this check can be cheated
        require(st.round2[idx].data.length == 0, "Already submitted");

        // TODO: verifyProof(proof, ciphertext, commitment);

        st.round2[idx] = RpSecretGenCiphertexts(ciphertext);

        _tryEmitFinalizeEvent(rpId, st);
    }

    // Finalize submission
    function addFinalizeContribtion(uint128 rpId) external {
        uint idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[rpId];
        require(allRound2Submitted(st), "Round2 not complete");
        require(!st.finalizeDone[idx], "Already submitted");

        st.finalizeDone[idx] = true;
        // If all round2 submitted, emit Finalize event for everyone
       _tryEmitNullifierKeyCreatedEvent(rpId, st);
    }

    // --- Helpers ---
    function allRound1Submitted(RpNullifierGenState storage st) private returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (st.round1[i].data.length == 0) return false;
        }
        return true;
    }

    function allRound2Submitted(RpNullifierGenState storage st) private returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (st.round2[i].data.length == 0) return false;
        }
        return true;
    }

    function allFinalizeSubmitted(RpNullifierGenState storage st) private returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (!st.finalizeDone[i]) return false;
        }
        return true;
    }

    function _tryEmitRound2Event(uint128 rpId, RpNullifierGenState storage st) private {
        if (st.round2EventEmitted) return;
        if (!allRound1Submitted(st)) return;

        st.round2EventEmitted = true;

        console.log("Emitting secret gen round2");
        emit SecretGenRound2(rpId, peerKeys);
    }

    function _tryEmitFinalizeEvent(uint128 rpId, RpNullifierGenState storage st) private {
        if (st.finalizeEventEmitted) return;
        if (!allRound2Submitted(st)) return;

        st.finalizeEventEmitted = true;

        console.log("Emitting secret gen round2");
        emit SecretGenFinalize(rpId, st.ecdsaPubKey, st.round2);
    }

    function _tryEmitNullifierKeyCreatedEvent(uint128 rpId, RpNullifierGenState storage st) private {
        if (st.storedNullifier) return;
        if (!allFinalizeSubmitted(st)) return;

        st.storedNullifier = true;
        //TODO: Need to set this to be the actual added full key...
        keyStorage[rpId] = st.round1;

        console.log("created nullifier key");
        emit SecretGenNullifierKeyCreated(rpId, st.round1);
    }

}
