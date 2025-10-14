// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/console.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[24] calldata _pubSignals
    ) external view returns (bool);
}

interface IBabyJubjub {
    function add(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) external view returns (uint256 x3, uint256 y3);

    function isOnCurve(
        uint256 x,
        uint256 y
    ) external view returns (bool);
}

contract KeyGen {
    IGroth16Verifier public immutable verifier;
    IBabyJubjub public immutable accumulator;

    struct Groth16Proof {
        uint[2] pA;
        uint[2][2] pB;
        uint[2] pC;
        uint[24] pubSignals;
    }

    struct BabyJubjubElement {
        uint256 pointX;
        uint256 pointY;
    }

    struct Round1Data {
        BabyJubjubElement commShare;
        // Hash of the polynomial created by participant
        uint256 commCoeffs;
    }

    address[] public participants;

    // participant -> party ID
    mapping(address => uint256) public participantIndex;

    // The keygen state for each RP
    mapping(uint128 => RpNullifierGenState) internal states;

    // The keygen state for each RP
    mapping(uint128 => bool) internal startedKeyGens;

    // Mapping between each rpId and the corresponding nullifier
    // TODO: What type should this be?
    mapping(uint128 => BabyJubjubElement) internal keyStorage;

    bytes public peerKeys;
    uint16 public threshold;

    struct RpSecretGenCommitment { bytes data; }
    struct RpSecretGenCiphertexts { bytes data; }

    struct RpNullifierGenState {
        bytes ecdsaPubKey; // session key
        Round1Data[] round1;
        RpSecretGenCiphertexts[] round2;
        BabyJubjubElement keyAggregate;
        bool[] finalizeDone;
        bool round2EventEmitted;
        bool finalizeEventEmitted;
        bool storedNullifier;
    }

    // Events
    event SecretGenRound1(uint128 indexed rpId, uint16 threshold);
    event SecretGenRound2(uint128 indexed rpId, bytes peerPublicKeyList);
    event SecretGenFinalize(uint128 indexed rpId, bytes rpPublicKey, Round1Data[] round1Contributions, RpSecretGenCiphertexts[] round2Contributions);
    event SecretGenNullifierKeyCreated(uint128 indexed rpId, BabyJubjubElement nullifierKey);

    constructor(
        address _verifierAddress,
        address _accumulatorAddress,
        address[] memory _participants,
        uint16 _threshold,
        bytes memory _peerKeys
    ) {
        require(_participants.length > 0, "Need participants");
        participants = _participants;
        for (uint i = 0; i < _participants.length; i++) participantIndex[_participants[i]] = i;
        peerKeys = _peerKeys;
        threshold = _threshold;
        // Pass in correct groth16 verifier contract address
        verifier = IGroth16Verifier(_verifierAddress);
        accumulator = IBabyJubjub(_accumulatorAddress);
    }

    function getMyId() external view returns (uint256) {
        uint256 idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");
        return idx;
    }

    function getPeerKeys() external view returns (bytes memory) {
        return peerKeys;
    }

    function getRpNullifierKey(uint128 rpId) external view returns (BabyJubjubElement memory) {
        return keyStorage[rpId];
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

        // Check that this rpId was not used already
        require(!startedKeyGens[rpId], "already started keygen for this id");

        RpNullifierGenState storage st = states[rpId];
        require(st.ecdsaPubKey.length == 0, "Session exists");

        st.ecdsaPubKey = ecdsaPubKey;

        uint n = participants.length;
        st.round1 = new Round1Data[](n);
        delete st.round2;
        delete st.finalizeDone;
        for (uint i = 0;i<n;i++) {
            st.round2.push(RpSecretGenCiphertexts({ data: "" }));
            st.finalizeDone.push(false);
        }

        st.round2EventEmitted = false;
        st.finalizeEventEmitted = false;
        st.keyAggregate.pointX = 0;
        st.keyAggregate.pointY = 0;

        // mark the key gen as started
        startedKeyGens[rpId] = true;

        // Emit Round1 event for everyone
        emit SecretGenRound1(rpId, threshold);
    }

    // Round1 submission
    function addRound1Contribution(
        uint128 rpId,
        Round1Data calldata data
    ) external {
        uint idx = participantIndex[msg.sender];
        console.log(msg.sender, "has idx:", idx);
        require(idx < participants.length, "Not a participant");

        // check that commitments are not zero
        require(!_isEmpty(data.commShare), "Cannot use null commitment share");
        require(data.commCoeffs != 0, "Cannot use null commitment");

        // check that we started the key-gen for this rp-id
        require(startedKeyGens[rpId], "RpId does not have a running key-gen");

        RpNullifierGenState storage st = states[rpId];
        // check that we don't have double submission
        require(_isEmpty(st.round1[idx].commShare), "Already submitted");
        require(st.round1[idx].commCoeffs == 0, "Already submitted");

        // Add BabyJubJub Elements together and keep running total
        uint256 pointX = data.commShare.pointX;
        uint256 pointY = data.commShare.pointY;
        _addToAggregate(st, pointX, pointY);

        st.round1[idx] = data;

        _tryEmitRound2Event(rpId, st);
    }

    // Round2 submission
    function addRound2Contribution(
        uint128 rpId,
        bytes calldata ciphertext,
        Groth16Proof calldata proof
    ) external {
        uint idx = participantIndex[msg.sender];
        require(idx < participants.length, "Not a participant");

        RpNullifierGenState storage st = states[rpId];
        require(allRound1Submitted(st), "Round1 not complete");
        require(ciphertext.length != 0, "Submitted empty ciphertext");
        // TODO: Check if this check can be cheated
        require(st.round2[idx].data.length == 0, "Already submitted");

        require(
            verifier.verifyProof(proof.pA, proof.pB, proof.pC, proof.pubSignals),
            "Invalid proof for contributions"
        );

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
    function allRound1Submitted(RpNullifierGenState storage st) private view returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            // we don't allow commitments to be zero, therefore if one
            // commitments is still 0, not all contributed.
            if (st.round1[i].commCoeffs == 0) return false;
        }
        return true;
    }

    function allRound2Submitted(RpNullifierGenState storage st) private view returns (bool) {
        for (uint i = 0; i < participants.length; i++) {
            if (st.round2[i].data.length == 0) return false;
        }
        return true;
    }

    function allFinalizeSubmitted(RpNullifierGenState storage st) private view returns (bool) {
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
        //TODO: Is this the correct type...?????
        keyStorage[rpId] = st.keyAggregate;

        emit SecretGenNullifierKeyCreated(rpId, st.keyAggregate);
    }

    function _addToAggregate(
        RpNullifierGenState storage st,
        uint256 newPointX,
        uint256 newPointY
    ) private {
        if (_isEmpty(st.keyAggregate)) {
            st.keyAggregate = BabyJubjubElement(newPointX, newPointY);
            return;
        }

        (uint256 resultX, uint256 resultY) = accumulator.add(
            st.keyAggregate.pointX,
            st.keyAggregate.pointY,
            newPointX,
            newPointY
        );

        st.keyAggregate = BabyJubjubElement(resultX, resultY);
    }

    function _isInfinity(BabyJubjubElement memory element) private view returns (bool) {
        return element.pointX == 0 && element.pointY == 1;
    }

    function _isEmpty(BabyJubjubElement memory element) private view returns (bool) {
        return element.pointX == 0 && element.pointY == 0;
    }

}
