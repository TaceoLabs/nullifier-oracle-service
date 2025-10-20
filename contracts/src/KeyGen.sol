// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Types.sol";
import {console} from "forge-std/Script.sol";

uint256 constant PUBLIC_INPUT_LENGTH_KEYGEN_13 = 24;

interface IGroth16VerifierKeyGen13 {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[PUBLIC_INPUT_LENGTH_KEYGEN_13] calldata _pubSignals
    ) external view returns (bool);
}

interface IBabyJubJub {
    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) external view returns (uint256 x3, uint256 y3);

    function isOnCurve(uint256 x, uint256 y) external view returns (bool);
}

contract KeyGen {
    using Types for Types.BabyJubJubElement;
    using Types for Types.EcDsaPubkeyCompressed;
    using Types for Types.OprfPeer;
    using Types for Types.Round1Contribution;
    using Types for Types.RpMaterial;
    using Types for Types.RpNullifierGenState;
    // Gets set to ready state once OPRF participants are registered

    bool public isContractReady;

    // Admin to start KeyGens
    //**IMPORTANT** If this key gets lost or the entity controlling this key
    // goes offline then effectively the system halts...
    address public immutable taceoAdmin;
    IGroth16VerifierKeyGen13 public immutable verifier;
    IBabyJubJub public immutable accumulator;
    uint256 public immutable threshold;
    uint256 public immutable numPeers;

    Types.BabyJubJubElement[] public peerPublicKeys;
    mapping(address => Types.OprfPeer) addressToPeer;

    // The keygen state for each RP
    mapping(uint128 => Types.RpNullifierGenState) internal runningKeyGens;

    // Mapping between each rpId and the corresponding nullifier
    mapping(uint128 => Types.RpMaterial) internal rpRegistry;

    modifier isReady() {
        if (!isContractReady) revert NotReady();
        _;
    }

    modifier onlyTACEO() {
        if (taceoAdmin != msg.sender) revert OnlyTACEO();
        _;
    }

    error OnlyTACEO();
    error NotAParticipant();
    error NotReady();
    error WrongRound();
    error AlreadySubmitted();
    error UnexpectedAmountPeers(uint256 expectedParties);
    error BadContribution();
    error InvalidProof();
    error UnknownId(uint128 id);

    constructor(
        address _taceoAdmin,
        address _verifierAddress,
        address _accumulatorAddress,
        uint256 _threshold,
        uint256 _numPeers
    ) {
        require(_numPeers >= 3);
        require(_threshold <= _numPeers);
        taceoAdmin = _taceoAdmin;
        verifier = IGroth16VerifierKeyGen13(_verifierAddress);
        accumulator = IBabyJubJub(_accumulatorAddress);
        threshold = _threshold;
        numPeers = _numPeers;
        isContractReady = false;
    }

    // ==================================
    //          TACEO FUNCTIONS
    // ==================================

    function registerOprfPeers(address[] calldata _peerAddresses, Types.BabyJubJubElement[] calldata _peerPublicKeys)
        external
        onlyTACEO
    {
        if (isContractReady) revert AlreadySubmitted();
        if (_peerAddresses.length != numPeers) revert UnexpectedAmountPeers(numPeers);
        if (_peerPublicKeys.length != numPeers) revert UnexpectedAmountPeers(numPeers);
        peerPublicKeys = _peerPublicKeys;
        for (uint256 i = 0; i < _peerAddresses.length; i++) {
            addressToPeer[_peerAddresses[i]] = Types.OprfPeer({isParticipant: true, partyId: i});
        }
        isContractReady = true;
    }

    function initKeyGen(uint128 rpId, Types.EcDsaPubkeyCompressed calldata ecdsaPubKey) external onlyTACEO isReady {
        // Check that this rpId was not used already
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (st.exists) revert AlreadySubmitted();
        // We store the ecdsa key in compressed form - therefore we need to enforce
        // that the parity bit is set to 2 or 3 (as produced by to_sec1_bytes in rust)
        if (ecdsaPubKey.yParity != 2 && ecdsaPubKey.yParity != 3) revert BadContribution();

        st.ecdsaPubKey = ecdsaPubKey;
        st.round1 = new Types.Round1Contribution[](numPeers);
        st.round2 = new Types.SecretGenCiphertext[][](numPeers);
        for (uint256 i = 0; i < numPeers; i++) {
            st.round2[i] = new Types.SecretGenCiphertext[](numPeers);
        }
        st.round2Done = new bool[](numPeers);
        st.round3Done = new bool[](numPeers);
        st.exists = true;

        // Emit Round1 event for everyone
        emit Types.SecretGenRound1(rpId, threshold);
    }

    // ==================================
    //        OPRF Peer FUNCTIONS
    // ==================================

    function addRound1Contribution(uint128 rpId, Types.Round1Contribution calldata data) external isReady {
        // check that commitments are not zero
        if (_isEmpty(data.commShare)) revert BadContribution();
        if (data.commCoeffs == 0) revert BadContribution();
        // check that we started the key-gen for this rp-id
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        if (st.round2EventEmitted) revert WrongRound();

        // return the partyId if sender is really a participant
        uint256 partyId = _internParticipantCheck();

        // check that we don't have double submission
        if (!_isEmpty(st.round1[partyId].commShare)) revert AlreadySubmitted();

        // Add BabyJubJub Elements together and keep running total
        _addToAggregate(st, data.commShare.x, data.commShare.y);
        st.round1[partyId] = data;
        _tryEmitRound2Event(rpId, st);
    }

    function addRound2Contribution(uint128 rpId, Types.Round2Contribution calldata data) external isReady {
        // check that the contribution is complete
        if (data.ciphers.length != numPeers) revert BadContribution();
        // check that we started the key-gen for this rp-id
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check that we are actually in round2
        if (!st.round2EventEmitted || st.round3EventEmitted) revert WrongRound();
        // return the partyId if sender is really a participant
        uint256 partyId = _internParticipantCheck();
        // check that this peer did not submit anything for this round
        if (st.round2Done[partyId]) revert AlreadySubmitted();

        // everything looks good - push the ciphertexts
        for (uint256 i = 0; i < numPeers; ++i) {
            st.round2[i][partyId] = data.ciphers[i];
        }
        // set the contribution to done
        st.round2Done[partyId] = true;

        // last step verify the proof and potentially revert if proof fails

        // build the public input:
        // 1) PublicKey from sender (Affine Point Babyjubjub)
        // 2) Commitment to share (Affine Point Babyjubjub)
        // 3) Commitment to coeffs (Basefield Babyjubjub)
        // 4) Ciphertexts for peers (in this case 3 Basefield BabyJubJub)
        // 5) Commitments to plaintexts (in this case 3 Affine Points BabyJubJub)
        // 6) Degree (Basefield BabyJubJub)
        // 7) Public Keys from peers (in this case 3 Affine Points BabyJubJub)
        // 8) Nonces (in this case 3 Basefield BabyJubJub)
        // verifier.verifyProof();
        uint256[PUBLIC_INPUT_LENGTH_KEYGEN_13] memory publicInputs;

        publicInputs[0] = peerPublicKeys[partyId].x;
        publicInputs[1] = peerPublicKeys[partyId].y;
        publicInputs[2] = st.round1[partyId].commShare.x;
        publicInputs[3] = st.round1[partyId].commShare.y;
        publicInputs[4] = st.round1[partyId].commCoeffs;
        publicInputs[14] = threshold - 1;
        // peer keys
        for (uint256 i = 0; i < numPeers; ++i) {
            publicInputs[5 + i] = data.ciphers[i].cipher;
            publicInputs[5 + numPeers + (i * 2) + 0] = data.ciphers[i].commitment.x;
            publicInputs[5 + numPeers + (i * 2) + 1] = data.ciphers[i].commitment.y;
            publicInputs[15 + (i * 2) + 0] = peerPublicKeys[i].x;
            publicInputs[15 + (i * 2) + 1] = peerPublicKeys[i].y;
            publicInputs[21 + i] = data.ciphers[i].nonce;
        }
        _tryEmitRound3Event(rpId, st);
        // As last step we call the foreign contract and revert the whole transaction in case anything is wrong.
        if (!verifier.verifyProof(data.proof.pA, data.proof.pB, data.proof.pC, publicInputs)) revert InvalidProof();
    }

    function addRound3Contribution(uint128 rpId) external isReady {
        // check that we started the key-gen for this rp-id
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check that we are actually in round3
        if (!st.round3EventEmitted || st.finalizeEventEmitted) revert NotReady();
        // return the partyId if sender is really a participant
        uint256 partyId = _internParticipantCheck();
        // check that this peer did not submit anything for this round
        if (st.round3Done[partyId]) revert AlreadySubmitted();
        st.round3Done[partyId] = true;

        if (allRound3Submitted(st)) {
            // We are done! Register the RP and emit event!
            rpRegistry[rpId] = Types.RpMaterial({ecdsaKey: st.ecdsaPubKey, nullifierKey: st.keyAggregate});
            // cleanup all old data
            delete st.ecdsaPubKey;
            delete st.round1;
            // we keep round2 ciphertexts in case we need to restore shares
            delete st.keyAggregate;
            delete st.round2Done;
            delete st.round3Done;
            // we keep the eventsEmitted and exists to prevent participants to double submit
            emit Types.SecretGenFinalize(rpId);
            st.finalizeEventEmitted = true;
        }
    }

    // ==================================
    //           HELPER FUNCTIONS
    // ==================================

    // must be accessible for Rust land - therefore we call the internal function that is called elsewhere as well.
    function checkIsParticipantAndReturnPartyId() external view isReady returns (uint256) {
        return _internParticipantCheck();
    }

    function _internParticipantCheck() internal view returns (uint256) {
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        return peer.partyId;
    }

    function checkIsParticipantAndReturnRound2Ciphers(uint128 rpId)
        external
        view
        isReady
        returns (Types.SecretGenCiphertext[] memory)
    {
        // check if a participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        // check if there exists this a key-gen
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check that round2 ciphers are finished
        if (!allRound2Submitted(st)) revert NotReady();
        return st.round2[peer.partyId];
    }

    function getPeerPublicKeys() external view isReady returns (Types.BabyJubJubElement[] memory) {
        return peerPublicKeys;
    }

    function getRpNullifierKey(uint128 rpId) external view isReady returns (Types.BabyJubJubElement memory) {
        Types.RpMaterial storage material = rpRegistry[rpId];
        if (_isEmpty(material.nullifierKey)) revert UnknownId(rpId);
        return rpRegistry[rpId].nullifierKey;
    }

    function getRpMaterial(uint128 rpId) external view isReady returns (Types.RpMaterial memory) {
        Types.RpMaterial storage material = rpRegistry[rpId];
        if (_isEmpty(material.nullifierKey)) revert UnknownId(rpId);
        return rpRegistry[rpId];
    }

    function allRound1Submitted(Types.RpNullifierGenState storage st) private view returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            // we don't allow commitments to be zero, therefore if one
            // commitments is still 0, not all contributed.
            if (st.round1[i].commCoeffs == 0) return false;
        }
        return true;
    }

    function allRound2Submitted(Types.RpNullifierGenState storage st) private view returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round2Done[i]) return false;
        }
        return true;
    }

    function allRound3Submitted(Types.RpNullifierGenState storage st) private view returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round3Done[i]) return false;
        }
        return true;
    }

    function _tryEmitRound2Event(uint128 rpId, Types.RpNullifierGenState storage st) private {
        if (st.round2EventEmitted) return;
        if (!allRound1Submitted(st)) return;

        st.round2EventEmitted = true;
        emit Types.SecretGenRound2(rpId);
    }

    function _tryEmitRound3Event(uint128 rpId, Types.RpNullifierGenState storage st) private {
        if (st.round3EventEmitted) return;
        if (!allRound2Submitted(st)) return;

        st.round3EventEmitted = true;
        emit Types.SecretGenRound3(rpId);
    }

    function _addToAggregate(Types.RpNullifierGenState storage st, uint256 newPointX, uint256 newPointY) private {
        if (_isEmpty(st.keyAggregate)) {
            st.keyAggregate = Types.BabyJubJubElement(newPointX, newPointY);
            return;
        }

        (uint256 resultX, uint256 resultY) = accumulator.add(st.keyAggregate.x, st.keyAggregate.y, newPointX, newPointY);

        st.keyAggregate = Types.BabyJubJubElement(resultX, resultY);
    }

    function _isInfinity(Types.BabyJubJubElement memory element) private pure returns (bool) {
        return element.x == 0 && element.y == 1;
    }

    function _isEmpty(Types.BabyJubJubElement memory element) private pure returns (bool) {
        return element.x == 0 && element.y == 0;
    }
}
