// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Types} from "./Types.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

uint256 constant PUBLIC_INPUT_LENGTH_KEYGEN_13 = 24;
uint256 constant PUBLIC_INPUT_LENGTH_NULLIFIER = 13;
uint256 constant AUTHENTICATOR_MERKLE_TREE_DEPTH = 30;

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

contract OprfKeyRegistry is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using Types for Types.BabyJubJubElement;
    using Types for Types.Groth16Proof;
    using Types for Types.OprfPeer;
    using Types for Types.Round1Contribution;
    using Types for Types.OprfKeyGenState;
    // Gets set to ready state once OPRF participants are registered

    bool public isContractReady;

    // Admins to start KeyGens
    mapping(address => bool) public keygenAdmins;
    uint256 public amountKeygenAdmins;

    IGroth16VerifierKeyGen13 public keyGenVerifier;
    IBabyJubJub public accumulator;
    uint256 public threshold;
    uint256 public numPeers;

    // The addresses of the currently participating peers.
    address[] public peerAddresses;
    // Maps the address of a peer to its party id.
    mapping(address => Types.OprfPeer) addressToPeer;

    // The keygen states for all OPRF key identifiers.
    mapping(uint256 => Types.OprfKeyGenState) internal runningKeyGens;

    // Mapping between each OPRF key identifier and the corresponding OPRF public-key.
    mapping(uint256 => Types.BabyJubJubElement) internal oprfKeyRegistry;

    // =============================================
    //                MODIFIERS
    // =============================================
    modifier isReady() {
        _isReady();
        _;
    }

    function _isReady() internal view {
        if (!isContractReady) revert NotReady();
    }

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    function _onlyAdmin() internal view {
        if (!keygenAdmins[msg.sender]) revert OnlyAdmin();
    }

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

    // =============================================
    //                Errors
    // =============================================
    error AlreadySubmitted();
    error BadContribution();
    error DeletedId(uint256 id);
    error ImplementationNotInitialized();
    error InvalidProof();
    error LastAdmin();
    error NotAParticipant();
    error NotReady();
    error OnlyAdmin();
    error OutdatedNullifier();
    error UnexpectedAmountPeers(uint256 expectedParties);
    error UnknownId(uint256 id);
    error WrongRound();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializer function to set up the OprfKeyRegistry contract, this is not a constructor due to the use of upgradeable proxies.
    /// @param _keygenAdmin The address of the key generation administrator, only party that is allowed to start key generation processes.
    /// @param _keyGenVerifierAddress The address of the Groth16 verifier contract for key generation.
    /// @param _accumulatorAddress The address of the BabyJubJub accumulator contract.
    function initialize(address _keygenAdmin, address _keyGenVerifierAddress, address _accumulatorAddress)
        public
        virtual
        initializer
    {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        keygenAdmins[_keygenAdmin] = true;
        amountKeygenAdmins += 1;
        keyGenVerifier = IGroth16VerifierKeyGen13(_keyGenVerifierAddress);
        accumulator = IBabyJubJub(_accumulatorAddress);
        // The current version of the contract has fixed parameters due to its reliance on specific zk-SNARK circuits.
        threshold = 2;
        numPeers = 3;
        isContractReady = false;
    }

    // ==================================
    //         ADMIN FUNCTIONS
    // ==================================

    /// @notice Revokes the access of an admin (in case of key-loss or similar). In the long run we still want that this function is only callable with a threshold authentication, but for now we stick with admins being able to call this (this of course means one admin can block all others).
    //
    /// @param _keygenAdmin The admin address we want to revoke
    function revokeKeyGenAdmin(address _keygenAdmin) external virtual onlyProxy onlyInitialized onlyAdmin {
        // if the _keygenAdmin is an admin, we remove them
        if (keygenAdmins[_keygenAdmin]) {
            if (amountKeygenAdmins == 1) {
                // we don't allow the last admin to remove themselves
                revert LastAdmin();
            }
            delete keygenAdmins[_keygenAdmin];
            amountKeygenAdmins -= 1;
            emit Types.KeyGenAdminRevoked(_keygenAdmin);
        }
    }

    /// @notice Adds another admin address that is allowed to init/stop key-generations. In the long run we still want that this function is only callable with a threshold authentication, but for now we stick with admins being able to call this.
    /// @param _keygenAdmin The admin address we want to revoke
    function addKeyGenAdmin(address _keygenAdmin) external virtual onlyProxy onlyInitialized onlyAdmin {
        // if the _keygenAdmin is not yet an admin, we add them
        if (!keygenAdmins[_keygenAdmin]) {
            keygenAdmins[_keygenAdmin] = true;
            amountKeygenAdmins += 1;
            emit Types.KeyGenAdminRegistered(_keygenAdmin);
        }
    }

    /// @notice Registers the OPRF peers with their addresses and public keys. Only callable by the contract owner.
    /// @param _peerAddresses An array of addresses of the OPRF peers.
    function registerOprfPeers(address[] calldata _peerAddresses) external virtual onlyProxy onlyInitialized onlyOwner {
        if (_peerAddresses.length != numPeers) revert UnexpectedAmountPeers(numPeers);
        // delete the old participants
        for (uint256 i = 0; i < peerAddresses.length; ++i) {
            delete addressToPeer[peerAddresses[i]];
        }
        // set the new ones
        for (uint256 i = 0; i < _peerAddresses.length; i++) {
            addressToPeer[_peerAddresses[i]] = Types.OprfPeer({isParticipant: true, partyId: i});
        }
        peerAddresses = _peerAddresses;
        isContractReady = true;
    }

    /// @notice Initializes the key generation process. Tries to use the provided oprfKeyId as identifier. If the identifier is already taken, reverts the transaction.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    function initKeyGen(uint160 oprfKeyId) external virtual onlyProxy isReady onlyAdmin {
        // Check that this oprfKeyId was not used already
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (st.exists) revert AlreadySubmitted();
        st.round1 = new Types.Round1Contribution[](numPeers);
        st.round2 = new Types.SecretGenCiphertext[][](numPeers);
        for (uint256 i = 0; i < numPeers; i++) {
            st.round2[i] = new Types.SecretGenCiphertext[](numPeers);
        }
        st.round2Done = new bool[](numPeers);
        st.round3Done = new bool[](numPeers);
        st.exists = true;

        // Emit Round1 event for everyone
        emit Types.SecretGenRound1(oprfKeyId, threshold);
    }

    /// @notice Deletes the OPRF public-key and its associated material. Works during key-gen or afterwards.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    function deleteOprfPublicKey(uint160 oprfKeyId) external virtual onlyProxy isReady onlyAdmin {
        // try to delete the runningKeyGen data
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        bool needToEmitEvent = false;
        if (st.exists) {
            // delete all the material and set to deleted
            delete st.round1;
            delete st.round2;
            delete st.keyAggregate;
            delete st.round2Done;
            delete st.round3Done;
            delete st.round2EventEmitted;
            delete st.round3EventEmitted;
            delete st.finalizeEventEmitted;
            // mark the key-gen as deleted
            // we need this to prevent race conditions during the key-gen
            st.deleted = true;
            needToEmitEvent = true;
        }

        Types.BabyJubJubElement memory oprfPublicKey = oprfKeyRegistry[oprfKeyId];
        if (!_isEmpty(oprfPublicKey)) {
            // delete the created key
            delete oprfPublicKey;
            needToEmitEvent = true;
        }

        if (needToEmitEvent) {
            emit Types.KeyDeletion(oprfKeyId);
        }
    }

    // ==================================
    //        OPRF Peer FUNCTIONS
    // ==================================

    /// @notice Adds a Round 1 contribution to the key generation process. Only callable by registered OPRF peers.
    /// @param oprfKeyId The unique identifier for the key-gen.
    /// @param data The Round 1 contribution data. See `Types.Round1Contribution` for details.
    function addRound1Contribution(uint160 oprfKeyId, Types.Round1Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
        // check that commitments are not zero
        if (_isEmpty(data.commShare)) revert BadContribution();
        if (data.commCoeffs == 0) revert BadContribution();
        if (_isEmpty(data.ephPubKey)) revert BadContribution();
        // check that we started the key-gen for this OPRF public-key
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the OPRF public-key was deleted in the meantime
        if (st.deleted) revert DeletedId(oprfKeyId);
        if (st.round2EventEmitted) revert WrongRound();

        // return the partyId if sender is really a participant
        uint256 partyId = _internParticipantCheck();

        // check that we don't have double submission
        if (!_isEmpty(st.round1[partyId].commShare)) revert AlreadySubmitted();

        // Add BabyJubJub Elements together and keep running total
        _addToAggregate(st, data.commShare.x, data.commShare.y);
        st.round1[partyId] = data;
        _tryEmitRound2Event(oprfKeyId, st);
    }

    /// @notice Adds a Round 2 contribution to the key generation process. Only callable by registered OPRF peers.
    /// @param oprfKeyId The unique identifier for the key-gen.
    /// @param data The Round 2 contribution data. See `Types.Round2Contribution` for details.
    /// @dev This internally verifies the Groth16 proof provided in the contribution data to ensure it is constructed correctly.
    function addRound2Contribution(uint160 oprfKeyId, Types.Round2Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
        // check that the contribution is complete
        if (data.ciphers.length != numPeers) revert BadContribution();
        // check that we started the key-gen for this OPRF public-key.
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the OPRF public-key was deleted in the meantime
        if (st.deleted) revert DeletedId(oprfKeyId);
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

        Types.BabyJubJubElement[] memory pubKeyList = _loadPeerPublicKeys(st);
        publicInputs[0] = pubKeyList[partyId].x;
        publicInputs[1] = pubKeyList[partyId].y;
        publicInputs[2] = st.round1[partyId].commShare.x;
        publicInputs[3] = st.round1[partyId].commShare.y;
        publicInputs[4] = st.round1[partyId].commCoeffs;
        publicInputs[14] = threshold - 1;
        // peer keys
        for (uint256 i = 0; i < numPeers; ++i) {
            publicInputs[5 + i] = data.ciphers[i].cipher;
            publicInputs[5 + numPeers + (i * 2) + 0] = data.ciphers[i].commitment.x;
            publicInputs[5 + numPeers + (i * 2) + 1] = data.ciphers[i].commitment.y;
            publicInputs[15 + (i * 2) + 0] = pubKeyList[i].x;
            publicInputs[15 + (i * 2) + 1] = pubKeyList[i].y;
            publicInputs[21 + i] = data.ciphers[i].nonce;
        }
        _tryEmitRound3Event(oprfKeyId, st);
        // As last step we call the foreign contract and revert the whole transaction in case anything is wrong.
        if (!keyGenVerifier.verifyProof(data.proof.pA, data.proof.pB, data.proof.pC, publicInputs)) {
            revert InvalidProof();
        }
    }

    /// @notice Adds a Round 3 contribution to the key generation process. Only callable by registered OPRF peers.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @dev This does not require any calldata, as it is simply an acknowledgment from the peer that is is done.
    function addRound3Contribution(uint160 oprfKeyId) external virtual onlyProxy isReady {
        // check that we started the key-gen for this OPRF public-key.
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the OPRF public-key was deleted in the meantime
        if (st.deleted) revert DeletedId(oprfKeyId);
        // check that we are actually in round3
        if (!st.round3EventEmitted || st.finalizeEventEmitted) revert NotReady();
        // return the partyId if sender is really a participant
        uint256 partyId = _internParticipantCheck();
        // check that this peer did not submit anything for this round
        if (st.round3Done[partyId]) revert AlreadySubmitted();
        st.round3Done[partyId] = true;

        if (allRound3Submitted(st)) {
            // We are done! Register the OPRF public-key and emit event!
            oprfKeyRegistry[oprfKeyId] = st.keyAggregate;
            // cleanup all old data
            delete st.round1;
            delete st.round2;
            delete st.keyAggregate;
            delete st.round2Done;
            delete st.round3Done;
            // we keep the eventsEmitted and exists to prevent participants to double submit
            emit Types.SecretGenFinalize(oprfKeyId);
            st.finalizeEventEmitted = true;
        }
    }

    // ==================================
    //           HELPER FUNCTIONS
    // ==================================

    /// @notice Checks if the caller is a registered OPRF participant and returns their party ID.
    /// @return The party ID of the caller if they are a registered participant.
    function checkIsParticipantAndReturnPartyId() external view virtual isReady onlyProxy returns (uint256) {
        return _internParticipantCheck();
    }

    function _internParticipantCheck() internal view virtual returns (uint256) {
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        return peer.partyId;
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns the ephemeral public keys created in round 1 of the key gen identified by the provided oprfKeyId.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return The ephemeral public keys generated in round 1
    function checkIsParticipantAndReturnEphemeralPublicKeys(uint160 oprfKeyId)
        external
        view
        virtual
        isReady
        onlyProxy
        returns (Types.BabyJubJubElement[] memory)
    {
        // check if a participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        // check if there exists this key-gen
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(oprfKeyId);
        return _loadPeerPublicKeys(st);
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns their Round 2 ciphertexts for the specified key-gen.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return An array of Round 2 ciphertexts belonging to the caller.
    function checkIsParticipantAndReturnRound2Ciphers(uint160 oprfKeyId)
        external
        view
        virtual
        onlyProxy
        isReady
        returns (Types.SecretGenCiphertext[] memory)
    {
        // check if a participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        // check if there exists this a key-gen
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(oprfKeyId);
        // check that round2 ciphers are finished
        if (!allRound2Submitted(st)) revert NotReady();
        return st.round2[peer.partyId];
    }

    /// @notice Retrieves the specified OPRF public-key.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return The BabyJubJub element representing the nullifier public key.
    function getOprfPublicKey(uint160 oprfKeyId)
        public
        view
        virtual
        onlyProxy
        isReady
        returns (Types.BabyJubJubElement memory)
    {
        Types.BabyJubJubElement storage oprfPublicKey = oprfKeyRegistry[oprfKeyId];
        if (_isEmpty(oprfPublicKey)) revert UnknownId(oprfKeyId);
        return oprfPublicKey;
    }

    function allRound1Submitted(Types.OprfKeyGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            // we don't allow commitments to be zero, therefore if one
            // commitments is still 0, not all contributed.
            if (st.round1[i].commCoeffs == 0) return false;
        }
        return true;
    }

    function allRound2Submitted(Types.OprfKeyGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round2Done[i]) return false;
        }
        return true;
    }

    function allRound3Submitted(Types.OprfKeyGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round3Done[i]) return false;
        }
        return true;
    }

    function _loadPeerPublicKeys(Types.OprfKeyGenState storage st)
        internal
        view
        returns (Types.BabyJubJubElement[] memory)
    {
        if (!st.round2EventEmitted) revert WrongRound();
        Types.BabyJubJubElement[] memory pubKeyList = new Types.BabyJubJubElement[](numPeers);
        for (uint256 i = 0; i < numPeers; ++i) {
            pubKeyList[i] = st.round1[i].ephPubKey;
        }
        return pubKeyList;
    }

    function _tryEmitRound2Event(uint160 oprfKeyId, Types.OprfKeyGenState storage st) internal virtual {
        if (st.round2EventEmitted) return;
        if (!allRound1Submitted(st)) return;

        st.round2EventEmitted = true;
        emit Types.SecretGenRound2(oprfKeyId);
    }

    function _tryEmitRound3Event(uint160 oprfKeyId, Types.OprfKeyGenState storage st) internal virtual {
        if (st.round3EventEmitted) return;
        if (!allRound2Submitted(st)) return;

        st.round3EventEmitted = true;
        emit Types.SecretGenRound3(oprfKeyId);
    }

    function _addToAggregate(Types.OprfKeyGenState storage st, uint256 newPointX, uint256 newPointY) internal virtual {
        if (!accumulator.isOnCurve(newPointX, newPointY)) {
            revert BadContribution();
        }

        if (_isEmpty(st.keyAggregate)) {
            // We checked above that the point is on curve, so we can just set it
            st.keyAggregate = Types.BabyJubJubElement(newPointX, newPointY);
            return;
        }

        // we checked above that the new point is on curve
        // the initial aggregate is on curve as well, checked inside the if above
        // induction: sum of two on-curve points is on-curve, so the result is on-curve as well
        (uint256 resultX, uint256 resultY) = accumulator.add(st.keyAggregate.x, st.keyAggregate.y, newPointX, newPointY);

        st.keyAggregate = Types.BabyJubJubElement(resultX, resultY);
    }

    function _isInfinity(Types.BabyJubJubElement memory element) internal pure virtual returns (bool) {
        return element.x == 0 && element.y == 1;
    }

    function _isEmpty(Types.BabyJubJubElement memory element) internal pure virtual returns (bool) {
        return element.x == 0 && element.y == 0;
    }
    ////////////////////////////////////////////////////////////
    //                    Upgrade Authorization               //
    ////////////////////////////////////////////////////////////

    /**
     *
     *
     * @dev Authorize upgrade to a new implementation
     *
     *
     * @param newImplementation Address of the new implementation contract
     *
     *
     * @notice Only the contract owner can authorize upgrades
     *
     *
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     *
     *
     * @dev Storage gap to allow for future upgrades without storage collisions
     *
     *
     * This is set to take a total of 50 storage slots for future state variables
     *
     *
     */
    uint256[40] private __gap;
}
