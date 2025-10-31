// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Types} from "./Types.sol";
import {CredentialSchemaIssuerRegistry} from "@world-id-protocol/contracts/CredentialSchemaIssuerRegistry.sol";
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

interface IGroth16VerifierNullifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[PUBLIC_INPUT_LENGTH_NULLIFIER] calldata _pubSignals
    ) external view returns (bool);
}

interface IBabyJubJub {
    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) external view returns (uint256 x3, uint256 y3);

    function isOnCurve(uint256 x, uint256 y) external view returns (bool);
}

contract RpRegistry is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using Types for Types.BabyJubJubElement;
    using Types for Types.EcDsaPubkeyCompressed;
    using Types for Types.OprfPeer;
    using Types for Types.Round1Contribution;
    using Types for Types.RpMaterial;
    using Types for Types.RpNullifierGenState;
    using Types for Types.Groth16Proof;
    // Gets set to ready state once OPRF participants are registered

    bool public isContractReady;

    // Admin to start KeyGens
    //**IMPORTANT** If this key gets lost or the entity controlling this key
    // goes offline then effectively the system halts...
    address public keygenAdmin;
    IGroth16VerifierKeyGen13 public keyGenVerifier;
    IGroth16VerifierNullifier public nullifierVerifier;
    IBabyJubJub public accumulator;
    uint256 public threshold;
    uint256 public numPeers;

    Types.BabyJubJubElement[] public peerPublicKeys;
    mapping(address => Types.OprfPeer) addressToPeer;

    // The keygen state for each RP
    mapping(uint128 => Types.RpNullifierGenState) internal runningKeyGens;

    // Mapping between each rpId and the corresponding nullifier
    mapping(uint128 => Types.RpMaterial) internal rpRegistry;

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
        if (keygenAdmin != msg.sender) revert OnlyAdmin();
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
    error ImplementationNotInitialized();
    error OnlyAdmin();
    error NotAParticipant();
    error NotReady();
    error WrongRound();
    error AlreadySubmitted();
    error UnexpectedAmountPeers(uint256 expectedParties);
    error BadContribution();
    error InvalidProof();
    error OutdatedNullifier();
    error UnknownId(uint128 id);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializer function to set up the RpRegistry contract, this is not a constructor due to the use of upgradeable proxies.
    /// @param _keygenAdmin The address of the key generation administrator, only party that is allowed to start key generation processes.
    /// @param _keyGenVerifierAddress The address of the Groth16 verifier contract for key generation.
    /// @param _nullifierVerifierAddress The address of the Groth16 verifier contract for nullifier verification.
    /// @param _accumulatorAddress The address of the BabyJubJub accumulator contract.
    /// @param _threshold The minimum number of OPRF peers required to participate.
    /// @param _numPeers The total number of OPRF peers participating.
    function initialize(
        address _keygenAdmin,
        address _keyGenVerifierAddress,
        address _nullifierVerifierAddress,
        address _accumulatorAddress,
        uint256 _threshold,
        uint256 _numPeers
    ) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        require(_numPeers >= 3);
        require(_threshold <= _numPeers);
        keygenAdmin = _keygenAdmin;
        keyGenVerifier = IGroth16VerifierKeyGen13(_keyGenVerifierAddress);
        nullifierVerifier = IGroth16VerifierNullifier(_nullifierVerifierAddress);
        accumulator = IBabyJubJub(_accumulatorAddress);
        threshold = _threshold;
        numPeers = _numPeers;
        isContractReady = false;
    }

    // ==================================
    //         ADMIN FUNCTIONS
    // ==================================

    /// @notice Registers the OPRF peers with their addresses and public keys. Only callable by the contract owner.
    /// @param _peerAddresses An array of addresses of the OPRF peers.
    /// @param _peerPublicKeys An array of BabyJubJub public keys corresponding to the OPRF peers.
    function registerOprfPeers(address[] calldata _peerAddresses, Types.BabyJubJubElement[] calldata _peerPublicKeys)
        external
        virtual
        onlyProxy
        onlyInitialized
        onlyOwner
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

    /// @notice Initializes the key generation process for a new RP.
    /// @param rpId The unique identifier for the RP.
    /// @param ecdsaPubKey The compressed ECDSA public key for the RP.
    function initKeyGen(uint128 rpId, Types.EcDsaPubkeyCompressed calldata ecdsaPubKey)
        external
        virtual
        onlyProxy
        isReady
        onlyAdmin
    {
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
    //        Public FUNCTIONS
    // ==================================

    /// @notice Verifies a nullifier proof. Retrieves the RP-specific information and uses is in the verification process.
    /// @param nullifier The nullifier to be verified.
    /// @param nullifierAction The action associated with the nullifier.
    /// @param rpId The unique identifier for the RP.
    /// @param identityCommitment The identity commitment of the user.
    /// @param nonce A nonce value for the proof.
    /// @param signalHash The signalHash associated with the proof.
    /// @param authenticatorMerkleRoot The Merkle root of the authenticator tree, already validated by the caller.
    /// @param proofTimestamp The timestamp when the proof was generated.
    /// @param credentialPublicKey The public key of the credential schema issuer, already validated by the caller.
    /// @param proof The Groth16 proof to be verified.
    /// @return A boolean indicating whether the proof is valid.
    function verifyNullifierProof(
        uint256 nullifier,
        uint256 nullifierAction,
        uint128 rpId,
        uint256 identityCommitment,
        uint256 nonce,
        uint256 signalHash,
        uint256 authenticatorMerkleRoot,
        uint256 proofTimestamp,
        CredentialSchemaIssuerRegistry.Pubkey calldata credentialPublicKey,
        Types.Groth16Proof calldata proof
    ) external view virtual onlyProxy isReady returns (bool) {
        // do not allow proofs from the future
        if (proofTimestamp > block.timestamp) {
            revert OutdatedNullifier();
        }
        // do not allow proofs older than 5 hours
        if (proofTimestamp + 5 hours < block.timestamp) {
            revert OutdatedNullifier();
        }

        // check if we have a valid rp id and get the rp material if so
        Types.BabyJubJubElement memory rpKey = getRpNullifierKey(rpId);

        // for this specific proof, we have 13 public signals
        // [0]: identity commitment
        // [1]: nullifier
        // [2]: credential public key x coordinate
        // [3]: credential public key y coordinate
        // [4]: current time stamp
        // [5]: Authenticator merkle tree root hash
        // [6]: Current depth of the Authenticator merkle tree
        // [7]: RP ID
        // [8]: Nullifier action
        // [9]: RP OPRF public key x coordinate
        // [10]: RP OPRF public key y coordinate
        // [11]: signal hash
        // [12]: nonce for the RP signature
        // use calldata since we set it once
        uint256[13] memory pubSignals;

        pubSignals[0] = identityCommitment;
        pubSignals[1] = nullifier;
        pubSignals[2] = credentialPublicKey.x;
        pubSignals[3] = credentialPublicKey.y;
        pubSignals[4] = proofTimestamp;
        pubSignals[5] = authenticatorMerkleRoot;
        pubSignals[6] = AUTHENTICATOR_MERKLE_TREE_DEPTH;
        pubSignals[7] = uint256(rpId);
        pubSignals[8] = nullifierAction;
        pubSignals[9] = rpKey.x;
        pubSignals[10] = rpKey.y;
        pubSignals[11] = signalHash;
        pubSignals[12] = nonce;

        return nullifierVerifier.verifyProof(proof.pA, proof.pB, proof.pC, pubSignals);
    }

    // ==================================
    //        OPRF Peer FUNCTIONS
    // ==================================

    /// @notice Adds a Round 1 contribution to the key generation process for a specific RP. Only callable by registered OPRF peers.
    /// @param rpId The unique identifier for the RP.
    /// @param data The Round 1 contribution data. See `Types.Round1Contribution` for details.
    function addRound1Contribution(uint128 rpId, Types.Round1Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
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

    /// @notice Adds a Round 2 contribution to the key generation process for a specific RP. Only callable by registered OPRF peers.
    /// @param rpId The unique identifier for the RP.
    /// @param data The Round 2 contribution data. See `Types.Round2Contribution` for details.
    /// @dev This internally verifies the Groth16 proof provided in the contribution data to ensure it is constructed correctly.
    function addRound2Contribution(uint128 rpId, Types.Round2Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
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
        if (!keyGenVerifier.verifyProof(data.proof.pA, data.proof.pB, data.proof.pC, publicInputs)) {
            revert InvalidProof();
        }
    }

    /// @notice Adds a Round 3 contribution to the key generation process for a specific RP. Only callable by registered OPRF peers.
    /// @param rpId The unique identifier for the RP.
    /// @dev This does not require any calldata, as it is simply an acknowledgment from the peer that is is done.
    function addRound3Contribution(uint128 rpId) external virtual onlyProxy isReady {
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

    /// @notice Checks if the caller is a registered OPRF participant and returns their Round 2 ciphertexts for a specific RP.
    /// @param rpId The unique identifier for the RP.
    /// @return An array of Round 2 ciphertexts belonging to the caller.
    function checkIsParticipantAndReturnRound2Ciphers(uint128 rpId)
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
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check that round2 ciphers are finished
        if (!allRound2Submitted(st)) revert NotReady();
        return st.round2[peer.partyId];
    }

    /// @notice Retrieves the public keys of all registered OPRF peers.
    /// @return An array of BabyJubJub public keys of the OPRF peers.
    function getPeerPublicKeys() external view virtual onlyProxy isReady returns (Types.BabyJubJubElement[] memory) {
        return peerPublicKeys;
    }

    /// @notice Retrieves the nullifier public key for a specific RP.
    /// @param rpId The unique identifier for the RP.
    /// @return The BabyJubJub element representing the nullifier public key for the specified RP.
    function getRpNullifierKey(uint128 rpId)
        public
        view
        virtual
        onlyProxy
        isReady
        returns (Types.BabyJubJubElement memory)
    {
        Types.RpMaterial storage material = rpRegistry[rpId];
        if (_isEmpty(material.nullifierKey)) revert UnknownId(rpId);
        return rpRegistry[rpId].nullifierKey;
    }

    /// @notice Retrieves the RP material (ECDSA public key and nullifier key) for a specific RP.
    /// @param rpId The unique identifier for the RP.
    /// @return The RpMaterial struct containing the ECDSA public key and nullifier key for the specified RP.
    function getRpMaterial(uint128 rpId) external view virtual onlyProxy isReady returns (Types.RpMaterial memory) {
        Types.RpMaterial storage material = rpRegistry[rpId];
        if (_isEmpty(material.nullifierKey)) revert UnknownId(rpId);
        return rpRegistry[rpId];
    }

    function allRound1Submitted(Types.RpNullifierGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            // we don't allow commitments to be zero, therefore if one
            // commitments is still 0, not all contributed.
            if (st.round1[i].commCoeffs == 0) return false;
        }
        return true;
    }

    function allRound2Submitted(Types.RpNullifierGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round2Done[i]) return false;
        }
        return true;
    }

    function allRound3Submitted(Types.RpNullifierGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round3Done[i]) return false;
        }
        return true;
    }

    function _tryEmitRound2Event(uint128 rpId, Types.RpNullifierGenState storage st) internal virtual {
        if (st.round2EventEmitted) return;
        if (!allRound1Submitted(st)) return;

        st.round2EventEmitted = true;
        emit Types.SecretGenRound2(rpId);
    }

    function _tryEmitRound3Event(uint128 rpId, Types.RpNullifierGenState storage st) internal virtual {
        if (st.round3EventEmitted) return;
        if (!allRound2Submitted(st)) return;

        st.round3EventEmitted = true;
        emit Types.SecretGenRound3(rpId);
    }

    function _addToAggregate(Types.RpNullifierGenState storage st, uint256 newPointX, uint256 newPointY)
        internal
        virtual
    {
        if (_isEmpty(st.keyAggregate)) {
            st.keyAggregate = Types.BabyJubJubElement(newPointX, newPointY);
            return;
        }

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
