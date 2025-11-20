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
    address public keygenAdmin;
    IGroth16VerifierKeyGen13 public keyGenVerifier;
    IBabyJubJub public accumulator;
    uint256 public threshold;
    uint256 public numPeers;

    // The addresses of the currently participating peers.
    address[] public peerAddresses;
    // Maps the address of a peer to its party id.
    mapping(address => Types.OprfPeer) addressToPeer;

    // The keygen state for each RP
    mapping(uint128 => Types.RpNullifierGenState) internal runningKeyGens;

    // Mapping between each rpId and the corresponding nullifier
    mapping(uint128 => Types.RpMaterial) internal rpRegistry;

    // =============================================
    //     ERC-4337 Support Variables
    // =============================================

    // Maps smart account addresses to their peer owners
    mapping(address => address) public smartAccountToPeer;

    // Authorized paymasters for gas sponsorship
    mapping(address => bool) public authorizedPaymasters;

    // Track if an address is a registered smart account
    mapping(address => bool) public isSmartAccount;

    // Track all smart account addresses for distinguishability
    address[] public smartAccountAddresses;

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
    error DeletedId(uint128 id);

    // New error for smart account validation
    error UnauthorizedSmartAccount();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializer function to set up the RpRegistry contract, this is not a constructor due to the use of upgradeable proxies.
    /// @param _keygenAdmin The address of the key generation administrator, only party that is allowed to start key generation processes.
    /// @param _keyGenVerifierAddress The address of the Groth16 verifier contract for key generation.
    /// @param _accumulatorAddress The address of the BabyJubJub accumulator contract.
    function initialize(
        address _keygenAdmin,
        address _keyGenVerifierAddress,
        address _accumulatorAddress
    ) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        keygenAdmin = _keygenAdmin;
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

    /// @notice Registers the OPRF peers with their addresses and public keys. Only callable by the contract owner.
    /// @param _peerAddresses An array of addresses of the OPRF peers.
    /// @param _smartAccounts An array of addresses of the associated smart accounts.
    function registerOprfPeers(
        address[] calldata _peerAddresses,
        address[] calldata _smartAccounts
    ) external virtual onlyProxy onlyInitialized onlyOwner {
        if (_peerAddresses.length != numPeers) revert UnexpectedAmountPeers(numPeers);

        // delete old participants
        for (uint256 i = 0; i < peerAddresses.length; ++i) {
            delete addressToPeer[peerAddresses[i]];
        }

        // delete old smart accounts
        for (uint256 i = 0; i < smartAccountAddresses.length; ++i) {
            address oldSmartAccount = smartAccountAddresses[i];
            delete addressToPeer[oldSmartAccount];
            delete smartAccountToPeer[oldSmartAccount];
            delete isSmartAccount[oldSmartAccount];
        }

        delete smartAccountAddresses;

        for (uint256 i = 0; i < _peerAddresses.length; i++) {
            addressToPeer[_peerAddresses[i]] = Types.OprfPeer({
                isParticipant: true,
                partyId: i
            });

            if (_smartAccounts.length > 0 && _smartAccounts[i] != address(0)) {
                smartAccountToPeer[_smartAccounts[i]] = _peerAddresses[i];
                isSmartAccount[_smartAccounts[i]] = true;
                addressToPeer[_smartAccounts[i]] = Types.OprfPeer({
                    isParticipant: true,
                    partyId: i
                });
                smartAccountAddresses.push(_smartAccounts[i]); // Track it
            }
        }

        peerAddresses = _peerAddresses;
        isContractReady = true;
    }

    /// @notice Authorize a paymaster for gas sponsorship
    /// @param paymaster The paymaster address
    /// @param authorized Whether to authorize or revoke
    function setPaymasterAuthorization(
        address paymaster,
        bool authorized
    ) external virtual onlyProxy onlyOwner {
        authorizedPaymasters[paymaster] = authorized;
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

    /// @notice Deletes the RP and its associated material. Works if during key-gen or afterwards.
    /// @param rpId The unique identifier for the RP.
    function deleteRpMaterial(uint128 rpId) external virtual onlyProxy isReady onlyAdmin {
        // try to delete the runningKeyGen data
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        bool needToEmitEvent = false;

        if (st.exists) {
            // delete all the material and set to deleted
            delete st.ecdsaPubKey;
            delete st.round1;
            delete st.round2;
            delete st.keyAggregate;
            delete st.round2Done;
            delete st.round3Done;
            delete st.round2EventEmitted;
            delete st.round3EventEmitted;
            delete st.finalizeEventEmitted;
            // mark the rp as deleted
            // we need this to prevent race conditions during the key-gen
            st.deleted = true;
            needToEmitEvent = true;
        }

        Types.RpMaterial storage material = rpRegistry[rpId];
        if (!_isEmpty(material.nullifierKey)) {
            // delete the created key and the ecdsa key
            delete material.ecdsaKey;
            delete material.nullifierKey;
            needToEmitEvent = true;
        }

        if (needToEmitEvent) {
            emit Types.KeyDeletion(rpId);
        }
    }

    // ==================================
    //      OPRF Peer FUNCTIONS
    //
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
        if (_isEmpty(data.ephPubKey)) revert BadContribution();
        // check that we started the key-gen for this rp-id
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check if the rp was deleted in the meantime
        if (st.deleted) revert DeletedId(rpId);
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
        // check if the rp was deleted in the meantime
        if (st.deleted) revert DeletedId(rpId);
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
        // check if the rp was deleted in the meantime
        if (st.deleted) revert DeletedId(rpId);
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
            delete st.round2;
            delete st.keyAggregate;
            delete st.round2Done;
            delete st.round3Done;
            // we keep the eventsEmitted and exists to prevent participants to double submit
            emit Types.SecretGenFinalize(rpId);
            st.finalizeEventEmitted = true;
        }
    }

    // ==================================
    //     ERC4337 MODIFIED HELPER FUNCTIONS
    // ==================================

    /// @notice Modified to support both EOAs and smart accounts
    function _internParticipantCheck() internal view virtual returns (uint256) {
        // First check if direct participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (peer.isParticipant) {
            return peer.partyId;
        }

        // If not, check if it's a registered smart account
        if (isSmartAccount[msg.sender]) {
            address peerOwner = smartAccountToPeer[msg.sender];
            peer = addressToPeer[peerOwner];
            if (peer.isParticipant) {
                return peer.partyId;
            }
        }

        revert NotAParticipant();
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns their party ID
    function checkIsParticipantAndReturnPartyId() external view virtual isReady onlyProxy returns (uint256) {
        return _internParticipantCheck();
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns the ephemeral public keys created in round 1 of the key gen identified by the provided rp id.
    /// @param rpId The unique identifier for the RP.
    /// @return The ephemeral public keys generated in round 1
    function checkIsParticipantAndReturnEphemeralPublicKeys(uint128 rpId)
        external
        view
        virtual
        isReady
        onlyProxy
        returns (Types.BabyJubJubElement[] memory)
    {
        _internParticipantCheck(); // Will revert if not participant

        // check if there exists this key-gen
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(rpId);
        return _loadPeerPublicKeys(st);
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
        uint256 partyId = _internParticipantCheck();

        // check if there exists this a key-gen
        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(rpId);
        // check that round2 ciphers are finished
        if (!allRound2Submitted(st)) revert NotReady();

        return st.round2[partyId];
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
    function getRpMaterial(uint128 rpId)
        external
        view
        virtual
        onlyProxy
        isReady
        returns (Types.RpMaterial memory)
    {
        Types.RpMaterial storage material = rpRegistry[rpId];
        if (_isEmpty(material.nullifierKey)) revert UnknownId(rpId);
        return rpRegistry[rpId];
    }

    // ==================================
    //    HELPER FUNCTIONS
    // ==================================

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

    function _loadPeerPublicKeys(Types.RpNullifierGenState storage st)
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

    function _addToAggregate(Types.RpNullifierGenState storage st, uint256 newPointX, uint256 newPointY) internal virtual {
        if (accumulator.isOnCurve(newPointX, newPointY) == false) {
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
    uint256[36] private __gap;
}