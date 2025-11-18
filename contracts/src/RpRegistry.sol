// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Types} from "./Types.sol";
import {CredentialSchemaIssuerRegistry} from "@world-id-protocol/contracts/CredentialSchemaIssuerRegistry.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

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

interface IPaymaster {
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external;
}

enum PostOpMode {
    opSucceeded,
    opReverted,
    postOpReverted
}

contract RpRegistry is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable, BaseAccount {
    using Types for Types.BabyJubJubElement;
    using Types for Types.EcDsaPubkeyCompressed;
    using Types for Types.OprfPeer;
    using Types for Types.Round1Contribution;
    using Types for Types.RpMaterial;
    using Types for Types.RpNullifierGenState;
    using Types for Types.Groth16Proof;

    // =============================================
    //           ERC-4337 State Variables
    // =============================================

    IEntryPoint private immutable _entryPoint;
    address public trustedPaymaster;
    mapping(address => bool) public authorizedPaymasters;
    mapping(address => uint256) public accountNonces;

    // Gas sponsorship tracking
    mapping(address => uint256) public sponsoredGasUsed;
    mapping(address => uint256) public sponsorshipLimits;

    // =============================================
    //           State Variables
    // =============================================

    bool public isContractReady;
    address public keygenAdmin;
    IGroth16VerifierKeyGen13 public keyGenVerifier;
    IBabyJubJub public accumulator;
    uint256 public threshold;
    uint256 public numPeers;
    address[] public peerAddresses;
    mapping(address => Types.OprfPeer) addressToPeer;
    mapping(uint128 => Types.RpNullifierGenState) internal runningKeyGens;
    mapping(uint128 => Types.RpMaterial) internal rpRegistry;

    // =============================================
    //                Events
    // =============================================

    event PaymasterAuthorized(address indexed paymaster, bool authorized);
    event SponsorshipLimitSet(address indexed account, uint256 limit);
    event GasSponsored(address indexed account, address indexed paymaster, uint256 gasUsed);
    event UserOperationExecuted(address indexed account, address indexed paymaster, bool success);

    // =============================================
    //                Errors
    // =============================================

    // Registry specific errors
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

    // ERC-4337 specific errors
    error UnauthorizedPaymaster();
    error InvalidEntryPoint();
    error SponsorshipLimitExceeded();
    error InvalidUserOperation();
    error OnlyEntryPoint();

    // =============================================
    //                Constructor
    // =============================================
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _ep) {
        _entryPoint = _ep;
        _disableInitializers();
    }

    // =============================================
    //                Initializer
    // =============================================
    function initialize(
        address _keygenAdmin,
        address _keyGenVerifierAddress,
        address _accumulatorAddress,
        address _trustedPaymaster
    ) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        keygenAdmin = _keygenAdmin;
        keyGenVerifier = IGroth16VerifierKeyGen13(_keyGenVerifierAddress);
        accumulator = IBabyJubJub(_accumulatorAddress);
        threshold = 2;
        numPeers = 3;
        isContractReady = false;
        // ERC-4337 initialization
        trustedPaymaster = _trustedPaymaster;
        if (_trustedPaymaster != address(0)) {
            authorizedPaymasters[_trustedPaymaster] = true;
        }
    }

    // =============================================
    //           ERC-4337 Implementation
    // =============================================

    /**
     * @notice Returns the EntryPoint contract address
     * @dev Required by IAccount interface
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @notice Validates a UserOperation
     * @dev Called by EntryPoint to validate if the contract accepts the UserOperation
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @param missingAccountFunds Funds needed to be deposited to EntryPoint
     * @return validationData Validation result (0 for success, 1 for failure, timestamp for time-range)
     */
     //TODO: Fix error typing for this..
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        // Validate the operation based on your business logic
        // For OPRF peers, we check if they're authorized participants

        // Extract signer from signature
        address signer = _recoverSigner(userOpHash, userOp.signature);

        // Check if signer is an authorized peer or admin
        Types.OprfPeer memory peer = addressToPeer[signer];
        bool isAuthorized = peer.isParticipant || signer == keygenAdmin || signer == owner();

        if (!isAuthorized) {
            return 1;
        }

        // Check paymaster authorization if present
        if (userOp.paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(userOp.paymasterAndData[:20]));
            if (!authorizedPaymasters[paymaster]) {
                return 1;
            }
        }

        return 0; // Validation successful
    }

    /**
     * @notice Execute a UserOperation
     * @dev Called by EntryPoint after successful validation
     * @param dest Target address for the call
     * @param value ETH value to send
     * @param func Function data to execute
     */
    function _call(address dest, uint256 value, bytes memory func) internal {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @notice Executes a UserOperation from the EntryPoint
     * @param dest Destination address
     * @param value ETH value to transfer
     * @param func Function calldata
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        _requireFromEntryPoint();
        _call(dest, value, func);
    }

    /**
     * @notice Executes a batch of UserOperations
     * @param dest Array of destination addresses
     * @param value Array of ETH values
     * @param func Array of function calldata
     */
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) external {
        _requireFromEntryPoint();
        require(
            dest.length == func.length && dest.length == value.length,
            "Length mismatch"
        );

        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], value[i], func[i]);
        }
    }

    // =============================================
    //         Paymaster Management
    // =============================================

    /**
     * @notice Authorize or revoke a paymaster
     * @param paymaster Address of the paymaster
     * @param authorized Whether to authorize or revoke
     */
    function setPaymasterAuthorization(
        address paymaster,
        bool authorized
    ) external onlyOwner {
        authorizedPaymasters[paymaster] = authorized;
        emit PaymasterAuthorized(paymaster, authorized);
    }

    /**
     * @notice Set gas sponsorship limit for an account
     * @param account Address of the account
     * @param limit Gas sponsorship limit in wei
     */
    function setSponsorshipLimit(
        address account,
        uint256 limit
    ) external onlyOwner {
        sponsorshipLimits[account] = limit;
        emit SponsorshipLimitSet(account, limit);
    }

    /**
     * @notice Check if an account can be sponsored for a certain gas amount
     * @param account Address to check
     * @param gasAmount Gas amount in wei
     * @return canSponsor Whether the account can be sponsored
     */
    function canSponsor(
        address account,
        uint256 gasAmount
    ) external view returns (bool canSponsor) {
        uint256 totalUsed = sponsoredGasUsed[account] + gasAmount;
        return totalUsed <= sponsorshipLimits[account];
    }

    /**
     * @notice Record sponsored gas usage
     * @param account Account that was sponsored
     * @param gasUsed Amount of gas used
     */
    function recordSponsoredGas(
        address account,
        uint256 gasUsed
    ) external {
        require(authorizedPaymasters[msg.sender], "Only authorized paymaster");
        sponsoredGasUsed[account] += gasUsed;
        emit GasSponsored(account, msg.sender, gasUsed);
    }

    // =============================================
    //         Modified OPRF Functions for AA
    // =============================================

    /**
     * @notice AA-compatible version of addRound1Contribution
     * @dev Can be called through UserOperation for gasless transactions
     */
    function addRound1ContributionAA(
        uint128 rpId,
        Types.Round1Contribution calldata data
    ) external virtual {
        // This can now be called via EntryPoint with sponsored gas
        _requireFromEntryPointOrAuthorized();
        _addRound1ContributionInternal(rpId, data, _getOperationSender());
    }

    /**
     * @notice Internal implementation of addRound1Contribution
     */
    // TODO: Put this in helpers I guess..
    function _addRound1ContributionInternal(
        uint128 rpId,
        Types.Round1Contribution memory data,
        address sender
    ) internal {
        if (_isEmpty(data.commShare)) revert BadContribution();
        if (data.commCoeffs == 0) revert BadContribution();
        if (_isEmpty(data.ephPubKey)) revert BadContribution();

        Types.RpNullifierGenState storage st = runningKeyGens[rpId];
        if (!st.exists) revert UnknownId(rpId);
        if (st.deleted) revert DeletedId(rpId);
        if (st.round2EventEmitted) revert WrongRound();

        uint256 partyId = _internParticipantCheckForAddress(sender);

        if (!_isEmpty(st.round1[partyId].commShare)) revert AlreadySubmitted();

        _addToAggregate(st, data.commShare.x, data.commShare.y);
        st.round1[partyId] = data;
        _tryEmitRound2Event(rpId, st);
    }

    // =============================================
    //        OPRF Functions
    // =============================================

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


    // =============================================
    //           Helper Functions
    // =============================================

    /**
     * @notice Ensures call is from EntryPoint
     */
    function _requireFromEntryPoint() internal view {
        require(
            msg.sender == address(entryPoint()),
            "Only EntryPoint"
        );
    }

    /**
     * @notice Ensures call is from EntryPoint or authorized address
     */
    function _requireFromEntryPointOrAuthorized() internal view {
        require(
            msg.sender == address(entryPoint()) ||
            addressToPeer[msg.sender].isParticipant ||
            msg.sender == keygenAdmin ||
            msg.sender == owner(),
            "Unauthorized"
        );
    }

    /**
     * @notice Get the actual sender of the operation
     */
    function _getOperationSender() internal view returns (address) {
        if (msg.sender == address(entryPoint())) {
            // In AA context, extract sender from calldata
            // This is a simplified version - actual implementation would decode UserOp
            return tx.origin; // Simplified for demonstration
        }
        return msg.sender;
    }

    /**
     * @notice Check participant status for a specific address
     */
    //TODO: Question: Do we still need onlyProxy anywhere..?
    function _internParticipantCheckForAddress(address addr)
        internal
        view
        virtual
        returns (uint256)
    {
        Types.OprfPeer memory peer = addressToPeer[addr];
        if (!peer.isParticipant) revert NotAParticipant();
        return peer.partyId;
    }

    /**
     * @notice Recover signer from signature
     */
    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");

        return ecrecover(hash, v, r, s);
    }

    // =============================================
    //         Modifiers
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

    function _isEmpty(Types.BabyJubJubElement memory element) internal pure virtual returns (bool) {
        return element.x == 0 && element.y == 0;
    }

    function _addToAggregate(
        Types.RpNullifierGenState storage st,
        uint256 newPointX,
        uint256 newPointY
    ) internal virtual {
        if (accumulator.isOnCurve(newPointX, newPointY) == false) {
            revert BadContribution();
        }

        if (_isEmpty(st.keyAggregate)) {
            st.keyAggregate = Types.BabyJubJubElement(newPointX, newPointY);
            return;
        }

        (uint256 resultX, uint256 resultY) = accumulator.add(
            st.keyAggregate.x,
            st.keyAggregate.y,
            newPointX,
            newPointY
        );

        st.keyAggregate = Types.BabyJubJubElement(resultX, resultY);
    }

    function _tryEmitRound2Event(uint128 rpId, Types.RpNullifierGenState storage st) internal virtual {
        if (st.round2EventEmitted) return;
        if (!allRound1Submitted(st)) return;

        st.round2EventEmitted = true;
        emit Types.SecretGenRound2(rpId);
    }

    function allRound1Submitted(Types.RpNullifierGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (st.round1[i].commCoeffs == 0) return false;
        }
        return true;
    }

    // =============================================
    //         Upgrade Authorization
    // =============================================

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    // =============================================
    //              Storage Gap
    // =============================================

    uint256[35] private __gap;
}
