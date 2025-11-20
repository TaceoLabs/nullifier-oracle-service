// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title OprfPeerAccount
 * @notice Simplified Smart Contract Account for OPRF peers to interact with RpRegistry via ERC-4337
 * @dev This account handles AA complexity so RpRegistry doesn't need to
 */
contract OprfPeerAccount is BaseAccount, Initializable, UUPSUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    
    // Account state
    address public owner;
    IEntryPoint private immutable _entryPoint;
    
    // Events
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    event CallExecuted(address indexed target, uint256 value, bytes data, bool success);
    
    // Errors
    error OnlyOwner();
    error OnlyOwnerOrEntryPoint();
    error CallFailed();
    
    // Modifiers
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }
    
    modifier onlyOwnerOrEntryPoint() {
        if (msg.sender != owner && msg.sender != address(_entryPoint)) {
            revert OnlyOwnerOrEntryPoint();
        }
        _;
    }
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }
    
    /**
     * @notice Initialize the account
     * @param anOwner The owner of this account (the OPRF peer)
     */
    function initialize(address anOwner) public virtual initializer {
        owner = anOwner;
    }
    
    // =============================================
    //           ERC-4337 Implementation
    // =============================================
    
    /**
     * @notice Return the EntryPoint address
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }
    
    /**
     * @notice Validate the signature of a user operation
     * @param userOp The user operation
     * @param userOpHash The hash of the user operation
     * @return validationData 0 for success, 1 for failure
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address recovered = hash.recover(userOp.signature);
        
        // Only the owner can sign operations
        if (recovered == owner) {
            return 0; // Valid signature
        }
        
        return 1; // Invalid signature
    }
    
    // =============================================
    //           Transaction Execution
    // =============================================
    
    /**
     * @notice Execute a transaction from the EntryPoint
     * @param dest Destination address
     * @param value ETH value to send
     * @param func Function calldata
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external onlyOwnerOrEntryPoint {
        _call(dest, value, func);
        emit CallExecuted(dest, value, func, true);
    }
    
    /**
     * @notice Execute a batch of transactions
     * @param dest Array of destination addresses
     * @param value Array of ETH values
     * @param func Array of function calldata
     */
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) external onlyOwnerOrEntryPoint {
        require(
            dest.length == func.length && dest.length == value.length,
            "Length mismatch"
        );
        
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], value[i], func[i]);
            emit CallExecuted(dest[i], value[i], func[i], true);
        }
    }
    
    /**
     * @notice Internal call function
     * @param target Target address
     * @param value ETH value
     * @param data Call data
     */
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            // If there's return data, bubble up the revert reason
            if (result.length > 0) {
                assembly {
                    let returndata_size := mload(result)
                    revert(add(32, result), returndata_size)
                }
            } else {
                revert CallFailed();
            }
        }
    }
    
    // =============================================
    //      RpRegistry Specific Helper Functions
    // =============================================
    
    /**
     * @notice Submit Round 1 contribution to RpRegistry
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     * @param commShareX Commitment share X coordinate
     * @param commShareY Commitment share Y coordinate
     * @param commCoeffs Commitment coefficients
     * @param ephPubKeyX Ephemeral public key X coordinate
     * @param ephPubKeyY Ephemeral public key Y coordinate
     */
    function submitRound1Contribution(
        address rpRegistryProxy,
        uint128 rpId,
        uint256 commShareX,
        uint256 commShareY,
        uint256 commCoeffs,
        uint256 ephPubKeyX,
        uint256 ephPubKeyY
    ) external onlyOwner {
        bytes memory callData = abi.encodeWithSignature(
            "addRound1Contribution(uint128,(uint256,uint256,uint256,(uint256,uint256)))",
            rpId,
            commShareX,
            commShareY,
            commCoeffs,
            ephPubKeyX,
            ephPubKeyY
        );
        
        _call(rpRegistryProxy, 0, callData);
    }
    
    /**
     * @notice Submit Round 2 contribution with proof to RpRegistry
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     * @param ciphers Array of ciphertexts for each peer
     * @param proof The Groth16 proof components
     */
    function submitRound2Contribution(
        address rpRegistryProxy,
        uint128 rpId,
        bytes calldata ciphers,  // Pre-encoded array of SecretGenCiphertext
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external onlyOwner {
        // Note: The ciphers parameter should be pre-encoded as it contains complex nested structures
        // This avoids stack too deep issues and complex encoding
        bytes memory callData = abi.encodeWithSignature(
            "addRound2Contribution(uint128,((uint256,(uint256,uint256),uint256)[],(uint256[2],uint256[2][2],uint256[2])))",
            rpId
        );
        
        // Append the pre-encoded data
        bytes memory fullCallData = abi.encodePacked(
            callData[:4], // Function selector
            abi.encode(rpId),
            ciphers,
            abi.encode(proofA, proofB, proofC)
        );
        
        _call(rpRegistryProxy, 0, fullCallData);
    }
    
    /**
     * @notice Submit Round 3 contribution (acknowledgment) to RpRegistry
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     */
    function submitRound3Contribution(
        address rpRegistryProxy,
        uint128 rpId
    ) external onlyOwner {
        bytes memory callData = abi.encodeWithSignature(
            "addRound3Contribution(uint128)",
            rpId
        );
        
        _call(rpRegistryProxy, 0, callData);
    }
    
    /**
     * @notice Check if this account is a participant and get party ID
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @return partyId The party ID of this account's owner
     */
    function checkParticipantStatus(
        address rpRegistryProxy
    ) external view returns (uint256 partyId) {
        (bool success, bytes memory result) = rpRegistryProxy.staticcall(
            abi.encodeWithSignature("checkIsParticipantAndReturnPartyId()")
        );
        require(success, "Failed to check participant status");
        return abi.decode(result, (uint256));
    }
    
    /**
     * @notice Get ephemeral public keys from Round 1
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     * @return The ephemeral public keys from all peers
     */
    function getEphemeralPublicKeys(
        address rpRegistryProxy,
        uint128 rpId
    ) external view returns (bytes memory) {
        (bool success, bytes memory result) = rpRegistryProxy.staticcall(
            abi.encodeWithSignature(
                "checkIsParticipantAndReturnEphemeralPublicKeys(uint128)",
                rpId
            )
        );
        require(success, "Failed to get ephemeral keys");
        return result; // Return raw bytes as the structure is complex
    }
    
    /**
     * @notice Get Round 2 ciphertexts for this peer
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     * @return The ciphertexts intended for this peer
     */
    function getRound2Ciphers(
        address rpRegistryProxy,
        uint128 rpId
    ) external view returns (bytes memory) {
        (bool success, bytes memory result) = rpRegistryProxy.staticcall(
            abi.encodeWithSignature(
                "checkIsParticipantAndReturnRound2Ciphers(uint128)",
                rpId
            )
        );
        require(success, "Failed to get Round 2 ciphers");
        return result; // Return raw bytes as the structure is complex
    }
    
    /**
     * @notice Get the nullifier key for a specific RP
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     * @return x The X coordinate of the nullifier key
     * @return y The Y coordinate of the nullifier key
     */
    function getRpNullifierKey(
        address rpRegistryProxy,
        uint128 rpId
    ) external view returns (uint256 x, uint256 y) {
        (bool success, bytes memory result) = rpRegistryProxy.staticcall(
            abi.encodeWithSignature("getRpNullifierKey(uint128)", rpId)
        );
        require(success, "Failed to get nullifier key");
        (x, y) = abi.decode(result, (uint256, uint256));
    }
    
    /**
     * @notice Get complete RP material (ECDSA key and nullifier key)
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpId The RP identifier
     * @return The encoded RP material
     */
    function getRpMaterial(
        address rpRegistryProxy,
        uint128 rpId
    ) external view returns (bytes memory) {
        (bool success, bytes memory result) = rpRegistryProxy.staticcall(
            abi.encodeWithSignature("getRpMaterial(uint128)", rpId)
        );
        require(success, "Failed to get RP material");
        return result;
    }
    
    // =============================================
    //      Batch Operation Helpers
    // =============================================
    
    /**
     * @notice Execute multiple RpRegistry operations in one transaction
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param callDatas Array of encoded function calls
     */
    function batchRpRegistryOperations(
        address rpRegistryProxy,
        bytes[] calldata callDatas
    ) external onlyOwner {
        for (uint256 i = 0; i < callDatas.length; i++) {
            _call(rpRegistryProxy, 0, callDatas[i]);
        }
    }
    
    /**
     * @notice Submit Round 1 contributions for multiple RPs
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpIds Array of RP identifiers
     * @param contributions Array of encoded Round 1 contributions
     */
    function batchRound1Contributions(
        address rpRegistryProxy,
        uint128[] calldata rpIds,
        bytes[] calldata contributions
    ) external onlyOwner {
        require(rpIds.length == contributions.length, "Length mismatch");
        
        for (uint256 i = 0; i < rpIds.length; i++) {
            bytes memory callData = abi.encodePacked(
                bytes4(keccak256("addRound1Contribution(uint128,(uint256,uint256,uint256,(uint256,uint256)))")),
                abi.encode(rpIds[i]),
                contributions[i]
            );
            _call(rpRegistryProxy, 0, callData);
        }
    }
    
    /**
     * @notice Submit Round 3 acknowledgments for multiple RPs
     * @param rpRegistryProxy The proxy address of RpRegistry
     * @param rpIds Array of RP identifiers to acknowledge
     */
    function batchRound3Contributions(
        address rpRegistryProxy,
        uint128[] calldata rpIds
    ) external onlyOwner {
        for (uint256 i = 0; i < rpIds.length; i++) {
            bytes memory callData = abi.encodeWithSignature(
                "addRound3Contribution(uint128)",
                rpIds[i]
            );
            _call(rpRegistryProxy, 0, callData);
        }
    }
    
    // =============================================
    //           Account Management
    // =============================================
    
    /**
     * @notice Transfer ownership of the account
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        
        address previousOwner = owner;
        owner = newOwner;
        
        emit OwnerChanged(previousOwner, newOwner);
    }
    
    /**
     * @notice Deposit funds to the EntryPoint
     */
    function addDeposit() external payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }
    
    /**
     * @notice Withdraw funds from the EntryPoint
     * @param withdrawAddress Address to withdraw to
     * @param amount Amount to withdraw
     */
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) external onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }
    
    /**
     * @notice Get the current deposit in EntryPoint
     * @return The current deposit amount
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }
    
    // =============================================
    //           Upgrade Functions
    // =============================================
    
    /**
     * @notice Authorize an upgrade (only owner can upgrade)
     * @param newImplementation The new implementation address
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}
    
    // =============================================
    //           Receive and Fallback
    // =============================================
    
    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
