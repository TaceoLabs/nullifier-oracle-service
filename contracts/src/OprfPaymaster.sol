// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Types} from "./Types.sol";

/**
 * @title OprfPaymaster
 * @notice Paymaster that sponsors gas for OPRF peer operations on RpRegistry
 * @dev Implements verification and sponsorship logic specific to OPRF use case
 */
contract OprfPaymaster is IPaymaster, Ownable {
    using ECDSA for bytes32;

    IEntryPoint public immutable entryPoint;
    address public immutable rpRegistry;

    // Track which smart accounts are authorized OPRF peer accounts
    mapping(address => bool) public authorizedAccounts;

    // Track gas usage per account
    mapping(address => uint256) public gasUsedByAccount;
    mapping(address => uint256) public gasLimitByAccount;

    // Global settings
    uint256 public maxGasPerOp = 10000000000; // 10B gas max per operation
    uint256 public globalGasUsed;
    uint256 public globalGasLimit;
    bool public isPaused;

    // Track operations per account (for rate limiting)
    // TODO: What to set these rate limits as..? How many calls do we expect in a given time frame?
    mapping(address => uint256) public operationCount;
    mapping(address => uint256) public maxOperationsPerAccount;

    // Events
    event AccountAuthorized(address indexed account, bool authorized);
    event GasLimitSet(address indexed account, uint256 limit);
    event GasSponsored(address indexed account, uint256 gasUsed, uint256 totalUsed);
    event GlobalLimitSet(uint256 limit);
    event Paused(bool isPaused);
    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);

    // Errors
    error AccountNotAuthorized();
    error GasLimitExceeded();
    error OperationLimitExceeded();
    error PaymasterPaused();
    error InvalidOperation();
    error GlobalGasLimitExceeded();


    constructor(
        IEntryPoint _entryPoint,
        address _rpRegistry
    ) Ownable(msg.sender) {
        entryPoint = _entryPoint;
        rpRegistry = _rpRegistry;
        globalGasLimit = 100 ether; // Default global limit
    }

    /**
     * @notice Validate a paymaster user operation
     * @param userOp The user operation
     * @param userOpHash Hash of the user operation
     * @param maxCost Maximum cost of the operation
     * @return context Context to pass to postOp
     * @return validationData 0 for valid, 1 for invalid
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        // Only EntryPoint can call this
        require(msg.sender == address(entryPoint), "Only EntryPoint");

        // Check if paused
        if (isPaused) revert PaymasterPaused();

        // Verify the account is authorized
        if (!authorizedAccounts[userOp.sender]) {
            revert AccountNotAuthorized();
        }

        // Check per-account gas limit
        uint256 accountGasUsed = gasUsedByAccount[userOp.sender];
        uint256 accountLimit = gasLimitByAccount[userOp.sender];

        if (accountLimit > 0 && accountGasUsed + maxCost > accountLimit) {
            revert GasLimitExceeded();
        }

        // Check global gas limit
        if (globalGasUsed + maxCost > globalGasLimit) {
            revert GlobalGasLimitExceeded();
        }

        // Check operation count limit
        uint256 opCount = operationCount[userOp.sender];
        uint256 maxOps = maxOperationsPerAccount[userOp.sender];

        if (maxOps > 0 && opCount >= maxOps) {
            revert OperationLimitExceeded();
        }

        // Verify the operation is calling RpRegistry functions
        if (!_isValidOperation(userOp)) {
            revert InvalidOperation();
        }

        // Check we have enough deposit
        uint256 balance = entryPoint.balanceOf(address(this));
        require(balance >= maxCost, "Insufficient paymaster balance");

        // Create context for postOp
        context = abi.encode(
            userOp.sender,
            accountGasUsed,
            opCount,
            globalGasUsed
        );

        return (context, 0); // 0 = validation success
    }

    /**
     * @notice Post-operation handler
     * @param mode Result mode of the operation
     * @param context Context from validatePaymasterUserOp
     * @param actualGasCost Actual gas cost of the operation
     */
    function postOp(
        IPaymaster.PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external override {
        // Only EntryPoint can call this
        require(msg.sender == address(entryPoint), "Only EntryPoint");

        // Decode context
        (
            address account,
            uint256 previousAccountGas,
            uint256 previousOpCount,
            uint256 previousGlobalGas
        ) = abi.decode(context, (address, uint256, uint256, uint256));

        // Update gas tracking
        gasUsedByAccount[account] = previousAccountGas + actualGasCost;
        globalGasUsed = previousGlobalGas + actualGasCost;

        // Update operation count
        operationCount[account] = previousOpCount + 1;

        emit GasSponsored(
            account,
            actualGasCost,
            gasUsedByAccount[account]
        );
    }

    /**
     * @notice Check if the operation is valid for sponsorship
     * @param userOp The user operation to check
     * @return valid Whether the operation should be sponsored
     */
    function _isValidOperation(PackedUserOperation calldata userOp) internal view returns (bool) {
        // Decode the calldata to check what's being called
        if (userOp.callData.length < 4) return false;

        bytes4 selector = bytes4(userOp.callData[:4]);

        // Check for execute() or executeBatch()
        // TODO: Is it best to just replace these calculations of function selectors with constants?
        if (selector == bytes4(keccak256("execute(address,uint256,bytes)"))) {
            // Decode to check the target
            (address target,,) = abi.decode(
                userOp.callData[4:],
                (address, uint256, bytes)
            );

            // Must be calling RpRegistry
            if (target != rpRegistry) return false;

            return true;

        } else if (selector == bytes4(keccak256("executeBatch(address[],uint256[],bytes[])"))) {
            // For batch, decode and check all targets
            (address[] memory targets,,) = abi.decode(
                userOp.callData[4:],
                (address[], uint256[], bytes[])
            );

            // All targets must be RpRegistry
            for (uint256 i = 0; i < targets.length; i++) {
                if (targets[i] != rpRegistry) return false;
            }
            return true;

        } else {
            // Check if it's one of the helper functions
            return _isHelperFunction(selector);
        }
    }

    /**
     * @notice Check if selector is a valid helper function
     * @param selector The function selector
     * @return valid Whether it's a valid helper
     */
    function _isHelperFunction(bytes4 selector) internal pure returns (bool) {
        return selector == bytes4(keccak256("submitRound1Contribution(address,uint128,((uint256,uint256),uint256,(uint256,uint256)))")) ||
               selector == bytes4(keccak256("submitRound2Contribution(address,uint128,bytes,uint256[2],uint256[2][2],uint256[2])")) ||
               selector == bytes4(keccak256("submitRound3Contribution(address,uint128)")) ||
               selector == bytes4(keccak256("batchRound1Contributions(address,uint128[],bytes[])")) ||
               selector == bytes4(keccak256("batchRound3Contributions(address,uint128[])"));
    }

    // =============================================
    //           Admin Functions
    // =============================================

    /**
     * @notice Authorize or revoke a smart account
     * @param account The account address
     * @param authorized Whether to authorize
     */
    function setAccountAuthorization(
        address account,
        bool authorized
    ) external onlyOwner {
        authorizedAccounts[account] = authorized;
        emit AccountAuthorized(account, authorized);
    }

    /**
     * @notice Batch authorize accounts
     * @param accounts Array of account addresses
     */
    function batchAuthorizeAccounts(
        address[] calldata accounts
    ) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            authorizedAccounts[accounts[i]] = true;
            emit AccountAuthorized(accounts[i], true);
        }
    }

    /**
     * @notice Set gas limit for an account
     * @param account The account address
     * @param limit Gas limit (0 for unlimited)
     */
    function setAccountGasLimit(
        address account,
        uint256 limit
    ) external onlyOwner {
        gasLimitByAccount[account] = limit;
        emit GasLimitSet(account, limit);
    }

    /**
     * @notice Set operation limit for an account
     * @param account The account address
     * @param limit Max operations (0 for unlimited)
     */
    function setAccountOperationLimit(
        address account,
        uint256 limit
    ) external onlyOwner {
        maxOperationsPerAccount[account] = limit;
    }

    /**
     * @notice Set global gas limit
     * @param limit New global gas limit
     */
    function setGlobalGasLimit(uint256 limit) external onlyOwner {
        globalGasLimit = limit;
        emit GlobalLimitSet(limit);
    }

    /**
     * @notice Pause or unpause sponsorship
     * @param _paused Whether to pause
     */
    function setPaused(bool _paused) external onlyOwner {
        isPaused = _paused;
        emit Paused(_paused);
    }

    /**
     * @notice Reset gas usage for an account
     * @param account The account to reset
     */
    function resetAccountGasUsage(address account) external onlyOwner {
        gasUsedByAccount[account] = 0;
        operationCount[account] = 0;
    }

    /**
     * @notice Reset global gas usage
     */
    function resetGlobalGasUsage() external onlyOwner {
        globalGasUsed = 0;
    }

    // =============================================
    //           Deposit Management
    // =============================================

    /**
     * @notice Add deposit to EntryPoint
     */
    function deposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw from EntryPoint
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function withdraw(address payable to, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(to, amount);
        emit Withdrawn(to, amount);
    }

    /**
     * @notice Get current deposit balance
     * @return Current balance in EntryPoint
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    // =============================================
    //           View Functions
    // =============================================

    /**
     * @notice Check if account can be sponsored
     * @param account The account to check
     * @param estimatedGas Estimated gas needed
     * @return canSponsor Whether account can be sponsored
     * @return reason Reason if cannot sponsor
     */
    function canSponsorAccount(
        address account,
        uint256 estimatedGas
    ) external view returns (bool canSponsor, string memory reason) {
        if (isPaused) {
            return (false, "Paymaster is paused");
        }

        if (!authorizedAccounts[account]) {
            return (false, "Account not authorized");
        }

        uint256 accountLimit = gasLimitByAccount[account];
        if (accountLimit > 0 && gasUsedByAccount[account] + estimatedGas > accountLimit) {
            return (false, "Account gas limit exceeded");
        }

        if (globalGasUsed + estimatedGas > globalGasLimit) {
            return (false, "Global gas limit exceeded");
        }

        uint256 maxOps = maxOperationsPerAccount[account];
        if (maxOps > 0 && operationCount[account] >= maxOps) {
            return (false, "Operation limit exceeded");
        }

        if (entryPoint.balanceOf(address(this)) < estimatedGas * tx.gasprice) {
            return (false, "Insufficient paymaster balance");
        }

        return (true, "Can sponsor");
    }

    /**
     * @notice Get remaining sponsorship for account
     * @param account The account to check
     * @return remainingGas Remaining gas available
     * @return remainingOps Remaining operations available
     */
    function getRemainingSponsorship(
        address account
    ) external view returns (uint256 remainingGas, uint256 remainingOps) {
        uint256 accountLimit = gasLimitByAccount[account];
        if (accountLimit > 0) {
            uint256 used = gasUsedByAccount[account];
            remainingGas = used < accountLimit ? accountLimit - used : 0;
        } else {
            // Check global limit
            uint256 globalUsed = globalGasUsed;
            remainingGas = globalUsed < globalGasLimit ? globalGasLimit - globalUsed : 0;
        }

        uint256 maxOps = maxOperationsPerAccount[account];
        if (maxOps > 0) {
            uint256 opsUsed = operationCount[account];
            remainingOps = opsUsed < maxOps ? maxOps - opsUsed : 0;
        } else {
            remainingOps = type(uint256).max; // Unlimited
        }
    }
}
