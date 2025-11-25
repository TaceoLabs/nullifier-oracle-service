// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {OprfPaymaster} from "../src/OprfPaymaster.sol";
import {OprfPeerAccount} from "../src/OprfPeerAccount.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {Types} from "../src/Types.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract MockEntryPoint {
    mapping(address => uint256) public balances;
    address public currentPaymaster;

    function depositTo(address account) external payable {
        balances[account] += msg.value;
    }

    function withdrawTo(address payable withdrawAddress, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        withdrawAddress.transfer(amount);
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    // Mock function to simulate EntryPoint calling paymaster
    function simulateValidation(
        address paymaster,
        PackedUserOperation calldata userOp,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        currentPaymaster = paymaster;
        return IPaymaster(paymaster).validatePaymasterUserOp(
            userOp,
            bytes32(0), // mock hash
            maxCost
        );
    }

    // Mock function to simulate postOp
    function simulatePostOp(
        address paymaster,
        IPaymaster.PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external {
        IPaymaster(paymaster).postOp(mode, context, actualGasCost, 0);
    }
}

contract OprfPaymasterTest is Test {
    OprfPaymaster public paymaster;
    OprfPeerAccount public peerAccount;
    RpRegistry public rpRegistry;
    MockEntryPoint public entryPoint;

    address public owner = address(this);
    address public peer1 = address(0x1);
    address public peer2 = address(0x2);
    address public peer3 = address(0x3);
    address public keygenAdmin = address(0x100);

    uint256 constant INITIAL_DEPOSIT = 10 ether;
    uint128 constant TEST_RP_ID = 1;

    event AccountAuthorized(address indexed account, bool authorized);
    event GasSponsored(address indexed account, uint256 gasUsed, uint256 totalUsed);
    event Deposited(address indexed from, uint256 amount);

    function setUp() public {
        // Deploy mock EntryPoint
        entryPoint = new MockEntryPoint();

        // Deploy RpRegistry (mock implementation)
        RpRegistry rpRegistryImpl = new RpRegistry();
        bytes memory initData = abi.encodeCall(
            RpRegistry.initialize,
            (keygenAdmin, address(0x500), address(0x600)) // mock verifier and accumulator
        );
        ERC1967Proxy rpRegistryProxy = new ERC1967Proxy(address(rpRegistryImpl), initData);
        rpRegistry = RpRegistry(address(rpRegistryProxy));

        // Deploy OprfPaymaster
        paymaster = new OprfPaymaster(
            IEntryPoint(address(entryPoint)),
            address(rpRegistry)
        );

        // Deploy a peer account for testing
        OprfPeerAccount accountImpl = new OprfPeerAccount(IEntryPoint(address(entryPoint)));
        bytes memory accountInitData = abi.encodeCall(
            OprfPeerAccount.initialize,
            (peer1)
        );
        ERC1967Proxy accountProxy = new ERC1967Proxy(
            address(accountImpl),
            accountInitData
        );
        peerAccount = OprfPeerAccount(payable(address(accountProxy)));

        // Fund the paymaster
        deal(address(this), INITIAL_DEPOSIT);
        paymaster.deposit{value: INITIAL_DEPOSIT}();
    }

    // =============================================
    //           Happy Path Tests
    // =============================================

    function test_InitialSetup() public {
        assertEq(address(paymaster.entryPoint()), address(entryPoint));
        assertEq(paymaster.rpRegistry(), address(rpRegistry));
        assertEq(paymaster.owner(), owner);
        assertEq(paymaster.globalGasLimit(), 100 ether);
        assertEq(paymaster.getDeposit(), INITIAL_DEPOSIT);
        assertFalse(paymaster.isPaused());
    }

    function test_AuthorizeAccount() public {
        // Authorize the peer account
        vm.expectEmit(true, false, false, false);
        emit AccountAuthorized(address(peerAccount), true);

        paymaster.setAccountAuthorization(address(peerAccount), true);

        assertTrue(paymaster.authorizedAccounts(address(peerAccount)));
    }

    function test_BatchAuthorizeAccounts() public {
        address[] memory accounts = new address[](3);
        accounts[0] = address(peerAccount);
        accounts[1] = address(0x1000);
        accounts[2] = address(0x2000);

        paymaster.batchAuthorizeAccounts(accounts);

        assertTrue(paymaster.authorizedAccounts(address(peerAccount)));
        assertTrue(paymaster.authorizedAccounts(address(0x1000)));
        assertTrue(paymaster.authorizedAccounts(address(0x2000)));
    }

    function test_ValidatePaymasterUserOp_Execute() public {
        // First authorize the account
        paymaster.setAccountAuthorization(address(peerAccount), true);

        // Create a valid UserOperation calling execute() -> RpRegistry
        bytes memory executeCallData = abi.encodeCall(
            peerAccount.execute,
            (
                address(rpRegistry),
                0,
                abi.encodeWithSignature("addRound3Contribution(uint128)", TEST_RP_ID)
            )
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(peerAccount),
            nonce: 0,
            initCode: bytes(""),
            callData: executeCallData,
            accountGasLimits: bytes32(uint256(100000) << 128 | 100000),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        // Validate the operation
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether // maxCost
        );

        assertEq(validationData, 0, "Validation should succeed");
        assertTrue(context.length > 0, "Context should be returned");

        // Decode and verify context
        (address account,,,) = abi.decode(context, (address, uint256, uint256, uint256));
        assertEq(account, address(peerAccount));
    }

    function test_ValidatePaymasterUserOp_HelperFunction() public {
        // Authorize the account
        paymaster.setAccountAuthorization(address(peerAccount), true);

        // Create UserOperation calling helper function directly
        bytes memory helperCallData = abi.encodeCall(
            peerAccount.submitRound3Contribution,
            (address(rpRegistry), TEST_RP_ID)
        );

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(peerAccount),
            nonce: 0,
            initCode: bytes(""),
            callData: helperCallData,
            accountGasLimits: bytes32(uint256(100000) << 128 | 100000),
            preVerificationGas: 21000,
            gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether
        );

        assertEq(validationData, 0, "Helper function validation should succeed");
    }

    function test_PostOp_UpdatesGasTracking() public {
        // Setup: authorize account
        paymaster.setAccountAuthorization(address(peerAccount), true);

        // Create context as if from validatePaymasterUserOp
        bytes memory context = abi.encode(
            address(peerAccount),  // account
            0,                      // previousAccountGas
            0,                      // previousOpCount
            0                       // previousGlobalGas
        );

        uint256 actualGasCost = 100000;

        // Call postOp
        vm.prank(address(entryPoint));
        vm.expectEmit(true, false, false, true);
        emit GasSponsored(address(peerAccount), actualGasCost, actualGasCost);

        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            context,
            actualGasCost,
            0
        );

        // Verify updates
        assertEq(paymaster.gasUsedByAccount(address(peerAccount)), actualGasCost);
        assertEq(paymaster.globalGasUsed(), actualGasCost);
        assertEq(paymaster.operationCount(address(peerAccount)), 1);
    }

    function test_FullFlow_MultipleOperations() public {
        // Authorize account and set limits
        paymaster.setAccountAuthorization(address(peerAccount), true);
        paymaster.setAccountGasLimit(address(peerAccount), 5 ether);
        paymaster.setAccountOperationLimit(address(peerAccount), 10);

        // Simulate multiple operations
        for (uint i = 0; i < 3; i++) {
            // Create UserOp
            bytes memory callData = abi.encodeCall(
                peerAccount.execute,
                (
                    address(rpRegistry),
                    0,
                    abi.encodeWithSignature("addRound3Contribution(uint128)", uint128(i))
                )
            );

            PackedUserOperation memory userOp = PackedUserOperation({
                sender: address(peerAccount),
                nonce: i,
                initCode: bytes(""),
                callData: callData,
                accountGasLimits: bytes32(uint256(100000) << 128 | 100000),
                preVerificationGas: 21000,
                gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei),
                paymasterAndData: bytes(""),
                signature: bytes("")
            });

            // Validate
            vm.prank(address(entryPoint));
            (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
                userOp,
                bytes32(uint256(i)),
                0.1 ether
            );

            assertEq(validationData, 0, "Validation should succeed");

            // PostOp
            vm.prank(address(entryPoint));
            paymaster.postOp(
                IPaymaster.PostOpMode.opSucceeded,
                context,
                0.1 ether,
                0
            );
        }

        // Verify final state
        assertEq(paymaster.gasUsedByAccount(address(peerAccount)), 0.3 ether);
        assertEq(paymaster.operationCount(address(peerAccount)), 3);
        assertEq(paymaster.globalGasUsed(), 0.3 ether);
    }

    function test_SetAccountLimits() public {
        address account = address(peerAccount);

        // Set gas limit
        paymaster.setAccountGasLimit(account, 2 ether);
        assertEq(paymaster.gasLimitByAccount(account), 2 ether);

        // Set operation limit
        paymaster.setAccountOperationLimit(account, 100);
        assertEq(paymaster.maxOperationsPerAccount(account), 100);
    }

    function test_ResetAccountUsage() public {
        address account = address(peerAccount);

        // First set some usage
        paymaster.setAccountAuthorization(account, true);

        // Simulate some gas usage via postOp
        bytes memory context = abi.encode(account, 0, 0, 0);
        vm.prank(address(entryPoint));
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, context, 1 ether, 0);

        assertEq(paymaster.gasUsedByAccount(account), 1 ether);
        assertEq(paymaster.operationCount(account), 1);

        // Reset
        paymaster.resetAccountGasUsage(account);

        assertEq(paymaster.gasUsedByAccount(account), 0);
        assertEq(paymaster.operationCount(account), 0);
    }

    function test_CanSponsorAccount_HappyPath() public {
        address account = address(peerAccount);
        paymaster.setAccountAuthorization(account, true);

        (bool canSponsor, string memory reason) = paymaster.canSponsorAccount(
            account,
            0.1 ether
        );

        assertTrue(canSponsor);
        assertEq(reason, "Can sponsor");
    }

    function test_GetRemainingSponsorship() public {
        address account = address(peerAccount);

        // Set limits
        paymaster.setAccountGasLimit(account, 5 ether);
        paymaster.setAccountOperationLimit(account, 10);

        (uint256 remainingGas, uint256 remainingOps) = paymaster.getRemainingSponsorship(account);

        assertEq(remainingGas, 5 ether);
        assertEq(remainingOps, 10);
    }

    function test_DepositAndWithdraw() public {
        // Additional deposit
        uint256 additionalDeposit = 5 ether;
        deal(address(this), additionalDeposit);

        vm.expectEmit(true, false, false, true);
        emit Deposited(address(this), additionalDeposit);

        paymaster.deposit{value: additionalDeposit}();
        assertEq(paymaster.getDeposit(), INITIAL_DEPOSIT + additionalDeposit);

        // Withdraw some
        address payable recipient = payable(address(0x9999));
        uint256 withdrawAmount = 3 ether;

        paymaster.withdraw(recipient, withdrawAmount);
        assertEq(paymaster.getDeposit(), INITIAL_DEPOSIT + additionalDeposit - withdrawAmount);
        assertEq(recipient.balance, withdrawAmount);
    }

    function test_PauseAndUnpause() public {
        assertFalse(paymaster.isPaused());

        paymaster.setPaused(true);
        assertTrue(paymaster.isPaused());

        paymaster.setPaused(false);
        assertFalse(paymaster.isPaused());
    }
}
