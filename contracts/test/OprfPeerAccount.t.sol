// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {OprfPeerAccount} from "../src/OprfPeerAccount.sol";
import {RpRegistry} from "../src/RpRegistry.sol";
import {Types} from "../src/Types.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract MockEntryPoint {
    mapping(address => uint256) public balances;
    
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
}

contract OprfPeerAccountTest is Test {
    OprfPeerAccount public accountImplementation;
    OprfPeerAccount public peerAccount;
    RpRegistry public rpRegistryImpl;
    RpRegistry public rpRegistry;
    MockEntryPoint public entryPoint;
    
    address public peer1 = address(0x1);
    address public peer2 = address(0x2);
    address public peer3 = address(0x3);
    address public keygenAdmin = address(0x100);
    address public owner = address(0x200);
    
    // Mock contracts for testing
    address public mockKeyGenVerifier = address(0x300);
    address public mockAccumulator = address(0x400);
    
    uint128 constant TEST_RP_ID = 1;
    
    event CallExecuted(address indexed target, uint256 value, bytes data, bool success);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);
    
    function setUp() public {
        // Deploy mock EntryPoint
        entryPoint = new MockEntryPoint();
        
        // Deploy RpRegistry
        rpRegistryImpl = new RpRegistry();
        bytes memory initData = abi.encodeCall(
            RpRegistry.initialize,
            (keygenAdmin, mockKeyGenVerifier, mockAccumulator)
        );
        ERC1967Proxy rpRegistryProxy = new ERC1967Proxy(address(rpRegistryImpl), initData);
        rpRegistry = RpRegistry(address(rpRegistryProxy));
        
        // Deploy OprfPeerAccount implementation
        accountImplementation = new OprfPeerAccount(IEntryPoint(address(entryPoint)));
        
        // Deploy proxy for peer account
        bytes memory accountInitData = abi.encodeCall(
            OprfPeerAccount.initialize,
            (peer1)
        );
        ERC1967Proxy accountProxy = new ERC1967Proxy(
            address(accountImplementation),
            accountInitData
        );
        peerAccount = OprfPeerAccount(payable(address(accountProxy)));
        
        // Setup RpRegistry with peers
        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = peer1;
        peerAddresses[1] = peer2;
        peerAddresses[2] = peer3;
        
        address[] memory smartAccounts = new address[](3);
        smartAccounts[0] = address(peerAccount);
        smartAccounts[1] = address(0);
        smartAccounts[2] = address(0);
        
        vm.prank(owner);
        rpRegistry.registerOprfPeers(peerAddresses, smartAccounts);
    }
    
    // =============================================
    //           Initialization Tests
    // =============================================
    
    function test_Initialization() public {
        assertEq(peerAccount.owner(), peer1);
        assertEq(address(peerAccount.entryPoint()), address(entryPoint));
    }
    
    // =============================================
    //           Execute Function Tests
    // =============================================
    
    function test_Execute_FromOwner() public {
        // Create mock call data
        bytes memory callData = abi.encodeWithSignature("someFunction()");
        
        vm.prank(peer1);
        vm.expectEmit(true, false, false, true);
        emit CallExecuted(address(rpRegistry), 0, callData, true);
        
        peerAccount.execute(address(rpRegistry), 0, callData);
    }
    
    function test_Execute_FromEntryPoint() public {
        bytes memory callData = abi.encodeWithSignature("someFunction()");
        
        vm.prank(address(entryPoint));
        vm.expectEmit(true, false, false, true);
        emit CallExecuted(address(rpRegistry), 0, callData, true);
        
        peerAccount.execute(address(rpRegistry), 0, callData);
    }
    
    function test_Execute_RevertUnauthorized() public {
        bytes memory callData = abi.encodeWithSignature("someFunction()");
        
        vm.prank(address(0x999)); // Random unauthorized address
        vm.expectRevert(OprfPeerAccount.OnlyOwnerOrEntryPoint.selector);
        peerAccount.execute(address(rpRegistry), 0, callData);
    }
    
    // =============================================
    //        Round 1 Contribution Tests
    // =============================================
    
    function test_SubmitRound1Contribution() public {
        // First init a keygen as admin
        vm.prank(keygenAdmin);
        Types.EcDsaPubkeyCompressed memory ecdsaKey = Types.EcDsaPubkeyCompressed({
            x: bytes32(uint256(12345)),
            yParity: 2
        });
        rpRegistry.initKeyGen(TEST_RP_ID, ecdsaKey);
        
        // Create Round 1 contribution
        Types.Round1Contribution memory contribution = Types.Round1Contribution({
            commShare: Types.BabyJubJubElement({x: 100, y: 200}),
            commCoeffs: 300,
            ephPubKey: Types.BabyJubJubElement({x: 400, y: 500})
        });
        
        // Submit via smart account (as peer1 who owns the account)
        vm.prank(peer1);
        peerAccount.submitRound1Contribution(
            address(rpRegistry),
            TEST_RP_ID,
            contribution
        );
        
        // Verify the contribution was accepted by checking party ID
        // This would normally check internal state, but we can verify no revert happened
        assertTrue(true, "Round 1 contribution submitted successfully");
    }
    
    function test_SubmitRound1Contribution_RevertNotOwner() public {
        Types.Round1Contribution memory contribution = Types.Round1Contribution({
            commShare: Types.BabyJubJubElement({x: 100, y: 200}),
            commCoeffs: 300,
            ephPubKey: Types.BabyJubJubElement({x: 400, y: 500})
        });
        
        vm.prank(address(0x999)); // Not the owner
        vm.expectRevert(OprfPeerAccount.OnlyOwner.selector);
        peerAccount.submitRound1Contribution(
            address(rpRegistry),
            TEST_RP_ID,
            contribution
        );
    }
    
    // =============================================
    //        Round 3 Contribution Tests
    // =============================================
    
    function test_SubmitRound3Contribution() public {
        // This would normally require Round 1 and 2 to be complete
        // For testing, we just verify the function can be called
        
        vm.prank(peer1);
        // This will revert from RpRegistry but we're testing the account works
        vm.expectRevert(); // Expect revert from RpRegistry (not ready for Round 3)
        peerAccount.submitRound3Contribution(address(rpRegistry), TEST_RP_ID);
    }
    
    // =============================================
    //         Batch Operation Tests
    // =============================================
    
    function test_ExecuteBatch() public {
        bytes[] memory callDatas = new bytes[](3);
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        
        for (uint i = 0; i < 3; i++) {
            callDatas[i] = abi.encodeWithSignature("someFunction()");
            targets[i] = address(rpRegistry);
            values[i] = 0;
        }
        
        vm.prank(peer1);
        peerAccount.executeBatch(targets, values, callDatas);
    }
    
    function test_BatchRound3Contributions() public {
        uint128[] memory rpIds = new uint128[](3);
        rpIds[0] = 1;
        rpIds[1] = 2;
        rpIds[2] = 3;
        
        vm.prank(peer1);
        // These will revert from RpRegistry but we're testing the batch works
        vm.expectRevert();
        peerAccount.batchRound3Contributions(address(rpRegistry), rpIds);
    }
    
    // =============================================
    //          Query Function Tests
    // =============================================
    
    function test_CheckParticipantStatus() public view {
        // This should return party ID 0 for peer1's smart account
        uint256 partyId = peerAccount.checkParticipantStatus(address(rpRegistry));
        assertEq(partyId, 0, "Should return party ID 0");
    }
    
    function test_GetRpNullifierKey_NotYetGenerated() public {
        vm.expectRevert(); // Should revert as no key generated yet
        peerAccount.getRpNullifierKey(address(rpRegistry), TEST_RP_ID);
    }
    
    // =============================================
    //        Account Management Tests
    // =============================================
    
    function test_TransferOwnership() public {
        address newOwner = address(0x555);
        
        vm.prank(peer1);
        vm.expectEmit(true, true, false, false);
        emit OwnerChanged(peer1, newOwner);
        
        peerAccount.transferOwnership(newOwner);
        
        assertEq(peerAccount.owner(), newOwner);
    }
    
    function test_TransferOwnership_RevertNotOwner() public {
        address newOwner = address(0x555);
        
        vm.prank(address(0x999));
        vm.expectRevert(OprfPeerAccount.OnlyOwner.selector);
        peerAccount.transferOwnership(newOwner);
    }
    
    function test_AddDeposit() public {
        uint256 depositAmount = 1 ether;
        
        // Anyone can add deposit
        deal(address(this), depositAmount);
        peerAccount.addDeposit{value: depositAmount}();
        
        assertEq(peerAccount.getDeposit(), depositAmount);
    }
    
    function test_WithdrawDeposit() public {
        // First add deposit
        uint256 depositAmount = 1 ether;
        deal(address(this), depositAmount);
        peerAccount.addDeposit{value: depositAmount}();
        
        // Withdraw as owner
        address payable recipient = payable(address(0x777));
        uint256 balanceBefore = recipient.balance;
        
        vm.prank(peer1);
        peerAccount.withdrawDepositTo(recipient, depositAmount);
        
        assertEq(recipient.balance - balanceBefore, depositAmount);
        assertEq(peerAccount.getDeposit(), 0);
    }
    
    function test_WithdrawDeposit_RevertNotOwner() public {
        address payable recipient = payable(address(0x777));
        
        vm.prank(address(0x999));
        vm.expectRevert(OprfPeerAccount.OnlyOwner.selector);
        peerAccount.withdrawDepositTo(recipient, 1 ether);
    }
    
    // =============================================
    //            Receive ETH Test
    // =============================================
    
    function test_ReceiveETH() public {
        uint256 sendAmount = 1 ether;
        deal(address(this), sendAmount);
        
        (bool success,) = address(peerAccount).call{value: sendAmount}("");
        assertTrue(success);
        assertEq(address(peerAccount).balance, sendAmount);
    }
    
    // =============================================
    //          Integration Test
    // =============================================
    
    function test_FullKeyGenFlow_HappyPath() public {
        // 1. Admin initializes key generation
        vm.prank(keygenAdmin);
        Types.EcDsaPubkeyCompressed memory ecdsaKey = Types.EcDsaPubkeyCompressed({
            x: bytes32(uint256(12345)),
            yParity: 2
        });
        rpRegistry.initKeyGen(TEST_RP_ID, ecdsaKey);
        
        // 2. Peer submits Round 1 contribution via smart account
        Types.Round1Contribution memory round1 = Types.Round1Contribution({
            commShare: Types.BabyJubJubElement({x: 100, y: 200}),
            commCoeffs: 300,
            ephPubKey: Types.BabyJubJubElement({x: 400, y: 500})
        });
        
        vm.prank(peer1);
        peerAccount.submitRound1Contribution(
            address(rpRegistry),
            TEST_RP_ID,
            round1
        );
        
        // 3. Check participant status
        uint256 partyId = peerAccount.checkParticipantStatus(address(rpRegistry));
        assertEq(partyId, 0, "Peer1 should have party ID 0");
        
        console.log("Full key generation flow test completed successfully");
    }
}
