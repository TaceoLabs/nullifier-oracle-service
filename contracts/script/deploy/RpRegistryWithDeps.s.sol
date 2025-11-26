// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {RpRegistry} from "../../src/RpRegistry.sol";
import {Groth16Verifier as Groth16VerifierKeyGen13} from "../../src/Groth16VerifierKeyGen13.sol";
import {BabyJubJub} from "../../src/BabyJubJub.sol";
import {Types} from "../../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {OprfPaymaster} from "../../src/OprfPaymaster.sol";
import {OprfPeerAccount} from "../../src/OprfPeerAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract DeployRpRegistryWithDepsScript is Script {
    using Types for Types.BabyJubJubElement;

    RpRegistry public rpRegistry;
    ERC1967Proxy public proxy;
    EntryPoint public entryPoint;
    OprfPaymaster public paymaster;
    OprfPeerAccount public peerAccount;

    uint256 public constant PAYMASTER_DEPOSIT = 10 ether;

    function setUp() public {}

    function deployGroth16VerifierKeyGen() public returns (address) {
        Groth16VerifierKeyGen13 verifier = new Groth16VerifierKeyGen13();
        console.log("Groth16VerifierKeyGen13 deployed to:", address(verifier));
        return address(verifier);
    }

    function deployAccumulator() public returns (address) {
        BabyJubJub acc = new BabyJubJub();
        console.log("Accumulator deployed to:", address(acc));
        return address(acc);
    }

     function deployEntryPoint() public returns (address) {
        entryPoint = new EntryPoint();
        console.log("\n=== Deploying EntryPoint ===");
        console.log("EntryPoint deployed to:", address(entryPoint));
        return address(entryPoint);
    }

    function deployPaymaster(address _entryPoint, address _rpRegistry) public returns (address) {
        console.log("\n=== Deploying OprfPaymaster ===");
        console.log("Using EntryPoint:", _entryPoint);
        console.log("Using RpRegistry:", _rpRegistry);

        paymaster = new OprfPaymaster(IEntryPoint(_entryPoint), _rpRegistry);
        console.log("OprfPaymaster deployed to:", address(paymaster));
        console.log("Paymaster owner:", paymaster.owner());

        // Fund the paymaster
        if (address(msg.sender).balance >= PAYMASTER_DEPOSIT) {
            console.log("Funding paymaster with:", PAYMASTER_DEPOSIT);
            paymaster.deposit{value: PAYMASTER_DEPOSIT}();
            console.log("Paymaster deposit successful");
            console.log("Paymaster balance in EntryPoint:", paymaster.getDeposit());
        } else {
            console.log("Warning: Insufficient balance to fund paymaster");
            console.log("Sender balance:", address(msg.sender).balance);
        }

        return address(paymaster);
    }

    function deployPeerAccount(address _entryPoint, address owner, string memory name) public returns (address) {
        console.log(string.concat("\n=== Deploying ", name, " Account ==="));
        console.log("Owner:", owner);
        console.log("EntryPoint:", _entryPoint);

        // Deploy implementation
        OprfPeerAccount implementation = new OprfPeerAccount(IEntryPoint(_entryPoint));
        console.log("Implementation deployed to:", address(implementation));

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeCall(
            OprfPeerAccount.initialize,
            (owner)
        );
        ERC1967Proxy accountProxy = new ERC1967Proxy(address(implementation), initData);

        console.log(string.concat(name, " proxy deployed to:"), address(accountProxy));

        // Verify initialization
        OprfPeerAccount account = OprfPeerAccount(payable(address(accountProxy)));
        console.log(string.concat(name, " account owner:"), account.owner());

        return address(accountProxy);
    }

    function run() public {
        vm.startBroadcast();

        address taceoAdminAddress = vm.envAddress("TACEO_ADMIN_ADDRESS");

        address accumulatorAddress = deployAccumulator();
        address keyGenVerifierAddress = deployGroth16VerifierKeyGen();

         // Deploy ERC-4337 infrastructure
        address entryPointAddress = deployEntryPoint();
        address paymasterAddress = deployPaymaster(entryPointAddress, address(rpRegistry));
        address peerAccountAddress = deployPeerAccount(entryPointAddress, taceoAdminAddress, "PeerAccount");

        // Deploy implementation
        RpRegistry implementation = new RpRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            RpRegistry.initialize.selector, taceoAdminAddress, keyGenVerifierAddress, accumulatorAddress
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        rpRegistry = RpRegistry(address(proxy));

        console.log("\n=== Deploying RpRegistry ===");
        console.log("RpRegistry implementation deployed to:", address(implementation));
        console.log("RpRegistry deployed to:", address(rpRegistry));
    }
}
