// test-gasless.ts
const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

interface DeployedContracts {
  rpRegistry?: string;
  rpRegistryImpl?: string;
  entryPoint?: string;
  paymaster?: string;
  aliceAccount?: string;
  bobAccount?: string;
  carolAccount?: string;
}

async function getDeployedContracts(): Promise<DeployedContracts> {
  const broadcastFile = path.join(
    __dirname,
    "../contracts/broadcast/RpRegistryWithDeps.s.sol/31337/run-latest.json"
  );
  
  if (!fs.existsSync(broadcastFile)) {
    throw new Error("No deployment found. Run deployment first!");
  }
  
  const data = JSON.parse(fs.readFileSync(broadcastFile, "utf8"));
  const contracts: DeployedContracts = {};
  const proxies: any[] = [];
  
  // Parse transactions to find our contracts
  for (const tx of data.transactions) {
    if (tx.contractName === "RpRegistry") {
      contracts.rpRegistryImpl = tx.contractAddress;
    } else if (tx.contractName === "EntryPoint") {
      contracts.entryPoint = tx.contractAddress;
    } else if (tx.contractName === "OprfPaymaster") {
      contracts.paymaster = tx.contractAddress;
    } else if (tx.contractName === "ERC1967Proxy") {
      proxies.push({
        address: tx.contractAddress,
        input: tx.transaction.input.toLowerCase()
      });
    }
  }

  
  // Identify proxies more carefully
  // Peer addresses (lowercase, no 0x)
  const peerAddresses = {
    alice: "14dc79964da2c08b23698b3d3cc7ca32193d9955",
    bob: "23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f", 
    carol: "a0ee7a142d267c1f36714e4a8f75612f20a79720"
  };
  

if (proxies.length >= 4) {
  contracts.rpRegistry = proxies[0].address;  
  contracts.aliceAccount = proxies[2].address; 
  contracts.bobAccount = proxies[3].address;
  contracts.carolAccount = proxies[1].address; 
}
  
  return contracts;
}

async function main() {
  console.log("🚀 Testing ERC-4337 Gasless Transactions");
  
  const provider = new ethers.providers.JsonRpcProvider("http://127.0.0.1:8545");
  
  // Get deployed contracts
  const contracts = await getDeployedContracts();
  console.log("Found contracts:");
  Object.entries(contracts).forEach(([name, addr]) => {
    console.log(`  ${name}: ${addr}`);
  });
  
  // Validate we have everything we need
  const required = ['rpRegistry', 'entryPoint', 'paymaster', 'aliceAccount'];
  const missing = required.filter(key => !contracts[key as keyof DeployedContracts]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required contracts: ${missing.join(', ')}`);
  }
  
  // ABIs
  const entryPointABI = [
    "function handleOps(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerficationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature)[] ops, address beneficiary)",
    "function getUserOpHash(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature) userOp) view returns (bytes32)",
    "function getNonce(address sender, uint192 key) view returns (uint256)"
  ];
  
  const accountABI = [
      "function submitRound1Contribution("
      + "address rpRegistryProxy,"
      + "uint128 rpId,"
      + "tuple("
          + "tuple(uint256 x, uint256 y) commShare,"
          + "uint256 commCoeffs,"
          + "tuple(uint256 x, uint256 y) ephPubKey"
      + ") data"
  + ")",
    "function owner() view returns (address)",
    "function execute(address dest, uint256 value, bytes calldata func)",
    "function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func)"
  ];
  
  const rpRegistryABI = [
    "function initKeyGen(uint128 rpId, tuple(bytes32 x, uint256 yParity) ecdsaPubKey)",
    "function isContractReady() view returns (bool)",
    "function owner() view returns (address)", 
    "function submitRound1Contribution(address rpRegistryProxy, uint128 rpId, tuple(tuple(uint256 x, uint256 y) commShare, uint256 commCoeffs, tuple(uint256 x, uint256 y) ephPubKey) contribution) returns (bool)"
  ];
  
  // Create contract instances
  const entryPoint = new ethers.Contract(contracts.entryPoint!, entryPointABI, provider);
  const aliceAccount = new ethers.Contract(contracts.aliceAccount!, accountABI, provider);
  const rpRegistry = new ethers.Contract(contracts.rpRegistry!, rpRegistryABI, provider);
  
  // Setup signers
  const adminPrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  const alicePrivateKey = "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356";
  
  const adminSigner = new ethers.Wallet(adminPrivateKey, provider);
  const aliceSigner = new ethers.Wallet(alicePrivateKey, provider);
  
  console.log("\n📋 Contract State:");
  console.log("  Admin address:", adminSigner.address);
  console.log("  Alice EOA:", aliceSigner.address);
  
  // Check if registry is ready
  const isReady = await rpRegistry.isContractReady();
  console.log("  Registry ready:", isReady);
  
  // Check Alice's account owner
  const owner = await aliceAccount.owner();
  console.log("  Alice account owner:", owner);
  console.log("  Expected owner:", aliceSigner.address);
  
  if (owner.toLowerCase() !== aliceSigner.address.toLowerCase()) {
    console.error("❌ Alice's account has wrong owner!");
    console.log("\n🔍 Debugging: Let's check all proxy deployments...");
    
    // Re-read the file to debug
    const data = JSON.parse(fs.readFileSync(
      path.join(__dirname, "../nullifier-oracle-service/contracts/broadcast/DeployRpRegistryWithDepsScript.s.sol/31337/run-latest.json"),
      "utf8"
    ));
    
    console.log("\nAll ERC1967Proxy deployments:");
    let proxyCount = 0;
    for (const tx of data.transactions) {
      if (tx.contractName === "ERC1967Proxy") {
        proxyCount++;
        console.log(`\nProxy #${proxyCount}:`);
        console.log(`  Address: ${tx.contractAddress}`);
        console.log(`  Input preview: ${tx.transaction.input.substring(0, 200)}...`);

        // Check what's in the input
        if (tx.transaction.input.toLowerCase().includes("14dc79964da2c08b23698b3d3cc7ca32193d9955")) {
          console.log("  -> Contains Alice's EOA");
        }
        if (tx.transaction.input.toLowerCase().includes("23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f")) {
          console.log("  -> Contains Bob's EOA");
        }
        if (tx.transaction.input.toLowerCase().includes("a0ee7a142d267c1f36714e4a8f75612f20a79720")) {
          console.log("  -> Contains Carol's EOA");
        }
      }
    }
    
    throw new Error("Account ownership mismatch - deployment may be incorrect");
  }


  console.log("\n🔑 Skipping key generation, testing gasless transactions...");
  const rpId = ethers.BigNumber.from(5)
  console.log("  Using test rpId:", rpId);
  
  // Get nonce for Alice's account
  const nonce = await entryPoint.getNonce(contracts.aliceAccount, 0);
  console.log("  Alice account nonce:", nonce.toString());
  
 // Create Round 1 contribution
  const contribution = {
   commShare: {
    x: "0x1713acbc11e0f0fdaebbcedceed52e57abf30f2b8c435f013ce0756e4377f097",
    y: "0x28145c47c630ed060a7f10ea3d727b9bc0d249796172c2bcb58b836d1e3d4bd4"
   },
   commCoeffs: "0x06fc7aa21491e4b6878290f06958efa50de23e427d7b4f17b49b8da6191ad41f", // Added leading 0
   ephPubKey: {
    x: "0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e",
    y: "0x03f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3" // Also added leading 0 here
   }
  }; 
  // Encode the call data for the account to execute
  const iface = new ethers.utils.Interface(accountABI);
  const callData = iface.encodeFunctionData("submitRound1Contribution", [
    contracts.rpRegistry,
    rpId,
    contribution
  ]);

  // Create Packed UserOperation
  const userOp = {
    sender: contracts.aliceAccount,
    nonce: nonce,
    initCode: "0x",
    callData: callData,
    accountGasLimits: ethers.utils.hexConcat([
      ethers.utils.hexZeroPad(ethers.BigNumber.from("150000").toHexString(), 16), // verificationGasLimit (16 bytes)
      ethers.utils.hexZeroPad(ethers.BigNumber.from("300000").toHexString(), 16)  // callGasLimit (16 bytes)
    ]), // bytes32: packed verificationGasLimit and callGasLimit
    preVerificationGas: ethers.BigNumber.from("50000"),
    gasFees: ethers.utils.hexConcat([
      ethers.utils.hexZeroPad(ethers.utils.parseUnits("1", "gwei").toHexString(), 16),  // maxPriorityFeePerGas (16 bytes)
      ethers.utils.hexZeroPad(ethers.utils.parseUnits("10", "gwei").toHexString(), 16)  // maxFeePerGas (16 bytes)
    ]), // bytes32: packed maxPriorityFeePerGas and maxFeePerGas
    paymasterAndData: contracts.paymaster,
    signature: "0x"
  };

  console.log("\n📝 Creating UserOperation...");
  console.log("  Sender:", userOp.sender);
  console.log("  Paymaster:", userOp.paymasterAndData);

  // TODO: Make sure Alices account is authorized to receive sponsorship in paymaster

  // Get user op hash
  const userOpHash = await entryPoint.getUserOpHash(userOp);
  console.log("  UserOp hash:", userOpHash);

  // Sign the hash with Alice's private key
  const signature = await aliceSigner.signMessage(ethers.utils.arrayify(userOpHash));
  userOp.signature = signature;
  console.log("  Signature:", signature);

  // Check Alice's balance before
  const balanceBefore = await provider.getBalance(aliceSigner.address);
  console.log("\n💰 Alice's balance before:", ethers.utils.formatEther(balanceBefore), "ETH");

  // Prepare InitKeygen in RpRegistry TODO: Question: Should this be gasless as well..?
  const ecdsaPubKey = {
    x: ethers.utils.hexZeroPad("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 32),
    yParity: 2
  };

  console.log(rpRegistry.interface.format(ethers.utils.FormatTypes.full));

  try {
    const initTx = await rpRegistry.connect(adminSigner).initKeyGen(
      rpId,
      ecdsaPubKey,
      { gasLimit: 3000000 }
    );
    const receipt = await initTx.wait();
    console.log("  ✅ Success! Gas used:", receipt.gasUsed.toString());
    console.log("  Transaction hash:", receipt.transactionHash);
  } catch (error: any) {
    console.log("  ❌ Transaction failed:", error.message);
  }


  // Submit UserOperation via EntryPoint
  console.log("\n🚀 Submitting UserOperation...");
  try {
    const entryPointWithSigner = entryPoint.connect(adminSigner);
    const handleOpsTx = await entryPointWithSigner.handleOps(
      [userOp],
      adminSigner.address,
      { gasLimit: 2000000 }
    );
    
    const receipt = await handleOpsTx.wait();
    console.log("  ✅ Transaction successful!");
    console.log("  Gas used:", receipt.gasUsed.toString());
    console.log("  Transaction hash:", receipt.transactionHash);
    
    // Check Alice's balance after
    const balanceAfter = await provider.getBalance(aliceSigner.address);
    console.log("\n💰 Alice's balance after:", ethers.utils.formatEther(balanceAfter), "ETH");
    
    if (balanceBefore.eq(balanceAfter)) {
      console.log("  ✅ GASLESS SUCCESS! Alice paid no gas!");
    } else {
      console.log("  ❌ Alice's balance changed - gas was paid");
    }
    
  } catch (error: any) {
    console.error("  ❌ UserOperation failed:", error.message);
    
    // Try direct call for debugging
    console.log("\n🔍 Attempting direct call for debugging...");
    try {
      const aliceAccountWithSigner = aliceAccount.connect(aliceSigner);
      const directTx = await aliceAccountWithSigner.submitRound1Contribution(
        contracts.rpRegistry,
        rpId,
        contribution,
        { gasLimit: 500000 }
      );
      await directTx.wait();
      console.log("  Direct call succeeded - issue is with UserOp validation");
    } catch (directError: any) {
      console.error("  Direct call also failed:", directError.message);
    }
  }
}

main().catch(error => {
  console.error("Fatal error:", error);
  process.exit(1);
});
