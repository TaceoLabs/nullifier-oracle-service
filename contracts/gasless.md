1. DEPLOY PHASE (Admin does once):
   - Deploy RpRegistry (proxy + implementation)
   - Deploy OprfAccountFactory
   - Deploy smart accounts for each peer
   - Deploy OprfPaymaster
   - Fund paymaster with ETH/World etc
   - Register peers and smart accounts and do normal keygen stuff.

2. OPERATION PHASE (Peers do repeatedly):
   - Peer signs UserOperation (off-chain)
   - Sends to bundler API
   - Bundler submits to EntryPoint (0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)
   - EntryPoint calls Paymaster.validatePaymasterUserOp()
   - EntryPoint calls SmartAccount.validateUserOp()
   - EntryPoint calls SmartAccount.submitRound1Contribution()
   - SmartAccount calls RpRegistry.addRound1Contribution() etc for all calls..
   - EntryPoint calls Paymaster.postOp() to track gas
