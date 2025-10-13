#!/bin/bash

AWS_ACCESS_KEY_ID=test
AWS_SECRET_KEY=test
echo $AWS_ACCESS_KEY_ID
mkdir -p logs
ls -al
# Start anvil
anvil &
anvil_pid=$!
echo "started anvil with PID $anvil_pid"
sleep 2
echo "############ starting AccountRegistry contract..."
cd contracts && TREE_DEPTH=10 forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 && cd ..
echo "############ starting KeyGen contract..."
cd contracts && forge script script/KeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 && cd ..
echo "############ btarting AuthTreeIndexer service..."
./auth-tree-indexer > logs/auth_tree_indexer.log 2>&1 &
auth_tree_indexer=$1
echo "started AuthTreeIndexer service with PID $auth_tree_indexer"
echo "setup finished"
trap "kill $auth_tree_indexer" SIGINT SIGTERM
wait $auth_tree_indexer


echo "exiting..."

# Exit with status of process that exited first
exit $?
