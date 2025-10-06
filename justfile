lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items

dev-up:
    cd oprf-service/deploy && docker-compose up -d

dev-down:
    cd oprf-service/deploy && docker-compose down

unit-tests:
    cargo test --release --all-features --lib

integration-tests:
    cargo test --release --package oprf-test

all-tests:
    cargo test --release --all-features

check-pr: lint all-tests

bench:
    cargo bench --all-features

run-account-registry:
    cd contracts && forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-create-account:
    cd contracts && ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script script/CreateAccount.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-key-gen:
    cd contracts && forge script script/KeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-init-key-gen:
    cd contracts && KEYGEN_CONTRACT=0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9 forge script script/InitKeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-auth-tree-indexer:
    #!/usr/bin/env bash
    cargo build --workspace
    RUST_LOG="debug" ./target/debug/auth-tree-indexer > logs/auth_tree_indexer.log 2>&1 &
    auth_tree_indexer=$!
    echo "started AuthTreeIndexer service with PID $auth_tree_indexer"
    trap "kill $auth_tree_indexer" SIGINT SIGTERM
    wait $auth_tree_indexer

run-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --key-gen-contract 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9 --chain-ws-rpc-url ws://localhost:8545 --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10000 --private-key-secret-id oprf/sk/n0 --environment dev --dlog-share-secret-id-suffix oprf/share/n0 --wallet-private-key 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356 > logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --key-gen-contract 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9 --chain-ws-rpc-url ws://localhost:8545 --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10001 --private-key-secret-id oprf/sk/n1 --environment dev --dlog-share-secret-id-suffix oprf/share/n1 --wallet-private-key 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97 > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --key-gen-contract 0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9 --chain-ws-rpc-url ws://localhost:8545  --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10002 --private-key-secret-id oprf/sk/n2 --environment dev --dlog-share-secret-id-suffix oprf/share/n2 --wallet-private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 > logs/service2.log 2>&1  &
    pid2=$!
    echo "started service2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

run-setup:
    #!/usr/bin/env bash
    echo "generating keys..."
    cargo run --bin key-gen -- --overwrite-old-keys
    mkdir -p logs
    anvil &
    anvil_pid=$!
    echo "started anvil with PID $anvil_pid"
    sleep 2
    echo "starting AccountRegistry contract..."
    just run-account-registry
    echo "starting KeyGen contract..."
    just run-key-gen
    echo "starting AuthTreeIndexer service..."
    just run-auth-tree-indexer &
    sleep 2
    echo "starting OPRF services..."
    just run-services &
    sleep 2
    echo "creating account..."
    just run-create-account
    echo "ready to run dev-client"
    trap "kill $anvil_pid" SIGINT SIGTERM
    wait $anvil_pid

run-dev-client *args:
    cargo run --release --bin oprf-dev-client -- --wallet-private-key 0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e {{args}}

build-push-docker-image-oprf-service-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service:{{TAG}}-amd64 -f build/Dockerfile.oprf-service .

build-push-docker-image-key-gen-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/key-gen:{{TAG}}-amd64 -f build/Dockerfile.key-gen .
  
build-push-docker-image-smart-contract-mock-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/smart-contract-mock:{{TAG}}-amd64 -f build/Dockerfile.smart-contract-mock .