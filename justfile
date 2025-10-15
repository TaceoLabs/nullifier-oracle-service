lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
    cd contracts && forge fmt

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

circom-tests:
    cd circom/tests && npm ci && npm test
    
contract-tests:
    cd contracts && forge test

check-pr: lint all-tests circom-tests contract-tests

bench:
    cargo bench --all-features

run-account-registry:
    cd contracts && TREE_DEPTH=10 forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-auth-tree-indexer *args:
    #!/usr/bin/env bash
    cargo build --workspace --release
    RUST_LOG="debug" ./target/release/auth-tree-indexer {{args}} > logs/auth_tree_indexer.log 2>&1 &
    auth_tree_indexer=$!
    echo "started AuthTreeIndexer service with PID $auth_tree_indexer"
    trap "kill $auth_tree_indexer" SIGINT SIGTERM
    wait $auth_tree_indexer

init-rp-registry:
    cargo build --workspace --release
    ./target/release/init-rp-registry-contract --overwrite-old-keys  

run-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace --release
    # anvil wallet 7
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10000 --private-key-secret-id oprf/sk/n0 --rp-secret-id-suffix oprf/rp/n0 --environment dev --wallet-private-key 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356 --key-gen-zkey-path ./keygen_13.zkey --key-gen-witness-graph-path ./keygen_graph.bin > logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10001 --private-key-secret-id oprf/sk/n1 --rp-secret-id-suffix oprf/rp/n1 --environment dev --wallet-private-key 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97 --key-gen-zkey-path ./keygen_13.zkey --key-gen-witness-graph-path ./keygen_graph.bin > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10002 --private-key-secret-id oprf/sk/n2 --rp-secret-id-suffix oprf/rp/n2 --environment dev --wallet-private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 --key-gen-zkey-path ./keygen_13.zkey --key-gen-witness-graph-path ./keygen_graph.bin > logs/service2.log 2>&1  &
    pid2=$!
    echo "started service2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

run-setup:
    #!/usr/bin/env bash
    mkdir -p logs
    anvil &
    anvil_pid=$!
    echo "started anvil with PID $anvil_pid"
    sleep 1
    echo "starting AccountRegistry contract..."
    just run-account-registry
    echo "starting RpRegistry contract.."
    just init-rp-registry
    echo "starting AuthTreeIndexer service..."
    just run-auth-tree-indexer &
    sleep 2
    echo "starting OPRF services..."
    just run-services &
    sleep 2
    echo "ready to run dev-client"
    trap "kill $anvil_pid" SIGINT SIGTERM
    wait $anvil_pid

run-dev-client *args:
    cargo build --workspace --release
    ./target/release/oprf-dev-client {{args}}

build-push-docker-image-oprf-service-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service:{{TAG}}-amd64 -f build/Dockerfile.oprf-service .

build-push-docker-image-key-gen-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/key-gen:{{TAG}}-amd64 -f build/Dockerfile.key-gen .