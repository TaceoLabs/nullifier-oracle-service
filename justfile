lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items

dev-up:
    cd oprf-service/deploy && docker-compose up -d
    cargo run --bin key-gen -- --overwrite-old-keys

dev-down:
    cd oprf-service/deploy && docker-compose down

unit-tests:
    cargo test --release --all-features --lib

check-pr: lint unit-tests

bench:
    cargo bench --all-features

run-mock:
    #!/usr/bin/env bash
    cargo build --workspace
    RUST_LOG="smart_contract_mock=trace,warn" ./target/debug/smart-contract-mock --oprf-services 3 --oprf-degree 1 > logs/mock_chain.log 2>&1 &
    pid_sc=$!
    echo "started smart contract mock with PID $pid_sc"
    trap "kill $pid_sc" SIGINT SIGTERM
    wait $pid_sc

run-account-registry:
    cd contracts && forge script script/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-create-account:
    cd contracts && ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script script/CreateAccount.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

run-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --chain-url http://localhost:6789 --chain-check-interval 1s --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10000 --private-key-secret-id oprf/sk/n0 --environment dev --dlog-share-secret-id-suffix oprf/share/n0 > logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --chain-url http://localhost:6789 --chain-check-interval 1s --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10001 --private-key-secret-id oprf/sk/n1 --environment dev --dlog-share-secret-id-suffix oprf/share/n1 > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --chain-url http://localhost:6789 --chain-check-interval 1s --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10002 --private-key-secret-id oprf/sk/n2 --environment dev --dlog-share-secret-id-suffix oprf/share/n2 > logs/service2.log 2>&1  &
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
    sleep 2
    just run-account-registry
    echo "started AccountRegistry"
    RUST_LOG=debug cargo run --release --bin auth-tree-indexer > logs/auth_tree_indexer.log 2>&1 &
    auth_tree_indexer=$!
    echo "started AuthTreeIndexer with PID $auth_tree_indexer"
    just run-mock & # TODO remove
    echo "started mock"
    sleep 2
    just run-services &
    echo "started services"
    sleep 2
    just run-create-account
    trap "kill $auth_tree_indexer $anvil_pid" SIGINT SIGTERM
    wait $auth_tree_indxer $anvil_pid

run-dev-client *args:
    cargo run --release --bin oprf-dev-client -- {{args}}

build-push-docker-image-oprf-service-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service:{{TAG}}-amd64 -f build/Dockerfile.oprf-service .

build-push-docker-image-key-gen-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/key-gen:{{TAG}}-amd64 -f build/Dockerfile.key-gen .
  
build-push-docker-image-smart-contract-mock-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/smart-contract-mock:{{TAG}}-amd64 -f build/Dockerfile.smart-contract-mock .