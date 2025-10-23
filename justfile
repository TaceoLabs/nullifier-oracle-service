[private]
default:
    @just --justfile {{justfile()}} --list --list-heading $'Project commands:\n'


[group: 'build']
dev-up:
    cd oprf-service/deploy && docker-compose up -d

[group: 'build']
dev-down:
    cd oprf-service/deploy && docker-compose down

[group: 'build']
export-contract-abi:
    cd contracts && forge build --silent && jq '.abi' out/RpRegistry.sol/RpRegistry.json > RpRegistry.json

[group: 'test']
unit-tests:
    cargo test --release --all-features --lib

[group: 'test']
integration-tests:
    cargo test --release --package oprf-test

[group: 'test']
all-rust-tests:
    cargo test --release --all-features

[group: 'test']
circom-tests:
    cd circom/tests && npm ci && npm test
    
[group: 'test']
contract-tests:
    cd contracts && forge test

[group: 'test']
all-tests: check-pr

[group: 'ci']
check-pr: lint all-rust-tests circom-tests contract-tests

[group: 'ci']
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
    cd contracts && forge fmt

[private]
run-account-registry:
    cd contracts && forge script script/test/AccountRegistry.s.sol --broadcast --rpc-url 127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[private]
run-auth-tree-indexer *args:
    #!/usr/bin/env bash
    cargo build --workspace --release
    RUST_LOG="debug" ./target/release/auth-tree-indexer {{args}} > logs/auth_tree_indexer.log 2>&1 &
    auth_tree_indexer=$!
    echo "started AuthTreeIndexer service with PID $auth_tree_indexer"
    trap "kill $auth_tree_indexer" SIGINT SIGTERM
    wait $auth_tree_indexer

[private]
run-rp-registry:
    cargo build --workspace --release
    ./target/release/test-setup-helper --overwrite-old-keys --chain-ws-rpc-url ws://127.0.0.1:8545

[group: 'local-setup']
run-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace --release
    # anvil wallet 7
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/query.vk.json --bind-addr 127.0.0.1:10000 --private-key-secret-id oprf/sk/n0 --rp-secret-id-suffix oprf/rp/n0 --environment dev --wallet-private-key 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356 --key-gen-zkey-path ./circom/keygen_13.zkey --key-gen-witness-graph-path ./circom/keygen_graph.bin > logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/query.vk.json --bind-addr 127.0.0.1:10001 --private-key-secret-id oprf/sk/n1 --rp-secret-id-suffix oprf/rp/n1 --environment dev --wallet-private-key 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97 --key-gen-zkey-path ./circom/keygen_13.zkey --key-gen-witness-graph-path ./circom/keygen_graph.bin > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/query.vk.json --bind-addr 127.0.0.1:10002 --private-key-secret-id oprf/sk/n2 --rp-secret-id-suffix oprf/rp/n2 --environment dev --wallet-private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 --key-gen-zkey-path ./circom/keygen_13.zkey --key-gen-witness-graph-path ./circom/keygen_graph.bin > logs/service2.log 2>&1  &
    pid2=$!
    echo "started service2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group: 'local-setup']
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
    just run-rp-registry
    echo "starting AuthTreeIndexer service..."
    just run-auth-tree-indexer &
    sleep 2
    echo "starting OPRF services..."
    just run-services &
    sleep 2
    echo "ready to run dev-client"
    trap "kill $anvil_pid" SIGINT SIGTERM
    wait $anvil_pid

[group: 'local-setup']
run-rp-registry-and-services account_registry:
    #!/usr/bin/env bash
    mkdir -p logs
    echo "starting RpRegistry contract.."
    just run-rp-registry | tee logs/rp_registry.log
    address=$(grep -oP 'RpRegistry deployed to \K0x[a-fA-F0-9]+' logs/rp_registry.log)
    echo $address
    sleep 2
    echo "starting OPRF services..."
    OPRF_SERVICE_ACCOUNT_REGISTRY_CONTRACT={{account_registry}} OPRF_SERVICE_RP_REGISTRY_CONTRACT=$address just run-services

[group: 'dev-client']
run-dev-client *args:
    cargo build --workspace --release
    ./target/release/oprf-dev-client {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/deploy']
deploy-rp-registry-with-deps-dry-run *args: 
    forge script RpRegistryWithDeps.s.sol -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/deploy']
deploy-rp-registry-with-deps *args: 
    forge script RpRegistryWithDeps.s.sol --broadcast --interactives 1 -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/deploy']
deploy-rp-registry-dry-run *args: 
    forge script RpRegistry.s.sol -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/deploy']
deploy-rp-registry *args: 
    forge script RpRegistry.s.sol --broadcast --interactives 1 -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/test']
deploy-account-registry-dry-run *args: 
    forge script AccountRegistry.s.sol -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/test']
deploy-account-registry *args: 
    forge script AccountRegistry.s.sol --broadcast --interactives 1 -vvvvv {{args}}


[group: 'deploy']
[working-directory: 'contracts/script/deploy']
register-participants *args: 
    forge script RegisterParticipants.s.sol --broadcast --interactives 1 -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/deploy']
register-participants-dry-run *args: 
    forge script RegisterParticipants.s.sol -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/test']
create-account-auth-tree *args: 
    forge script CreateAccount.s.sol --broadcast --interactives 1 -vvvvv {{args}}

[group: 'deploy']
[working-directory: 'contracts/script/test']
create-account-auth-tree-dry-run *args: 
    forge script CreateAccount.s.sol -vvvvv {{args}}


[group: 'anvil']
[working-directory: 'contracts/script/deploy']
deploy-rp-registry-with-deps-anvil: 
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 forge script RpRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group: 'anvil']
[working-directory: 'contracts/script/deploy']
deploy-rp-registry-anvil: 
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 forge script RpRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group: 'anvil']
[working-directory: 'contracts/script/test']
deploy-account-registry-anvil: 
    forge script AccountRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group: 'anvil']
[working-directory: 'contracts/script/deploy']
register-participants-anvil: 
    RP_REGISTRY_ADDRESS=0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9 ALICE_ADDRESS=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955 BOB_ADDRESS=0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f CAROL_ADDRESS=0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group: 'anvil']
[working-directory: 'contracts/script/test']
create-account-auth-tree-anvil: 
    ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script CreateAccount.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group: 'docker']
build-push-docker-image-oprf-service-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service:{{TAG}}-amd64 -f build/Dockerfile.oprf-service .

[group: 'docker']
build-push-docker-image-key-gen-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/key-gen:{{TAG}}-amd64 -f build/Dockerfile.key-gen .
