[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[private]
prepare-localstack-secrets:
    aws --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n0 \
      --secret-string '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356'
    aws --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n1 \
      --secret-string '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97'
    aws --endpoint-url=http://localhost:4566 secretsmanager create-secret \
      --name oprf/eth/n2 \
      --secret-string '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6'

[group('build')]
dev-up *args:
    cd oprf-service/deploy && docker-compose up -d {{ args }}

[group('build')]
dev-down:
    cd oprf-service/deploy && docker-compose down

[group('build')]
export-contract-abi:
    cd contracts && forge build --silent && jq '.abi' out/RpRegistry.sol/RpRegistry.json > RpRegistry.json

[group('build')]
[working-directory('circom')]
print-constraints:
    #!/usr/bin/env bash
    key_gen=$(circom main/OPRFKeyGenProof.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    nullifier=$(circom main/OPRFNullifierProof.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    proof=$(circom main/OPRFQueryProof.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    eddsa_poseidon2=$(circom debug/eddsaposeidon2.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    verify_dlog=$(circom debug/verify_dlog.circom -l . --r1cs --O2 | grep -oP "non-linear constraints: \K[0-9]+")
    printf "%-20s %s\n" "Circuit" "Constraints"
    printf "%-20s %s\n" "KeyGen(3-1)" "$key_gen"
    printf "%-20s %s\n" "OPRFNullifier" "$nullifier"
    printf "%-20s %s\n" "QueryProof" "$proof"
    printf "%-20s %s\n" "EdDSA-Poseidon2" "$eddsa_poseidon2"
    printf "%-20s %s\n" "Verify DLog" "$verify_dlog"

[group('test')]
unit-tests:
    cargo test --release --all-features --lib

[group('test')]
integration-tests:
    cargo test --release --package oprf-test

[group('test')]
all-rust-tests:
    cargo test --release --all-features

[group('test')]
circom-tests:
    cd circom/tests && npm ci && npm test

[group('test')]
contract-tests:
    cd contracts && forge test

[group('test')]
all-tests: all-rust-tests circom-tests contract-tests

[group('ci')]
check-pr: lint all-rust-tests circom-tests contract-tests

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items
    cd contracts && forge fmt

[group('local-setup')]
run-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace --release
    # anvil wallet 7
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/main/query/OPRFQuery.vk.json --bind-addr 127.0.0.1:10000 --rp-secret-id-prefix oprf/rp/n0 --environment dev --wallet-private-key-secret-id oprf/eth/n0 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin > logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    # anvil wallet 8
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/main/query/OPRFQuery.vk.json --bind-addr 127.0.0.1:10001 --rp-secret-id-prefix oprf/rp/n1 --environment dev --wallet-private-key-secret-id oprf/eth/n1 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    # anvil wallet 9
    RUST_LOG="oprf_service=trace,warn" ./target/release/oprf-service --user-verification-key-path ./circom/main/query/OPRFQuery.vk.json --bind-addr 127.0.0.1:10002 --rp-secret-id-prefix oprf/rp/n2 --environment dev --wallet-private-key-secret-id oprf/eth/n2 --key-gen-zkey-path ./circom/main/key-gen/OPRFKeyGen.13.zkey --key-gen-witness-graph-path ./circom/main/key-gen/OPRFKeyGenGraph.13.bin > logs/service2.log 2>&1  &
    pid2=$!
    echo "started service2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

[group('local-setup')]
run-setup:
    #!/usr/bin/env bash
    mkdir -p logs
    echo "starting localstack and anvil"
    just dev-up localstack anvil
    sleep 1
    echo "preparing localstack"
    just prepare-localstack-secrets
    echo "starting AccountRegistry contract..."
    just deploy-account-registry-anvil | tee logs/deploy_account_registry.log
    account_registry=$(grep -oP 'AccountRegistry deployed to: \K0x[a-fA-F0-9]+' logs/deploy_account_registry.log)
    echo "starting RpRegistry contract.."
    just deploy-rp-registry-with-deps-anvil | tee logs/deploy_rp_registry.log
    rp_registry=$(grep -oP 'RpRegistry deployed to: \K0x[a-fA-F0-9]+' logs/deploy_rp_registry.log)
    echo "register oprf-nodes..."
    RP_REGISTRY_PROXY=$rp_registry just register-participants-anvil
    echo "starting indexer..."
    REGISTRY_ADDRESS=$account_registry just dev-up postgres world-id-indexer
    echo "starting OPRF services..."
    OPRF_SERVICE_RP_REGISTRY_CONTRACT=$rp_registry OPRF_SERVICE_ACCOUNT_REGISTRY_CONTRACT=$account_registry just run-services
    echo "stoping containers..."
    just dev-down

[group('local-setup')]
run-rp-registry-and-services account_registry:
    #!/usr/bin/env bash
    mkdir -p logs
    echo "starting RpRegistry contract.."
    just deploy-rp-registry-with-deps-anvil | tee logs/rp_registry.log
    address=$(grep -oP 'RpRegistry deployed to: \K0x[a-fA-F0-9]+' logs/rp_registry.log)
    sleep 1
    echo "starting OPRF services..."
    OPRF_SERVICE_ACCOUNT_REGISTRY_CONTRACT={{ account_registry }} OPRF_SERVICE_RP_REGISTRY_CONTRACT=$address just run-services

[group('dev-client')]
run-dev-client *args:
    cargo build --workspace --release
    ./target/release/oprf-dev-client {{ args }}

[working-directory('contracts')]
show-contract-errors:
    forge inspect src/RpRegistry.sol:RpRegistry errors

[working-directory('contracts')]
show-contract-methods:
    forge inspect src/RpRegistry.sol:RpRegistry methodIdentifiers

[group('deploy')]
[working-directory('contracts/script/deploy')]
deploy-rp-registry-with-deps-dry-run *args:
    forge script RpRegistryWithDeps.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script/deploy')]
deploy-rp-registry-with-deps *args:
    forge script RpRegistryWithDeps.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL

[group('deploy')]
[working-directory('contracts/script/deploy')]
deploy-rp-registry-dry-run *args:
    forge script RpRegistry.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script/deploy')]
deploy-rp-registry *args:
    forge script RpRegistry.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL

[group('deploy')]
[working-directory('contracts/script/test')]
deploy-account-registry-dry-run *args:
    forge script AccountRegistry.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script/test')]
deploy-account-registry *args:
    forge script AccountRegistry.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL

[group('deploy')]
[working-directory('contracts/script/deploy')]
register-participants *args:
    forge script RegisterParticipants.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL

[group('deploy')]
[working-directory('contracts/script/deploy')]
register-participants-dry-run *args:
    forge script RegisterParticipants.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script/test')]
create-account-auth-tree *args:
    forge script CreateAccount.s.sol --broadcast --interactives 1 -vvvvv {{ args }} --rpc-url $RPC_URL

[group('deploy')]
[working-directory('contracts/script/test')]
create-account-auth-tree-dry-run *args:
    forge script CreateAccount.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script')]
revoke-key-gen-admin-dry-run *args:
    forge script RevokeKeyGenAdmin.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script')]
revoke-key-gen-admin *args:
    forge script RevokeKeyGenAdmin.s.sol -vvvvv --broadcast --interactives 1 {{ args }} --rpc-url $RPC_URL

[group('deploy')]
[working-directory('contracts/script')]
register-key-gen-admin-dry-run *args:
    forge script RegisterKeyGenAdmin.s.sol -vvvvv {{ args }}

[group('deploy')]
[working-directory('contracts/script')]
register-key-gen-admin *args:
    forge script RegisterKeyGenAdmin.s.sol -vvvvv --broadcast --interactives 1 {{ args }} --rpc-url $RPC_URL

[group('anvil')]
[working-directory('contracts/script/deploy')]
deploy-rp-registry-with-deps-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 forge script RpRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script/deploy')]
deploy-rp-registry-anvil:
    TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 forge script RpRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script/test')]
deploy-account-registry-anvil:
    forge script AccountRegistry.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script/deploy')]
register-participants-anvil:
    ALICE_ADDRESS=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955 BOB_ADDRESS=0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f CAROL_ADDRESS=0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script')]
revoke-key-gen-admin-anvil:
    forge script RevokeKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script')]
register-key-gen-admin-anvil:
    forge script RegisterKeyGenAdmin.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('anvil')]
[working-directory('contracts/script/test')]
create-account-auth-tree-anvil:
    ACCOUNT_REGISTRY=0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 forge script CreateAccount.s.sol --broadcast --fork-url http://127.0.0.1:8545 -vvvvv --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

[group('docker')]
build-push-docker-image-oprf-service-amd TAG:
    docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service:{{ TAG }}-amd64 -f build/Dockerfile.oprf-service .

[group('docker')]
build-push-docker-image-key-gen-amd TAG:
    docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/key-gen:{{ TAG }}-amd64 -f build/Dockerfile.key-gen .
