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

run-all:
    #!/usr/bin/env bash
    killall -9 anvil
    anvil  &
    pid_anvil=$!  
    sleep 1
    cargo build --workspace
    cargo run --bin key-gen -- --overwrite-old-keys
    cd contracts && forge script script/KeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    cd ..
    mkdir -p logs
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10000 --private-key-secret-id oprf/sk/n0 --environment dev --dlog-share-secret-id-suffix oprf/share/n0 --chain-url http://localhost:6789 --wallet-private-key 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356> logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10001 --private-key-secret-id oprf/sk/n1 --environment dev --dlog-share-secret-id-suffix oprf/share/n1 --chain-url http://localhost:6789 --wallet-private-key 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97 > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10002 --private-key-secret-id oprf/sk/n2 --environment dev --dlog-share-secret-id-suffix oprf/share/n2 --chain-url http://localhost:6789 --wallet-private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 > logs/service2.log 2>&1  &
    pid2=$!
    echo "started service2 with PID $pid2"
    sleep 2
    cd contracts && KEYGEN_CONTRACT=0x5FbDB2315678afecb367f032d93F642f64180aa3 forge script script/InitKeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    trap "kill $pid0 $pid1 $pid2 $pid_anvil" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2 $pid_anvil

init-kengen:
    cd contracts && KEYGEN_CONTRACT=0x5FbDB2315678afecb367f032d93F642f64180aa3 forge script script/InitKeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    

run-mock:
    #!/usr/bin/env bash
    cargo build --workspace
    RUST_LOG="smart_contract_mock=trace,warn" ./target/debug/smart-contract-mock --oprf-services 3 --oprf-degree 1 > logs/mock_chain.log 2>&1 &
    pid_sc=$!
    echo "started smart contract mock with PID $pid_sc"
    trap "kill $pid_sc" SIGINT SIGTERM
    wait $pid_sc

run-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --key-gen-contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 --key-gen-rpc-url ws://localhost:8545 --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10000 --private-key-secret-id oprf/sk/n0 --environment dev --dlog-share-secret-id-suffix oprf/share/n0 --chain-url http://localhost:6789 --wallet-private-key 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356> logs/service0.log 2>&1 &
    pid0=$!
    echo "started service0 with PID $pid0"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --key-gen-contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 --key-gen-rpc-url ws://localhost:8545 --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10001 --private-key-secret-id oprf/sk/n1 --environment dev --dlog-share-secret-id-suffix oprf/share/n1 --chain-url http://localhost:6789 --wallet-private-key 0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97 > logs/service1.log 2>&1 &
    pid1=$!
    echo "started service1 with PID $pid1"
    RUST_LOG="oprf_service=trace,warn" ./target/debug/oprf-service --key-gen-contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 --key-gen-rpc-url ws://localhost:8545  --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10002 --private-key-secret-id oprf/sk/n2 --environment dev --dlog-share-secret-id-suffix oprf/share/n2 --chain-url http://localhost:6789 --wallet-private-key 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6 > logs/service2.log 2>&1  &
    pid2=$!
    echo "started service2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2

run-dev-client *args:
    cargo run --release --bin oprf-dev-client -- {{args}}

build-push-docker-image-oprf-service-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/oprf-service:{{TAG}}-amd64 -f build/Dockerfile.oprf-service .

build-push-docker-image-key-gen-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/key-gen:{{TAG}}-amd64 -f build/Dockerfile.key-gen .
  
build-push-docker-image-smart-contract-mock-amd TAG:
  docker buildx build --build-arg GIT_HASH=$(git rev-parse HEAD) --platform linux/amd64 --push -t 651706750785.dkr.ecr.eu-central-1.amazonaws.com/nullifier-oracle-service/smart-contract-mock:{{TAG}}-amd64 -f build/Dockerfile.smart-contract-mock .