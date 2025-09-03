lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps

unit-tests:
    cargo test --release --all-features --lib

check-pr: lint unit-tests

bench:
    cargo bench --all-features

start-services:
    #!/usr/bin/env bash
    mkdir -p logs
    cargo build --workspace
    ./target/debug/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10000 > logs/service0.log 2> logs/service0.err &
    pid0=$!
    echo "started service0 with PID $pid0"
    ./target/debug/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10001 > logs/service1.log 2> logs/service1.err &
    pid1=$!
    echo "started service1 with PID $pid1"
    ./target/debug/oprf-service --user-verification-key-path ./circom/main/OPRFQueryProof.vk.json --bind-addr 127.0.0.1:10002 > logs/service2.log 2> logs/service2.err &
    pid2=$!
    echo "started service2 with PID $pid2"
    trap "kill $pid0 $pid1 $pid2" SIGINT SIGTERM
    wait $pid0 $pid1 $pid2
