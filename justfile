ci: format clippy test build

format:
 cargo fmt --check

clippy:
    cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic

test:
    cargo nextest run --locked

build:
    cargo build --locked
