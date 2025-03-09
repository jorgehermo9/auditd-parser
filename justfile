ci: fmt clippy test doc-test build msrv-verify

fmt:
 cargo fmt --check --all

clippy:
    cargo clippy --all-targets --all-features -- -Dwarnings -Dclippy::all -Dclippy::pedantic

test:
    cargo nextest run --locked --all-targets --all-features

doc-test:
    cargo test --doc --all-features

build:
    cargo build --all-targets --all-features --locked

msrv-verify:
    cargo msrv verify --all-features
