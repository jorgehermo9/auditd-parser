ci: fmt clippy test doc-test build deny-check msrv-verify

fmt:
 cargo fmt --check --all

clippy:
    cargo clippy --all-targets --all-features -- -Dwarnings -Dclippy::all -Dclippy::pedantic

# https://github.com/nextest-rs/nextest
test:
    cargo nextest run --locked --all-targets --all-features

doc-test:
    cargo test --doc --all-features

build:
    cargo build --all-targets --all-features --locked

# https://github.com/EmbarkStudios/cargo-deny
deny-check:
    cargo deny check

# https://github.com/foresterre/cargo-msrv
msrv-verify:
    cargo msrv verify --all-features
