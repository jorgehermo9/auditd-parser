ci: fmt clippy test build

fmt:
 cargo fmt --check

clippy:
    cargo clippy --all-targets --all-features -- -Dwarnings -Dclippy::all -Dclippy::pedantic

test:
    cargo nextest run --locked

build:
    cargo build --locked
