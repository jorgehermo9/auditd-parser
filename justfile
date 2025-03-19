ci $CI="true": fmt clippy test build deny-check msrv-verify

fmt:
 cargo fmt --check --all

clippy:
    cargo clippy --all-targets --all-features -- -Dwarnings -Dclippy::all -Dclippy::pedantic

test: unit-test integration-test doc-test

# https://github.com/nextest-rs/nextest
unit-test:
    # --lib to just run unit tests
    cargo nextest run --locked --all-targets --all-features --lib

integration-test:
    cargo insta test --test integration_test --all-features --unreferenced reject

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

insta-test-review:
    cargo insta test --test integration_test --all-features --review
    # TODO: Report bug to insta
    # Workaround as `--review` with `--unreferenced reject` does not work,
    # the review will not be shown and the snapshots will be auto-approved
    cargo insta test --test integration_test --all-features --unreferenced reject
