pub fn main() {
    // https://docs.rs/rstest/0.26.1/rstest/attr.rstest.html#files-path-as-input-arguments
    println!("cargo::rerun-if-changed=tests/data");
    println!("cargo::rerun-if-env-changed=BASE_TEST_DIR");
}
