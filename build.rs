use std::env;
use std::path::PathBuf;

pub fn main() {
    // https://docs.rs/rstest/0.26.1/rstest/attr.rstest.html#files-path-as-input-arguments
    println!("cargo::rerun-if-changed=tests/data");
    println!("cargo::rerun-if-env-changed=BASE_TEST_DIR");

    // Generate bindings from Linux kernel headers
    println!("cargo::rerun-if-changed=bindings.h");

    let bindings = bindgen::Builder::default()
        .header("bindings.h")
        // Signal constants
        .allowlist_var("SIG.*")
        // Architecture and audit constants
        .allowlist_var("EM_.*")
        .allowlist_var("AUDIT_ARCH_.*")
        .allowlist_var("__AUDIT_ARCH_.*")
        // Socket address family constants
        .allowlist_var("AF_UNIX")
        .allowlist_var("AF_INET")
        .allowlist_var("AF_INET6")
        .allowlist_var("AF_NETLINK")
        // File type and mode constants
        .allowlist_var("S_IF.*")
        .allowlist_var("S_IS.*")
        .allowlist_var("S_IRWX.*")
        .allowlist_var("S_IR.*")
        .allowlist_var("S_IW.*")
        .allowlist_var("S_IX.*")
        // Disable layout tests to avoid issues with different architectures
        .layout_tests(false)
        // Parse callbacks
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
