// crates/ads-sentinel/build.rs
fn main() {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        println!("cargo:rustc-link-search=native={}/../../native/ardyn_isa_scrubber", manifest_dir);
    }
    println!("cargo:rustc-link-search=native=native/ardyn_isa_scrubber");
    println!("cargo:rustc-link-search=native=../../native/ardyn_isa_scrubber");
    println!("cargo:rustc-link-lib=dylib=ardyn_isa_scrubber");
}
