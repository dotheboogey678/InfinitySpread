fn main() {
    println!("cargo:rustc-link-search=native={}", "preloader");
    println!("cargo:rustc-link-lib=preloader");
}