use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=/usr/local/lib");

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=pbc");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=wrapper.c");

    cc::Build::new().files(["wrapper.c"]).compile("extern");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .generate_inline_functions(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .wrap_static_fns(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Tell cargo to statically link against the `libextern` static library.
    // println!("cargo:rustc-link-lib=static=extern");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
    bindings.write_to_file("./src/bindings.rs").unwrap();
}
