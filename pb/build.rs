use std::io::Result;

fn main() -> Result<()> {
    if std::env::vars().any(|(k, _)| k == "GITHUB_ACTIONS") {
        println!("github actions");
        return Ok(());
    };
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    config.out_dir("src/");
    config.type_attribute(".", "#[derive(PartialOrd)]");
    walkdir::WalkDir::new("./proto")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().unwrap_or_default() == "proto")
        .for_each(|e| {
            println!("cargo:rerun-if-changed={}", e.path().display());
            config.compile_protos(&[e.path()], &["."]).unwrap();
        });
    Ok(())
}
