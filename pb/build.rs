use std::io::Result;
fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    config.out_dir("src/");
    config.type_attribute(".", "#[derive(PartialOrd)]");
    config.compile_protos(
        &[
            "./proto/register_ta_gs.proto",
            "./proto/register_ta_uav.proto",
        ],
        &["."],
    )?;
    Ok(())
}
