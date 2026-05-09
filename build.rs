fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=vendor/sparkplug-b/sparkplug_b.proto");
    prost_build::compile_protos(
        &["vendor/sparkplug-b/sparkplug_b.proto"],
        &["vendor/sparkplug-b/"],
    )?;
    Ok(())
}
