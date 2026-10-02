fn main() -> Result<(), Box<dyn std::error::Error>> {
    uniffi_build::generate_scaffolding("src/shadowmesh.udl").unwrap();

    std::env::set_var("PROTOC", protobuf_src::protoc());
    tonic_build::compile_protos("proto/shadowmesh.proto")?;
    Ok(())
}
