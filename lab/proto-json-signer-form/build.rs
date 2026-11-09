// Compiles proto/a2a.proto (A2A v1.0.1) with protox (no protoc), writes the full descriptor set for
// prost-reflect / @bufbuild/protobuf / protobufjs, and generates prost + pbjson types for lf.a2a.v1.
use prost::Message;
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=proto");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let fds = protox::compile(["a2a.proto"], ["proto"]).expect("protox");
    fs::write(out.join("a2a.binpb"), fds.encode_to_vec()).unwrap();

    // Codegen only needs lf.a2a.v1; google.api annotations do not affect the JSON mapping.
    let mut keep = fds.clone();
    keep.file.retain(|f| !f.name().starts_with("google/api/"));
    for f in &mut keep.file {
        f.dependency.retain(|d| !d.starts_with("google/api/"));
    }
    let mut cfg = prost_build::Config::new();
    cfg.compile_well_known_types();
    cfg.extern_path(".google.protobuf", "::pbjson_types");
    cfg.btree_map(["."]);
    cfg.compile_fds(keep.clone()).expect("prost-build");
    pbjson_build::Builder::new()
        .register_descriptors(&keep.encode_to_vec())
        .unwrap()
        .btree_map(["."])
        .build(&[".lf.a2a.v1"])
        .expect("pbjson-build");
}
