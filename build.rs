use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/walletd.proto"], &["proto"])?;
    
    println!("cargo:rerun-if-changed=proto/walletd.proto");
    
    // Build Zig libraries if they exist
    build_zig_libraries()?;
    
    // Set up linking for Zig libraries
    setup_zig_linking()?;
    
    Ok(())
}

fn build_zig_libraries() -> Result<(), Box<dyn std::error::Error>> {
    let zig_projects = vec![
        ("../zcrypto", "libzcrypto"),
        ("../zsig", "libzsig"),
        ("../zwallet", "libzwallet"),
    ];
    
    for (project_dir, lib_name) in zig_projects {
        let project_path = PathBuf::from(project_dir);
        if project_path.exists() {
            println!("cargo:warning=Building Zig library: {}", lib_name);
            
            // Build the Zig project as a shared library
            let output = Command::new("zig")
                .args(&["build", "-Doptimize=ReleaseFast", "-Dshared=true"])
                .current_dir(&project_path)
                .output()?;
                
            if !output.status.success() {
                eprintln!("Warning: Failed to build {}: {}", lib_name, String::from_utf8_lossy(&output.stderr));
                // Continue anyway - the libraries might be pre-built
            }
        } else {
            println!("cargo:warning=Zig project not found at {}. Using stub implementations.", project_dir);
        }
    }
    
    Ok(())
}

fn setup_zig_linking() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    
    // Add include directory for FFI headers
    println!("cargo:rustc-link-search=native={}/include", manifest_dir);
    
    // Try to link Zig libraries if they exist
    let lib_dirs = vec![
        PathBuf::from("../zcrypto/zig-out/lib"),
        PathBuf::from("../zsig/zig-out/lib"),
        PathBuf::from("../zwallet/zig-out/lib"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib"),
    ];
    
    for lib_dir in lib_dirs {
        if lib_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }
    }
    
    // Link the libraries (optional - will use stubs if not found)
    if cfg!(feature = "zig-ffi") {
        println!("cargo:rustc-link-lib=dylib=zcrypto");
        println!("cargo:rustc-link-lib=dylib=zsig");
        println!("cargo:rustc-link-lib=dylib=zwallet");
    }
    
    // Tell cargo to rerun if Zig projects change
    println!("cargo:rerun-if-changed=../zcrypto/build.zig");
    println!("cargo:rerun-if-changed=../zsig/build.zig");
    println!("cargo:rerun-if-changed=../zwallet/build.zig");
    println!("cargo:rerun-if-changed=include/");
    
    Ok(())
}
