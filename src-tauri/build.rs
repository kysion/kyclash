fn main() {
    build_route_helper_registration();

    #[cfg(any(feature = "clippy", feature = "networking-dev", feature = "networking-system-lab"))]
    {
        println!("cargo:warning=Skipping tauri_build for non-application validation");
    }

    #[cfg(not(any(feature = "clippy", feature = "networking-dev", feature = "networking-system-lab")))]
    tauri_build::build();
}

#[allow(clippy::expect_used)]
fn build_route_helper_registration() {
    if std::env::var_os("CARGO_FEATURE_NETWORKING_PRODUCTION").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return;
    }
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is required"));
    let sources = [
        std::path::Path::new("../macos/route-helper/registration.m"),
        std::path::Path::new("../macos/route-helper/client.m"),
    ];
    let objects = [
        output.join("kyclash-route-helper-registration.o"),
        output.join("kyclash-route-helper-client.o"),
    ];
    let archive = output.join("libkyclash_route_helper_registration.a");
    for (source, object) in sources.iter().zip(&objects) {
        let status = std::process::Command::new("xcrun")
            .args([
                "clang",
                "-fobjc-arc",
                "-fblocks",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-mmacosx-version-min=13.0",
                "-c",
                source.to_str().expect("route-helper bridge source path must be UTF-8"),
                "-o",
                object.to_str().expect("route-helper bridge object path must be UTF-8"),
            ])
            .status()
            .expect("xcrun clang must be available for networking-production");
        assert!(status.success(), "failed to compile route-helper bridge");
    }
    let status = std::process::Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .args(&objects)
        .status()
        .expect("ar must be available for networking-production");
    assert!(status.success(), "failed to archive SMAppService registration bridge");
    for source in sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=kyclash_route_helper_registration");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=ServiceManagement");
}
