fn main() {
    build_route_helper_registration();

    #[cfg(any(
        feature = "clippy",
        all(feature = "networking-dev", not(feature = "networking-userspace-lab-app")),
        all(
            feature = "networking-system-lab",
            not(feature = "networking-production"),
            not(feature = "networking-userspace-lab-app"),
            not(feature = "networking-vm-external-peer-lab-app")
        )
    ))]
    {
        println!("cargo:warning=Skipping tauri_build for non-application validation");
    }

    #[cfg(not(any(
        feature = "clippy",
        all(feature = "networking-dev", not(feature = "networking-userspace-lab-app")),
        all(
            feature = "networking-system-lab",
            not(feature = "networking-production"),
            not(feature = "networking-userspace-lab-app"),
            not(feature = "networking-vm-external-peer-lab-app")
        )
    )))]
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
        // Keep the broker-bound v3 client in the same production-only archive;
        // the production factory still constructs it only after explicit
        // Connect and after the broker has issued its bound session receipt.
        std::path::Path::new("../macos/route-helper/client-v3.m"),
        std::path::Path::new("../macos/tunnel-broker/client.m"),
    ];
    let objects = [
        output.join("kyclash-route-helper-registration.o"),
        output.join("kyclash-route-helper-client.o"),
        output.join("kyclash-route-helper-client-v3.o"),
        output.join("kyclash-tunnel-broker-client.o"),
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
    println!("cargo:rustc-link-lib=framework=Security");
}
