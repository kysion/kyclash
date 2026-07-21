fn main() {
    #[cfg(any(feature = "clippy", feature = "networking-system-lab"))]
    {
        println!("cargo:warning=Skipping tauri_build for non-application validation");
    }

    #[cfg(not(any(feature = "clippy", feature = "networking-system-lab")))]
    tauri_build::build();
}
