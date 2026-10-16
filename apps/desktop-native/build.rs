use slint_build::CompilerConfiguration;

fn main() {
    // Native-adjacent widget styling per platform (design-system: Google-Grade
    // Adaptivity). The truly-native style requires the GPL/Qt backend, which we
    // deliberately avoid — Cupertino matches the Apple-Grade physics mandate,
    // Fluent matches Windows conventions.
    let style = if cfg!(target_os = "windows") { "fluent" } else { "cupertino" };

    let config = CompilerConfiguration::new().with_style(style.into());
    slint_build::compile_with_config("src/main.slint", config).expect("Slint compilation failed");
}
