// Embeds the icon and version info in vylt.exe (Windows resources).
fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("ProductName", "Vylt")
            .set("FileDescription", "Vylt — gestionnaire de mots de passe")
            .set("LegalCopyright", "© 2026 ozzylac");
        res.compile().expect("embedding Windows resources");
    }
}
