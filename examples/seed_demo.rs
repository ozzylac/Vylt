//! Dev helper: builds an isolated demo profile ("Demo") under `<dir>/Vylt`.
//! Usage: cargo run --example seed_demo -- <dir>   then launch the app with APPDATA=<dir>.

use std::path::PathBuf;

use vylt::destroy::Verifier;
use vylt::lock::{EntryLock, LockKind};
use vylt::vault::{Code, Entry, KdfParams, SecretKey, Vault};

const PASSWORD: &str = "demo-passphrase-2026";

fn entry(site: &str, user: &str, pw: &str, cat: &str, notes: &str) -> Entry {
    let mut e = Entry::blank();
    e.site = site.into();
    e.username = user.into();
    e.password = pw.into();
    e.category = cat.into();
    e.notes = notes.into();
    e.updated = 1_790_000_000;
    e
}

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: seed_demo <dir>")).join("Vylt");
    let pdir = dir.join("profiles").join("demo");
    std::fs::create_dir_all(&pdir).unwrap();
    let (vault_path, key_path) = (pdir.join("vault.svault"), pdir.join("secret.key"));
    let sk = SecretKey::generate().unwrap();
    sk.save(&key_path).unwrap();
    let mut v = Vault::create(&vault_path, PASSWORD, &sk, KdfParams::DEFAULT).unwrap();

    let mut gh = entry("GitHub", "zatheo.man@gmail.com", "k7#Qm2!vZp9&Lx4$Wd8nTe5@", "Travail", "Compte pro, clé SSH sur la YubiKey.");
    gh.codes.push(Code { label: "GitHub (perso)".into(), note: "compte principal".into(), secret: "JBSWY3DPEHPK3PXP".into(), totp: true });
    gh.codes.push(Code { label: "Codes de secours".into(), note: "code n° 1 sur 10".into(), secret: "a1b2-c3d4-e5f6".into(), totp: false });
    let mut bank = entry("Banque Postale", "zatheo", "Vr9$tH2#mQ7!xL4pZ8wK", "Banque", "");
    bank.lock = Some(EntryLock::new(LockKind::Pin6, "123456").unwrap());
    v.entries = vec![
        gh,
        entry("Netflix", "famille@mail.fr", "azerty123", "Perso", ""),
        bank,
        entry("Disney+", "famille@mail.fr", "azerty123", "Perso", ""),
        entry("Notion", "zatheo.man@gmail.com", "Rt5@nB8!cV2#yU6mQ9zX", "Travail", ""),
        entry("Amazon", "famille@mail.fr", "Lp3$wE7!aS1#dF5gH9jK", "Perso", ""),
    ];
    v.entries[5].updated = 1_700_000_000;
    v.save().unwrap();

    let cfg = serde_json::json!({
        "profiles": [{
            "name": "ozzylac",
            "vault_path": vault_path,
            "key_path": key_path,
            "color": 0,
            "destruct": Verifier::new("demo-destruct-2026").unwrap(),
        }],
        "last": 0, "lang": "Fr", "dark": true,
    })
    .to_string();
    std::fs::write(dir.join("config.json"), cfg).unwrap();
    println!("demo profile ready in {} (password: {PASSWORD})", dir.display());
}
