//! Moving a profile between this PC (installed mode) and a USB drive (portable mode).

use std::fs;
use std::path::{Path, PathBuf};

use vylt::decoy;
use vylt::destroy::{self, Targets};
use zeroize::Zeroizing;

use crate::config::{self, Config, Profile};
use crate::i18n::tr;

pub fn same(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Copy `src` to `dst` (never over an existing file) and check the copy byte for byte.
fn copy_checked(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() {
        return Err(format!("{} ({})", tr("Un fichier existe déjà à cet emplacement."), dst.display()));
    }
    if let Some(p) = dst.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let data = Zeroizing::new(fs::read(src).map_err(|e| e.to_string())?);
    {
        // Flushed to the device, not only to Windows' cache, before the original can be erased.
        use std::io::Write;
        let mut f = fs::File::create(dst).map_err(|e| e.to_string())?;
        f.write_all(&data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    }
    if *Zeroizing::new(fs::read(dst).map_err(|e| e.to_string())?) != *data {
        let _ = vylt::import::shred(dst);
        return Err(tr("La copie ne correspond pas à l'original.").into());
    }
    Ok(())
}

/// Copy profile `idx` of `src` (whose config lives in `src_dir`) into the config in `dst_dir`, then
/// erase the originals. `key_dst`: new location of the secret key; it is never dropped. `verify`
/// must open the copied vault: nothing is erased unless it does.
pub fn move_profile(
    src: &mut Config,
    src_dir: &Path,
    idx: usize,
    dst_dir: &Path,
    key_dst: Option<PathBuf>,
    verify: &dyn Fn(&Profile) -> bool,
) -> Result<Profile, String> {
    let p = src.profiles.get(idx).cloned().ok_or_else(|| tr("Profil introuvable.").to_owned())?;
    let mut dst = config::load_from(dst_dir).unwrap_or_else(|| {
        let mut c = Config::default();
        (c.lang, c.dark, c.accent) = (src.lang, src.dark, src.accent);
        c
    });
    let folder = config::folder_name(&p.name);
    if dst.profiles.iter().any(|q| config::folder_name(&q.name) == folder) {
        return Err(tr("Un profil de ce nom existe déjà à la destination.").into());
    }
    let key_file = p.key_file();
    let move_key = p.use_key && key_dst.as_ref().is_some_and(|k| !same(k, &key_file));
    let mut q = p.clone();
    q.vault_path = dst_dir.join("profiles").join(&folder).join("vault.svault");
    if p.use_key {
        q.key_path = if move_key { key_dst.clone().unwrap_or_default() } else { key_file.clone() };
    }

    let mut copied: Vec<PathBuf> = Vec::new();
    let mut run = || -> Result<(), String> {
        copy_checked(&p.vault_path, &q.vault_path)?;
        copied.push(q.vault_path.clone());
        let decoy = decoy::decoy_path(&p.vault_path);
        if decoy.exists() {
            let d = decoy::decoy_path(&q.vault_path);
            copy_checked(&decoy, &d)?;
            copied.push(d);
        }
        if move_key {
            copy_checked(&key_file, &q.key_path)?;
            copied.push(q.key_path.clone());
        }
        if let Some(a) = p.avatar.as_ref().filter(|a| a.exists()) {
            let d = dst_dir.join("avatars").join(a.file_name().unwrap_or_default());
            copy_checked(a, &d)?;
            copied.push(d.clone());
            q.avatar = Some(d);
        }
        dst.profiles.push(q.clone());
        config::save_to(&dst, dst_dir);
        match config::load_from(dst_dir) {
            Some(c) if c.profiles.iter().any(|x| same(&x.vault_path, &q.vault_path)) => {}
            _ => return Err(tr("Impossible d'enregistrer la configuration de destination.").into()),
        }
        if !verify(&q) {
            // Take the profile back out of the destination config before cleaning up the copies.
            let mut c = config::load_from(dst_dir).unwrap_or_default();
            c.profiles.retain(|x| !same(&x.vault_path, &q.vault_path));
            config::save_to(&c, dst_dir);
            return Err(tr("La copie du coffre n'a pas pu être ouverte : rien n'a été effacé.").into());
        }
        Ok(())
    };
    if let Err(e) = run() {
        for f in &copied {
            let _ = vylt::import::shred(f);
        }
        if let Some(d) = q.vault_path.parent() {
            let _ = fs::remove_dir(d);
        }
        return Err(e);
    }

    src.profiles.remove(idx);
    src.last = 0;
    config::save_to(src, src_dir);
    destroy::wipe_profile(&Targets { vault: &p.vault_path, key: move_key.then_some(key_file.as_path()) });
    config::remove_avatar(&p);
    Ok(q)
}

/// Copy the program to `X:\Vylt` (if not there yet) and move the profile into its `data\`.
pub fn to_portable(cfg: &mut Config, idx: usize, drive: char, key_dst: Option<PathBuf>, verify: &dyn Fn(&Profile) -> bool) -> Result<String, String> {
    let root = PathBuf::from(format!("{drive}:\\Vylt"));
    let exe = root.join("vylt.exe");
    if !exe.exists() {
        copy_checked(&std::env::current_exe().map_err(|e| e.to_string())?, &exe)?;
    }
    let flag = root.join(config::PORTABLE_FLAG);
    if !flag.exists() {
        fs::write(&flag, b"").map_err(|e| e.to_string())?;
    }
    move_profile(cfg, &config::data_dir(), idx, &root.join("data"), key_dst, verify)?;
    Ok(tr("Le profil se trouve maintenant sur la clé USB. Pour l'ouvrir, lancez {exe}.").replace("{exe}", &exe.display().to_string()))
}

pub fn to_fixed(cfg: &mut Config, idx: usize, key_dst: Option<PathBuf>, verify: &dyn Fn(&Profile) -> bool) -> Result<String, String> {
    move_profile(cfg, &config::data_dir(), idx, &config::installed_dir(), key_dst, verify)?;
    Ok(tr("Le profil se trouve maintenant sur cet ordinateur. Ouvrez-le avec Vylt installé sur ce PC.").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vylt::destroy::Verifier;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vylt-move-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn vault_bytes(fill: u8) -> Vec<u8> {
        [b"SVLT\x01".as_slice(), &[fill; 300]].concat()
    }

    fn setup(src: &Path, name: &str) -> Config {
        let pdir = src.join("profiles").join(name);
        fs::create_dir_all(&pdir).unwrap();
        let p = Profile {
            name: name.into(),
            vault_path: pdir.join("vault.svault"),
            key_path: pdir.join("secret.key"),
            use_key: true,
            destruct: Some(Verifier::new("own-destruct-password").unwrap()),
            actions: None,
            avatar: None,
            color: 3,
            ..Default::default()
        };
        fs::write(&p.vault_path, vault_bytes(7)).unwrap();
        fs::write(decoy::decoy_path(&p.vault_path), vault_bytes(8)).unwrap();
        fs::write(&p.key_path, [9u8; 32]).unwrap();
        let mut c = Config::default();
        c.profiles.push(p);
        config::save_to(&c, src);
        c
    }

    #[test]
    fn move_copies_everything_then_erases_the_originals() {
        let (src, dst, keys) = (tmp("src"), tmp("dst"), tmp("keys"));
        let mut cfg = setup(&src, "alice");
        let old = cfg.profiles[0].clone();
        let key = keys.join("alice-perso.key");

        let q = move_profile(&mut cfg, &src, 0, &dst, Some(key.clone()), &|_| true).unwrap();

        assert_eq!(fs::read(&q.vault_path).unwrap(), vault_bytes(7));
        assert_eq!(fs::read(decoy::decoy_path(&q.vault_path)).unwrap(), vault_bytes(8));
        assert_eq!(fs::read(&key).unwrap(), [9u8; 32]);
        assert!(!old.vault_path.exists() && !old.key_path.exists() && !decoy::decoy_path(&old.vault_path).exists());
        assert!(cfg.profiles.is_empty() && config::load_from(&src).unwrap().profiles.is_empty());

        let d = config::load_from(&dst).unwrap();
        assert_eq!(d.profiles.len(), 1);
        let r = &d.profiles[0];
        assert!(same(&r.vault_path, &q.vault_path) && same(&r.key_path, &key));
        assert!(r.use_key && r.destruct.is_some() && r.color == 3);
        let raw = config::deobfuscate(&fs::read(config::cfg_file(&dst)).unwrap());
        assert!(String::from_utf8_lossy(&raw).contains("{data}"), "paths inside the destination are stored relative");
        for d in [src, dst, keys] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn name_taken_at_destination_changes_nothing() {
        let (src, dst) = (tmp("src2"), tmp("dst2"));
        let mut cfg = setup(&src, "bob");
        setup(&dst, "bob");
        let old = cfg.profiles[0].clone();
        assert!(move_profile(&mut cfg, &src, 0, &dst, None, &|_| true).is_err());
        assert!(old.vault_path.exists() && old.key_path.exists() && cfg.profiles.len() == 1);
        assert_eq!(config::load_from(&dst).unwrap().profiles.len(), 1);
        for d in [src, dst] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn key_left_in_place_is_not_erased() {
        let (src, dst) = (tmp("src3"), tmp("dst3"));
        let mut cfg = setup(&src, "carol");
        let key = cfg.profiles[0].key_path.clone();
        let q = move_profile(&mut cfg, &src, 0, &dst, Some(key.clone()), &|_| true).unwrap();
        assert!(key.exists() && same(&q.key_path, &key));
        for d in [src, dst] {
            let _ = fs::remove_dir_all(d);
        }
    }

    #[test]
    fn a_copy_that_does_not_open_erases_nothing() {
        let (src, dst, keys) = (tmp("src4"), tmp("dst4"), tmp("keys4"));
        let mut cfg = setup(&src, "dave");
        let old = cfg.profiles[0].clone();
        let key = keys.join("dave.key");
        assert!(move_profile(&mut cfg, &src, 0, &dst, Some(key.clone()), &|_| false).is_err());
        assert!(old.vault_path.exists() && old.key_path.exists(), "originals untouched");
        assert!(!key.exists() && !dst.join("profiles").join("dave").join("vault.svault").exists(), "copies removed");
        assert_eq!(cfg.profiles.len(), 1);
        assert!(config::load_from(&dst).is_none_or(|c| c.profiles.is_empty()));
        for d in [src, dst, keys] {
            let _ = fs::remove_dir_all(d);
        }
    }
}
