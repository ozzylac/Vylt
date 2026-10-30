<div align="center">

# Vylt

**Desktop password manager — local, offline, end-to-end encrypted.**

Written in Rust for Windows 11 · Interface in French, English and Spanish.

[Français](README.fr.md) · **English** · [Español](README.es.md)

</div>

---

## Why Vylt

Your passwords never leave your computer. No account, no cloud, no telemetry: everything is stored
locally in an encrypted vault that only you can open.

## Security

- **Derivation** Argon2id + HKDF, **encryption** XChaCha20-Poly1305 with an authenticated header (AAD).
- **Optional secret key**: a 32-byte file, kept separate from the vault, that you carry with you
  (USB drive, another disk) as a hardware second factor.
- **Camouflaged configuration**: the settings file is hidden and scrambled — no readable profile
  name or keyword appears on disk.
- **Process hardening** at startup: other programs cannot read Vylt's memory, legacy injection is
  blocked, and DLL loading is restricted to System32.
- **Constant-time comparisons**, atomic file writes, secrets wiped from memory after use (`zeroize`).

## Features

| | |
|---|---|
| **Multiple profiles** | Several independent vaults, automatic lock after inactivity. |
| **Two-factor unlock** | A TOTP code required when unlocking. |
| **Protected entries** | A PIN per sensitive entry; fully hidden categories. |
| **Duress mode** | An indistinguishable decoy vault opens with a second password. |
| **Destruction** | Per-profile wipe, or global between two linked profiles, with sealed actions. |
| **Passkeys** | Via a browser extension and a Windows provider. |
| **Sharing** | Encrypted transfer between devices, CSV import. |
| **Portable mode** | Program and vaults on a USB drive — nothing is written to the PC. |
| **Hygiene** | Breach check (Have I Been Pwned), opt-in, using k-anonymity. |

## Building

Requirements: [Rust](https://rustup.rs) (2024 edition) and the MSVC build tools.

```sh
cargo build --release      # produces target/release/vylt.exe
cargo test                 # test suite (library + binary)
cargo clippy --all-targets # static analysis
cargo deny check           # dependency and licence audit
```

### Windows installer

```powershell
installer\build.ps1        # requires Inno Setup 6
```

Produces `target\installer\Vylt-Setup-<version>.exe`. The installer offers the language and the
install type: **on the PC** (Start-menu shortcut, data in `%APPDATA%\Vylt`) or **portable**
(everything on a USB drive, nothing left on the computer).

## Privacy

Everything stays on this computer. By default, no data is sent over the Internet. The only possible
network request is the breach check, which you enable manually and which sends only the first five
characters of a hash (k-anonymity) — never a password.

## Licence

**PolyForm Noncommercial 1.0.0** — non-commercial use only, no resale. See [`LICENSE`](LICENSE).
