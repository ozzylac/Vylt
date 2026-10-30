<div align="center">

# Vylt

**Gestionnaire de mots de passe de bureau — local, hors ligne, chiffré de bout en bout.**

Écrit en Rust pour Windows 11 · Interface en français, anglais et espagnol.

**Français** · [English](README.en.md) · [Español](README.es.md)

</div>

---

## Pourquoi Vylt

Vos mots de passe ne quittent jamais votre ordinateur. Aucun compte, aucun cloud, aucune
télémétrie : tout est stocké localement dans un coffre chiffré que vous seul pouvez ouvrir.

## Sécurité

- **Dérivation** Argon2id + HKDF, **chiffrement** XChaCha20-Poly1305 avec en-tête authentifié (AAD).
- **Clé secrète** optionnelle : un fichier de 32 octets, séparé du coffre, à garder sur vous
  (clé USB, autre disque) pour un second facteur matériel.
- **Configuration camouflée** : le fichier de réglages est caché et brouillé — aucun nom de profil
  ni mot-clé lisible sur le disque.
- **Durcissement du processus** au démarrage : les autres programmes ne peuvent pas lire la mémoire
  de Vylt, l'injection héritée est bloquée et le chargement de DLL est restreint à System32.
- **Comparaisons à temps constant**, écriture atomique des fichiers, secrets effacés de la mémoire
  après usage (`zeroize`).

## Fonctions

| | |
|---|---|
| **Profils multiples** | Plusieurs coffres indépendants, verrouillage automatique après inactivité. |
| **Double authentification** | Code TOTP exigé au déverrouillage. |
| **Entrées protégées** | Un digicode par entrée sensible ; catégories entièrement cachées. |
| **Mode contrainte** | Un faux coffre indiscernable s'ouvre avec un second mot de passe. |
| **Destruction** | Effacement par profil, ou global entre deux profils liés, avec actions scellées. |
| **Clés d'accès** | Passkeys via extension navigateur et fournisseur Windows. |
| **Partage** | Transfert chiffré entre appareils, import CSV. |
| **Mode portable** | Programme et coffres sur une clé USB — rien n'est écrit sur le PC. |
| **Hygiène** | Vérification des fuites (Have I Been Pwned) en option, par k-anonymat. |

## Construction

Prérequis : [Rust](https://rustup.rs) (édition 2024) et les outils de build MSVC.

```sh
cargo build --release      # produit target/release/vylt.exe
cargo test                 # suite de tests (bibliothèque + binaire)
cargo clippy --all-targets # analyse statique
cargo deny check           # audit des dépendances et licences
```

### Installateur Windows

```powershell
installer\build.ps1        # nécessite Inno Setup 6
```

Produit `target\installer\Vylt-Setup-<version>.exe`. L'installateur propose la langue et le type
d'installation : **sur le PC** (raccourci menu Démarrer, données dans `%APPDATA%\Vylt`) ou
**portable** (tout sur une clé USB, rien laissé sur l'ordinateur).

## Confidentialité

Tout reste sur cet ordinateur. Par défaut, aucune donnée n'est envoyée sur Internet. La seule
requête réseau possible est la vérification des fuites, activable manuellement, qui n'envoie que les
cinq premiers caractères d'une empreinte (k-anonymat) — jamais un mot de passe.

## Licence

**PolyForm Noncommercial 1.0.0** — usage non commercial uniquement, pas de revente.
Voir [`LICENSE`](LICENSE).
