<div align="center">

# Vylt

**Gestor de contraseñas de escritorio — local, sin conexión, cifrado de extremo a extremo.**

Escrito en Rust para Windows 11 · Interfaz en francés, inglés y español.

[Français](README.fr.md) · [English](README.md) · **Español**

</div>

---

## Por qué Vylt

Sus contraseñas nunca salen de su ordenador. Sin cuenta, sin nube, sin telemetría: todo se almacena
localmente en una caja fuerte cifrada que solo usted puede abrir.

## Seguridad

- **Derivación** Argon2id + HKDF, **cifrado** XChaCha20-Poly1305 con encabezado autenticado (AAD).
- **Clave secreta** opcional: un archivo de 32 bytes, separado de la caja fuerte, que usted lleva
  consigo (memoria USB, otro disco) como segundo factor físico.
- **Configuración camuflada**: el archivo de ajustes está oculto y codificado — ningún nombre de
  perfil ni palabra clave queda legible en el disco.
- **Endurecimiento del proceso** al inicio: otros programas no pueden leer la memoria de Vylt, se
  bloquea la inyección heredada y la carga de DLL se restringe a System32.
- **Comparaciones en tiempo constante**, escritura atómica de archivos, secretos borrados de la
  memoria tras su uso (`zeroize`).

## Funciones

| | |
|---|---|
| **Perfiles múltiples** | Varias cajas fuertes independientes, bloqueo automático por inactividad. |
| **Doble autenticación** | Código TOTP requerido al desbloquear. |
| **Entradas protegidas** | Un código PIN por entrada sensible; categorías totalmente ocultas. |
| **Modo coacción** | Una caja fuerte señuelo indistinguible se abre con una segunda contraseña. |
| **Destrucción** | Borrado por perfil, o global entre dos perfiles vinculados, con acciones selladas. |
| **Llaves de acceso** | Passkeys mediante extensión de navegador y proveedor de Windows. |
| **Compartir** | Transferencia cifrada entre dispositivos, importación CSV. |
| **Modo portátil** | Programa y cajas fuertes en una memoria USB — nada se escribe en el PC. |
| **Higiene** | Comprobación de filtraciones (Have I Been Pwned), opcional, con k-anonimato. |

## Compilación

Requisitos: [Rust](https://rustup.rs) (edición 2024) y las herramientas de compilación MSVC.

```sh
cargo build --release      # produce target/release/vylt.exe
cargo test                 # conjunto de pruebas (biblioteca + binario)
cargo clippy --all-targets # análisis estático
cargo deny check           # auditoría de dependencias y licencias
```

### Instalador de Windows

```powershell
installer\build.ps1        # requiere Inno Setup 6
```

Produce `target\installer\Vylt-Setup-<version>.exe`. El instalador ofrece el idioma y el tipo de
instalación: **en el PC** (acceso directo en el menú Inicio, datos en `%APPDATA%\Vylt`) o
**portátil** (todo en una memoria USB, sin dejar nada en el ordenador).

## Privacidad

Todo permanece en este ordenador. De forma predeterminada, no se envía ningún dato por Internet. La
única petición de red posible es la comprobación de filtraciones, que usted activa manualmente y que
solo envía los cinco primeros caracteres de un hash (k-anonimato) — nunca una contraseña.

## Licencia

**PolyForm Noncommercial 1.0.0** — solo uso no comercial, sin reventa. Consulte [`LICENSE`](LICENSE).
