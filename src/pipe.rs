//! Browser extension link: the native-messaging host (`vylt.exe chrome-extension://…`)
//! relays each request over a local named pipe to the running app, which answers it.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Registry::{RegDeleteTreeW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::broker;
use crate::config::{self, now_secs};

pub const HOST_NAME: &str = "com.vylt.passkeys";
/// Fixed by the public key in extension/manifest.json.
pub const EXTENSION_ID: &str = "oookfoeckhfahodheckiopicnimkcfee";
const MAX_FRAME: usize = 1 << 20;
/// Longer than a browser's usual WebAuthn timeout, so the page gives up first.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(170);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let tag: String = vylt::passkey::sha256(user.as_bytes()).iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!(r"\\.\pipe\vylt-passkeys-{tag}")
}

/// Native messaging framing: u32 length (little endian on Windows), then UTF-8 JSON.
pub fn read_frame(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return None;
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).ok()?;
    Some(b)
}

pub fn write_frame(w: &mut impl Write, b: &[u8]) -> bool {
    w.write_all(&(b.len() as u32).to_le_bytes()).is_ok() && w.write_all(b).is_ok() && w.flush().is_ok()
}

// ---- app side -----------------------------------------------------------------------------------

/// Serve the pipe on a background thread. A second Vylt instance leaves it to the first.
pub fn start_server() {
    std::thread::spawn(|| {
        let name = wide(&pipe_name());
        let mut first = true;
        loop {
            let open = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
            let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
            let h = unsafe { CreateNamedPipeW(name.as_ptr(), open, mode, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, std::ptr::null()) };
            if h == INVALID_HANDLE_VALUE {
                return;
            }
            first = false;
            let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if !connected || !client_is_this_program(h) {
                unsafe { CloseHandle(h) };
                continue;
            }
            let file = unsafe { File::from_raw_handle(h as _) };
            std::thread::spawn(move || serve(file));
        }
    });
}

/// Only our own executable (started by the browser as native host) may talk to the vault.
fn client_is_this_program(h: HANDLE) -> bool {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(h, &mut pid) } == 0 {
        return false;
    }
    let p = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if p.is_null() {
        return false;
    }
    let mut buf = [0u16; 1024];
    let mut n = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(p, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } != 0;
    unsafe { CloseHandle(p) };
    let client = PathBuf::from(String::from_utf16_lossy(&buf[..n as usize]));
    ok && std::env::current_exe().is_ok_and(|me| crate::portable::same(&me, &client))
}

fn serve(mut f: File) {
    while let Some(b) = read_frame(&mut f) {
        if !write_frame(&mut f, answer(&b).to_string().as_bytes()) {
            break;
        }
    }
}

fn answer(b: &[u8]) -> Value {
    broker::LAST_EXTENSION.store(now_secs(), Ordering::Relaxed);
    let Ok(v) = serde_json::from_slice::<Value>(b) else { return json!({ "status": "fallback" }) };
    match broker::from_extension(&v) {
        Ok(req) => broker::to_extension(&broker::submit(req, ANSWER_TIMEOUT)),
        Err(e) => e,
    }
}

// ---- native host side ---------------------------------------------------------------------------

pub fn is_native_host_launch() -> bool {
    // Chrome passes "chrome-extension://<id>/" as argv[1]; require exactly our extension's id.
    let ours = format!("chrome-extension://{EXTENSION_ID}");
    std::env::args().nth(1).is_some_and(|a| a.starts_with(&ours))
}

/// Base name of the process that launched this one, lowercased, via a Toolhelp snapshot.
fn parent_image() -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    let me = unsafe { GetCurrentProcessId() };
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // First pass: find our parent's pid. Second pass: find that pid's image name.
    let mut parent_pid = None;
    let mut parent_name = None;
    for find_name in [false, true] {
        let mut ok = unsafe { Process32FirstW(snap, &mut e) } != 0;
        while ok {
            if !find_name && e.th32ProcessID == me {
                parent_pid = Some(e.th32ParentProcessID);
                break;
            }
            if find_name && Some(e.th32ProcessID) == parent_pid {
                let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                parent_name = Some(String::from_utf16_lossy(&e.szExeFile[..n]).to_lowercase());
                break;
            }
            ok = unsafe { Process32NextW(snap, &mut e) } != 0;
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        }
        if find_name {
            break;
        }
        parent_pid?;
    }
    unsafe { CloseHandle(snap) };
    parent_name
}

/// Native messaging is only ever started by a Chromium-family browser. A plain local process
/// launching the exe with the extension argument (to relay attacker-controlled, origin-spoofed
/// frames) is refused here.
fn launched_by_browser() -> bool {
    const BROWSERS: [&str; 7] = ["chrome.exe", "msedge.exe", "brave.exe", "chromium.exe", "vivaldi.exe", "opera.exe", "thorium.exe"];
    parent_image().is_some_and(|p| BROWSERS.contains(&p.as_str()))
}

pub fn run_native_host() {
    if !launched_by_browser() {
        return;
    }
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout().lock());
    let mut pipe: Option<File> = None;
    while let Some(msg) = read_frame(&mut input) {
        if pipe.is_none() {
            pipe = connect();
        }
        let reply = pipe.as_mut().and_then(|p| if write_frame(p, &msg) { read_frame(p) } else { None });
        if reply.is_none() {
            pipe = None;
        }
        let reply = reply.unwrap_or_else(|| br#"{"status":"fallback"}"#.to_vec());
        if !write_frame(&mut output, &reply) {
            break;
        }
    }
}

/// Reach the running app; start it (once) if it is not running.
fn connect() -> Option<File> {
    let name = pipe_name();
    let open = || OpenOptions::new().read(true).write(true).open(&name).ok();
    if let Some(f) = open() {
        return Some(f);
    }
    let exe = std::env::current_exe().ok()?;
    crate::platform::spawn_detached(&exe.to_string_lossy(), &[]);
    for _ in 0..120 {
        std::thread::sleep(Duration::from_millis(150));
        if let Some(f) = open() {
            return Some(f);
        }
    }
    None
}

// ---- installation -------------------------------------------------------------------------------

const FILES: [(&str, &[u8]); 5] = [
    ("manifest.json", include_bytes!("../extension/manifest.json")),
    ("background.js", include_bytes!("../extension/background.js")),
    ("content.js", include_bytes!("../extension/content.js")),
    ("inject.js", include_bytes!("../extension/inject.js")),
    ("icon.png", include_bytes!("../extension/icon.png")),
];

const BROWSERS: [&str; 4] = [
    r"Software\Google\Chrome\NativeMessagingHosts\",
    r"Software\Microsoft\Edge\NativeMessagingHosts\",
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\",
    r"Software\Chromium\NativeMessagingHosts\",
];

pub fn extension_dir() -> PathBuf {
    config::data_dir().join("extension")
}

/// Write the extension folder and the host manifest, and register the host for this user's
/// Chromium browsers (HKCU, no administrator rights). Returns the folder to load in the browser.
pub fn install() -> Result<PathBuf, String> {
    let dir = extension_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (name, data) in FILES {
        std::fs::write(dir.join(name), data).map_err(|e| e.to_string())?;
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let host = config::data_dir().join("native-host.json");
    let manifest = json!({
        "name": HOST_NAME,
        "description": "Vylt passkeys",
        "path": exe,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    std::fs::write(&host, serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let value = wide(&host.to_string_lossy());
    for b in BROWSERS {
        let key = wide(&format!("{b}{HOST_NAME}"));
        let rc = unsafe {
            RegSetKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), std::ptr::null(), REG_SZ, value.as_ptr().cast(), (value.len() * 2) as u32)
        };
        if rc != 0 {
            return Err(format!("registre ({rc})"));
        }
    }
    Ok(dir)
}

pub fn uninstall() {
    for b in BROWSERS {
        let key = wide(&format!("{b}{HOST_NAME}"));
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr()) };
    }
    let _ = std::fs::remove_file(config::data_dir().join("native-host.json"));
    let _ = std::fs::remove_dir_all(extension_dir());
}

pub fn host_manifest_points_here() -> bool {
    let Ok(b) = std::fs::read(config::data_dir().join("native-host.json")) else { return false };
    let path = serde_json::from_slice::<Value>(&b).ok().and_then(|v| v["path"].as_str().map(PathBuf::from));
    path.zip(std::env::current_exe().ok()).is_some_and(|(p, me)| crate::portable::same(Path::new(&p), &me))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_oversize_is_rejected() {
        let mut buf = Vec::new();
        assert!(write_frame(&mut buf, br#"{"a":1}"#));
        assert_eq!(read_frame(&mut buf.as_slice()).unwrap(), br#"{"a":1}"#);
        let mut big = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        big.extend_from_slice(&[0u8; 16]);
        assert!(read_frame(&mut big.as_slice()).is_none());
        assert!(read_frame(&mut [1u8, 0].as_slice()).is_none(), "truncated header");
    }

    #[test]
    fn extension_id_matches_the_manifest_key() {
        let m: Value = serde_json::from_slice(FILES[0].1).unwrap();
        let der = vylt::passkey::b64::decode(m["key"].as_str().unwrap()).unwrap();
        let id: String = vylt::passkey::sha256(&der)[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(id, EXTENSION_ID);
    }
}
