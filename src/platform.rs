//! Windows-specific hardening: capture protection and clipboard handling.

use arboard::{Clipboard, SetExtWindows};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::WTSRegisterSessionNotification;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW, SetWindowDisplayAffinity,
    TranslateMessage, HWND_MESSAGE, MSG, WDA_EXCLUDEFROMCAPTURE, WNDCLASSW,
};

/// Hide the window from screenshots / screen recording / remote capture. Returns true once applied.
pub fn protect_window(frame: &eframe::Frame) -> bool {
    let Ok(handle) = frame.window_handle() else { return false };
    let RawWindowHandle::Win32(h) = handle.as_raw() else { return false };
    let hwnd = h.hwnd.get() as HWND;
    unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0 }
}

/// Fingerprint of the secret last put on the clipboard, and when to clear it.
static CLIP: Mutex<Option<([u8; 32], Instant)>> = Mutex::new(None);

fn fingerprint(text: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).into()
}

/// Copy text and keep it out of Windows clipboard history / cloud sync. A background thread
/// clears it after `ttl`, even while the window is minimized or the app is gone from the screen.
pub fn copy_secret(text: &str, ttl: Duration) -> bool {
    let ok = Clipboard::new().and_then(|mut c| c.set().exclude_from_history().text(text.to_owned())).is_ok();
    if ok {
        if let Ok(mut g) = CLIP.lock() {
            *g = Some((fingerprint(text), Instant::now() + ttl));
        }
        static TIMER: std::sync::Once = std::sync::Once::new();
        TIMER.call_once(|| {
            std::thread::spawn(|| loop {
                std::thread::sleep(Duration::from_millis(250));
                let due = CLIP.lock().ok().and_then(|g| *g).is_some_and(|(_, at)| Instant::now() >= at);
                if due {
                    clear_clipboard();
                }
            });
        });
    }
    ok
}

/// Clear the clipboard if it still holds the secret Vylt put there (never what the user
/// copied since, from another program).
pub fn clear_clipboard() {
    let Ok(mut g) = CLIP.lock() else { return };
    let Some((fp, _)) = g.take() else { return };
    if let Ok(mut c) = Clipboard::new()
        && c.get_text().is_ok_and(|t| fingerprint(&t) == fp)
    {
        let _ = c.clear();
    }
}

/// Decode a QR code from an image currently in the clipboard (e.g. Win+Shift+S screenshot).
pub fn clipboard_qr() -> Option<String> {
    let img = Clipboard::new().ok()?.get_image().ok()?;
    vylt::otp::decode_qr_rgba(img.width, img.height, &img.bytes)
}

// ---- lock on Windows session lock / sleep -------------------------------------------------

static LOCK_REQUEST: AtomicBool = AtomicBool::new(false);

/// True once if Windows locked the session, disconnected it or is going to sleep.
pub fn take_lock_request() -> bool {
    LOCK_REQUEST.swap(false, Ordering::SeqCst)
}

const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const WM_POWERBROADCAST: u32 = 0x0218;
const PBT_APMSUSPEND: usize = 0x4;
const WTS_CONSOLE_DISCONNECT: usize = 0x2;
const WTS_REMOTE_DISCONNECT: usize = 0x4;
const WTS_SESSION_LOCK: usize = 0x7;
const NOTIFY_FOR_THIS_SESSION: u32 = 0;

unsafe extern "system" fn watcher_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let lock = match msg {
        WM_WTSSESSION_CHANGE => matches!(wp, WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT),
        WM_POWERBROADCAST => wp == PBT_APMSUSPEND,
        _ => false,
    };
    if lock {
        LOCK_REQUEST.store(true, Ordering::SeqCst);
    }
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

/// Spawn a hidden message-only window that listens for session lock / sleep events.
pub fn start_lock_watcher() {
    std::thread::spawn(|| unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class: Vec<u16> = "VyltWatcher\0".encode_utf16().collect();
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(watcher_proc);
        wc.hInstance = hinst;
        wc.lpszClassName = class.as_ptr();
        if RegisterClassW(&wc) == 0 {
            return;
        }
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return;
        }
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        let mut m: MSG = std::mem::zeroed();
        while GetMessageW(&mut m, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    });
}

/// Start `program` directly (no shell, no console window) and do not wait for it.
pub fn spawn_detached(program: &str, args: &[String]) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .is_ok()
}

/// Take the per-data-folder instance lock. If Vylt already runs on the same data, bring
/// its window forward and return false (the caller then exits).
pub fn single_instance(data_dir: &std::path::Path) -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE};
    let tag: String = vylt::passkey::sha256(data_dir.to_string_lossy().to_lowercase().as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect();
    let name: Vec<u16> = format!("Local\\Vylt-{tag}").encode_utf16().chain([0]).collect();
    // The handle is kept for the life of the process on purpose.
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if h.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        return true;
    }
    let title: Vec<u16> = "Vylt\0".encode_utf16().collect();
    let w = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    if !w.is_null() {
        unsafe {
            ShowWindow(w, SW_RESTORE);
            SetForegroundWindow(w);
        }
    }
    false
}

/// Letters of removable drives (USB keys), in order.
pub fn removable_drives() -> Vec<char> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE: u32 = 2;
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| (b'A' + i) as char)
        .filter(|&l| {
            let root: Vec<u16> = format!("{l}:\\\0").encode_utf16().collect();
            unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_REMOVABLE }
        })
        .collect()
}

/// Give a file the Windows "hidden" attribute so it does not show up by default.
pub fn hide_file(path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
    let w: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    unsafe {
        SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_HIDDEN);
    }
}

/// Best-effort process hardening, run once at startup. Blocks DLL planting / legacy injection, and
/// stops other same-user processes from reading this process's memory (mitigates live secret
/// theft). Every step is best-effort: a failure never stops the app.
pub fn harden() {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{AddAccessAllowedAce, GetTokenInformation, InitializeAcl, TokenUser, ACL, DACL_SECURITY_INFORMATION, TOKEN_USER};
    use windows_sys::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
    };

    const TOKEN_QUERY: u32 = 0x0008;
    const ACL_REVISION: u32 = 2;
    // Rights other openers may still have — never memory read/write/operation, thread creation or
    // handle duplication (those are how a secret-stealer reaches into the process).
    const GRANT: u32 = 0x0001/*TERMINATE*/ | 0x0100/*SET_QUOTA*/ | 0x0200/*SET_INFORMATION*/
        | 0x0400/*QUERY_INFORMATION*/ | 0x0800/*SUSPEND_RESUME*/ | 0x1000/*QUERY_LIMITED_INFORMATION*/ | 0x0010_0000/*SYNCHRONIZE*/;

    unsafe {
        // Only load DLLs from System32 by default (process-wide anti-planting).
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        // Block AppInit / legacy hook / IME injection.
        let ext: u32 = 1;
        SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext as *const u32 as *const c_void, 4);
        // Refuse remote, low-integrity images; prefer System32.
        let img: u32 = 0b111;
        SetProcessMitigationPolicy(ProcessImageLoadPolicy, &img as *const u32 as *const c_void, 4);

        // Replace the process DACL: grant this user only management rights, never VM read.
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            if len > 0 {
                let mut buf = vec![0u8; len as usize];
                if GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len) != 0 {
                    let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
                    let mut acl = [0u32; 256]; // 1 KiB, DWORD-aligned
                    let aclp = acl.as_mut_ptr() as *mut ACL;
                    if InitializeAcl(aclp, (acl.len() * 4) as u32, ACL_REVISION) != 0 && AddAccessAllowedAce(aclp, ACL_REVISION, GRANT, sid) != 0 {
                        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), aclp, std::ptr::null());
                    }
                }
            }
            CloseHandle(token);
        }
    }
}
