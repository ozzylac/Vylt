//! Windows 11 passkey provider ("plugin authenticator"): a COM server that Windows calls when a
//! browser or app creates or uses a passkey with Vylt. Needs package identity (see
//! installer/msix) and Windows 11 24H2/25H2 with the plugin APIs; webauthn.dll is loaded at run
//! time so that older Windows versions simply report the feature as unavailable.

use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Duration;

use windows_sys::core::{GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_LIST,
    WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptImportKeyPair, BCryptOpenAlgorithmProvider, BCryptVerifySignature,
    BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_KEY_HANDLE, BCRYPT_PAD_PSS, BCRYPT_PSS_PADDING_INFO,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
};
use windows_sys::Win32::System::Com::{CoInitializeEx, CoRegisterClassObject, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, REGCLS_MULTIPLEUSE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};

use crate::broker::{self, ClientData, CreateReq, GetReq, Reply, Request};

/// COM class of the Vylt plugin (also in installer/msix/AppxManifest.xml).
pub const CLSID: GUID = GUID::from_u128(0xca87518c_8253_437f_b8ed_1e5a4a59f99a);
const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_c000_000000000046);
const IID_ICLASSFACTORY: GUID = GUID::from_u128(0x00000001_0000_0000_c000_000000000046);
const IID_PLUGIN: GUID = GUID::from_u128(0xd26bcf6f_b54c_43ff_9f06_d5bf148625f7);
const IID_PLUGIN_EXPERIMENTAL: GUID = GUID::from_u128(0xe6466e9a_b2f3_47c5_b88d_89bc14a8d998);

const S_OK: HRESULT = 0;
const E_NOINTERFACE: HRESULT = 0x8000_4002_u32 as i32;
const E_POINTER: HRESULT = 0x8000_4003_u32 as i32;
const E_FAIL: HRESULT = 0x8000_4005_u32 as i32;
const E_OUTOFMEMORY: HRESULT = 0x8007_000E_u32 as i32;
const CLASS_E_NOAGGREGATION: HRESULT = 0x8004_0110_u32 as i32;
const NTE_BAD_SIGNATURE: HRESULT = 0x8009_0006_u32 as i32;
const NTE_EXISTS: HRESULT = 0x8009_000F_u32 as i32;
const NTE_NOT_SUPPORTED: HRESULT = 0x8009_0029_u32 as i32;
const NTE_USER_CANCELLED: HRESULT = 0x8009_0036_u32 as i32;

const PROMPT_TIMEOUT: Duration = Duration::from_secs(170);

// ---- webauthnplugin.h / pluginauthenticator.h (Windows SDK 10.0.26100.7175) ---------------------

#[repr(C)]
struct OpRequest {
    hwnd: HWND,
    transaction_id: GUID,
    cb_signature: u32,
    pb_signature: *const u8,
    request_type: i32,
    cb_request: u32,
    pb_request: *const u8,
}

#[repr(C)]
struct ExperimentalOpRequest {
    hwnd: HWND,
    transaction_id: GUID,
    cb_signature: u32,
    pb_signature: *const u8,
    cb_request: u32,
    pb_request: *const u8,
}

#[repr(C)]
struct OpResponse {
    cb: u32,
    pb: *mut u8,
}

#[repr(C)]
struct CancelRequest {
    transaction_id: GUID,
    cb_signature: u32,
    pb_signature: *const u8,
}

/// Leading fields of WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST (only read, allocated by Windows).
#[repr(C)]
struct MakeCredentialRequest {
    version: u32,
    cb_rp_id: u32,
    pb_rp_id: *const u8,
    cb_client_data_hash: u32,
    pb_client_data_hash: *const u8,
    rp: *const WEBAUTHN_RP_ENTITY_INFORMATION,
    user: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    params: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    exclude: WEBAUTHN_CREDENTIAL_LIST,
}

/// Leading fields of WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST.
#[repr(C)]
struct GetAssertionRequest {
    version: u32,
    rp_id_w: PCWSTR,
    cb_rp_id: u32,
    pb_rp_id: *const u8,
    cb_client_data_hash: u32,
    pb_client_data_hash: *const u8,
    allow: WEBAUTHN_CREDENTIAL_LIST,
}

/// WEBAUTHN_ASSERTION as in the 26100.7175 SDK (windows-sys stops at version 5).
#[repr(C)]
struct Assertion {
    base: WEBAUTHN_ASSERTION,
    cb_client_data_json: u32,
    pb_client_data_json: *mut u8,
    cb_authentication_response_json: u32,
    pb_authentication_response_json: *mut u8,
}

/// WEBAUTHN_CREDENTIAL_ATTESTATION as in the 26100.7175 SDK (windows-sys stops at version 6).
#[repr(C)]
struct Attestation {
    base: WEBAUTHN_CREDENTIAL_ATTESTATION,
    hmac_secret: *mut c_void,
    third_party_payment: i32,
    transports: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *mut u8,
    cb_registration_response_json: u32,
    pb_registration_response_json: *mut u8,
}

#[repr(C)]
struct GetAssertionResponse {
    assertion: Assertion,
    user: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    number_of_credentials: u32,
    user_selected: i32,
    cb_large_blob_key: u32,
    pb_large_blob_key: *mut u8,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *mut u8,
}

#[repr(C)]
struct AddAuthenticatorOptions {
    name: PCWSTR,
    clsid: *const GUID,
    plugin_rp_id: PCWSTR,
    light_logo_svg: PCWSTR,
    dark_logo_svg: PCWSTR,
    cb_info: u32,
    pb_info: *const u8,
    c_rp_ids: u32,
    rp_ids: *const PCWSTR,
}

#[repr(C)]
struct AddAuthenticatorResponse {
    cb: u32,
    pb: *mut u8,
}

#[repr(C)]
struct CredentialDetails {
    cb_id: u32,
    pb_id: *const u8,
    rp_id: PCWSTR,
    rp_name: PCWSTR,
    cb_user_id: u32,
    pb_user_id: *const u8,
    user_name: PCWSTR,
    user_display_name: PCWSTR,
}

#[allow(non_snake_case)]
struct Api {
    GetAuthenticatorState: unsafe extern "system" fn(*const GUID, *mut i32) -> HRESULT,
    AddAuthenticator: unsafe extern "system" fn(*const AddAuthenticatorOptions, *mut *mut AddAuthenticatorResponse) -> HRESULT,
    FreeAddAuthenticatorResponse: unsafe extern "system" fn(*mut AddAuthenticatorResponse),
    RemoveAuthenticator: unsafe extern "system" fn(*const GUID) -> HRESULT,
    AddCredentials: unsafe extern "system" fn(*const GUID, u32, *const CredentialDetails) -> HRESULT,
    RemoveCredentials: unsafe extern "system" fn(*const GUID, u32, *const CredentialDetails) -> HRESULT,
    RemoveAllCredentials: unsafe extern "system" fn(*const GUID) -> HRESULT,
    GetOperationSigningPublicKey: unsafe extern "system" fn(*const GUID, *mut u32, *mut *mut u8) -> HRESULT,
    FreePublicKeyResponse: unsafe extern "system" fn(*mut u8),
    DecodeMakeCredentialRequest: unsafe extern "system" fn(u32, *const u8, *mut *mut MakeCredentialRequest) -> HRESULT,
    FreeDecodedMakeCredentialRequest: unsafe extern "system" fn(*mut MakeCredentialRequest),
    EncodeMakeCredentialResponse: unsafe extern "system" fn(*const Attestation, *mut u32, *mut *mut u8) -> HRESULT,
    DecodeGetAssertionRequest: unsafe extern "system" fn(u32, *const u8, *mut *mut GetAssertionRequest) -> HRESULT,
    FreeDecodedGetAssertionRequest: unsafe extern "system" fn(*mut GetAssertionRequest),
    EncodeGetAssertionResponse: unsafe extern "system" fn(*const GetAssertionResponse, *mut u32, *mut *mut u8) -> HRESULT,
}

// The `f!` macro transmutes each GetProcAddress result into the field's own fn-pointer type; the
// target type is fixed by the Api struct, so a per-call annotation would only repeat it.
#[allow(clippy::missing_transmute_annotations)]
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| unsafe {
        // System32 only: a planted webauthn.dll next to the exe must never be loaded.
        let lib = LoadLibraryExW(wide("webauthn.dll").as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if lib.is_null() {
            return None;
        }
        macro_rules! f {
            ($name:literal) => {
                std::mem::transmute(GetProcAddress(lib, concat!($name, "\0").as_ptr())?)
            };
        }
        Some(Api {
            GetAuthenticatorState: f!("WebAuthNPluginGetAuthenticatorState"),
            AddAuthenticator: f!("WebAuthNPluginAddAuthenticator"),
            FreeAddAuthenticatorResponse: f!("WebAuthNPluginFreeAddAuthenticatorResponse"),
            RemoveAuthenticator: f!("WebAuthNPluginRemoveAuthenticator"),
            AddCredentials: f!("WebAuthNPluginAuthenticatorAddCredentials"),
            RemoveCredentials: f!("WebAuthNPluginAuthenticatorRemoveCredentials"),
            RemoveAllCredentials: f!("WebAuthNPluginAuthenticatorRemoveAllCredentials"),
            GetOperationSigningPublicKey: f!("WebAuthNPluginGetOperationSigningPublicKey"),
            FreePublicKeyResponse: f!("WebAuthNPluginFreePublicKeyResponse"),
            DecodeMakeCredentialRequest: f!("WebAuthNDecodeMakeCredentialRequest"),
            FreeDecodedMakeCredentialRequest: f!("WebAuthNFreeDecodedMakeCredentialRequest"),
            EncodeMakeCredentialResponse: f!("WebAuthNEncodeMakeCredentialResponse"),
            DecodeGetAssertionRequest: f!("WebAuthNDecodeGetAssertionRequest"),
            FreeDecodedGetAssertionRequest: f!("WebAuthNFreeDecodedGetAssertionRequest"),
            EncodeGetAssertionResponse: f!("WebAuthNEncodeGetAssertionResponse"),
        })
    })
    .as_ref()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

unsafe fn from_wide(p: PCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 && n < 4096 {
        n += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

unsafe fn bytes(p: *const u8, n: u32) -> Vec<u8> {
    if p.is_null() || n == 0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(p, n as usize) }.to_vec() }
}

unsafe fn credential_ids(l: &WEBAUTHN_CREDENTIAL_LIST) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    if l.ppCredentials.is_null() {
        return v;
    }
    for i in 0..l.cCredentials.min(1024) as usize {
        let c = unsafe { *l.ppCredentials.add(i) };
        if !c.is_null() {
            v.push(unsafe { bytes((*c).pbId, (*c).cbId) });
        }
    }
    v
}

// ---- state --------------------------------------------------------------------------------------

pub enum State {
    /// webauthn.dll has no plugin API (Windows older than 24H2 with the 2025 updates).
    Unsupported,
    /// The process has no package identity: the identity package is not registered yet.
    NoIdentity,
    NotRegistered,
    Disabled,
    Enabled,
}

pub fn has_identity() -> bool {
    use windows_sys::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
    let mut n = 0u32;
    // ERROR_INSUFFICIENT_BUFFER (122) means a package exists; APPMODEL_ERROR_NO_PACKAGE (15700) not.
    unsafe { GetCurrentPackageFullName(&mut n, std::ptr::null_mut()) == 122 }
}

pub fn state() -> State {
    let Some(a) = api() else { return State::Unsupported };
    if !has_identity() {
        return State::NoIdentity;
    }
    let mut s = 0i32;
    match unsafe { (a.GetAuthenticatorState)(&CLSID, &mut s) } {
        S_OK if s == 1 => State::Enabled,
        S_OK => State::Disabled,
        _ => State::NotRegistered,
    }
}

const LOGO_SVG: &str = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OCA0OCI+PHJlY3QgeD0iMiIgeT0iMiIgd2lkdGg9IjQ0IiBoZWlnaHQ9IjQ0IiByeD0iMTMiIGZpbGw9IiMxOTE5MUQiLz48Y2lyY2xlIGN4PSIyNCIgY3k9IjIwIiByPSI2IiBmaWxsPSIjRDZBMjRBIi8+PHBhdGggZD0iTTIxIDIyaDZsMiAxM0gxOXoiIGZpbGw9IiNENkEyNEEiLz48L3N2Zz4=";

/// Register Vylt as a passkey provider (the user then enables it in Windows Settings).
pub fn register() -> Result<(), String> {
    let a = api().ok_or("webauthn.dll")?;
    let info = vylt::passkey::authenticator_info();
    let (name, logo) = (wide("Vylt"), wide(LOGO_SVG));
    let opts = AddAuthenticatorOptions {
        name: name.as_ptr(),
        clsid: &CLSID,
        plugin_rp_id: std::ptr::null(),
        light_logo_svg: logo.as_ptr(),
        dark_logo_svg: logo.as_ptr(),
        cb_info: info.len() as u32,
        pb_info: info.as_ptr(),
        c_rp_ids: 0,
        rp_ids: std::ptr::null(),
    };
    let mut resp: *mut AddAuthenticatorResponse = std::ptr::null_mut();
    let hr = unsafe { (a.AddAuthenticator)(&opts, &mut resp) };
    if !resp.is_null() {
        unsafe { (a.FreeAddAuthenticatorResponse)(resp) };
    }
    if hr == S_OK || hr == NTE_EXISTS { Ok(()) } else { Err(format!("0x{:08X}", hr as u32)) }
}

pub fn unregister() {
    if let Some(a) = api() {
        unsafe {
            (a.RemoveAllCredentials)(&CLSID);
            (a.RemoveAuthenticator)(&CLSID);
        }
    }
}

/// Tell Windows which passkeys exist (names shown in its account picker and autofill).
pub fn publish(passkeys: &[&vylt::passkey::Passkey], add: bool) {
    let Some(a) = api() else { return };
    if passkeys.is_empty() || !has_identity() {
        return;
    }
    let strings: Vec<[Vec<u16>; 4]> = passkeys.iter().map(|p| [wide(&p.rp_id), wide(&p.rp_name), wide(&p.user_name), wide(&p.user_display)]).collect();
    let details: Vec<CredentialDetails> = passkeys
        .iter()
        .zip(&strings)
        .map(|(p, s)| CredentialDetails {
            cb_id: p.credential_id.len() as u32,
            pb_id: p.credential_id.as_ptr(),
            rp_id: s[0].as_ptr(),
            rp_name: s[1].as_ptr(),
            cb_user_id: p.user_handle.len() as u32,
            pb_user_id: p.user_handle.as_ptr(),
            user_name: s[2].as_ptr(),
            user_display_name: s[3].as_ptr(),
        })
        .collect();
    unsafe {
        if add {
            (a.AddCredentials)(&CLSID, details.len() as u32, details.as_ptr());
        } else {
            (a.RemoveCredentials)(&CLSID, details.len() as u32, details.as_ptr());
        }
    }
}

/// Open Windows Settings where the user turns Vylt on as a passkey provider.
pub fn open_settings() {
    crate::platform::spawn_detached("explorer.exe", &["ms-settings:savedpasskeys".into()]);
}

/// Mirror this profile's passkeys into Windows (shown in its account picker / autofill). Only the
/// main vault's passkeys are published — never hidden-category ones.
pub fn sync(passkeys: &[&vylt::passkey::Passkey]) {
    let Some(a) = api() else { return };
    if !has_identity() {
        return;
    }
    unsafe {
        (a.RemoveAllCredentials)(&CLSID);
    }
    publish(passkeys, true);
}

/// After a Windows update or a reinstall, make sure the authenticator is still registered.
pub fn reregister_if_known() {
    if matches!(state(), State::Enabled | State::Disabled) {
        let _ = register();
    }
}

// ---- request signature (Windows signs each request with a key it gave us at registration) -------

fn verify_request(request: &[u8], signature: &[u8]) -> bool {
    let Some(a) = api() else { return false };
    let (mut n, mut p) = (0u32, std::ptr::null_mut());
    if unsafe { (a.GetOperationSigningPublicKey)(&CLSID, &mut n, &mut p) } != S_OK || p.is_null() {
        return false;
    }
    let blob = unsafe { bytes(p, n) };
    unsafe { (a.FreePublicKeyResponse)(p) };
    let digest = vylt::passkey::sha256(request);
    let rsa = blob.starts_with(b"RSA1");
    let (alg_id, blob_type) = if rsa { (BCRYPT_RSA_ALGORITHM, BCRYPT_RSAPUBLIC_BLOB) } else { (BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECCPUBLIC_BLOB) };
    unsafe {
        let mut alg: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
        if BCryptOpenAlgorithmProvider(&mut alg, alg_id, std::ptr::null(), 0) != 0 {
            return false;
        }
        let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
        let ok = BCryptImportKeyPair(alg, std::ptr::null_mut(), blob_type, &mut key, blob.as_ptr(), blob.len() as u32, 0) == 0 && {
            let pss = BCRYPT_PSS_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, cbSalt: 32 };
            let (pad, flags) = if rsa { (&pss as *const _ as *const c_void, BCRYPT_PAD_PSS) } else { (std::ptr::null(), 0) };
            BCryptVerifySignature(key, pad, digest.as_ptr(), digest.len() as u32, signature.as_ptr(), signature.len() as u32, flags) == 0
        };
        if !key.is_null() {
            BCryptDestroyKey(key);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        ok
    }
}

// ---- operations ---------------------------------------------------------------------------------

fn hr_of(r: &Reply) -> HRESULT {
    match r {
        Reply::Declined => NTE_USER_CANCELLED,
        Reply::Excluded => NTE_EXISTS,
        Reply::Error(_) => E_FAIL,
        _ => S_OK,
    }
}

unsafe fn make_credential(request: &[u8], signature: &[u8], out: &mut OpResponse) -> HRESULT {
    let Some(a) = api() else { return NTE_NOT_SUPPORTED };
    if !verify_request(request, signature) {
        return NTE_BAD_SIGNATURE;
    }
    let mut d: *mut MakeCredentialRequest = std::ptr::null_mut();
    if unsafe { (a.DecodeMakeCredentialRequest)(request.len() as u32, request.as_ptr(), &mut d) } != S_OK || d.is_null() {
        return E_FAIL;
    }
    let r = unsafe { &*d };
    let es256 = !r.params.pCredentialParameters.is_null()
        && (0..r.params.cCredentialParameters as usize).any(|i| unsafe { (*r.params.pCredentialParameters.add(i)).lAlg } as i64 == vylt::passkey::ES256);
    let req = unsafe {
        CreateReq {
            rp_id: String::from_utf8_lossy(&bytes(r.pb_rp_id, r.cb_rp_id)).into_owned(),
            rp_name: if r.rp.is_null() { String::new() } else { from_wide((*r.rp).pwszName) },
            user_name: if r.user.is_null() { String::new() } else { from_wide((*r.user).pwszName) },
            user_display: if r.user.is_null() { String::new() } else { from_wide((*r.user).pwszDisplayName) },
            user_handle: if r.user.is_null() { Vec::new() } else { bytes((*r.user).pbId, (*r.user).cbId) },
            exclude: credential_ids(&r.exclude),
            client: ClientData::Hash(bytes(r.pb_client_data_hash, r.cb_client_data_hash)),
        }
    };
    unsafe { (a.FreeDecodedMakeCredentialRequest)(d) };
    if !es256 {
        return NTE_NOT_SUPPORTED;
    }
    if req.rp_id.is_empty() || req.user_handle.is_empty() || req.user_handle.len() > 64 {
        return E_FAIL;
    }
    let reply = broker::submit(Request::Create(req), PROMPT_TIMEOUT);
    let Reply::Created { mut credential_id, mut auth_data, mut attestation_object, .. } = reply else { return hr_of(&reply) };
    let fmt = wide("none");
    let mut att_stmt = vec![0xa0u8];
    let base = WEBAUTHN_CREDENTIAL_ATTESTATION {
        dwVersion: 6,
        pwszFormatType: fmt.as_ptr(),
        cbAuthenticatorData: auth_data.len() as u32,
        pbAuthenticatorData: auth_data.as_mut_ptr(),
        cbAttestation: att_stmt.len() as u32,
        pbAttestation: att_stmt.as_mut_ptr(),
        cbAttestationObject: attestation_object.len() as u32,
        pbAttestationObject: attestation_object.as_mut_ptr(),
        cbCredentialId: credential_id.len() as u32,
        pbCredentialId: credential_id.as_mut_ptr(),
        bResidentKey: 1,
        ..Default::default()
    };
    let att = Attestation {
        base,
        hmac_secret: std::ptr::null_mut(),
        third_party_payment: 0,
        transports: 0,
        cb_client_data_json: 0,
        pb_client_data_json: std::ptr::null_mut(),
        cb_registration_response_json: 0,
        pb_registration_response_json: std::ptr::null_mut(),
    };
    let (mut n, mut p) = (0u32, std::ptr::null_mut());
    let hr = unsafe { (a.EncodeMakeCredentialResponse)(&att, &mut n, &mut p) };
    if hr != S_OK {
        return hr;
    }
    (out.cb, out.pb) = (n, p);
    S_OK
}

unsafe fn get_assertion(request: &[u8], signature: &[u8], out: &mut OpResponse) -> HRESULT {
    let Some(a) = api() else { return NTE_NOT_SUPPORTED };
    if !verify_request(request, signature) {
        return NTE_BAD_SIGNATURE;
    }
    let mut d: *mut GetAssertionRequest = std::ptr::null_mut();
    if unsafe { (a.DecodeGetAssertionRequest)(request.len() as u32, request.as_ptr(), &mut d) } != S_OK || d.is_null() {
        return E_FAIL;
    }
    let r = unsafe { &*d };
    let req = unsafe {
        GetReq {
            rp_id: String::from_utf8_lossy(&bytes(r.pb_rp_id, r.cb_rp_id)).into_owned(),
            allow: credential_ids(&r.allow),
            client: ClientData::Hash(bytes(r.pb_client_data_hash, r.cb_client_data_hash)),
        }
    };
    unsafe { (a.FreeDecodedGetAssertionRequest)(d) };
    let reply = broker::submit(Request::Get(req), PROMPT_TIMEOUT);
    let Reply::Asserted { mut credential_id, mut auth_data, mut signature, mut user_handle, user_name, user_display, .. } = reply else {
        return hr_of(&reply);
    };
    let (kind, name, display) = (wide("public-key"), wide(&user_name), wide(&user_display));
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: 1,
        cbId: user_handle.len() as u32,
        pbId: user_handle.as_mut_ptr(),
        pwszName: name.as_ptr(),
        pwszIcon: std::ptr::null(),
        pwszDisplayName: display.as_ptr(),
    };
    let mut assertion = WEBAUTHN_ASSERTION {
        dwVersion: 1,
        cbAuthenticatorData: auth_data.len() as u32,
        pbAuthenticatorData: auth_data.as_mut_ptr(),
        cbSignature: signature.len() as u32,
        pbSignature: signature.as_mut_ptr(),
        cbUserId: user.cbId,
        pbUserId: user.pbId,
        ..Default::default()
    };
    assertion.Credential.dwVersion = 1;
    assertion.Credential.cbId = credential_id.len() as u32;
    assertion.Credential.pbId = credential_id.as_mut_ptr();
    assertion.Credential.pwszCredentialType = kind.as_ptr();
    let resp = GetAssertionResponse {
        assertion: Assertion {
            base: assertion,
            cb_client_data_json: 0,
            pb_client_data_json: std::ptr::null_mut(),
            cb_authentication_response_json: 0,
            pb_authentication_response_json: std::ptr::null_mut(),
        },
        user: &user,
        number_of_credentials: 1,
        user_selected: 1,
        cb_large_blob_key: 0,
        pb_large_blob_key: std::ptr::null_mut(),
        cb_unsigned_extension_outputs: 0,
        pb_unsigned_extension_outputs: std::ptr::null_mut(),
    };
    let (mut n, mut p) = (0u32, std::ptr::null_mut());
    let hr = unsafe { (a.EncodeGetAssertionResponse)(&resp, &mut n, &mut p) };
    if hr != S_OK {
        return hr;
    }
    (out.cb, out.pb) = (n, p);
    S_OK
}

// ---- COM objects (static singletons: AddRef/Release do not free anything) -----------------------

#[repr(C)]
struct UnknownVtbl {
    query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct FactoryVtbl {
    base: UnknownVtbl,
    create_instance: unsafe extern "system" fn(*mut c_void, *mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    lock_server: unsafe extern "system" fn(*mut c_void, i32) -> HRESULT,
}

#[repr(C)]
struct PluginVtbl {
    base: UnknownVtbl,
    make_credential: unsafe extern "system" fn(*mut c_void, *const OpRequest, *mut OpResponse) -> HRESULT,
    get_assertion: unsafe extern "system" fn(*mut c_void, *const OpRequest, *mut OpResponse) -> HRESULT,
    cancel: unsafe extern "system" fn(*mut c_void, *const CancelRequest) -> HRESULT,
    lock_status: unsafe extern "system" fn(*mut c_void, *mut i32) -> HRESULT,
}

#[repr(C)]
struct ExperimentalVtbl {
    base: UnknownVtbl,
    make_credential: unsafe extern "system" fn(*mut c_void, *const ExperimentalOpRequest, *mut *mut OpResponse) -> HRESULT,
    get_assertion: unsafe extern "system" fn(*mut c_void, *const ExperimentalOpRequest, *mut *mut OpResponse) -> HRESULT,
    cancel: unsafe extern "system" fn(*mut c_void, *const CancelRequest) -> HRESULT,
}

#[repr(C)]
struct Obj<V: 'static> {
    vtbl: &'static V,
}

unsafe extern "system" fn add_ref(_: *mut c_void) -> u32 {
    2
}
unsafe extern "system" fn release(_: *mut c_void) -> u32 {
    1
}

fn same(a: *const GUID, b: &GUID) -> bool {
    !a.is_null() && unsafe { (*a).data1 == b.data1 && (*a).data2 == b.data2 && (*a).data3 == b.data3 && (*a).data4 == b.data4 }
}

unsafe extern "system" fn factory_qi(this: *mut c_void, riid: *const GUID, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    if same(riid, &IID_IUNKNOWN) || same(riid, &IID_ICLASSFACTORY) {
        unsafe { *out = this };
        S_OK
    } else {
        unsafe { *out = std::ptr::null_mut() };
        E_NOINTERFACE
    }
}

unsafe extern "system" fn create_instance(_: *mut c_void, outer: *mut c_void, riid: *const GUID, out: *mut *mut c_void) -> HRESULT {
    if !outer.is_null() {
        return CLASS_E_NOAGGREGATION;
    }
    unsafe { plugin_qi(std::ptr::null_mut(), riid, out) }
}

unsafe extern "system" fn lock_server(_: *mut c_void, _: i32) -> HRESULT {
    S_OK
}

unsafe extern "system" fn plugin_qi(_: *mut c_void, riid: *const GUID, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let p: *mut c_void = if same(riid, &IID_IUNKNOWN) || same(riid, &IID_PLUGIN) {
        &PLUGIN as *const _ as *mut c_void
    } else if same(riid, &IID_PLUGIN_EXPERIMENTAL) {
        &EXPERIMENTAL as *const _ as *mut c_void
    } else {
        std::ptr::null_mut()
    };
    unsafe { *out = p };
    if p.is_null() { E_NOINTERFACE } else { S_OK }
}

unsafe extern "system" fn mc(_: *mut c_void, r: *const OpRequest, out: *mut OpResponse) -> HRESULT {
    if r.is_null() || out.is_null() {
        return E_POINTER;
    }
    let r = unsafe { &*r };
    unsafe { make_credential(&bytes(r.pb_request, r.cb_request), &bytes(r.pb_signature, r.cb_signature), &mut *out) }
}

unsafe extern "system" fn ga(_: *mut c_void, r: *const OpRequest, out: *mut OpResponse) -> HRESULT {
    if r.is_null() || out.is_null() {
        return E_POINTER;
    }
    let r = unsafe { &*r };
    unsafe { get_assertion(&bytes(r.pb_request, r.cb_request), &bytes(r.pb_signature, r.cb_signature), &mut *out) }
}

unsafe extern "system" fn cancel(_: *mut c_void, _: *const CancelRequest) -> HRESULT {
    broker::cancel_all();
    S_OK
}

unsafe extern "system" fn lock_status(_: *mut c_void, out: *mut i32) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { *out = broker::UNLOCKED.load(std::sync::atomic::Ordering::Relaxed) as i32 };
    S_OK
}

/// The experimental interface returns a response the plugin allocates with CoTaskMemAlloc.
unsafe fn experimental(r: *const ExperimentalOpRequest, out: *mut *mut OpResponse, create: bool) -> HRESULT {
    use windows_sys::Win32::System::Com::CoTaskMemAlloc;
    if r.is_null() || out.is_null() {
        return E_POINTER;
    }
    let r = unsafe { &*r };
    let mut resp = OpResponse { cb: 0, pb: std::ptr::null_mut() };
    let (req, sig) = unsafe { (bytes(r.pb_request, r.cb_request), bytes(r.pb_signature, r.cb_signature)) };
    let hr = unsafe { if create { make_credential(&req, &sig, &mut resp) } else { get_assertion(&req, &sig, &mut resp) } };
    if hr != S_OK {
        return hr;
    }
    let p = unsafe { CoTaskMemAlloc(std::mem::size_of::<OpResponse>()) } as *mut OpResponse;
    if p.is_null() {
        return E_OUTOFMEMORY;
    }
    unsafe {
        p.write(resp);
        *out = p;
    }
    S_OK
}

unsafe extern "system" fn emc(_: *mut c_void, r: *const ExperimentalOpRequest, out: *mut *mut OpResponse) -> HRESULT {
    unsafe { experimental(r, out, true) }
}

unsafe extern "system" fn ega(_: *mut c_void, r: *const ExperimentalOpRequest, out: *mut *mut OpResponse) -> HRESULT {
    unsafe { experimental(r, out, false) }
}

static FACTORY: Obj<FactoryVtbl> = Obj {
    vtbl: &FactoryVtbl { base: UnknownVtbl { query_interface: factory_qi, add_ref, release }, create_instance, lock_server },
};
static PLUGIN: Obj<PluginVtbl> = Obj {
    vtbl: &PluginVtbl { base: UnknownVtbl { query_interface: plugin_qi, add_ref, release }, make_credential: mc, get_assertion: ga, cancel, lock_status },
};
static EXPERIMENTAL: Obj<ExperimentalVtbl> = Obj {
    vtbl: &ExperimentalVtbl { base: UnknownVtbl { query_interface: plugin_qi, add_ref, release }, make_credential: emc, get_assertion: ega, cancel },
};

/// Serve the COM class while the app runs (only meaningful with package identity).
pub fn start_server() {
    if api().is_none() || !has_identity() {
        return;
    }
    std::thread::spawn(|| unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32);
        let mut cookie = 0u32;
        if CoRegisterClassObject(&CLSID, &FACTORY as *const _ as *mut c_void, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE as u32, &mut cookie) == S_OK {
            loop {
                std::thread::park();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_layouts_match_the_sdk_headers() {
        // x64 values printed by a C probe compiled with MSVC against the 26100 SDK headers.
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<OpRequest>(), 56);
        assert_eq!(offset_of!(OpRequest, cb_request), 44);
        assert_eq!(offset_of!(OpRequest, pb_request), 48);
        assert_eq!(size_of::<ExperimentalOpRequest>(), 56);
        assert_eq!(size_of::<OpResponse>(), 16);
        assert_eq!(size_of::<CancelRequest>(), 32);
        assert_eq!(offset_of!(MakeCredentialRequest, rp), 32);
        assert_eq!(offset_of!(MakeCredentialRequest, params), 48);
        assert_eq!(offset_of!(MakeCredentialRequest, exclude), 64);
        assert_eq!(offset_of!(GetAssertionRequest, cb_rp_id), 16);
        assert_eq!(offset_of!(GetAssertionRequest, allow), 48);
        assert_eq!(size_of::<GetAssertionResponse>(), 216);
        assert_eq!(offset_of!(GetAssertionResponse, user), 168);
        assert_eq!(offset_of!(GetAssertionResponse, pb_unsigned_extension_outputs), 208);
        assert_eq!(size_of::<AddAuthenticatorOptions>(), 72);
        assert_eq!(size_of::<AddAuthenticatorResponse>(), 16);
        assert_eq!(size_of::<CredentialDetails>(), 64);
        assert_eq!(size_of::<Assertion>(), 168);
        assert_eq!(size_of::<Attestation>(), 192);
        assert_eq!(offset_of!(Attestation, base) + offset_of!(WEBAUTHN_CREDENTIAL_ATTESTATION, bResidentKey), 124);
    }

    #[test]
    fn com_interfaces_answer_only_known_iids() {
        let mut p = std::ptr::null_mut();
        unsafe {
            assert_eq!(plugin_qi(std::ptr::null_mut(), &IID_PLUGIN, &mut p), S_OK);
            assert_eq!(p, &PLUGIN as *const _ as *mut c_void);
            assert_eq!(plugin_qi(std::ptr::null_mut(), &IID_ICLASSFACTORY, &mut p), E_NOINTERFACE);
            assert!(p.is_null());
            assert_eq!(factory_qi(&FACTORY as *const _ as *mut c_void, &IID_ICLASSFACTORY, &mut p), S_OK);
            let mut status = -1;
            assert_eq!(lock_status(std::ptr::null_mut(), &mut status), S_OK);
            assert!(status == 0 || status == 1);
        }
    }
}
