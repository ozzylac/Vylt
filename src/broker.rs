//! Passkey requests (browser extension, Windows), queued for the UI and answered by the open vault.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};

use eframe::egui;
use vylt::passkey::{self, b64, Passkey};
use vylt::vault::Entry;
use serde_json::{json, Value};

use crate::config::now_secs;

pub enum ClientData {
    /// Windows already hashed the client data.
    Hash(Vec<u8>),
    /// The extension gives the parts; Vylt writes `clientDataJSON` itself.
    Build { origin: String, challenge: Vec<u8>, cross_origin: bool },
}

pub struct CreateReq {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display: String,
    pub user_handle: Vec<u8>,
    pub exclude: Vec<Vec<u8>>,
    pub client: ClientData,
}

pub struct GetReq {
    pub rp_id: String,
    pub allow: Vec<Vec<u8>>,
    pub client: ClientData,
}

pub enum Request {
    Create(CreateReq),
    Get(GetReq),
}

impl Request {
    pub fn rp_id(&self) -> &str {
        match self {
            Request::Create(c) => &c.rp_id,
            Request::Get(g) => &g.rp_id,
        }
    }
}

pub enum Reply {
    Created { credential_id: Vec<u8>, client_data_json: Option<String>, auth_data: Vec<u8>, attestation_object: Vec<u8>, public_spki: Vec<u8> },
    Asserted { credential_id: Vec<u8>, client_data_json: Option<String>, auth_data: Vec<u8>, signature: Vec<u8>, user_handle: Vec<u8>, user_name: String, user_display: String },
    /// The user declined, or Vylt has nothing for this site: let the browser handle it.
    Declined,
    /// `excludeCredentials` names a passkey already stored here.
    Excluded,
    Error(String),
}

/// A request waiting for the user, plus the state of its prompt.
pub struct Job {
    pub req: Request,
    reply: Sender<Reply>,
    cancelled: Arc<AtomicBool>,
    pub ui: PromptState,
}

#[derive(Default)]
pub struct PromptState {
    pub choice: usize,
    pub pw: crate::session::Secret,
    pub code: crate::session::Secret,
    pub err: String,
}

impl Job {
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn answer(self, r: Reply) {
        let _ = self.reply.send(r);
    }
}

fn queue() -> &'static Mutex<VecDeque<Job>> {
    static Q: OnceLock<Mutex<VecDeque<Job>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(VecDeque::new()))
}

static CTX: OnceLock<egui::Context> = OnceLock::new();
/// Unix time of the last request received from the browser extension.
pub static LAST_EXTENSION: AtomicU64 = AtomicU64::new(0);
/// A vault is open (reported to Windows as the plugin lock status).
pub static UNLOCKED: AtomicBool = AtomicBool::new(false);

fn waiting() -> &'static Mutex<Vec<Arc<AtomicBool>>> {
    static W: OnceLock<Mutex<Vec<Arc<AtomicBool>>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(Vec::new()))
}

/// Windows cancelled the operation: drop every pending prompt.
pub fn cancel_all() {
    if let Ok(w) = waiting().lock() {
        for c in w.iter() {
            c.store(true, Ordering::SeqCst);
        }
    }
    if let Ok(mut q) = queue().lock() {
        q.clear();
    }
}

pub fn set_context(ctx: &egui::Context) {
    let _ = CTX.set(ctx.clone());
}

/// Queue a request for the UI and bring the window forward. Waits at most `timeout`.
pub fn submit(req: Request, timeout: std::time::Duration) -> Reply {
    let (tx, rx): (Sender<Reply>, Receiver<Reply>) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let job = Job { req, reply: tx, cancelled: cancelled.clone(), ui: PromptState::default() };
    match queue().lock() {
        Ok(mut q) => q.push_back(job),
        Err(_) => return Reply::Error("queue".into()),
    }
    if let Ok(mut w) = waiting().lock() {
        w.push(cancelled.clone());
    }
    if let Some(ctx) = CTX.get() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.request_repaint();
    }
    let mut r = Reply::Declined;
    let until = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < until && !cancelled.load(Ordering::SeqCst) {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(x) => {
                r = x;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    cancelled.store(true, Ordering::SeqCst);
    if let Ok(mut w) = waiting().lock() {
        w.retain(|c| !Arc::ptr_eq(c, &cancelled));
    }
    r
}

pub fn take() -> Option<Job> {
    queue().lock().ok()?.pop_front()
}

// ---- vault side ---------------------------------------------------------------------------------

/// Host part of an entry's "site" field: `https://www.github.com/login` -> `github.com`.
pub fn site_host(site: &str) -> String {
    let s = site.trim().to_ascii_lowercase();
    let s = s.split_once("://").map_or(s.as_str(), |(_, r)| r);
    let h = s.split(['/', '?', '#', ':']).next().unwrap_or("");
    h.strip_prefix("www.").unwrap_or(h).to_owned()
}

/// Whether an entry's site belongs to the relying party `rp_id`. A site written as a bare name
/// ("GitHub") matches the domain's main label (github.com). Only used to suggest an entry.
pub fn site_matches(site: &str, rp_id: &str) -> bool {
    let (h, rp) = (site_host(site), rp_id.to_ascii_lowercase());
    if h.is_empty() {
        return false;
    }
    if !h.contains('.') {
        let h: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        return rp.rsplit('.').nth(1) == Some(h.as_str());
    }
    h == rp || h.ends_with(&format!(".{rp}")) || rp.ends_with(&format!(".{h}"))
}

pub fn client_hash(c: &ClientData, ty: &str) -> (Vec<u8>, Option<String>) {
    match c {
        ClientData::Hash(h) => (h.clone(), None),
        ClientData::Build { origin, challenge, cross_origin } => {
            let j = passkey::client_data_json(ty, challenge, origin, *cross_origin);
            (passkey::sha256(j.as_bytes()), Some(j))
        }
    }
}

/// Whether `entries` already hold one of the excluded credentials for this site.
pub fn is_excluded(entries: &[Entry], req: &CreateReq) -> bool {
    entries.iter().flat_map(|e| &e.passkeys).any(|p| p.rp_id == req.rp_id && req.exclude.contains(&p.credential_id))
}

/// Create the passkey in `entry` (or a new entry pushed to `entries` when `entry` is None).
pub fn create_in(entries: &mut Vec<Entry>, entry: Option<usize>, req: &CreateReq) -> Result<Reply, String> {
    let now = now_secs();
    let pk = Passkey::generate(&req.rp_id, &req.rp_name, &req.user_name, &req.user_display, &req.user_handle, now).map_err(|e| e.to_string())?;
    let auth_data = pk.registration_auth_data(true).map_err(|e| e.to_string())?;
    let public_spki = pk.public_spki().map_err(|e| e.to_string())?;
    let (_, client_data_json) = client_hash(&req.client, "webauthn.create");
    let reply = Reply::Created {
        credential_id: pk.credential_id.clone(),
        client_data_json,
        attestation_object: passkey::attestation_object(&auth_data),
        auth_data,
        public_spki,
    };
    let idx = match entry.filter(|&i| i < entries.len()) {
        Some(i) => i,
        None => {
            let mut e = Entry::blank();
            e.site = req.rp_id.clone();
            e.username = req.user_name.clone();
            e.updated = now;
            entries.push(e);
            entries.len() - 1
        }
    };
    entries[idx].passkeys.push(pk);
    Ok(reply)
}

/// Sign with passkey `p` of entry `e`.
pub fn assert_with(entries: &mut [Entry], e: usize, p: usize, req: &GetReq) -> Result<Reply, String> {
    let pk = entries.get_mut(e).and_then(|x| x.passkeys.get_mut(p)).ok_or("passkey")?;
    let (hash, client_data_json) = client_hash(&req.client, "webauthn.get");
    let auth_data = pk.assertion_auth_data(true);
    let signature = pk.sign(&auth_data, &hash).map_err(|e| e.to_string())?;
    pk.last_used = now_secs();
    Ok(Reply::Asserted {
        credential_id: pk.credential_id.clone(),
        client_data_json,
        auth_data,
        signature,
        user_handle: pk.user_handle.clone(),
        user_name: pk.user_name.clone(),
        user_display: pk.user_display.clone(),
    })
}

/// (entry, passkey) pairs usable for `req`.
pub fn candidates(entries: &[Entry], req: &GetReq) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        for (j, p) in e.passkeys.iter().enumerate() {
            if p.rp_id == req.rp_id && (req.allow.is_empty() || req.allow.contains(&p.credential_id)) {
                v.push((i, j));
            }
        }
    }
    v
}

// ---- extension wire format ----------------------------------------------------------------------

fn bytes(v: &Value) -> Option<Vec<u8>> {
    b64::decode(v.as_str()?)
}

fn str_of(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_owned()
}

fn ids(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().map(|a| a.iter().filter_map(|c| bytes(&c["id"])).collect()).unwrap_or_default()
}

/// Parse a request from the extension. `origin` comes from the browser itself (sender.origin).
pub fn from_extension(v: &Value) -> Result<Request, Value> {
    let err = |name: &str, msg: &str| json!({ "status": "error", "name": name, "message": msg });
    let origin = str_of(&v["origin"]);
    let host = passkey::origin_host(&origin).ok_or_else(|| err("SecurityError", "insecure origin"))?;
    let pk = &v["publicKey"];
    let challenge = bytes(&pk["challenge"]).filter(|c| !c.is_empty()).ok_or_else(|| err("TypeError", "challenge"))?;
    let client = ClientData::Build { origin: origin.clone(), challenge, cross_origin: v["crossOrigin"].as_bool().unwrap_or(false) };
    let check = |rp: String| if passkey::rp_id_allowed(&rp, &origin) { Ok(rp.to_ascii_lowercase()) } else { Err(err("SecurityError", "rp id")) };
    match v["type"].as_str() {
        Some("create") => {
            let rp_id = check(pk["rp"]["id"].as_str().map_or(host.clone(), str::to_owned))?;
            let es256 = pk["pubKeyCredParams"].as_array().is_some_and(|a| a.iter().any(|p| p["alg"].as_i64() == Some(passkey::ES256)));
            if !es256 {
                return Err(json!({ "status": "fallback" }));
            }
            let user_handle = bytes(&pk["user"]["id"]).filter(|u| !u.is_empty() && u.len() <= 64).ok_or_else(|| err("TypeError", "user.id"))?;
            Ok(Request::Create(CreateReq {
                rp_name: str_of(&pk["rp"]["name"]),
                user_name: str_of(&pk["user"]["name"]),
                user_display: str_of(&pk["user"]["displayName"]),
                user_handle,
                exclude: ids(&pk["excludeCredentials"]),
                rp_id,
                client,
            }))
        }
        Some("get") => {
            let rp_id = check(pk["rpId"].as_str().map_or(host.clone(), str::to_owned))?;
            Ok(Request::Get(GetReq { rp_id, allow: ids(&pk["allowCredentials"]), client }))
        }
        _ => Err(err("NotSupportedError", "type")),
    }
}

pub fn to_extension(r: &Reply) -> Value {
    match r {
        Reply::Created { credential_id, client_data_json, auth_data, attestation_object, public_spki } => json!({
            "status": "ok",
            "credential": {
                "id": b64::encode(credential_id),
                "response": {
                    "clientDataJSON": b64::encode(client_data_json.as_deref().unwrap_or_default().as_bytes()),
                    "attestationObject": b64::encode(attestation_object),
                    "authenticatorData": b64::encode(auth_data),
                    "publicKey": b64::encode(public_spki),
                    "publicKeyAlgorithm": passkey::ES256,
                    "transports": ["internal", "hybrid"],
                }
            }
        }),
        Reply::Asserted { credential_id, client_data_json, auth_data, signature, user_handle, .. } => json!({
            "status": "ok",
            "credential": {
                "id": b64::encode(credential_id),
                "response": {
                    "clientDataJSON": b64::encode(client_data_json.as_deref().unwrap_or_default().as_bytes()),
                    "authenticatorData": b64::encode(auth_data),
                    "signature": b64::encode(signature),
                    "userHandle": b64::encode(user_handle),
                }
            }
        }),
        Reply::Declined => json!({ "status": "fallback" }),
        Reply::Excluded => json!({ "status": "error", "name": "InvalidStateError", "message": "already registered" }),
        Reply::Error(m) => json!({ "status": "error", "name": "UnknownError", "message": m }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{DerSignature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    fn create_msg(origin: &str, rp: Option<&str>) -> Value {
        json!({
            "type": "create", "origin": origin,
            "publicKey": {
                "rp": { "id": rp, "name": "GitHub" },
                "user": { "id": b64::encode(b"user-1"), "name": "alice", "displayName": "Alice" },
                "challenge": b64::encode(b"challenge-1"),
                "pubKeyCredParams": [{ "type": "public-key", "alg": -8 }, { "type": "public-key", "alg": -7 }],
                "excludeCredentials": []
            }
        })
    }

    #[test]
    fn full_create_then_get_roundtrip_like_a_relying_party_checks_it() {
        let mut entries = vec![{
            let mut e = Entry::blank();
            e.site = "https://www.github.com/login".into();
            e
        }];
        let Request::Create(c) = from_extension(&create_msg("https://github.com", Some("github.com"))).unwrap() else { panic!() };
        assert!(site_matches(&entries[0].site, &c.rp_id));
        let r = create_in(&mut entries, Some(0), &c).unwrap();
        let Reply::Created { credential_id, client_data_json, public_spki, auth_data, .. } = &r else { panic!() };
        let cd: Value = serde_json::from_str(client_data_json.as_deref().unwrap()).unwrap();
        assert_eq!(cd["type"], "webauthn.create");
        assert_eq!(cd["origin"], "https://github.com");
        assert_eq!(cd["challenge"], b64::encode(b"challenge-1"));
        assert_eq!(&auth_data[55..87], &credential_id[..]);
        assert_eq!(entries[0].passkeys.len(), 1);

        let get = json!({ "type": "get", "origin": "https://github.com", "publicKey": { "rpId": "github.com", "challenge": b64::encode(b"challenge-2"), "allowCredentials": [] } });
        let Request::Get(g) = from_extension(&get).unwrap() else { panic!() };
        let found = candidates(&entries, &g);
        assert_eq!(found, vec![(0, 0)]);
        let Reply::Asserted { auth_data, signature, client_data_json, user_handle, .. } = assert_with(&mut entries, 0, 0, &g).unwrap() else { panic!() };
        assert_eq!(user_handle, b"user-1");
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&passkey::sha256(client_data_json.unwrap().as_bytes()));
        let vk = VerifyingKey::from_public_key_der(public_spki).unwrap();
        assert!(vk.verify(&msg, &DerSignature::try_from(signature.as_slice()).unwrap()).is_ok());
        assert!(entries[0].passkeys[0].last_used > 0);
        let out = to_extension(&r);
        assert_eq!(out["status"], "ok");
        assert_eq!(out["credential"]["response"]["publicKeyAlgorithm"], -7);
    }

    #[test]
    fn hostile_requests_are_refused() {
        assert!(from_extension(&create_msg("https://evil.com", Some("github.com"))).is_err(), "foreign rp id");
        assert!(from_extension(&create_msg("http://github.com", Some("github.com"))).is_err(), "plain http");
        assert!(from_extension(&create_msg("https://github.com", Some("com"))).is_err(), "top-level rp id");
        let mut m = create_msg("https://github.com", None);
        m["publicKey"]["pubKeyCredParams"] = json!([{ "type": "public-key", "alg": -257 }]);
        assert_eq!(from_extension(&m).err().unwrap()["status"], "fallback", "no ES256: browser handles it");
        let mut m = create_msg("https://github.com", None);
        m["publicKey"]["challenge"] = json!("");
        assert!(from_extension(&m).is_err());
        assert!(from_extension(&json!({ "type": "delete", "origin": "https://github.com", "publicKey": { "challenge": "AA" } })).is_err());
    }

    #[test]
    fn excluded_and_unknown_credentials() {
        let mut entries = Vec::new();
        let Request::Create(c) = from_extension(&create_msg("https://github.com", None)).unwrap() else { panic!() };
        create_in(&mut entries, None, &c).unwrap();
        assert_eq!(entries[0].site, "github.com");
        assert_eq!(entries[0].username, "alice");
        let mut again = c;
        again.exclude = vec![entries[0].passkeys[0].credential_id.clone()];
        assert!(is_excluded(&entries, &again));
        let g = GetReq { rp_id: "github.com".into(), allow: vec![vec![1, 2, 3]], client: ClientData::Hash(vec![0; 32]) };
        assert!(candidates(&entries, &g).is_empty());
        let other = GetReq { rp_id: "gitlab.com".into(), allow: vec![], client: ClientData::Hash(vec![0; 32]) };
        assert!(candidates(&entries, &other).is_empty());
    }

    #[test]
    fn site_matching() {
        assert!(site_matches("https://www.github.com/login", "github.com"));
        assert!(site_matches("github.com", "github.com"));
        assert!(site_matches("accounts.google.com", "google.com"));
        assert!(site_matches("google.com", "accounts.google.com"));
        assert!(!site_matches("notgithub.com", "github.com"));
        assert!(!site_matches("", "github.com"));
        assert!(site_matches("GitHub", "github.com"));
        assert!(site_matches("Google", "accounts.google.com"));
        assert!(!site_matches("GitLab", "github.com"));
    }
}
