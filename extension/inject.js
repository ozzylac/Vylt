// Runs in the page (MAIN world): routes WebAuthn calls to Vylt, falls back to the browser.
(() => {
  if (!window.navigator.credentials || window.__vyltPasskeys) return;
  window.__vyltPasskeys = true;

  const creds = navigator.credentials;
  const nativeCreate = creds.create.bind(creds);
  const nativeGet = creds.get.bind(creds);

  const bytes = (v) => v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  const b64 = (v) => {
    let s = "";
    for (const c of bytes(v)) s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64 = (s) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };

  let seq = 0;
  const pending = new Map();
  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.__sv !== "res") return;
    const done = pending.get(e.data.id);
    if (done) {
      pending.delete(e.data.id);
      done(e.data.payload);
    }
  });
  const ask = (msg) => new Promise((resolve) => {
    const id = `${++seq}:${Math.random()}`;
    pending.set(id, resolve);
    window.postMessage({ __sv: "req", id, msg }, window.location.origin);
  });

  const list = (l) => (l || []).map((c) => ({ id: b64(c.id), type: c.type }));
  const encCreate = (pk) => ({
    rp: { id: pk.rp && pk.rp.id, name: pk.rp && pk.rp.name },
    user: { id: b64(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
    challenge: b64(pk.challenge),
    pubKeyCredParams: (pk.pubKeyCredParams || []).map((p) => ({ type: p.type, alg: p.alg })),
    excludeCredentials: list(pk.excludeCredentials),
  });
  const encGet = (pk) => ({
    rpId: pk.rpId,
    challenge: b64(pk.challenge),
    allowCredentials: list(pk.allowCredentials),
  });

  function credential(c, create) {
    const r = c.response;
    const response = { clientDataJSON: unb64(r.clientDataJSON) };
    if (create) {
      const ad = unb64(r.authenticatorData);
      const spki = unb64(r.publicKey);
      response.attestationObject = unb64(r.attestationObject);
      response.getAuthenticatorData = () => ad;
      response.getPublicKey = () => spki;
      response.getPublicKeyAlgorithm = () => r.publicKeyAlgorithm;
      response.getTransports = () => r.transports;
      Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    } else {
      response.authenticatorData = unb64(r.authenticatorData);
      response.signature = unb64(r.signature);
      response.userHandle = r.userHandle ? unb64(r.userHandle) : null;
      Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    }
    const extensions = create ? { credProps: { rk: true } } : {};
    const cred = {
      id: c.id,
      rawId: unb64(c.id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => extensions,
      toJSON: () => ({ id: c.id, rawId: c.id, type: "public-key", authenticatorAttachment: "platform", response: r, clientExtensionResults: extensions }),
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred;
  }

  async function route(kind, options, encode, fallback) {
    let answer = null;
    try {
      answer = await ask({ type: kind, publicKey: encode(options.publicKey) });
    } catch (_) {
      answer = null;
    }
    if (!answer || answer.status === "fallback") return fallback(options);
    if (answer.status === "error") throw new DOMException(answer.message || "Vylt", answer.name || "NotAllowedError");
    return credential(answer.credential, kind === "create");
  }

  creds.create = function (options) {
    if (!options || !options.publicKey) return nativeCreate(options);
    return route("create", options, encCreate, nativeCreate);
  };
  creds.get = function (options) {
    // Autofill (conditional) requests stay with the browser: Vylt only answers explicit ones.
    if (!options || !options.publicKey || options.mediation === "conditional") return nativeGet(options);
    return route("get", options, encGet, nativeGet);
  };
  if (window.PublicKeyCredential) {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = () => Promise.resolve(true);
  }
})();
