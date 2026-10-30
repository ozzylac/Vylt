// Service worker: adds the origin as the browser reports it (never what the page claims) and
// forwards the request to the Vylt app through native messaging.
const HOST = "com.vylt.passkeys";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const ok = sender.tab && sender.frameId === 0 && sender.origin && msg && (msg.type === "create" || msg.type === "get");
  if (!ok) {
    sendResponse({ status: "fallback" });
    return false;
  }
  const req = { type: msg.type, origin: sender.origin, crossOrigin: false, publicKey: msg.publicKey };
  chrome.runtime.sendNativeMessage(HOST, req).then(
    (r) => sendResponse(r || { status: "fallback" }),
    () => sendResponse({ status: "fallback" }),
  );
  return true;
});
