// Isolated world: relays the page's WebAuthn requests to the service worker and back.
window.addEventListener("message", (e) => {
  if (e.source !== window || !e.data || e.data.__sv !== "req") return;
  const { id, msg } = e.data;
  const reply = (payload) => window.postMessage({ __sv: "res", id, payload }, window.location.origin);
  chrome.runtime.sendMessage(msg).then(reply, () => reply({ status: "fallback" }));
});
