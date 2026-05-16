// ─────────────────────────────────────────────
//  ScamShield — content.js
//  Injected into every page, responds to messages
// ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "EXTRACT") {
    sendResponse(extractAll());
  }
  return true;
});

function extractAll() {
  const url      = window.location.href;
  const domain   = window.location.hostname;
  const protocol = window.location.protocol;
  const title    = document.title || "";

  // Meta tags
  const getMeta = n =>
    document.querySelector(`meta[name="${n}"]`)?.content ||
    document.querySelector(`meta[property="${n}"]`)?.content || "";

  const description = getMeta("description") || getMeta("og:description");
  const keywords    = getMeta("keywords");

  // Visible body text (strip tags, limit 4000 chars)
  const clone = document.body?.cloneNode(true);
  ["script","style","noscript","svg","iframe"].forEach(t =>
    clone?.querySelectorAll(t).forEach(el => el.remove())
  );
  const bodyText = (clone?.innerText || "").replace(/\s+/g," ").trim().substring(0, 4000);

  // All forms
  const forms = Array.from(document.forms).map(f => ({
    action:     f.action || "",
    method:     (f.method || "get").toLowerCase(),
    inputTypes: Array.from(f.elements).map(el => el.type || "text"),
    inputNames: Array.from(f.elements).map(el => (el.name || "").toLowerCase()),
  }));

  const passwordFields = document.querySelectorAll('input[type="password"]').length;

  // Inline scripts (for wallet address detection)
  const scriptText = Array.from(document.querySelectorAll("script:not([src])"))
    .map(s => s.textContent).join(" ").substring(0, 2000);

  // Crypto + urgency signal words
  const txt = (bodyText + " " + title).toLowerCase();
  const CRYPTO  = ["bitcoin","ethereum","btc","eth","crypto","wallet","deposit","withdrawal","blockchain","defi","nft","token","staking","mining","roi","invest"];
  const URGENCY = ["act now","limited time","expires soon","last chance","don't miss","today only","hurry","immediately","urgent","offer ends","while supplies"];
  const hasCrypto  = CRYPTO.filter(w  => txt.includes(w));
  const hasUrgency = URGENCY.filter(w => txt.includes(w));

  return {
    url, domain, protocol,
    title, description, keywords,
    bodyText, forms,
    passwordFields,
    scriptText,
    hasCrypto, hasUrgency,
    extractedAt: Date.now(),
  };
}