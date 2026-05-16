// ─────────────────────────────────────────────
//  ScamShield — popup.js
//  Handles UI state, tab detection, API calls
// ─────────────────────────────────────────────

const API_URL = "http://localhost:3000/analyze";
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// ── DOM refs ──────────────────────────────────
const scanBtn      = document.getElementById("scanBtn");
const urlText      = document.getElementById("urlText");
const urlDot       = document.getElementById("urlDot");

const stIdle       = document.getElementById("state-idle");
const stLoading    = document.getElementById("state-loading");
const stError      = document.getElementById("state-error");
const stResults    = document.getElementById("state-results");

const loadingStep  = document.getElementById("loadingStep");
const errorMsg     = document.getElementById("errorMsg");

const riskBadge    = document.getElementById("riskBadge");
const badgeNum     = document.getElementById("badgeNum");
const badgeLabel   = document.getElementById("badgeLabel");
const riskVerdict  = document.getElementById("riskVerdict");
const riskUrl      = document.getElementById("riskUrl");
const scoreFill    = document.getElementById("scoreFill");
const reasonsList  = document.getElementById("reasonsList");
const explainBox   = document.getElementById("explainBox");
const recBox       = document.getElementById("recBox");
const footerStatus = document.getElementById("footerStatus");

// ── State ──────────────────────────────────────
let activeTab = null;

// ── Boot ───────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  showState("idle");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tab;

    const url = tab?.url || "";
    urlText.textContent = url || "Unknown page";
    urlDot.className = "url-dot " + (url.startsWith("https://") ? "secure" : "insecure");

    // Show cached result if available
    const cached = await getCache(url);
    if (cached) renderResults(cached);

  } catch (e) {
    urlText.textContent = "Could not detect page";
  }
});

// ── Scan button ────────────────────────────────
scanBtn.addEventListener("click", async () => {
  if (!activeTab) return;
  await runScan();
});

// ── Main scan pipeline ─────────────────────────
async function runScan() {
  scanBtn.disabled = true;
  showState("loading");
  setStep("Extracting page content…");

  try {
    // 1. Extract page data via injected function
    let pageData;
    try {
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        func: extractPageData,
      });
      pageData = result?.result;
    } catch (_) {
      // Fallback for restricted pages (chrome://, etc.)
      pageData = buildFallback(activeTab);
    }

    if (!pageData) throw new Error("Failed to extract page data.");

    // 2. Call backend
    setStep("Running AI analysis…");
    const res = await fetch(API_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(pageData),
      signal:  AbortSignal.timeout(30000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server error ${res.status}`);
    }

    const data = await res.json();

    // 3. Cache + display
    await setCache(activeTab.url, data);
    renderResults(data);
    setFooter("ok", "scanned just now");

  } catch (e) {
    showState("error");
    errorMsg.textContent = e.message || "Unknown error. Is the backend running?";
    setFooter("err", "scan failed");
  } finally {
    scanBtn.disabled = false;
  }
}

// ── Content script function (injected into page) ─
function extractPageData() {
  const url      = window.location.href;
  const domain   = window.location.hostname;
  const protocol = window.location.protocol;
  const title    = document.title || "";

  const getMeta = (name) =>
    document.querySelector(`meta[name="${name}"]`)?.content ||
    document.querySelector(`meta[property="${name}"]`)?.content || "";

  const description = getMeta("description") || getMeta("og:description");

  // Clean visible text
  const clone = document.body?.cloneNode(true);
  if (clone) {
    ["script","style","noscript","svg","iframe"].forEach(t =>
      clone.querySelectorAll(t).forEach(el => el.remove())
    );
  }
  const bodyText = (clone?.innerText || "").replace(/\s+/g," ").trim().substring(0, 4000);

  // Forms
  const forms = Array.from(document.forms).map(f => ({
    action: f.action || "",
    method: (f.method || "get").toLowerCase(),
    inputTypes: Array.from(f.elements).map(el => el.type || "text"),
  }));

  const passwordFields = document.querySelectorAll('input[type="password"]').length;

  // Crypto signals
  const txt = bodyText.toLowerCase();
  const CRYPTO_WORDS = ["bitcoin","ethereum","btc","eth","crypto","wallet","deposit","withdrawal","blockchain","defi","nft","token","staking","mining"];
  const URGENCY_WORDS = ["act now","limited time","expires soon","last chance","don't miss","today only","hurry","immediately","urgent","offer ends"];

  const hasCrypto  = CRYPTO_WORDS.filter(w => txt.includes(w));
  const hasUrgency = URGENCY_WORDS.filter(w => txt.includes(w));

  return { url, domain, protocol, title, description, bodyText, forms, passwordFields, hasCrypto, hasUrgency };
}

function buildFallback(tab) {
  const url = tab.url || "";
  let domain = "", protocol = "";
  try { const u = new URL(url); domain = u.hostname; protocol = u.protocol; } catch(_){}
  return { url, domain, protocol, title: tab.title || "", description: "", bodyText: "", forms: [], passwordFields: 0, hasCrypto: [], hasUrgency: [] };
}

// ── Render results ─────────────────────────────
function renderResults(data) {
  showState("results");

  const score = Math.min(100, Math.max(0, data.score || 0));
  const risk  = (data.risk || "LOW").toUpperCase();
  const cls   = riskClass(risk);

  // Badge
  badgeNum.textContent   = score;
  badgeLabel.textContent = risk;
  riskBadge.className    = `risk-badge ${cls}`;

  // Verdict
  riskVerdict.textContent = verdictText(risk, score);
  riskVerdict.className   = `risk-verdict ${cls}`;
  riskUrl.textContent     = activeTab?.url || "—";

  // Score bar (animate after tiny delay)
  setTimeout(() => {
    scoreFill.style.width = `${score}%`;
    scoreFill.className   = `score-fill ${cls}`;
  }, 60);

  // Reasons
  reasonsList.innerHTML = "";
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  if (reasons.length === 0) {
    reasonsList.innerHTML = `<div class="reason sev-low"><span class="reason-dot">✓</span><span class="reason-txt">No suspicious signals detected.</span></div>`;
  } else {
    reasons.forEach((r, i) => {
      const sev = i === 0 && score >= 65 ? "high" : i <= 1 && score >= 35 ? "medium" : "low";
      const dot = sev === "high" ? "🔴" : sev === "medium" ? "🟡" : "🟢";
      const div = document.createElement("div");
      div.className = `reason sev-${sev}`;
      div.innerHTML = `<span class="reason-dot">${dot}</span><span class="reason-txt">${esc(r)}</span>`;
      reasonsList.appendChild(div);
    });
  }

  // Explanation
  explainBox.textContent = data.explanation || "No explanation available.";

  // Recommendation
  recBox.className   = `rec-box ${cls}`;
  recBox.textContent = data.recommendation || defaultRec(risk);
}

// ── Helpers ────────────────────────────────────
function showState(s) {
  [stIdle, stLoading, stError, stResults].forEach(el => el.style.display = "none");
  const map = { idle: stIdle, loading: stLoading, error: stError, results: stResults };
  if (map[s]) map[s].style.display = s === "results" ? "flex" : "block";
}

function setStep(msg) { loadingStep.textContent = msg; }

function setFooter(type, msg) {
  footerStatus.className = `footer-status ${type}`;
  footerStatus.textContent = msg;
}

function riskClass(level) {
  return level === "HIGH" ? "high" : level === "MEDIUM" ? "medium" : "low";
}

function verdictText(level, score) {
  if (level === "HIGH")   return "⚠ High Risk — Likely Scam";
  if (level === "MEDIUM") return "⚡ Suspicious — Use Caution";
  return "✓ Appears Safe";
}

function defaultRec(level) {
  if (level === "HIGH")   return "🚨 Do NOT enter personal or financial info. Leave this site now.";
  if (level === "MEDIUM") return "⚠️ Proceed with caution. Verify through official channels first.";
  return "✅ This site appears safe. Standard internet safety still applies.";
}

function esc(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── Cache ──────────────────────────────────────
async function setCache(url, data) {
  try {
    await chrome.storage.local.set({ [`ss_${url}`]: { data, ts: Date.now() } });
  } catch(_){}
}

async function getCache(url) {
  try {
    const r = await chrome.storage.local.get(`ss_${url}`);
    const e = r[`ss_${url}`];
    if (e && Date.now() - e.ts < CACHE_TTL) return e.data;
  } catch(_){}
  return null;
}