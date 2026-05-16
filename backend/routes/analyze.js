// ─────────────────────────────────────────────
//  ScamShield — routes/analyze.js
//  POST /analyze  — orchestrates all detection
// ─────────────────────────────────────────────

const express     = require("express");
const router      = express.Router();
const riskEngine  = require("../services/riskEngine");
const aiService   = require("../services/aiService");

router.post("/", async (req, res) => {
  const t0 = Date.now();

  // ── 1. Validate input ──────────────────────
  const {
    url            = "",
    domain         = "",
    protocol       = "",
    title          = "",
    description    = "",
    bodyText       = "",
    forms          = [],
    passwordFields = 0,
    hasCrypto      = [],
    hasUrgency     = [],
    scriptText     = "",
  } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid url" });
  }

  let parsedUrl;
  try { parsedUrl = new URL(url); }
  catch { return res.status(400).json({ error: "Malformed URL" }); }

  const cleanDomain = domain || parsedUrl.hostname;
  console.log(`[ScamShield] Analyzing: ${cleanDomain}`);

  // ── 2. Rule-based engine ───────────────────
  const ruleResult = riskEngine.analyze({
    url: parsedUrl.href,
    domain: cleanDomain,
    protocol: protocol || parsedUrl.protocol,
    title,
    description,
    bodyText,
    forms: Array.isArray(forms) ? forms : [],
    passwordFields: Number(passwordFields) || 0,
    hasCrypto:  Array.isArray(hasCrypto)  ? hasCrypto  : [],
    hasUrgency: Array.isArray(hasUrgency) ? hasUrgency : [],
    scriptText,
  });

  // ── 3. AI analysis ─────────────────────────
  let aiResult = null;
  try {
    aiResult = await aiService.analyze({
      url: parsedUrl.href,
      domain: cleanDomain,
      title,
      bodyText: bodyText.substring(0, 1500),
      ruleSignals: ruleResult.reasons,
      ruleScore:   ruleResult.score,
    });
  } catch (e) {
    console.warn("[ScamShield] AI service failed:", e.message);
  }

  // ── 4. Merge scores ────────────────────────
  //   60 % rule-based + 40 % AI
  let finalScore   = ruleResult.score;
  let finalReasons = [...ruleResult.reasons];
  let finalExplain = ruleResult.explanation;

  if (aiResult) {
    finalScore = Math.round(ruleResult.score * 0.6 + aiResult.risk_score * 0.4);

    // Merge + deduplicate reasons (max 8)
    const seen = new Set();
    finalReasons = [...ruleResult.reasons, ...(aiResult.reasons || [])]
      .filter(r => { const k = r.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; })
      .slice(0, 8);

    finalExplain = aiResult.explanation || ruleResult.explanation;
  }

  finalScore = Math.min(100, Math.max(0, finalScore));

  // ── 5. Risk level ──────────────────────────
  const riskLevel =
    finalScore >= 65 ? "HIGH" :
    finalScore >= 35 ? "MEDIUM" : "LOW";

  // ── 6. Recommendation ──────────────────────
  const recommendation = buildRec(riskLevel, finalReasons);

  // ── 7. Respond ─────────────────────────────
  console.log(`[ScamShield] Done in ${Date.now()-t0}ms | score=${finalScore} | risk=${riskLevel}`);

  return res.json({
    score:          finalScore,
    risk:           riskLevel,
    reasons:        finalReasons,
    explanation:    finalExplain,
    recommendation,
    _meta: {
      domain:  cleanDomain,
      aiUsed:  aiResult !== null,
      elapsed: Date.now() - t0,
    },
  });
});

// ── Recommendation builder ─────────────────────
function buildRec(risk, reasons) {
  const hasPhishing = reasons.some(r => /phish|password|login|credential/i.test(r));
  const hasCrypto   = reasons.some(r => /crypto|bitcoin|deposit|wallet|invest/i.test(r));
  const hasJob      = reasons.some(r => /job|salary|hiring|employ/i.test(r));

  if (risk === "HIGH") {
    if (hasPhishing) return "🚨 DANGER: This looks like a phishing site. Do NOT enter any credentials. Close this tab immediately.";
    if (hasCrypto)   return "🚨 DANGER: This is likely a crypto scam. Never send cryptocurrency to unverified platforms.";
    if (hasJob)      return "🚨 DANGER: This looks like a job scam. Legitimate employers never charge fees before hiring.";
    return "🚨 DANGER: High scam probability. Do NOT share personal or financial information. Leave this site now.";
  }
  if (risk === "MEDIUM") {
    return "⚠️ CAUTION: Suspicious signals found. Verify this site through official sources before entering any information.";
  }
  return "✅ This site appears safe. Always verify URLs and avoid sharing sensitive information on unfamiliar sites.";
}

module.exports = router;