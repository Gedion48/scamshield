// ─────────────────────────────────────────────
// ScamShield — services/aiService.js
// Stable Gemini AI scam analysis
// ─────────────────────────────────────────────

const { GoogleGenerativeAI } = require("@google/generative-ai");

const GEMINI_KEY = process.env.GEMINI_API_KEY;

// Initialize Gemini safely
let model = null;

if (GEMINI_KEY) {
  const genAI = new GoogleGenerativeAI(GEMINI_KEY);

  model = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
  });
}

/**
 * Analyze a website for scam risk using Gemini AI.
 */
async function analyze({
  url,
  domain,
  title,
  bodyText,
  ruleSignals,
  ruleScore,
}) {

  // No Gemini key
  if (!GEMINI_KEY || !model) {

    console.log(
      "[AIService] No Gemini API key — using fallback"
    );

    return fallback({
      domain,
      ruleScore,
      ruleSignals,
    });
  }

  try {

    const prompt = buildPrompt({
      url,
      domain,
      title,
      bodyText,
      ruleSignals,
      ruleScore,
    });

    // Simple Gemini request (MOST STABLE)
    const result = await model.generateContent(prompt);

    const text = result.response.text();

    if (!text) {
      throw new Error("Empty Gemini response");
    }

    // Clean markdown wrappers
    const cleaned = text
      .replace(/```json/g, "")
      .replace(/```/g, "")
      .trim();

    // Debug output
    console.log("\n[Gemini RAW Response]");
    console.log(cleaned);

    // Extract JSON safely
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);

    if (!jsonMatch) {
      throw new Error("No JSON found in Gemini response");
    }

    let parsed;

    try {

      parsed = JSON.parse(jsonMatch[0]);

    } catch (jsonErr) {

      console.log("\n[AIService] Invalid JSON from Gemini");

      // Emergency cleanup
      const repaired = jsonMatch[0]
        .replace(/,\s*}/g, "}")
        .replace(/,\s*]/g, "]")
        .replace(/\n/g, " ")
        .trim();

      parsed = JSON.parse(repaired);
    }

    return validate(parsed);

  } catch (err) {

    console.warn(
      "[AIService] Gemini failed:",
      err.message,
      "— using fallback"
    );

    return fallback({
      domain,
      ruleScore,
      ruleSignals,
    });
  }
}

// ─────────────────────────────────────────────
// Prompt Builder
// ─────────────────────────────────────────────

function buildPrompt({
  url,
  domain,
  title,
  bodyText,
  ruleSignals,
  ruleScore,
}) {

  return `
You are a cybersecurity AI specialized in scam detection.

Analyze this website carefully.

Website Information:
URL: ${url}
Domain: ${domain}
Title: ${title || "none"}

Website Content Preview:
${(bodyText || "").substring(0, 1000)}

Detected Signals:
${ruleSignals.join(", ") || "none"}

Current Rule Score:
${ruleScore}/100

Check for:
- phishing
- fake login pages
- credential harvesting
- crypto scams
- investment fraud
- fake e-commerce
- impersonation
- job scams

IMPORTANT RULES:
- Return ONLY valid JSON
- No markdown
- No explanations outside JSON
- No code blocks

Return EXACTLY this format:

{
  "risk_score": 25,
  "risk_level": "LOW",
  "reasons": [
    "reason 1",
    "reason 2"
  ],
  "explanation": "short explanation"
}
`;
}

// ─────────────────────────────────────────────
// Validate AI response
// ─────────────────────────────────────────────

function validate(parsed) {

  const risk_score = Math.min(
    100,
    Math.max(
      0,
      Number(parsed.risk_score) || 0
    )
  );

  const risk_level =
    ["LOW", "MEDIUM", "HIGH"].includes(parsed.risk_level)
      ? parsed.risk_level
      : risk_score >= 65
      ? "HIGH"
      : risk_score >= 35
      ? "MEDIUM"
      : "LOW";

  const reasons = Array.isArray(parsed.reasons)
    ? parsed.reasons
        .filter((r) => typeof r === "string")
        .slice(0, 6)
    : [];

  const explanation =
    typeof parsed.explanation === "string"
      ? parsed.explanation
      : "AI analysis complete.";

  return {
    risk_score,
    risk_level,
    reasons,
    explanation,
  };
}

// ─────────────────────────────────────────────
// Intelligent fallback
// ─────────────────────────────────────────────

function fallback({
  domain,
  ruleScore,
  ruleSignals,
}) {

  const reasons = [];

  let aiBoost = 0;

  // Long domain
  if (domain.length > 28) {

    reasons.push(
      "Domain is unusually long"
    );

    aiBoost += 5;
  }

  // Numeric patterns
  if (/\d{5,}/.test(domain)) {

    reasons.push(
      "Suspicious numeric sequence detected in domain"
    );

    aiBoost += 5;
  }

  // Crypto patterns
  if (
    ruleSignals.some((s) =>
      /crypto|bitcoin|invest/i.test(s)
    )
  ) {

    reasons.push(
      "Cryptocurrency scam indicators detected"
    );

    aiBoost += 8;
  }

  // Phishing patterns
  if (
    ruleSignals.some((s) =>
      /phish|password|login|credential/i.test(s)
    )
  ) {

    reasons.push(
      "Potential phishing or credential harvesting indicators detected"
    );

    aiBoost += 10;
  }

  // Job scam patterns
  if (
    ruleSignals.some((s) =>
      /job|salary|hire|employ/i.test(s)
    )
  ) {

    reasons.push(
      "Potential fake job recruitment indicators detected"
    );

    aiBoost += 8;
  }

  // Multiple suspicious indicators
  if (
    ruleScore >= 50 &&
    ruleSignals.length >= 3
  ) {

    reasons.push(
      "Multiple suspicious indicators detected"
    );

    aiBoost += 5;
  }

  const finalScore = Math.min(
    100,
    ruleScore + aiBoost
  );

  let explanation;

  if (finalScore >= 65) {

    explanation =
      "This website shows several indicators commonly associated with scams or phishing attacks. Avoid sharing personal or financial information.";

  } else if (finalScore >= 35) {

    explanation =
      `Some suspicious characteristics were detected on "${domain}". Verify the legitimacy of the website before proceeding.`;

  } else {

    explanation =
      `"${domain}" does not currently show strong scam indicators, though standard internet safety practices are still recommended.`;
  }

  return {

    risk_score: finalScore,

    risk_level:
      finalScore >= 65
        ? "HIGH"
        : finalScore >= 35
        ? "MEDIUM"
        : "LOW",

    reasons,

    explanation,
  };
}

module.exports = {
  analyze,
};