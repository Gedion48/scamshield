// ─────────────────────────────────────────────
//  ScamShield — services/riskEngine.js
//  Full rule-based detection engine
//  Returns: { score, reasons, explanation }
// ─────────────────────────────────────────────

// ══════════════════════════════════════════════
//  KEYWORD DICTIONARIES
// ══════════════════════════════════════════════

const SCAM_KW = [
  "guaranteed profit","guaranteed returns","guaranteed income",
  "double your money","triple your investment","10x your money",
  "instant withdrawal","instant profit","withdraw anytime",
  "100% profit","zero risk","risk-free investment","no risk",
  "easy money","make money fast","get rich quick",
  "passive income guaranteed","financial freedom now",
  "limited time offer","act now","act immediately",
  "offer expires today","today only","last chance",
  "don't miss this","claim your bonus","free money",
  "government grant","unclaimed funds","you have been selected",
  "you are a winner","congratulations you won","claim your prize",
  "verify your account","update your payment info",
  "your account will be suspended","confirm your identity",
  "unusual activity detected","unauthorized access detected",
];

const CRYPTO_SCAM_KW = [
  "deposit bitcoin","send eth","send bitcoin",
  "guaranteed roi","1000% return","500% profit","100x returns",
  "mining profit guaranteed","staking guaranteed returns",
  "buy crypto now guaranteed","elon musk crypto",
  "celebrity crypto giveaway","send crypto receive more",
  "double your bitcoin","btc doubler","eth giveaway",
  "crypto investment guaranteed","defi guaranteed profit",
];

const JOB_SCAM_KW = [
  "no experience required high salary","earn $5000 a week",
  "earn $10000 weekly","make $500 a day","make $1000 a day",
  "no interview required","immediate start no experience",
  "work from home $1000 daily","data entry earn thousands",
  "pay training fee","purchase starter kit",
  "buy your equipment","send money to get job",
  "registration fee required","processing fee required",
  "admin fee before employment",
];

const PHISHING_KW = [
  "enter your password","confirm your password",
  "reset your password","verify your email",
  "update your billing","payment details required",
  "enter card number","social security number",
  "bank account details","routing number",
  "wire transfer required",
];

const SUSPICIOUS_TLDS = [
  ".xyz",".top",".click",".link",".online",".site",
  ".tk",".cf",".ga",".gq",".ml",".pw",".cc",
  ".su",".info",".biz",".ws",
];

const TYPOSQUAT_PATTERNS = [
  "paypa1","paypall","payp4l",
  "g00gle","googl3","g0ogle",
  "amaz0n","amazom","amzon","amazone",
  "faceb00k","facebok","faceboook",
  "microso","microsofft","micros0ft",
  "app1e","aple","aplle",
  "netfl1x","netflx","netfflix",
  "1inkedin","linkedn","lnkedin",
  "twitterr","tw1tter","twiter",
  "instagramm","instagra","1nstagram",
  "binance0","binanc3","binnance",
  "coinbas3","coinbasee",
];

const SCAM_DOMAIN_WORDS = [
  "scam","phish","fraud","fake","spoof","clone","hack",
  "free-bitcoin","get-rich","double-btc","earn-crypto",
  "investment-profit","guaranteed-return","easy-money",
];

// ══════════════════════════════════════════════
//  MAIN ANALYZE FUNCTION
// ══════════════════════════════════════════════

function analyze(data) {
  const {
    url, domain, protocol, title, description,
    bodyText, forms, passwordFields,
    hasCrypto, hasUrgency, scriptText,
  } = data;

  const fullText  = `${title} ${description} ${bodyText}`.toLowerCase();
  const reasons   = [];
  let score       = 0;

  // ──────────────────────────────────────────
  //  A. DOMAIN ANALYSIS  (up to 30 pts)
  // ──────────────────────────────────────────

  // No HTTPS
  if (protocol !== "https:") {
    score += 15;
    reasons.push("No HTTPS — the connection is unencrypted and insecure");
  }

  // Suspicious TLD
  const tld = SUSPICIOUS_TLDS.find(t => domain.endsWith(t));
  if (tld) {
    score += 10;
    reasons.push(`Suspicious domain extension "${tld}" — commonly used by scam sites`);
  }

  // Typosquatting
  const typo = TYPOSQUAT_PATTERNS.find(p => domain.includes(p));
  if (typo) {
    score += 25;
    reasons.push(`Domain resembles a known brand (possible impersonation): "${domain}"`);
  }

  // Known brand name used in domain (not the real domain) — impersonation
  const KNOWN_BRANDS = ['paypal','google','amazon','facebook','microsoft','apple','netflix','linkedin','twitter','instagram','bankofamerica','citibank','chase','wellsfargo','binance','coinbase'];
  const brandInDomain = KNOWN_BRANDS.find(b => domain.includes(b));
  const isTrustedDomain = KNOWN_BRANDS.some(b => domain === b + '.com' || domain === 'www.' + b + '.com');
  if (brandInDomain && !isTrustedDomain) {
    score += 20;
    reasons.push(`Brand name "${brandInDomain}" used in non-official domain — likely impersonation`);
  }

  // Scam word in domain
  const scamWord = SCAM_DOMAIN_WORDS.find(w => domain.includes(w));
  if (scamWord) {
    score += 20;
    reasons.push(`Domain name contains a known scam keyword: "${scamWord}"`);
  }

  // IP address as domain
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    score += 20;
    reasons.push("Website uses a raw IP address instead of a domain name");
  }

  // Excessive hyphens (3+)
  const hyphens = (domain.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += 8;
    reasons.push(`Domain has ${hyphens} hyphens — common pattern in scam domains`);
  }

  // Deep subdomain chains (5+ levels)
  if (domain.split(".").length >= 5) {
    score += 7;
    reasons.push("Unusually complex domain structure — many subdomain levels");
  }

  // Letter-number substitution (l33t speak)
  if (/[a-z][0-9][a-z]/i.test(domain) || /[0-9][a-z][0-9]/i.test(domain)) {
    score += 8;
    reasons.push("Domain uses letter-number substitutions (e.g. 0 for O) — typosquatting signal");
  }

  // ──────────────────────────────────────────
  //  B. CONTENT ANALYSIS  (up to 25 pts)
  // ──────────────────────────────────────────

  const scamHits = SCAM_KW.filter(kw => fullText.includes(kw));
  if (scamHits.length > 0) {
    const pts = Math.min(20, scamHits.length * 4);
    score += pts;
    reasons.push(`Scam language detected: "${scamHits.slice(0,3).join('", "')}"`);
  }

  // Urgency tactics (from content script)
  if (Array.isArray(hasUrgency) && hasUrgency.length >= 2) {
    score += 10;
    reasons.push(`High-pressure urgency tactics: "${hasUrgency.slice(0,2).join('", "')}"`);
  } else if (Array.isArray(hasUrgency) && hasUrgency.length === 1) {
    score += 5;
    reasons.push(`Urgency tactic detected: "${hasUrgency[0]}"`);
  }

  // ALL-CAPS overuse
  const capsCount = (bodyText.match(/\b[A-Z]{4,}\b/g) || []).length;
  const wordCount = (bodyText.match(/\b\w+\b/g) || []).length || 1;
  if (capsCount / wordCount > 0.12 && capsCount > 8) {
    score += 6;
    reasons.push("Excessive ALL-CAPS text — common manipulation tactic in scam content");
  }

  // Excessive exclamation marks
  const excl = (bodyText.match(/!/g) || []).length;
  if (excl > 15) {
    score += 4;
    reasons.push(`Excessive exclamation marks (${excl} found) — high-pressure persuasion tactic`);
  }

  // ──────────────────────────────────────────
  //  C. CRYPTO SCAM  (up to 25 pts)
  // ──────────────────────────────────────────

  const cryptoScamHits = CRYPTO_SCAM_KW.filter(kw => fullText.includes(kw));
  if (cryptoScamHits.length > 0) {
    const pts = Math.min(20, cryptoScamHits.length * 6);
    score += pts;
    reasons.push(`Crypto scam language: "${cryptoScamHits.slice(0,2).join('", "')}"`);
  }

  // Wallet addresses in page/scripts
  const combined = bodyText + (scriptText || "");
  const ethWallets = combined.match(/0x[a-fA-F0-9]{40}/g) || [];
  const btcWallets = combined.match(/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/g) || [];
  if (ethWallets.length + btcWallets.length > 0) {
    score += 15;
    reasons.push("Cryptocurrency wallet address found on page — possible deposit request");
  }

  // Unrealistic ROI percentages
  const roiMatch = bodyText.match(/\b(\d{3,})\s*%\s*(profit|return|roi|gain|interest)/gi) || [];
  if (roiMatch.length > 0) {
    score += 15;
    reasons.push(`Unrealistic return claims: "${roiMatch[0]}" — no legitimate investment guarantees this`);
  }

  // Crypto signal words + scam context
  const cryptoRed = ["deposit","withdrawal","wallet","btc","eth"];
  const redFound  = Array.isArray(hasCrypto) ? hasCrypto.filter(w => cryptoRed.includes(w)) : [];
  if (redFound.length >= 2 && scamHits.length >= 1) {
    score += 10;
    reasons.push("Crypto transaction language combined with investment promises");
  }

  // ──────────────────────────────────────────
  //  D. JOB SCAM  (up to 20 pts)
  // ──────────────────────────────────────────

  const jobHits = JOB_SCAM_KW.filter(kw => fullText.includes(kw));
  if (jobHits.length > 0) {
    const pts = Math.min(20, jobHits.length * 6);
    score += pts;
    reasons.push(`Job scam patterns: "${jobHits.slice(0,2).join('", "')}"`);
  }

  // Unrealistic salary claims
  const salaryRx = /\$\s*(\d[\d,]*)\s*(per\s*(day|hour|week)|daily|hourly|weekly)/gi;
  const salaryMatches = bodyText.match(salaryRx) || [];
  for (const m of salaryMatches) {
    const n = parseInt(m.replace(/[^0-9]/g,""));
    const isHigh =
      (/day|daily/i.test(m)  && n > 500) ||
      (/hour/i.test(m)       && n > 80)  ||
      (/week/i.test(m)       && n > 5000);
    if (isHigh) {
      score += 10;
      reasons.push(`Suspiciously high salary claim: "${m.trim()}" — likely unrealistic`);
      break;
    }
  }

  // ──────────────────────────────────────────
  //  E. PHISHING DETECTION  (up to 30 pts)
  // ──────────────────────────────────────────

  if (passwordFields >= 1 && (score > 10 || protocol !== "https:")) {
    score += 20;
    reasons.push(`Password field on a ${protocol !== "https:" ? "non-HTTPS" : "suspicious"} site — possible credential harvesting`);
  }

  const phishHits = PHISHING_KW.filter(kw => fullText.includes(kw));
  if (phishHits.length > 0) {
    score += Math.min(15, phishHits.length * 5);
    reasons.push(`Credential-harvesting language: "${phishHits.slice(0,2).join('", "')}"`);
  }

  // Form submitting to external domain
  const extForms = Array.isArray(forms) ? forms.filter(f => {
    if (!f.action) return false;
    try {
      const actionHost = new URL(f.action).hostname;
      return actionHost && actionHost !== domain;
    } catch { return false; }
  }) : [];
  if (extForms.length > 0) {
    score += 15;
    reasons.push("Form sends data to an external domain — possible data theft");
  }

  // ──────────────────────────────────────────
  //  F. EXTERNAL / BLACKLIST CHECK (mock)
  // ──────────────────────────────────────────
  // In production: replace with Google Safe Browsing API / VirusTotal

  const MOCK_BLACKLIST = [
    "btc-profit","double-bitcoin","crypto-invest-now","earn-free-btc",
    "fast-profit","forex-guarantee","job-money-fast","hire-now-pay",
  ];
  if (MOCK_BLACKLIST.some(b => domain.includes(b))) {
    score += 30;
    reasons.push("Domain matches known scam blacklist pattern");
  }

  // ──────────────────────────────────────────
  //  Final score + explanation
  // ──────────────────────────────────────────
  score = Math.min(100, Math.max(0, score));

  return {
    score,
    reasons,
    explanation: buildExplanation(score, reasons, domain),
  };
}

function buildExplanation(score, reasons, domain) {
  if (reasons.length === 0) {
    return `"${domain}" passed all rule-based checks. No scam indicators found in the domain, content structure, or page behaviour.`;
  }
  if (score >= 65) {
    return `"${domain}" shows ${reasons.length} strong scam indicator(s). Our engine detected patterns consistent with fraudulent websites — including ${reasons.slice(0,2).map(r => r.split(" — ")[0].toLowerCase()).join(" and ")}. This site should NOT be trusted.`;
  }
  if (score >= 35) {
    return `"${domain}" has ${reasons.length} suspicious characteristic(s). While not definitively fraudulent, these signals are commonly associated with scam or low-quality sites. Verify through official sources before sharing any information.`;
  }
  return `"${domain}" has very minor signals (score: ${score}). These may be false positives on an otherwise legitimate site. Overall risk is low.`;
}

module.exports = { analyze };