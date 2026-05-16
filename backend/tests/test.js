// ─────────────────────────────────────────────
//  ScamShield — tests/test.js
//  Run: node tests/test.js  (server must be running)
// ─────────────────────────────────────────────

const BASE = "http://localhost:3000";

const TESTS = [
  {
    name:     "🔴 Crypto Investment Scam",
    expected: "HIGH",
    body: {
      url: "http://btc-profit-guaranteed.xyz/invest",
      domain: "btc-profit-guaranteed.xyz",
      protocol: "http:",
      title: "Guaranteed 500% Bitcoin Returns",
      description: "Double your bitcoin in 24 hours. Risk-free investment.",
      bodyText: "GUARANTEED 500% RETURNS! Act now — limited spots! Double your money! Send Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf. Instant withdrawal. Don't miss this offer! Free money!",
      forms: [{ action: "http://steal-data.ru/collect", method: "post", inputTypes: ["text","number"] }],
      passwordFields: 0,
      hasCrypto: ["bitcoin","btc","wallet","deposit","withdrawal"],
      hasUrgency: ["act now","limited time","today only"],
    },
  },
  {
    name:     "🔴 Phishing / Fake Bank",
    expected: "HIGH",
    body: {
      url: "https://secure-bankofamerica-login.online/verify",
      domain: "secure-bankofamerica-login.online",
      protocol: "https:",
      title: "Bank of America — Verify Account",
      description: "Unusual activity detected. Verify your identity now.",
      bodyText: "URGENT: Unusual activity detected on your account. Enter your password to confirm identity. Account will be suspended. Update billing information. Social security number required.",
      forms: [{ action: "https://secure-bankofamerica-login.online/submit", method: "post", inputTypes: ["text","password","text"] }],
      passwordFields: 1,
      hasCrypto: [],
      hasUrgency: ["immediately","urgent"],
    },
  },
  {
    name:     "🟡 Suspicious Job Offer",
    expected: "MEDIUM",
    body: {
      url: "https://jobs-work-from-home.site/apply",
      domain: "jobs-work-from-home.site",
      protocol: "https:",
      title: "Earn $5000 Weekly — No Experience",
      description: "Work from home. No interview required.",
      bodyText: "Earn $5000 a week! No experience required. No interview required. Immediate start. Pay training fee to begin. Purchase starter kit. Limited positions!",
      forms: [],
      passwordFields: 0,
      hasCrypto: [],
      hasUrgency: ["limited","don't miss"],
    },
  },
  {
    name:     "🟢 Safe — BBC News",
    expected: "LOW",
    body: {
      url: "https://www.bbc.com/news",
      domain: "www.bbc.com",
      protocol: "https:",
      title: "BBC News — World News",
      description: "Breaking news, analysis, and world news from the BBC.",
      bodyText: "Welcome to BBC News. World news, UK politics, business, science, technology, health and entertainment. Trusted journalism since 1922.",
      forms: [],
      passwordFields: 0,
      hasCrypto: [],
      hasUrgency: [],
    },
  },
  {
    name:     "🟢 Safe — Amazon",
    expected: "LOW",
    body: {
      url: "https://www.amazon.com/dp/B09G3HRMVS",
      domain: "www.amazon.com",
      protocol: "https:",
      title: "Amazon.com — Shop Electronics",
      description: "Millions of products with free delivery.",
      bodyText: "Add to Cart. Buy Now. Customer reviews. Free shipping on eligible orders. Secure checkout. Returns accepted within 30 days.",
      forms: [{ action: "https://www.amazon.com/checkout", method: "post", inputTypes: ["text"] }],
      passwordFields: 0,
      hasCrypto: [],
      hasUrgency: [],
    },
  },
];

// ── Runner ──────────────────────────────────────
async function run() {
  console.log("\n🛡  ScamShield — Test Suite");
  console.log("━".repeat(60));

  // Health check
  try {
    const h = await fetch(`${BASE}/health`);
    const d = await h.json();
    console.log(`✅ Server OK | AI: ${d.ai}\n`);
  } catch {
    console.error("❌  Cannot reach server. Run: cd backend && npm start");
    process.exit(1);
  }

  let pass = 0, fail = 0;

  for (const t of TESTS) {
    process.stdout.write(`Test: ${t.name}\n`);
    try {
      const t0  = Date.now();
      const res = await fetch(`${BASE}/analyze`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(t.body),
      });
      const d      = await res.json();
      const elapsed = Date.now() - t0;
      const ok      = d.risk === t.expected;

      if (ok) { pass++; console.log(`  ✅ PASS`); }
      else    { fail++; console.log(`  ❌ FAIL — expected ${t.expected}, got ${d.risk}`); }

      console.log(`  Score: ${d.score}/100 | Risk: ${d.risk} | Time: ${elapsed}ms`);
      console.log(`  Signals: ${d.reasons.length} | Top: ${(d.reasons[0]||"").substring(0,60)}`);
    } catch (e) {
      fail++;
      console.log(`  ❌ ERROR: ${e.message}`);
    }
    console.log();
  }

  console.log("━".repeat(60));
  console.log(`Results: ${pass}/${TESTS.length} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

run();