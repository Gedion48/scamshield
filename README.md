# 🛡 ScamShield — AI Scam & Fake Detector

> A production-ready Chrome Extension powered by AI that analyzes any website in real time and detects scams, phishing pages, fake crypto platforms, and fraudulent job offers.

![ScamShield Demo](https://img.shields.io/badge/Status-Active-brightgreen) ![Version](https://img.shields.io/badge/Version-1.0.0-blue) ![License](https://img.shields.io/badge/License-MIT-purple) ![Node](https://img.shields.io/badge/Node.js-18%2B-green) ![Manifest](https://img.shields.io/badge/Manifest-V3-orange)

---
<img width="1341" height="619" alt="image" src="https://github.com/user-attachments/assets/a05bcd9d-857c-4a70-8040-29e647b5dc70" />
## 📸 Preview

The extension popup analyzes the current page and returns a risk score, detection signals, AI explanation, and a safety recommendation — all in under 3 seconds.

| Safe Site | Suspicious | Scam Detected |
|-----------|------------|---------------|
| 🟢 Score 0–34 | 🟡 Score 35–64 | 🔴 Score 65–100 |

---

## 🎯 What It Detects

| Threat Type | What It Looks For |
|-------------|-------------------|
| 🪙 **Crypto Scams** | Fake investment platforms, wallet address requests, unrealistic ROI claims |
| 🎣 **Phishing** | Fake login forms, credential harvesting, brand impersonation |
| 💼 **Job Scams** | Advance fee fraud, unrealistic salaries, "pay before work" patterns |
| 🛒 **Fake Websites** | Typosquatted domains, suspicious TLDs, missing HTTPS |
| ⚡ **Urgency Tactics** | "Act now", "Limited time", high-pressure language |

---

## 🏗 Architecture

```
User visits a website
        │
        ▼
content.js ──── extracts ────► URL, title, text, forms, keywords
        │
        ▼
popup.js ──── POST /analyze ──► Backend (localhost:3000)
                                        │
                              ┌─────────┴──────────┐
                              ▼                    ▼
                        riskEngine.js         aiService.js
                        (Rule-based)          (OpenAI GPT-4o-mini)
                              │                    │
                              └─────────┬──────────┘
                                        ▼
                                 Merged Score
                               (60% rules + 40% AI)
                                        │
                                        ▼
                            {score, risk, reasons,
                             explanation, recommendation}
                                        │
                                        ▼
                               popup.html renders UI
```

---

## 📁 Project Structure

```
scamshield/
│
├── extension/                  ← Chrome Extension (Manifest V3)
│   ├── manifest.json           ← Extension config
│   ├── popup.html              ← Extension UI
│   ├── popup.js                ← UI logic + API calls
│   ├── content.js              ← Page data extraction
│   ├── background.js           ← Service worker
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
├── backend/                    ← Node.js + Express API
│   ├── server.js               ← Entry point
│   ├── package.json
│   ├── .env.example            ← Environment template
│   ├── make-icons.js           ← Icon generator utility
│   ├── routes/
│   │   └── analyze.js          ← POST /analyze handler
│   ├── services/
│   │   ├── riskEngine.js       ← Rule-based detection engine
│   │   └── aiService.js        ← OpenAI integration + fallback
│   └── tests/
│       └── test.js             ← Automated test suite
│
└── README.md
```

---

## 🚀 Setup & Installation

### Prerequisites
- [Node.js](https://nodejs.org) v18 or higher
- Google Chrome browser
- OpenAI API key *(optional — works without it in mock mode)*

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/Gedion48/scamshield.git
cd scamshield
```

---

### Step 2 — Install backend dependencies

```bash
cd backend
npm install
```

---

### Step 3 — Configure environment

```bash
cp .env.example .env
```

Open `.env` and fill in your values:

```env
PORT=3000
OPENAI_API_KEY=sk-your-openai-key-here
```

> **Note:** The app works fully without an OpenAI key using intelligent mock mode. Add your key from [platform.openai.com](https://platform.openai.com/api-keys) for real AI-powered analysis.

---

### Step 4 — Generate extension icons

```bash
node make-icons.js
```

---

### Step 5 — Start the backend server

```bash
npm start
```

You should see:
```
🛡  ScamShield API  →  http://localhost:3000
   AI mode : OpenAI ✓
   Health  : http://localhost:3000/health
```

Verify it works by visiting: `http://localhost:3000/health`

---

### Step 6 — Load the extension in Chrome

1. Open Chrome and go to `chrome://extensions/`
2. Toggle **Developer mode** ON *(top-right corner)*
3. Click **Load unpacked**
4. Select the `scamshield/extension/` folder
5. Click the puzzle icon in Chrome toolbar → pin **ScamShield**

---

## 🧪 Testing

Run the automated test suite *(backend must be running)*:

```bash
node tests/test.js
```

Expected output:
```
🛡  ScamShield — Test Suite
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Server OK | AI: openai-connected

✅ PASS  🔴 Crypto Investment Scam   | Score: 100 | Risk: HIGH
✅ PASS  🔴 Phishing / Fake Bank     | Score: 74  | Risk: HIGH
✅ PASS  🟡 Suspicious Job Offer     | Score: 43  | Risk: MEDIUM
✅ PASS  🟢 Safe — BBC News          | Score: 0   | Risk: LOW
✅ PASS  🟢 Safe — Amazon            | Score: 0   | Risk: LOW

Results: 5/5 passed
```

---

## 📡 API Reference

### `POST /analyze`

Analyzes a webpage for scam risk.

**Request body:**
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "protocol": "https:",
  "title": "Page title",
  "description": "Meta description",
  "bodyText": "Visible page text (max 4000 chars)",
  "forms": [{ "action": "...", "method": "post", "inputTypes": ["text"] }],
  "passwordFields": 0,
  "hasCrypto": ["bitcoin", "wallet"],
  "hasUrgency": ["act now"]
}
```

**Response:**
```json
{
  "score": 82,
  "risk": "HIGH",
  "reasons": [
    "Crypto scam language: \"double your bitcoin\"",
    "Cryptocurrency wallet address found on page",
    "No HTTPS — connection is unencrypted"
  ],
  "explanation": "This website shows multiple signs of a crypto investment scam...",
  "recommendation": "🚨 DANGER: Never send cryptocurrency to unverified platforms."
}
```

### `GET /health`

Returns server status.

```json
{
  "status": "ok",
  "version": "1.0.0",
  "ai": "openai-connected",
  "time": "2025-01-01T00:00:00.000Z"
}
```

---

## 🧮 Risk Scoring System

| Category | Max Points | What's Checked |
|----------|-----------|----------------|
| Domain Analysis | 30 pts | HTTPS, TLD, typosquatting, brand impersonation |
| Content Analysis | 25 pts | Scam keywords, urgency tactics, ALL-CAPS abuse |
| Crypto Scam | 25 pts | Wallet addresses, ROI claims, deposit requests |
| Job Scam | 20 pts | Advance fees, unrealistic salaries, no experience |
| Phishing | 30 pts | Password fields, credential language, form hijacking |
| Blacklist | 30 pts | Known scam domain patterns |
| AI Analysis | 30 pts | OpenAI contextual reasoning (merged at 40% weight) |

**Final score = (Rules × 60%) + (AI × 40%), capped at 100**

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0 – 34 | 🟢 LOW | Site appears safe |
| 35 – 64 | 🟡 MEDIUM | Suspicious — verify before proceeding |
| 65 – 100 | 🔴 HIGH | Likely scam or phishing — avoid |

---

## 🔐 Security Features

- ✅ Rate limited — 30 requests/minute per IP
- ✅ CORS restricted to extension and localhost origins
- ✅ Helmet.js security headers
- ✅ Input validation and sanitization
- ✅ No user data stored — fully stateless
- ✅ 5-minute result cache in `chrome.storage.local`

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Extension | Chrome Manifest V3, Vanilla JS |
| Backend | Node.js, Express.js |
| AI | OpenAI GPT-4o-mini |
| Security | Helmet.js, express-rate-limit |
| Environment | dotenv |

---

## 🔮 Future Improvements

- [ ] Google Safe Browsing API integration
- [ ] VirusTotal domain reputation check
- [ ] Real WHOIS domain age lookup
- [ ] Automatic scan on page load
- [ ] Scan history panel
- [ ] Community scam reporting
- [ ] Export report as PDF

---

## ⚠️ Disclaimer

ScamShield is a tool to assist in identifying potentially fraudulent websites. It is not 100% accurate and should not be the sole basis for security decisions. Always exercise your own judgment and verify websites through official channels.

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Gedion48** — [github.com/Gedion48](https://github.com/Gedion48)

---

<p align="center">Built with ❤️ to make the internet safer</p>
