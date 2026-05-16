// ─────────────────────────────────────────────
//  ScamShield — server.js
//  Node.js + Express backend
// ─────────────────────────────────────────────

require("dotenv").config();

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");

const analyzeRoute = require("./routes/analyze");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Security ───────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: (origin, cb) => {
    // Allow Chrome extensions and localhost dev
    if (!origin || /chrome-extension:\/\//.test(origin) || /localhost/.test(origin)) {
      cb(null, true);
    } else {
      cb(new Error("CORS blocked"));
    }
  },
}));

// ── Body parsing ───────────────────────────────
app.use(express.json({ limit: "512kb" }));

// ── Rate limiting ──────────────────────────────
app.use("/analyze", rateLimit({
  windowMs: 60_000,
  max: 30,
  message: { error: "Too many requests — please slow down." },
}));

// ── Routes ─────────────────────────────────────
app.use("/analyze", analyzeRoute);

app.get("/health", (_req, res) => res.json({
  status:  "ok",
  version: "1.0.0",
  ai:      process.env.GEMINI_API_KEY ? "Gemini-connected" : "mock-mode",
  time:    new Date().toISOString(),
}));

// ── 404 ────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// ── Global error handler ───────────────────────
app.use((err, _req, res, _next) => {
  console.error("[ScamShield]", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ── Start ──────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡  ScamShield API  →  http://localhost:${PORT}`);
  console.log(`   AI mode : ${process.env.GEMINI_API_KEY ? "Gemini ✓" : "Mock (no GEMINI_API_KEY)"}`);
  console.log(`   Health  : http://localhost:${PORT}/health\n`);
});

module.exports = app;