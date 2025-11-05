// server.js — Render + Resend + Stripe + (optional) Upstash Redis persistence

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const stripe = require("stripe")(process.env.STRIPE_API_KEY || "sk_test_dummy");
const { Redis } = require("@upstash/redis"); // ✅ correct CJS import for Upstash

// ---------- Crash visibility (helpful on Render) ----------
process.on("unhandledRejection", (r) => console.error("🚨 UnhandledRejection:", r));
process.on("uncaughtException", (e) => console.error("🚨 UncaughtException:", e));

// ---------- Config ----------
const PORT = process.env.PORT || 10000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";
const SENDER_EMAIL = process.env.SENDER_EMAIL || "BingoCardGen <no-reply@bingocardgen.com>";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const ENABLE_TEST_ROUTES = process.env.ENABLE_TEST_ROUTES === "1";

// ---------- Redis (optional) ----------
const url   = (process.env.UPSTASH_REDIS_REST_URL   || "").trim().replace(/\/+$/, "");
const token = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const USE_REDIS = !!(url && token);
const redis = USE_REDIS ? new Redis({ url, token }) : null; // ✅ single init

// Simple DB adapter: Redis if configured, otherwise in-memory Maps
const mem = { SESSIONS: new Map(), USERS: new Map(), C2E: new Map(), OTP: new Map() };
const DB = {
  // USERS
  async getUser(email) {
    if (!email) return null;
    if (redis) return await redis.get(`USER:${email}`);
    return mem.USERS.get(email) || null;
  },
  async setUser(email, obj) {
    if (!email) return;
    if (redis) await redis.set(`USER:${email}`, obj);
    else mem.USERS.set(email, obj);
  },

  // CustomerId <-> Email
  async mapCustomer(cusId, email) {
    if (!cusId || !email) return;
    if (redis) await redis.set(`C2E:${cusId}`, email);
    else mem.C2E.set(cusId, email);
  },
  async emailByCustomer(cusId) {
    if (redis) return await redis.get(`C2E:${cusId}`);
    return mem.C2E.get(cusId) || null;
  },

  // OTP (5 min TTL)
  async setOTP(email, code, ttlSec = 300) {
    if (redis) await redis.set(`OTP:${email}`, code, { ex: ttlSec });
    else mem.OTP.set(email, { code, exp: Date.now() + ttlSec * 1000 });
  },
  async getOTP(email) {
    if (redis) return await redis.get(`OTP:${email}`);
    const rec = mem.OTP.get(email);
    if (!rec) return null;
    if (rec.exp < Date.now()) { mem.OTP.delete(email); return null; }
    return rec.code;
  },
  async delOTP(email) {
    if (redis) await redis.del(`OTP:${email}`); else mem.OTP.delete(email);
  },

  // Sessions (14d TTL)
  async newSession(email) {
    const sidRaw = crypto.randomBytes(16).toString("hex");
    const sig = crypto.createHmac("sha256", SESSION_SECRET).update(sidRaw).digest("hex");
    const sid = `${sidRaw}.${sig}`;
    const ttlSec = 14 * 24 * 3600;
    if (redis) await redis.set(`SID:${sid}`, email, { ex: ttlSec });
    else mem.SESSIONS.set(sid, { email, exp: Date.now() + ttlSec * 1000 });
    return sid;
  },
  async readSessionSid(sid) {
    if (!sid) return null;
    if (redis) return await redis.get(`SID:${sid}`);
    const rec = mem.SESSIONS.get(sid);
    if (!rec) return null;
    if (rec.exp < Date.now()) { mem.SESSIONS.delete(sid); return null; }
    return rec.email;
  },
  async delSession(sid) {
    if (redis) await redis.del(`SID:${sid}`); else mem.SESSIONS.delete(sid);
  }
};

// ---------- App ----------
const app = express();

app.set('trust proxy', 1);

const ALLOW = new Set([
  'https://bingocardgen.com',
  'https://www.bingocardgen.com',
  // allow any CF Pages preview if you use them:
  // 'https://*.bingocardgen.pages.dev'  // (use a custom check for wildcard)
]);

function originOk(origin) {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    const host = u.hostname;
    if (ALLOW.has(origin)) return true;
    if (host.endsWith('.bingocardgen.pages.dev')) return true;
    return false;
  } catch { return false; }
}

const cors = require('cors');
app.use(cors({
  origin: (origin, cb) => originOk(origin) ? cb(null, true) : cb(new Error('CORS blocked')),
  credentials: true,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.options('*', cors());

// ---------- Stripe webhook (RAW body) ----------
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const whsec = process.env.STRIPE_WEBHOOK_SECRET;
  if (!whsec) return res.status(500).send("Webhook not configured");

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], whsec);
  } catch (err) {
    console.error("❌ Stripe signature verify failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const s = event.data.object;
        const email = (s.customer_details && s.customer_details.email) || s.customer_email || "";
        const customerId = s.customer || "";
        if (email) {
          const key = email.toLowerCase();
          const u = (await DB.getUser(key)) || { createdAt: Date.now(), pro: false };
          u.pro = true;
          if (customerId) { u.stripe_customer = customerId; await DB.mapCustomer(customerId, key); }
          await DB.setUser(key, u);
          console.log("✅ PRO ON via checkout:", key, customerId || "");
        } else {
          console.warn("checkout.session.completed without email");
        }
        break;
      }
      case "customer.subscription.updated": {
        const sub = event.data.object;
        const emailKey = await DB.emailByCustomer(sub.customer);
        if (emailKey) {
          const u = (await DB.getUser(emailKey)) || { createdAt: Date.now(), pro: false };
          const st = sub.status;
          u.pro = st === "active" || st === "trialing" || st === "past_due";
          await DB.setUser(emailKey, u);
          console.log(`🔁 PRO ${u.pro ? "ON" : "OFF"} (subscription.updated)`, emailKey, st);
        }
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const emailKey = await DB.emailByCustomer(sub.customer);
        if (emailKey) {
          const u = (await DB.getUser(emailKey)) || { createdAt: Date.now(), pro: false };
          u.pro = false;
          await DB.setUser(emailKey, u);
          console.log("🛑 PRO OFF (subscription.deleted)", emailKey);
        }
        break;
      }
      default: break;
    }
    res.json({ received: true });
  } catch (e) {
    console.error("Webhook handler error:", e);
    res.status(500).send("handler error");
  }
});

// JSON parser for all other routes (must come after raw webhook)
app.use(express.json());

// ---------- Helpers ----------
const randCode = () => String(Math.floor(100000 + Math.random() * 900000));

// ---------- Routes ----------
app.get("/api/health", (_req, res) =>
  res.json({ ok: true, redis: !!redis, time: new Date().toISOString() })
);

// start OTP
app.post("/api/auth/otp/start", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
      return res.status(400).json({ ok: false, error: "bad_email" });

    const code = randCode();
    await DB.setOTP(email, code, 300);

    const u = (await DB.getUser(email)) || { createdAt: Date.now(), pro: false };
    await DB.setUser(email, u);

    if (!RESEND_API_KEY) {
      console.log("🔐 OTP for", email, "=>", code);
      return res.json({ ok: true, sent: "log" });
    }

    const html = `
      <div style="font-family:system-ui,Arial,sans-serif;padding:18px;background:#0b1220;color:#eafaff;border-radius:12px">
        <h2 style="margin:0 0 8px">Your BingoCardGen Code</h2>
        <p style="font-size:18px;margin:0 0 14px"><b>${code}</b></p>
        <p style="opacity:.8;margin:0">This code expires in 5 minutes.</p>
      </div>`.trim();

    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: SENDER_EMAIL, to: [email], subject: "Your BingoCardGen sign-in code", html }),
    });
    if (!resp.ok) {
      console.error("Resend send failed:", await resp.text());
      return res.status(500).json({ ok: false, error: "send_failed" });
    }

    res.json({ ok: true, sent: "email" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// verify OTP
app.post("/api/auth/otp/verify", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();
  const stored = await DB.getOTP(email);
  if (!stored) return res.status(400).json({ ok: false, error: "expired_or_missing" });
  if (stored !== code) return res.status(400).json({ ok: false, error: "invalid_code" });

  await DB.delOTP(email);

  const sid = await DB.newSession(email);
  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 14 * 24 * 3600 * 1000 });

  const u = (await DB.getUser(email)) || { createdAt: Date.now(), pro: false };
  await DB.setUser(email, u);
  res.json({ ok: true, user: { email, pro: !!u.pro } });
});

// session info
app.get("/api/me", async (req, res) => {
  const sid = req.cookies?.sid || "";
  const email = await DB.readSessionSid(sid);
  if (!email) return res.json({ authed: false });
  const u = (await DB.getUser(email)) || { pro: false };
  res.json({ authed: true, email, pro: !!u.pro });
});

// logout
app.post("/api/logout", async (req, res) => {
  const sid = req.cookies?.sid; if (sid) await DB.delSession(sid);
  res.clearCookie("sid", { httpOnly: true, sameSite: "lax", secure: true });
  res.json({ ok: true });
});

// ---------- Optional Test Email Route ----------
if (ENABLE_TEST_ROUTES) {
  app.all("/api/test-email", async (req, res) => {
    const method = req.method.toUpperCase();
    const email = method === "GET" ? (req.query.email || "").toString().trim() : (req.body?.email || "").toString().trim();
    if (!email) return res.status(400).send(`<div style="font-family:system-ui;padding:20px">
      <h3>✅ BingoCardGen Email Test</h3>
      <pre>GET  /api/test-email?email=you@bingocardgen.com</pre>
      <pre>POST /api/test-email {"email":"you@bingocardgen.com"}</pre></div>`);
    if (!RESEND_API_KEY) return res.status(500).send("Missing RESEND_API_KEY");

    const html = `<div style="font-family:system-ui,Arial,sans-serif;padding:20px;background:#0b1220;color:#eafaff;border-radius:10px">
      <h2>👋 BingoCardGen Email Test</h2><p>Resend is working.</p><p>From ${SENDER_EMAIL}</p></div>`;

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: SENDER_EMAIL, to: [email], subject: "✅ BingoCardGen Resend Test", html }),
    });
    if (!r.ok) return res.status(500).send(`<b>Resend failed:</b><pre>${await r.text()}</pre>`);
    res.send(`<div style="font-family:system-ui;padding:20px">Email sent to <b>${email}</b> ✅</div>`);
  });
} else {
  app.all("/api/test-email", (_req, res) => res.status(404).send("Not found"));
}

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`BCG API listening on ${PORT} | Redis: ${USE_REDIS ? "ON" : "OFF"}`);
});