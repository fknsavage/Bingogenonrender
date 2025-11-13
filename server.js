// server.js — Render + Resend + Stripe + (optional) Upstash Redis persistence

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

// --- Stripe init ---
const RAW_KEY = (process.env.STRIPE_API_KEY || "").trim();
const CLEAN_KEY = RAW_KEY.replace(/[\r\n\t\s]+/g, "");
const Stripe = require("stripe");
const stripe = new Stripe(CLEAN_KEY || "sk_test_dummy");
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
const SUPPORT_TO = process.env.SUPPORT_TO || "you@yourdomain.com";
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || "https://bingocardgen.com";

// ---------- Redis (optional) ----------
const url   = (process.env.UPSTASH_REDIS_REST_URL   || "").trim().replace(/\/+$/, "");
const token = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const USE_REDIS = !!(url && token);
const redis = USE_REDIS ? new Redis({ url, token }) : null; // ✅ single init

// Simple DB adapter: Redis if configured, otherwise in-memory Maps
const mem = { SESSIONS: new Map(), USERS: new Map(), C2E: new Map(), OTP: new Map(), PENDING: new Map() };

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
  },

  // --- Pending Stripe checkout session <-> email (24h TTL) ---
  async setPending(sessionId, email) {
    if (!sessionId || !email) return;
    if (redis) await redis.set(`PENDING:${sessionId}`, email, { ex: 24 * 3600 });
    else mem.PENDING.set(sessionId, { email, exp: Date.now() + 24 * 3600 * 1000 });
  },
  async getPending(sessionId) {
    if (redis) return await redis.get(`PENDING:${sessionId}`);
    const rec = mem.PENDING.get(sessionId);
    if (!rec) return null;
    if (rec.exp < Date.now()) { mem.PENDING.delete(sessionId); return null; }
    return rec.email;
  },
  async delPending(sessionId) {
    if (redis) await redis.del(`PENDING:${sessionId}`); else mem.PENDING.delete(sessionId);
  },

  // Safe PRO toggle helper (legacy)
  async setPro(email, on, customerId) {
    const key = (email || "").toLowerCase(); if (!key) return;
    const u = (await DB.getUser(key)) || { createdAt: Date.now(), pro: false, tickets: 0 };
    u.pro = !!on;
    if (customerId) u.stripe_customer = customerId;
    await DB.setUser(key, u);
  }
};

// ---------- High-level user helpers ----------
async function getOrCreateUser(email) {
  const key = (email || "").toLowerCase();
  if (!key) return null;
  let u = await DB.getUser(key);
  if (!u) {
    u = { createdAt: Date.now(), pro: false, tickets: 0 };
    await DB.setUser(key, u);
  } else if (typeof u.tickets !== "number") {
    u.tickets = 0;
    await DB.setUser(key, u);
  }
  return u;
}

async function getTickets(email) {
  const u = await getOrCreateUser(email);
  return u ? Number(u.tickets || 0) : 0;
}

async function creditTickets(email, amount) {
  if (!amount || amount <= 0) return;
  const key = (email || "").toLowerCase();
  const u = await getOrCreateUser(key);
  u.tickets = Number(u.tickets || 0) + amount;
  await DB.setUser(key, u);
  return u.tickets;
}

async function setPlan(email, plan) {
  const key = (email || "").toLowerCase();
  const u = await getOrCreateUser(key);
  u.plan = plan;
  if (plan) u.pro = true;
  await DB.setUser(key, u);
  return u;
}

// ---------- SKU maps for Store + Subs ----------
const STORE_SKUS = {
  "tickets-50": {
    price: process.env.STRIPE_PRICE_TICKETS_50,
    tickets: 50
  },
  "tickets-150": {
    price: process.env.STRIPE_PRICE_TICKETS_150,
    tickets: 150
  },
  "tickets-400": {
    price: process.env.STRIPE_PRICE_TICKETS_400,
    tickets: 400
  },
  "tickets-500": {
    price: process.env.STRIPE_PRICE_TICKETS_500,
    tickets: 500
  },
  "tickets-1200": {
    price: process.env.STRIPE_PRICE_TICKETS_1200,
    tickets: 1200
  }
};

const SUB_SKUS = {
  "creator-monthly": {
    price: process.env.STRIPE_PRICE_CREATOR,
    plan: "creator"
  },
  "prohost-monthly": {
    price: process.env.STRIPE_PRICE_PROHOST,
    plan: "prohost"
  },
  "lifetime": {
    price: process.env.STRIPE_PRICE_LIFETIME,
    plan: "lifetime"
  }
};

// ---------- App ----------
const app = express();

// ---- CORS (single, robust block) ----
app.set("trust proxy", 1);

const ALLOW = new Set([
  "https://bingocardgen.com",
  "https://www.bingocardgen.com",
  "https://api.bingocardgen.com",            // direct API access
  "https://bingogenonrender.onrender.com"    // Render fallback
]);

function isAllowed(origin) {
  if (!origin) return true; // curl/health/native apps
  try {
    const u = new URL(origin);
    if (ALLOW.has(origin)) return true;
    if (u.hostname.endsWith(".bingocardgen.pages.dev")) return true;
  } catch (_) {}
  return false;
}

app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (isAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "https://bingocardgen.com");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

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
        const metadata = s.metadata || {};
        const sku = metadata.sku || null;

        let email =
          (s.customer_details && s.customer_details.email) ||
          s.customer_email ||
          metadata.email ||
          "";

        const customerId = s.customer || "";

        if (!email) {
          console.warn("checkout.session.completed without email");
          break;
        }

        const key = email.toLowerCase();
        const u = await getOrCreateUser(key);

        // Map Stripe customer <-> email
        if (customerId) {
          u.stripe_customer = customerId;
          await DB.mapCustomer(customerId, key);
        }

        // 1) Ticket packs (STORE SKUs)
        if (sku && STORE_SKUS[sku]) {
          const pack = STORE_SKUS[sku];
          const added = Number(pack.tickets || 0);
          if (added > 0) {
            const newBal = await creditTickets(key, added);
            console.log(
              `🎟️ Ticket pack ${sku} -> +${added} tickets for ${key}, new balance=${newBal}`
            );
          }
        }
        // 2) Subscription / lifetime plans (SUB SKUs)
        else if (sku && SUB_SKUS[sku]) {
          const planCfg = SUB_SKUS[sku];
          await setPlan(key, planCfg.plan);
          console.log(`⭐ Plan '${planCfg.plan}' activated via checkout for ${key}`);
        }
        // 3) Legacy single PRO checkout (no SKU)
        else {
          u.pro = true;
          await DB.setUser(key, u);
          console.log("✅ Legacy PRO ON via checkout:", key, customerId || "");
        }

        break;
      }

      case "customer.subscription.updated": {
        const sub = event.data.object;
        const emailKey = await DB.emailByCustomer(sub.customer);
        if (emailKey) {
          const u = await getOrCreateUser(emailKey);
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
          const u = await getOrCreateUser(emailKey);
          u.pro = false;
          await DB.setUser(emailKey, u);
          console.log("🛑 PRO OFF (subscription.deleted)", emailKey);
        }
        break;
      }

      default:
        break;
    }

    res.json({ received: true });
  } catch (e) {
    console.error("Webhook handler error:", e);
    res.status(500).send("handler error");
  }
});

// JSON parser for all other routes (must come after raw webhook)
app.use(express.json());

// ✅ parse cookies for session reads
app.use(cookieParser(SESSION_SECRET));

// ---------- Helpers ----------
const randCode = () => String(Math.floor(100000 + Math.random() * 900000));

// Simple auth middleware (session cookie -> req.userEmail / req.user)
async function requireAuth(req, res, next) {
  try {
    const sid = req.cookies?.sid || "";
    const email = await DB.readSessionSid(sid);
    if (!email) {
      return res.status(401).json({ ok: false, error: "unauthenticated" });
    }
    const u = await getOrCreateUser(email);
    req.userEmail = email;
    req.user = u;
    next();
  } catch (e) {
    console.error("requireAuth error:", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
}

// ---------- Routes ----------

// Contact form: /api/contact
app.post("/api/contact", async (req, res) => {
  try {
    const { email, subject, message } = req.body || {};

    if (!message || typeof message !== "string" || !message.trim()) {
      return res.status(400).json({ ok: false, error: "message_required" });
    }

    const fromEmail =
      (email && String(email).trim()) || "no-email-provided@bingocardgen.com";
    const safeSubject =
      (subject && String(subject).trim()) || "BingoCardGen question or idea";

    if (!RESEND_API_KEY) {
      console.error("❌ /api/contact: Missing RESEND_API_KEY");
      return res.json({ ok: true, fallback: true });
    }

    const text =
      `From: ${fromEmail}\n` +
      `Subject: ${safeSubject}\n\n` +
      `${message}`;

    const payload = {
      from: SENDER_EMAIL,
      to: [SUPPORT_TO],
      subject: `[BCG Contact] ${safeSubject}`,
      text
    };

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!r.ok) {
      const body = await r.text();
      console.error("❌ Resend contact send failed:", body);
      return res.status(502).json({ ok: false, error: "provider_error" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("❌ /api/contact error:", err);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.get("/api/health", (_req, res) =>
  res.json({ ok: true, redis: !!redis, time: new Date().toISOString() })
);

// start OTP (with anti-double-send throttle)
app.post("/api/auth/otp/start", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
      return res.status(400).json({ ok: false, error: "bad_email" });

    // 1. Reuse existing valid OTP if present
    let code = await DB.getOTP(email);
    if (code) {
      console.log(`⏱️ Reusing existing valid OTP for ${email}: ${code}`);
    } else {
      code = randCode();
      await DB.setOTP(email, code, 300); // 5 min
      console.log(`✅ Generated new OTP for ${email}: ${code}`);
    }

    // ensure user record exists
    await getOrCreateUser(email);

    // 2. Throttle email sends
    const throttleKey = `OTP:SENT:${email}`;
    const recent = redis ? await redis.get(throttleKey) : mem.OTP.get(throttleKey);

    if (recent && RESEND_API_KEY) {
      console.log(`⏱️ Email send throttled for ${email}`);
      return res.json({ ok: true, sent: "throttled" });
    }

    if (redis) await redis.set(throttleKey, "1", { ex: 20 });
    else mem.OTP.set(throttleKey, { code: 1, exp: Date.now() + 20000 });

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
      body: JSON.stringify({ from: SENDER_EMAIL, to: [email], subject: "Your BingoCardGen sign-in code", html })
    });

    if (!resp.ok) {
      console.error("Resend send failed:", await resp.text());
      return res.status(500).json({ ok: false, error: "send_failed" });
    }

    res.json({ ok: true, sent: "email" });
  } catch (e) {
    console.error("❌ OTP start error:", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// verify OTP
app.post("/api/auth/otp/verify", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code  = String(req.body?.code  || "").trim();

    if (!email || !code) {
      console.warn("VERIFY missing_fields", { email, codeLen: code.length });
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    const stored = await DB.getOTP(email);
    console.log("VERIFY attempt", { email, code, stored });

    if (!stored) {
      console.warn("VERIFY expired_or_missing", { email });
      return res.status(400).json({ ok: false, error: "expired_or_missing" });
    }

    if (String(stored).trim() !== code) {
      console.warn("VERIFY invalid_code", { email, code, stored: String(stored).trim() });
      return res.status(400).json({ ok: false, error: "invalid_code" });
    }

    await DB.delOTP(email);

    const sid = await DB.newSession(email);
    res.cookie("sid", sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      maxAge: 14 * 24 * 3600 * 1000
    });

    const u = await getOrCreateUser(email);

    console.log("VERIFY success", { email, pro: !!u.pro });
    return res.json({ ok: true, user: { email, pro: !!u.pro } });
  } catch (e) {
    console.error("❌ OTP verify error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// session info
app.get("/api/me", async (req, res) => {
  const sid = req.cookies?.sid || "";
  const email = await DB.readSessionSid(sid);
  if (!email) return res.json({ authed: false });
  const u = await getOrCreateUser(email);
  res.json({ authed: true, email, pro: !!u.pro, plan: u.plan || null, tickets: Number(u.tickets || 0) });
});

// logout
app.post("/api/logout", async (req, res) => {
  const sid = req.cookies?.sid; if (sid) await DB.delSession(sid);
  res.clearCookie("sid", { httpOnly: true, sameSite: "lax", secure: true });
  res.json({ ok: true });
});

// ---------- Wallet route (for syncWalletFromServer) ----------
app.get("/api/wallet", requireAuth, async (req, res) => {
  try {
    const tickets = await getTickets(req.userEmail);
    res.json({ ok: true, tickets });
  } catch (e) {
    console.error("wallet get error", e);
    res.status(500).json({ ok: false, error: "wallet_failed" });
  }
});

// ---------- Optional Test Email Route ----------
if (ENABLE_TEST_ROUTES) {
  app.all("/api/test-email", async (req, res) => {
    const method = req.method.toUpperCase();
    const email =
      method === "GET"
        ? (req.query.email || "").toString().trim()
        : (req.body?.email || "").toString().trim();

    if (!email) {
      return res.status(400).send(
        `<div style="font-family:system-ui;padding:20px">
          <h3>✅ BingoCardGen Email Test</h3>
          <pre>GET  /api/test-email?email=you@bingocardgen.com</pre>
          <pre>POST /api/test-email {"email":"you@bingocardgen.com"}</pre>
        </div>`
      );
    }

    if (!RESEND_API_KEY) {
      return res.status(500).send("Missing RESEND_API_KEY");
    }

    const html = `
      <div style="font-family:system-ui,Arial,sans-serif;padding:20px;background:#0b1220;color:#eafaff;border-radius:10px">
        <h2>👋 BingoCardGen Email Test</h2>
        <p>Resend is working.</p>
        <p>From ${SENDER_EMAIL}</p>
      </div>`.trim();

    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: SENDER_EMAIL,
        to: [email],
        subject: "✅ BingoCardGen Resend Test",
        html
      })
    });

    if (!r.ok) {
      return res
        .status(500)
        .send(`<b>Resend failed:</b><pre>${await r.text()}</pre>`);
    }

    res.send(
      `<div style="font-family:system-ui;padding:20px">
         Email sent to <b>${email}</b> ✅
       </div>`
    );
  });
} else {
  app.all("/api/test-email", (_req, res) =>
    res.status(404).send("Not found")
  );
}

// --- Debug: verify Stripe connectivity (safe; returns only acct id) ---
if (ENABLE_TEST_ROUTES) {
  app.get("/api/debug/stripe", async (_req, res) => {
    try {
      const acct = await stripe.accounts.retrieve();
      res.json({ ok: true, account: acct.id });
    } catch (e) {
      console.error("Stripe debug error:", e);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}

// ---------- Stripe: Store ticket packs ----------
app.post("/api/stripe/store-checkout", requireAuth, async (req, res) => {
  try {
    const { sku } = req.body || {};
    const item = STORE_SKUS[sku];
    if (!item || !item.price) {
      return res.status(400).json({ ok: false, error: "unknown_sku" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: req.userEmail,
      line_items: [
        {
          price: item.price,
          quantity: 1
        }
      ],
      metadata: {
        email: req.userEmail,
        sku
      },
      success_url: `${FRONTEND_BASE_URL}/?store=success`,
      cancel_url: `${FRONTEND_BASE_URL}/?store=cancel`
    });

    await DB.setPending(session.id, req.userEmail);
    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("store checkout error", e);
    res.status(500).json({ ok: false, error: "checkout_failed" });
  }
});

// ---------- Stripe: Subscriptions (Creator / Pro Host / Lifetime) ----------
app.post("/api/stripe/subscribe", requireAuth, async (req, res) => {
  try {
    const { sku } = req.body || {};
    const sub = SUB_SKUS[sku];
    if (!sub || !sub.price) {
      return res.status(400).json({ ok: false, error: "unknown_sku" });
    }

    const isLifetime = sku === "lifetime";

    const session = await stripe.checkout.sessions.create({
      mode: isLifetime ? "payment" : "subscription",
      customer_email: req.userEmail,
      line_items: [
        {
          price: sub.price,
          quantity: 1
        }
      ],
      metadata: {
        email: req.userEmail,
        sku
      },
      success_url: `${FRONTEND_BASE_URL}/?pro=success`,
      cancel_url: `${FRONTEND_BASE_URL}/?pro=cancel`
    });

    await DB.setPending(session.id, req.userEmail);
    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("sub checkout error", e);
    res.status(500).json({ ok: false, error: "subscription_failed" });
  }
});

// ---------- Legacy Stripe Checkout (single PRO @ 10.99) ----------
app.post("/api/stripe/create-checkout", async (req, res) => {
  try {
    const sid = req.cookies?.sid;
    const email = sid
      ? await DB.readSessionSid(sid)
      : (req.body?.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ ok: false, error: "unauthenticated" });
    }

    await getOrCreateUser(email);

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: email,
      allow_promotion_codes: true,
      line_items: [
        {
          price_data: {
            currency: "cad",
            product_data: {
              name: "BingoCardGen PRO",
              description:
                "Unlimited themes, multipliers, ad-free printing, and batch tools. Billed monthly in Canadian dollars (CA$10.99).",
              images: ["https://bingocardgen.com/assets/logo-mini.png"]
            },
            unit_amount: 1099,
            recurring: { interval: "month" }
          },
          quantity: 1
        }
      ],
      success_url: `${FRONTEND_BASE_URL}/?pro=success&sid={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_BASE_URL}/?pro=cancel&sid={CHECKOUT_SESSION_ID}`,
      metadata: { email }
    });

    await DB.setPending(session.id, email);

    console.log("✅ Stripe session created:", email, session.id);
    return res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("❌ Stripe create-checkout error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Create a Stripe Billing Portal session
app.post("/api/stripe/portal", async (req, res) => {
  try {
    const sid = req.cookies?.sid;
    const email = sid && (await DB.readSessionSid(sid));
    if (!email) {
      return res.status(401).json({ ok: false, error: "unauthenticated" });
    }

    const u = await getOrCreateUser(email);
    if (!u?.stripe_customer) {
      return res.status(400).json({ ok: false, error: "no_customer" });
    }

    const portal = await stripe.billingPortal.sessions.create({
      customer: u.stripe_customer,
      return_url: FRONTEND_BASE_URL
    });

    return res.json({ ok: true, url: portal.url });
  } catch (e) {
    console.error("portal error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Force-check subscription state from Stripe (support tool)
app.post("/api/stripe/refresh-pro", async (req, res) => {
  try {
    const { email } = req.body || {};
    const key = (email || "").toLowerCase();
    if (!key) {
      return res.status(400).json({ ok: false, error: "bad_email" });
    }

    const u = await getOrCreateUser(key);
    if (!u?.stripe_customer) {
      return res.json({
        ok: true,
        updated: false,
        pro: !!u?.pro
      });
    }

    const subs = await stripe.subscriptions.list({
      customer: u.stripe_customer,
      status: "all",
      limit: 1
    });

    const sub = subs.data[0];
    const active =
      !!sub &&
      ["active", "trialing", "past_due"].includes(sub.status);

    u.pro = active;
    await DB.setUser(key, u);

    return res.json({
      ok: true,
      updated: true,
      pro: u.pro,
      status: sub?.status || "none"
    });
  } catch (e) {
    console.error("refresh-pro error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`BCG API listening on ${PORT} | Redis: ${USE_REDIS ? "ON" : "OFF"}`);
});