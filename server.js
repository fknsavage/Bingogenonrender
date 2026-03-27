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
const ADMIN_SUBSCRIBER_WHITELIST = [
  "fgrant042@gmail.com",
  "lynnbrandi1@icloud.com",
  "angie-angie2025@hotmail.com"
].map((email) => String(email || "").trim().toLowerCase());

// ---------- Redis (optional) ----------
const url   = (process.env.UPSTASH_REDIS_REST_URL   || "").trim().replace(/\/+$/, "");
const token = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const USE_REDIS = !!(url && token);
const redis = USE_REDIS ? new Redis({ url, token }) : null; // ✅ single init
let redisHealthy = USE_REDIS;

async function redisGetSafe(key) {
  if (!redis || !redisHealthy) return null;
  try {
    return await redis.get(key);
  } catch (err) {
    redisHealthy = false;
    console.error("Redis get failed, falling back to memory:", err?.message || err);
    return null;
  }
}

async function redisSetSafe(key, value, options) {
  if (!redis || !redisHealthy) return false;
  try {
    await redis.set(key, value, options);
    return true;
  } catch (err) {
    redisHealthy = false;
    console.error("Redis set failed, falling back to memory:", err?.message || err);
    return false;
  }
}

async function redisDelSafe(key) {
  if (!redis || !redisHealthy) return false;
  try {
    await redis.del(key);
    return true;
  } catch (err) {
    redisHealthy = false;
    console.error("Redis del failed, falling back to memory:", err?.message || err);
    return false;
  }
}

function isWhitelistedSubscriber(email) {
  const key = String(email || "").trim().toLowerCase();
  return !!key && ADMIN_SUBSCRIBER_WHITELIST.includes(key);
}

function applyWhitelistedSubscriberOverride(email, user) {
  if (!user || !isWhitelistedSubscriber(email)) return user;
  user.pro = true;
  user.subscription_status = "active";
  user.renews_at = null;
  return user;
}

// Simple DB adapter: Redis if configured, otherwise in-memory Maps
const mem = {
  SESSIONS: new Map(),
  USERS:    new Map(),
  C2E:      new Map(),
  OTP:      new Map(),
  PENDING:  new Map(),
  DAILY:    new Map()   // 👈 daily reward claims when Redis is off
};

const DB = {
  // USERS
  async getUser(email) {
    if (!email) return null;
    const fromRedis = await redisGetSafe(`USER:${email}`);
    if (fromRedis) return fromRedis;
    return mem.USERS.get(email) || null;
  },
  async setUser(email, obj) {
    if (!email) return;
    obj = applyWhitelistedSubscriberOverride(email, obj);
    const saved = await redisSetSafe(`USER:${email}`, obj);
    if (!saved) mem.USERS.set(email, obj);
  },

  // CustomerId <-> Email
  async mapCustomer(cusId, email) {
    if (!cusId || !email) return;
    const saved = await redisSetSafe(`C2E:${cusId}`, email);
    if (!saved) mem.C2E.set(cusId, email);
  },
  async emailByCustomer(cusId) {
    const fromRedis = await redisGetSafe(`C2E:${cusId}`);
    if (fromRedis) return fromRedis;
    return mem.C2E.get(cusId) || null;
  },
  async unmapCustomer(cusId) {
    if (!cusId) return;
    const deleted = await redisDelSafe(`C2E:${cusId}`);
    if (!deleted) mem.C2E.delete(cusId);
  },

  // OTP (5 min TTL)
  async setOTP(email, code, ttlSec = 300) {
    const saved = await redisSetSafe(`OTP:${email}`, code, { ex: ttlSec });
    if (!saved) mem.OTP.set(email, { code, exp: Date.now() + ttlSec * 1000 });
  },
  async getOTP(email) {
    const fromRedis = await redisGetSafe(`OTP:${email}`);
    if (fromRedis) return fromRedis;
    const rec = mem.OTP.get(email);
    if (!rec) return null;
    if (rec.exp < Date.now()) { mem.OTP.delete(email); return null; }
    return rec.code;
  },
  async delOTP(email) {
    const deleted = await redisDelSafe(`OTP:${email}`);
    if (!deleted) mem.OTP.delete(email);
  },

  // Sessions (14d TTL)
  async newSession(email) {
    const sidRaw = crypto.randomBytes(16).toString("hex");
    const sig = crypto.createHmac("sha256", SESSION_SECRET).update(sidRaw).digest("hex");
    const sid = `${sidRaw}.${sig}`;
    const ttlSec = 14 * 24 * 3600;
    const saved = await redisSetSafe(`SID:${sid}`, email, { ex: ttlSec });
    if (!saved) mem.SESSIONS.set(sid, { email, exp: Date.now() + ttlSec * 1000 });
    return sid;
  },
  async readSessionSid(sid) {
    if (!sid) return null;
    const fromRedis = await redisGetSafe(`SID:${sid}`);
    if (fromRedis) return fromRedis;
    const rec = mem.SESSIONS.get(sid);
    if (!rec) return null;
    if (rec.exp < Date.now()) { mem.SESSIONS.delete(sid); return null; }
    return rec.email;
  },
  async delSession(sid) {
    const deleted = await redisDelSafe(`SID:${sid}`);
    if (!deleted) mem.SESSIONS.delete(sid);
  },

  // --- Pending Stripe checkout session <-> email (24h TTL) ---
  async setPending(sessionId, email) {
    if (!sessionId || !email) return;
    const saved = await redisSetSafe(`PENDING:${sessionId}`, email, { ex: 24 * 3600 });
    if (!saved) mem.PENDING.set(sessionId, { email, exp: Date.now() + 24 * 3600 * 1000 });
  },
  async getPending(sessionId) {
    const fromRedis = await redisGetSafe(`PENDING:${sessionId}`);
    if (fromRedis) return fromRedis;
    const rec = mem.PENDING.get(sessionId);
    if (!rec) return null;
    if (rec.exp < Date.now()) { mem.PENDING.delete(sessionId); return null; }
    return rec.email;
  },
  async delPending(sessionId) {
    const deleted = await redisDelSafe(`PENDING:${sessionId}`);
    if (!deleted) mem.PENDING.delete(sessionId);
  },

  // Safe PRO toggle helper (legacy)
  async setPro(email, on, customerId) {
    const key = (email || "").toLowerCase(); if (!key) return;
    const u = (await DB.getUser(key)) || { createdAt: Date.now(), pro: false, tickets: 0 };
    u.pro = !!on;
    if (customerId) u.stripe_customer = customerId;
    applyWhitelistedSubscriberOverride(key, u);
    await DB.setUser(key, u);
  }
};

const CARD_CATALOG = {
  betty: { slug: "betty", name: "Betty Boop", priceCents: 0, priceDisplay: "Demo", free: true },
  breakfast: { slug: "breakfast", name: "Breakfast Club", priceCents: 0, priceDisplay: "Demo", free: true },
  puppy: { slug: "puppy", name: "Puppy Party", priceCents: 0, priceDisplay: "Demo", free: true },
  ghostface: { slug: "ghostface", name: "Ghostface Bingo", priceCents: 499, priceDisplay: "$4.99", free: false },
  casinofortune: { slug: "casinofortune", name: "Casino Fortune", priceCents: 499, priceDisplay: "$4.99", free: false },
  annabelle: { slug: "annabelle", name: "Annabelle Bingo", priceCents: 499, priceDisplay: "$4.99", free: false },
  chucky: { slug: "chucky", name: "Playtime Gone Wrong", priceCents: 499, priceDisplay: "$4.99", free: false },
  freddyvsjason: { slug: "freddyvsjason", name: "Freddy Vs Jason", priceCents: 499, priceDisplay: "$4.99", free: false },
  crimescene: { slug: "crimescene", name: "Crime Scene", priceCents: 499, priceDisplay: "$4.99", free: false },
  pennywise: { slug: "pennywise", name: "Pennywise Bingo", priceCents: 499, priceDisplay: "$4.99", free: false },
  badsanta: { slug: "badsanta", name: "Bad Santa Bingo", priceCents: 399, priceDisplay: "$3.99", free: false },
  drunkelfs: { slug: "drunkelfs", name: "Drunk Elfs Bingo", priceCents: 399, priceDisplay: "$3.99", free: false },
  elegantwineandcheesenight: { slug: "elegantwineandcheesenight", name: "Elegant Wine & Cheese Night", priceCents: 499, priceDisplay: "$4.99", free: false },
  glamorouspinkluxury: { slug: "glamorouspinkluxury", name: "Glamorous Pink Luxury", priceCents: 499, priceDisplay: "$4.99", free: false },
  reindeers: { slug: "reindeers", name: "Gangster Reindeers Bingo", priceCents: 399, priceDisplay: "$3.99", free: false },
  grinch: { slug: "grinch", name: "Grinch Bingo", priceCents: 399, priceDisplay: "$3.99", free: false },
  luxuriousfashion: { slug: "luxuriousfashion", name: "Luxurious Fashion", priceCents: 499, priceDisplay: "$4.99", free: false },
  louisvuitton: { slug: "louisvuitton", name: "Louis Vuitton", priceCents: 499, priceDisplay: "$4.99", free: false },
  cheech: { slug: "cheech", name: "Up In Smoke", priceCents: 499, priceDisplay: "$4.99", free: false },
  titanic: { slug: "titanic", name: "Titanic", priceCents: 499, priceDisplay: "$4.99", free: false }
};

const FREE_DEMO_SLUGS = new Set(["breakfast", "puppy"]);

function normalizeOwnedCards(input) {
  const raw = Array.isArray(input) ? input : [];
  const seen = new Set();
  const out = [];
  raw.forEach((slug) => {
    const key = String(slug || "").trim().toLowerCase();
    if (!CARD_CATALOG[key] || CARD_CATALOG[key].free || seen.has(key)) return;
    seen.add(key);
    out.push(key);
  });
  return out;
}

function normalizeCardSelection(input) {
  const raw = Array.isArray(input) ? input : [];
  const seen = new Set();
  const out = [];
  raw.forEach((slug) => {
    const key = String(slug || "").trim().toLowerCase();
    if (!CARD_CATALOG[key] || CARD_CATALOG[key].free || seen.has(key)) return;
    seen.add(key);
    out.push(key);
  });
  return out;
}

function normalizeFavoriteCards(input) {
  const raw = Array.isArray(input) ? input : [];
  const seen = new Set();
  const out = [];
  raw.forEach((slug) => {
    const key = String(slug || "").trim().toLowerCase();
    if (!CARD_CATALOG[key] || seen.has(key)) return;
    seen.add(key);
    out.push(key);
  });
  return out;
}

// ---------- High-level user helpers ----------
async function getOrCreateUser(email) {
  const key = (email || "").toLowerCase();
  if (!key) return null;

  let u = await DB.getUser(key);

  if (!u) {
    u = {
      createdAt: Date.now(),
      pro: false,
      tickets: 0,
      lastDaily: null,
      dailyStreak: 0,
      owned_cards: [],
      favorite_cards: [],
      subscription_status: "none",
      renews_at: null,
      current_sid: null
    };
  } else {
    if (typeof u.tickets !== "number") u.tickets = 0;
    if (typeof u.dailyStreak !== "number") u.dailyStreak = 0;
    if (!("lastDaily" in u)) u.lastDaily = null;
    u.owned_cards = normalizeOwnedCards(u.owned_cards);
    u.favorite_cards = normalizeFavoriteCards(u.favorite_cards);
    if (!("subscription_status" in u)) u.subscription_status = u.pro ? "active" : "none";
    if (!("renews_at" in u)) u.renews_at = null;
    if (!("current_sid" in u)) u.current_sid = null;
  }

  applyWhitelistedSubscriberOverride(key, u);
  await DB.setUser(key, u);
  return u;
}

function isMissingStripeCustomerError(err, customerId) {
  return (
    !!customerId &&
    err?.code === "resource_missing" &&
    (err?.param === "customer" ||
      err?.resource === "customer" ||
      String(err?.message || "").toLowerCase().includes("no such customer"))
  );
}

async function clearStaleStripeCustomer(email, customerId, user) {
  const key = (email || "").trim().toLowerCase();
  if (!key || !customerId) return null;

  const u = user || (await getOrCreateUser(key));
  if (!u) return null;

  if (u.stripe_customer === customerId) {
    delete u.stripe_customer;
  }
  u.pro = false;
  u.subscription_status = "none";
  u.renews_at = null;

  await DB.setUser(key, u);
  await DB.unmapCustomer(customerId);

  console.log(`Cleared stale Stripe customer for ${key}`);
  return u;
}

async function getOrCreateStripeCustomer(email, user) {
  const key = (email || "").trim().toLowerCase();
  if (!key) return null;

  const u = user || (await getOrCreateUser(key));
  if (!u) return null;

  if (u.stripe_customer) {
    return { customerId: u.stripe_customer, user: u };
  }

  const customer = await stripe.customers.create({ email: key });
  u.stripe_customer = customer.id;
  await DB.setUser(key, u);
  await DB.mapCustomer(customer.id, key);

  return { customerId: customer.id, user: u };
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

// ---------- Daily Reward helpers + streak ----------
function todayKey() {
  return new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
}

function parseYmd(str) {
  if (!str) return null;
  const [y, m, d] = String(str).split("-").map((x) => parseInt(x, 10));
  if (!y || !m || !d) return null;
  return new Date(y, m - 1, d);
}

function daysBetween(a, b) {
  const da = parseYmd(a);
  const db = parseYmd(b);
  if (!da || !db) return Infinity;
  da.setHours(0, 0, 0, 0);
  db.setHours(0, 0, 0, 0);
  return Math.round((db - da) / 86400000);
}

async function hasClaimedDaily(email) {
  const day = todayKey();
  const key = `DAILY:${email}:${day}`;

  if (redisHealthy) {
    const v = await redisGetSafe(key);
    return !!v;
  }

  return mem.DAILY.has(key);
}

async function markClaimedDaily(email) {
  const day = todayKey();
  const key = `DAILY:${email}:${day}`;

  if (redisHealthy) {
    // 26h TTL just to be safe with timezones
    const saved = await redisSetSafe(key, "1", { ex: 26 * 3600 });
    if (saved) return;
  }
  mem.DAILY.set(key, Date.now());
}

async function setPlan(email, plan) {
  const key = (email || "").toLowerCase();
  const u = await getOrCreateUser(key);
  u.plan = plan;
  if (plan) u.pro = true;
  applyWhitelistedSubscriberOverride(key, u);
  await DB.setUser(key, u);
  return u;
}

async function addOwnedCards(email, cards) {
  const key = (email || "").toLowerCase();
  const selection = normalizeCardSelection(cards);
  if (!key || !selection.length) return [];
  const u = await getOrCreateUser(key);
  const owned = new Set(normalizeOwnedCards(u.owned_cards));
  selection.forEach((slug) => owned.add(slug));
  u.owned_cards = Array.from(owned);
  await DB.setUser(key, u);
  return u.owned_cards;
}

async function getOwnedCards(email) {
  const u = await getOrCreateUser(email);
  return normalizeOwnedCards(u?.owned_cards);
}

async function addFavoriteCard(email, slug) {
  const key = (email || "").toLowerCase();
  const theme = normalizeFavoriteCards([slug]);
  if (!key || !theme.length) return [];
  const u = await getOrCreateUser(key);
  const saved = new Set(normalizeFavoriteCards(u.favorite_cards));
  saved.add(theme[0]);
  u.favorite_cards = Array.from(saved);
  await DB.setUser(key, u);
  return u.favorite_cards;
}

async function removeFavoriteCard(email, slug) {
  const key = (email || "").toLowerCase();
  const u = await getOrCreateUser(key);
  const saved = new Set(normalizeFavoriteCards(u.favorite_cards));
  saved.delete(String(slug || "").trim().toLowerCase());
  u.favorite_cards = Array.from(saved);
  await DB.setUser(key, u);
  return u.favorite_cards;
}

async function getFavoriteCards(email) {
  const u = await getOrCreateUser(email);
  return normalizeFavoriteCards(u?.favorite_cards);
}

async function rotateSingleSession(email) {
  const key = (email || "").toLowerCase();
  const u = await getOrCreateUser(key);
  const priorSid = u.current_sid || "";
  if (priorSid) {
    await DB.delSession(priorSid);
  }
  const sid = await DB.newSession(key);
  u.current_sid = sid;
  await DB.setUser(key, u);
  return { sid, user: u };
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

// ---- Simple News storage (Redis if available, else in-memory) ----
const NEWS_REDIS_KEY = "BCG:NEWS_JSON";

// Default fallback if nothing saved yet
let NEWS_FALLBACK = [
  {
    date: "2025-11-10",
    emoji: "🎄",
    title: "Xmas pack in testing",
    body: "Drunk Elves, Reindeer Bingo & Grinch Boards.",
    tag: "themes"
  },
  {
    date: "2025-11-11",
    emoji: "💳",
    title: "Billing & invoices",
    body: "Pro billing + PDF invoice history syncing to one login.",
    tag: "system"
  },
  {
    date: "2025-11-12",
    emoji: "🚀",
    title: "Glass Gateway UI",
    body: "Glass Gateway UI live in sandbox — Accounts moving to /account.",
    tag: "devlog"
  }
];

async function readNewsFeed() {
  try {
    if (redisHealthy) {
      const stored = await redisGetSafe(NEWS_REDIS_KEY);
      if (stored && Array.isArray(stored)) {
        return stored;
      }
    }
  } catch (e) {
    console.error("news read error:", e);
  }
  return NEWS_FALLBACK;
}

async function writeNewsFeed(items) {
  // keep a local fallback as well
  NEWS_FALLBACK = items;
  if (!redisHealthy) return;
  try {
    await redisSetSafe(NEWS_REDIS_KEY, items);
  } catch (e) {
    console.error("news write error:", e);
  }
}

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
        const checkoutKind = metadata.kind || "legacy";
        const cardSlugs = normalizeCardSelection(String(metadata.cards || "").split(","));

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
        if (checkoutKind === "cards" && cardSlugs.length) {
          const ownedCards = await addOwnedCards(key, cardSlugs);
          console.log(`🃏 Card checkout completed for ${key}:`, ownedCards.join(", "));
        }
        else if (sku && STORE_SKUS[sku]) {
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
          const u2 = await setPlan(key, planCfg.plan);
          u2.subscription_status = "active";
          if (sku === "lifetime") u2.renews_at = null;
          await DB.setUser(key, u2);
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
          u.subscription_status = st || "none";
          u.renews_at = sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
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
          u.subscription_status = sub.status || "canceled";
          u.renews_at = null;
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
    if (!u.current_sid || u.current_sid !== sid) {
      if (sid) await DB.delSession(sid);
      return res.status(401).json({ ok: false, error: "session_replaced" });
    }
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
      console.log(`⏱️ Reusing existing valid OTP for ${email}`);
    } else {
      code = randCode();
      await DB.setOTP(email, code, 300); // 5 min
      console.log(`✅ Generated new OTP for ${email}`);
    }

    // ensure user record exists
    await getOrCreateUser(email);

    // 2. Throttle email sends
    const throttleKey = `OTP:SENT:${email}`;
    const recent = redisHealthy ? await redisGetSafe(throttleKey) : mem.OTP.get(throttleKey);

    if (recent && RESEND_API_KEY) {
      console.log(`⏱️ Email send throttled for ${email}`);
      return res.json({ ok: true, sent: "throttled" });
    }

    if (redisHealthy) {
      const saved = await redisSetSafe(throttleKey, "1", { ex: 20 });
      if (!saved) mem.OTP.set(throttleKey, { code: 1, exp: Date.now() + 20000 });
    } else {
      mem.OTP.set(throttleKey, { code: 1, exp: Date.now() + 20000 });
    }

    if (!RESEND_API_KEY) {
      console.log("🔐 OTP generated for", email);
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
    if (!stored) {
      console.warn("VERIFY expired_or_missing", { email });
      return res.status(400).json({ ok: false, error: "expired_or_missing" });
    }

    if (String(stored).trim() !== code) {
      console.warn("VERIFY invalid_code", { email });
      return res.status(400).json({ ok: false, error: "invalid_code" });
    }

    await DB.delOTP(email);

    const { sid, user } = await rotateSingleSession(email);
    res.cookie("sid", sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      maxAge: 14 * 24 * 3600 * 1000
    });

    console.log("VERIFY success", { email, pro: !!user.pro });
    return res.json({ ok: true, user: { email, pro: !!user.pro } });
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
  if (!u.current_sid || u.current_sid !== sid) {
    if (sid) await DB.delSession(sid);
    return res.json({ authed: false });
  }
  res.json({
    authed: true,
    email,
    pro: !!u.pro,
    plan: u.plan || null,
    subscription_status: u.subscription_status || (u.pro ? "active" : "none"),
    renews_at: u.renews_at || null,
    tickets: Number(u.tickets || 0),
    owned_cards: normalizeOwnedCards(u.owned_cards),
    favorite_cards: normalizeFavoriteCards(u.favorite_cards)
  });
});

// logout
app.post("/api/logout", async (req, res) => {
  const sid = req.cookies?.sid;
  if (sid) {
    const email = await DB.readSessionSid(sid);
    if (email) {
      const u = await getOrCreateUser(email);
      if (u.current_sid === sid) {
        u.current_sid = null;
        await DB.setUser(email, u);
      }
    }
    await DB.delSession(sid);
  }
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

app.get("/api/me/library", requireAuth, async (req, res) => {
  try {
    const favorites = await getFavoriteCards(req.userEmail);
    res.json({
      ok: true,
      email: req.userEmail,
      favorite_cards: favorites,
      demo_cards: Object.values(CARD_CATALOG).filter((card) => card.free).map((card) => card.slug)
    });
  } catch (e) {
    console.error("library get error", e);
    res.status(500).json({ ok: false, error: "library_failed" });
  }
});

app.post("/api/me/library", requireAuth, async (req, res) => {
  try {
    const slug = String(req.body?.slug || "").trim().toLowerCase();
    const action = String(req.body?.action || "add").trim().toLowerCase();
    if (!CARD_CATALOG[slug]) {
      return res.status(400).json({ ok: false, error: "invalid_theme" });
    }

    const u = await getOrCreateUser(req.userEmail);
    let favoriteCards = [];
    if (action === "remove") {
      favoriteCards = await removeFavoriteCard(req.userEmail, slug);
    } else {
      if (!u.pro && !FREE_DEMO_SLUGS.has(slug)) {
        return res.status(402).json({ ok: false, error: "subscription_required" });
      }
      favoriteCards = await addFavoriteCard(req.userEmail, slug);
    }

    return res.json({ ok: true, favorite_cards: favoriteCards });
  } catch (e) {
    console.error("library update error", e);
    res.status(500).json({ ok: false, error: "library_failed" });
  }
});

// ---------- Daily Reward (GET status / POST claim) ----------
const DAILY_REWARD_AMOUNT = 15;  // base per day
const DAILY_STREAK_TARGET = 7;   // bonus every 7th day
const DAILY_STREAK_BONUS  = 50;  // bonus tickets on that day

// Status (for UI)
app.get("/api/reward/daily", requireAuth, async (req, res) => {
  try {
    const claimed = await hasClaimedDaily(req.userEmail);
    const u = await getOrCreateUser(req.userEmail);

    const today = todayKey();
    const last  = u.lastDaily || null;
    const streak = Number(u.dailyStreak || 0);

    const diff = last ? daysBetween(last, today) : Infinity;
    let effectiveStreak = streak;

    // if they've missed a day, streak would reset next claim
    if (diff > 1) effectiveStreak = 0;

    const nextStep = (DAILY_STREAK_TARGET - (effectiveStreak || 0));
    const nextBonusIn = nextStep <= 0 ? DAILY_STREAK_TARGET : nextStep;

    res.json({
      ok: true,
      claimed,
      amount: DAILY_REWARD_AMOUNT,
      streak: effectiveStreak,
      bonusTarget: DAILY_STREAK_TARGET,
      nextBonusIn
    });
  } catch (e) {
    console.error("/api/reward/daily GET error:", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Claim
app.post("/api/reward/daily", requireAuth, async (req, res) => {
  try {
    // hard anti double-claim for the calendar day
    const already = await hasClaimedDaily(req.userEmail);
    if (already) {
      return res
        .status(409)
        .json({ ok: false, error: "already_claimed" });
    }

    const u = await getOrCreateUser(req.userEmail);
    const today = todayKey();
    const last  = u.lastDaily || null;
    const prevStreak = Number(u.dailyStreak || 0);

    const diff = last ? daysBetween(last, today) : Infinity;

    // streak maths:
    //  - same day is blocked above by hasClaimedDaily
    //  - diff == 1 -> consecutive day, streak+1
    //  - otherwise -> new streak starting at 1
    let newStreak;
    if (!last || diff > 1) {
      newStreak = 1;
    } else if (diff === 1) {
      newStreak = prevStreak + 1;
    } else {
      // diff == 0 is protected by already-claimed guard, but keep safe:
      newStreak = prevStreak || 1;
    }

    // base reward
    const base = DAILY_REWARD_AMOUNT;
    let bonus = 0;

    // if they *hit* the target today, pay bonus & reset streak to 0 so
    // they can start a fresh 7-day run
    if (newStreak >= DAILY_STREAK_TARGET) {
      bonus = DAILY_STREAK_BONUS;
      newStreak = 0;
    }

    const totalEarned = base + bonus;

    // credit tickets
    const newBalance = await creditTickets(req.userEmail, totalEarned);

    // update user streak meta
    u.lastDaily   = today;
    u.dailyStreak = newStreak;
    await DB.setUser(req.userEmail.toLowerCase(), u);

    // mark as claimed for today
    await markClaimedDaily(req.userEmail);

    res.json({
      ok: true,
      claimed: true,
      amount: base,
      bonus,
      totalEarned,
      streak: newStreak,
      tickets: newBalance
    });
  } catch (e) {
    console.error("/api/reward/daily POST error:", e);
    res.status(500).json({ ok: false, error: "server_error" });
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

    const { customerId } = await getOrCreateStripeCustomer(req.userEmail);

    let session;
    try {
      session = await stripe.checkout.sessions.create({
        mode: "payment",
        customer: customerId,
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
    } catch (e) {
      if (isMissingStripeCustomerError(e, customerId)) {
        await clearStaleStripeCustomer(req.userEmail, customerId);
        const fresh = await getOrCreateStripeCustomer(req.userEmail);
        session = await stripe.checkout.sessions.create({
          mode: "payment",
          customer: fresh.customerId,
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
      } else {
        throw e;
      }
    }

    await DB.setPending(session.id, req.userEmail);
    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("store checkout error", e);
    res.status(500).json({ ok: false, error: "checkout_failed" });
  }
});

app.post("/api/stripe/cards-checkout", requireAuth, async (req, res) => {
  try {
    const requested = normalizeCardSelection(req.body?.cards);
    if (!requested.length) {
      return res.status(400).json({ ok: false, error: "no_cards" });
    }

    const alreadyOwned = new Set(await getOwnedCards(req.userEmail));
    const checkoutCards = requested.filter((slug) => !alreadyOwned.has(slug));
    if (!checkoutCards.length) {
      return res.status(400).json({ ok: false, error: "already_owned" });
    }

    const line_items = checkoutCards.map((slug) => {
      const card = CARD_CATALOG[slug];
      return {
        price_data: {
          currency: "usd",
          product_data: {
            name: `${card.name} Digital Bingo Card`,
            description: "Tablet-first Caller 15x5 digital bingo card.",
            images: [`${FRONTEND_BASE_URL}/assets/themes/${slug}.png`]
          },
          unit_amount: card.priceCents
        },
        quantity: 1
      };
    });

    const { customerId } = await getOrCreateStripeCustomer(req.userEmail);

    let session;
    try {
      session = await stripe.checkout.sessions.create({
        mode: "payment",
        customer: customerId,
        allow_promotion_codes: true,
        line_items,
        metadata: {
          email: req.userEmail,
          kind: "cards",
          cards: checkoutCards.join(",")
        },
        success_url: `${FRONTEND_BASE_URL}/beta.html?checkout=success`,
        cancel_url: `${FRONTEND_BASE_URL}/beta.html?checkout=cancel`
      });
    } catch (e) {
      if (isMissingStripeCustomerError(e, customerId)) {
        await clearStaleStripeCustomer(req.userEmail, customerId);
        const fresh = await getOrCreateStripeCustomer(req.userEmail);
        session = await stripe.checkout.sessions.create({
          mode: "payment",
          customer: fresh.customerId,
          allow_promotion_codes: true,
          line_items,
          metadata: {
            email: req.userEmail,
            kind: "cards",
            cards: checkoutCards.join(",")
          },
          success_url: `${FRONTEND_BASE_URL}/beta.html?checkout=success`,
          cancel_url: `${FRONTEND_BASE_URL}/beta.html?checkout=cancel`
        });
      } else {
        throw e;
      }
    }

    await DB.setPending(session.id, req.userEmail);
    res.json({ ok: true, url: session.url, cards: checkoutCards });
  } catch (e) {
    console.error("cards checkout error", e);
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

    const { customerId } = await getOrCreateStripeCustomer(req.userEmail);

    let session;
    try {
      session = await stripe.checkout.sessions.create({
        mode: isLifetime ? "payment" : "subscription",
        customer: customerId,
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
        success_url: `${FRONTEND_BASE_URL}/beta.html?subscribe=success`,
        cancel_url: `${FRONTEND_BASE_URL}/beta.html?subscribe=cancel`
      });
    } catch (e) {
      if (isMissingStripeCustomerError(e, customerId)) {
        await clearStaleStripeCustomer(req.userEmail, customerId);
        const fresh = await getOrCreateStripeCustomer(req.userEmail);
        session = await stripe.checkout.sessions.create({
          mode: isLifetime ? "payment" : "subscription",
          customer: fresh.customerId,
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
          success_url: `${FRONTEND_BASE_URL}/beta.html?subscribe=success`,
          cancel_url: `${FRONTEND_BASE_URL}/beta.html?subscribe=cancel`
        });
      } else {
        throw e;
      }
    }

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

    const { customerId } = await getOrCreateStripeCustomer(email);

    let session;
    try {
      session = await stripe.checkout.sessions.create({
        mode: "subscription",
        payment_method_types: ["card"],
        customer: customerId,
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
    } catch (e) {
      if (isMissingStripeCustomerError(e, customerId)) {
        await clearStaleStripeCustomer(email, customerId);
        const fresh = await getOrCreateStripeCustomer(email);
        session = await stripe.checkout.sessions.create({
          mode: "subscription",
          payment_method_types: ["card"],
          customer: fresh.customerId,
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
      } else {
        throw e;
      }
    }

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

    let portal;
    try {
      portal = await stripe.billingPortal.sessions.create({
        customer: u.stripe_customer,
        return_url: FRONTEND_BASE_URL
      });
    } catch (e) {
      if (isMissingStripeCustomerError(e, u.stripe_customer)) {
        await clearStaleStripeCustomer(email, u.stripe_customer, u);
        return res.status(400).json({ ok: false, error: "no_customer" });
      }
      throw e;
    }

    return res.json({ ok: true, url: portal.url });
  } catch (e) {
    console.error("portal error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Force-check subscription state from Stripe (support tool)
app.post("/api/stripe/refresh-pro", requireAuth, async (req, res) => {
  try {
    const key = (req.userEmail || "").toLowerCase();

    const u = await getOrCreateUser(key);
    if (!u?.stripe_customer) {
      return res.json({
        ok: true,
        updated: false,
        pro: !!u?.pro
      });
    }

    let subs;
    try {
      subs = await stripe.subscriptions.list({
        customer: u.stripe_customer,
        status: "all",
        limit: 1
      });
    } catch (e) {
      if (isMissingStripeCustomerError(e, u.stripe_customer)) {
        const cleared = await clearStaleStripeCustomer(key, u.stripe_customer, u);
        return res.json({
          ok: true,
          updated: true,
          pro: false,
          status: cleared?.subscription_status || "none",
          renews_at: null
        });
      }
      throw e;
    }

    const sub = subs.data[0];
    const active =
      !!sub &&
      ["active", "trialing", "past_due"].includes(sub.status);

    u.pro = active;
    u.subscription_status = sub?.status || "none";
    u.renews_at = sub?.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
    await DB.setUser(key, u);

    return res.json({
      ok: true,
      updated: true,
      pro: u.pro,
      status: sub?.status || "none",
      renews_at: u.renews_at
    });
  } catch (e) {
    console.error("refresh-pro error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

if (ENABLE_TEST_ROUTES) {
  app.post("/api/dev/grant-card", requireAuth, async (req, res) => {
    try {
      const cards = normalizeCardSelection(req.body?.cards || [req.body?.card]);
      if (!cards.length) {
        return res.status(400).json({ ok: false, error: "no_cards" });
      }
      const owned = await addOwnedCards(req.userEmail, cards);
      return res.json({ ok: true, owned_cards: owned });
    } catch (e) {
      console.error("grant-card error:", e);
      return res.status(500).json({ ok: false, error: "server_error" });
    }
  });
}

// ---------- Public News feed (front-end FEED URL) ----------
app.get("/api/news", async (_req, res) => {
  try {
    const items = await readNewsFeed();
    res.json(items);
  } catch (e) {
    console.error("/api/news error:", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// ---------- Admin: publish News ----------
app.post("/api/admin/news", async (req, res) => {
  try {
    const adminKeyEnv = process.env.NEWS_ADMIN_KEY || "bcg-goblin-2025";
    const { key, items } = req.body || {};

    if (!key || key !== adminKeyEnv) {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }
    if (!Array.isArray(items)) {
      return res.status(400).json({ ok: false, error: "bad_payload" });
    }

    // Basic sanitizing and shape
    const safe = items.map((i) => ({
      date: String(i.date || "").slice(0, 10),
      emoji: String(i.emoji || "📰").slice(0, 4),
      title: String(i.title || "").slice(0, 140),
      body: String(i.body || "").slice(0, 4000),
      tag: String(i.tag || "general").slice(0, 32)
    }));

    await writeNewsFeed(safe);

    return res.json({ ok: true, count: safe.length });
  } catch (e) {
    console.error("/api/admin/news error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`BCG API listening on ${PORT} | Redis: ${USE_REDIS ? "ON" : "OFF"}`);
});
