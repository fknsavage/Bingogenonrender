// server.js — BingoCardGen API (Render)
// Endpoints kept identical to the Worker:
//   POST /api/auth/otp/start
//   POST /api/auth/otp/verify
//   GET  /api/me
//   POST /api/logout
//   POST /api/stripe/webhook
//
// Env you set on Render:
//   RESEND_API_KEY  (or leave empty to log codes)
//   SENDER_EMAIL    e.g. "BingoCardGen <no-reply@bingocardgen.com>"
//   STRIPE_WEBHOOK_SECRET (optional now; add later)
//   SESSION_SECRET  any long random string

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import fetch from "node-fetch";

// ---------- tiny KV emulation with TTL ----------
function makeTTLStore(){
  const m = new Map();
  return {
    async get(k){ return m.get(k)?.v ?? null; },
    async put(k,v,{ttl}){ const exp=Date.now()+ttl*1000; m.set(k,{v,exp}); },
    async del(k){ m.delete(k); },
    sweep(){
      const now=Date.now();
      for (const [k,obj] of m.entries()) if ((obj.exp||0)<now) m.delete(k);
    }
  };
}
const OTP   = makeTTLStore();      // otp:email -> 6 digits (10 min)
const RATE  = makeTTLStore();      // rate:email -> "1" (30s)
const ATTEM = makeTTLStore();      // attempt:email:ip -> count (10 min)
const SESS  = makeTTLStore();      // sess:<id> -> {email,pro,exp} (24h)
const USERS = new Map();           // user:email -> {pro,createdAt,updatedAt}

setInterval(()=>{ OTP.sweep(); RATE.sweep(); ATTEM.sweep(); SESS.sweep(); }, 30_000);

// ---------- helpers ----------
const app = express();
app.use(express.json());
app.use(cookieParser(process.env.SESSION_SECRET || "insecure-dev"));

const ALLOW = new Set(["https://bingocardgen.com", "https://www.bingocardgen.com"]);
app.use(cors({
  origin: (o,cb)=> cb(null, ALLOW.has(o||"") ? o : "https://bingocardgen.com"),
  credentials: true
}));

const validEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e||"");
const six       = () => String(Math.floor(100000 + Math.random()*900000));
const randHex   = (n=24)=> crypto.randomBytes(n).toString("hex");
const getIP     = (req)=> (req.headers["x-forwarded-for"]||"").toString().split(",")[0].trim() || req.ip || "";

// ---------- health ----------
app.get("/api/health", (req,res)=> res.json({ ok:true, time:new Date().toISOString() }));

// ---------- OTP: start ----------
app.post("/api/auth/otp/start", async (req,res)=>{
  const email = String(req.body?.email||"").trim();
  if (!validEmail(email)) return res.status(400).json({ ok:false, error:"bad_email" });

  // rate: once per 30s
  if (await RATE.get(`rate:${email}`)) return res.json({ ok:true, rate:true });
  await RATE.put(`rate:${email}`, "1", { ttl: 30 });

  const code = six();
  await OTP.put(`otp:${email}`, code, { ttl: 600 });

  // send email via Resend (optional)
  if (process.env.RESEND_API_KEY){
    const html = renderOtpEmailHTML(code);
    const text = `Your BingoCardGen login code: ${code}\nExpires in 10 minutes.`;
    try{
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: process.env.SENDER_EMAIL || "BingoCardGen <no-reply@bingocardgen.com>",
          to: [email],
          subject: "Your BingoCardGen login code",
          html, text
        })
      });
    }catch(err){ console.error("Resend send failed:", err); }
  } else {
    console.log("OTP for", email, "=>", code);
  }

  res.json({ ok:true });
});

// ---------- OTP: verify ----------
app.post("/api/auth/otp/verify", async (req,res)=>{
  const email = String(req.body?.email||"").trim();
  const code  = String(req.body?.code||"").trim();
  if (!validEmail(email) || !/^\d{6}$/.test(code)) return res.status(400).json({ ok:false, error:"bad_request" });

  // throttle brute force per email+IP
  const ip = getIP(req);
  const akey = `attempt:${email}:${ip}`;
  const tries = Number(await ATTEM.get(akey) || "0");
  if (tries >= 8) return res.status(429).json({ ok:false, error:"too_many_attempts" });

  const saved = await OTP.get(`otp:${email}`);
  if (!saved || saved !== code){
    await ATTEM.put(akey, String(tries+1), { ttl: 600 });
    return res.status(400).json({ ok:false, error:"invalid_code" });
  }

  // success → clear OTP/attempts
  await OTP.del?.(`otp:${email}`);
  await ATTEM.del?.(akey);

  // seed user if new
  const ukey = email.toLowerCase();
  const user = USERS.get(ukey) || { pro:false, createdAt: Date.now() };
  USERS.set(ukey, user);

  // create session
  const sid = randHex(24);
  const sess = { email, pro: !!user.pro, exp: Date.now() + 24*60*60*1000 };
  await SESS.put(`sess:${sid}`, JSON.stringify(sess), { ttl: 24*60*60 + 300 });

  // SameSite=Lax, Secure, HttpOnly
  res.cookie("bcg_s", sid, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 24*60*60*1000
  });

  res.json({ ok:true, user: { email, pro: !!user.pro } });
});

// ---------- /api/me ----------
app.get("/api/me", async (req,res)=>{
  const sid = req.cookies?.bcg_s;
  if (!sid) return res.json({ ok:true, authed:false });
  const raw = await SESS.get(`sess:${sid}`);
  if (!raw) return res.json({ ok:true, authed:false });

  const sess = JSON.parse(raw);
  if (Date.now() > (sess.exp||0)) return res.json({ ok:true, authed:false });

  // slide another 24h
  sess.exp = Date.now() + 24*60*60*1000;
  await SESS.put(`sess:${sid}`, JSON.stringify(sess), { ttl: 24*60*60 + 300 });

  res.json({ ok:true, authed:true, email:sess.email, pro:!!sess.pro });
});

// ---------- logout ----------
app.post("/api/logout", async (req,res)=>{
  res.cookie("bcg_s", "", { httpOnly:true, secure:true, sameSite:"lax", path:"/", maxAge:0 });
  res.json({ ok:true });
});

// ---------- Stripe webhook (optional now) ----------
app.post("/api/stripe/webhook", express.text({ type: "*/*" }), async (req,res)=>{
  // For first deploy you can simply acknowledge:
  // return res.status(200).send("ok");
  // Later: verify with STRIPE_WEBHOOK_SECRET and flip USERS[email].pro like your Worker does.
  res.status(200).send("ignored");
});

// ---------- email HTML ----------
function renderOtpEmailHTML(code){
  return `
<!doctype html><html><body style="margin:0;padding:0;background:#0b1220;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0b1220;padding:24px 0">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:560px;max-width:560px;background:#0e1a2b;border-radius:12px;border:1px solid #10233b">
        <tr><td style="padding:22px 24px 12px 24px">
          <div style="display:inline-block;padding:10px 14px;border:2px solid #00eaff;border-radius:12px;font-weight:900;letter-spacing:.5px;color:#00eaff">
            BingoCardGen
          </div>
          <h1 style="margin:18px 0 6px;color:#eafaff;font-size:20px;line-height:1.3">Your login code</h1>
          <p style="margin:0;color:#b7c8d9;font-size:14px;line-height:1.6">Use the code below to sign in. It expires in 10 minutes.</p>
        </td></tr>
        <tr><td align="center" style="padding:6px 24px 8px 24px">
          <div style="display:inline-block;background:#001018;border:1px solid #00c8d6;border-radius:14px;padding:18px 22px">
            <div style="font-size:28px;letter-spacing:6px;font-weight:900;color:#00f0ff">${code}</div>
          </div>
        </td></tr>
        <tr><td style="padding:8px 24px 18px 24px">
          <p style="margin:0;color:#93a7bc;font-size:13px;line-height:1.6">If you didn’t request this, you can safely ignore this email.</p>
        </td></tr>
        <tr><td style="padding:14px 24px 22px 24px;border-top:1px solid #10233b;color:#6d8095;font-size:12px">© ${new Date().getFullYear()} BingoCardGen • Secure one-time code</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`.trim();
}

// ---------- boot ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, ()=> console.log("BCG API listening on", PORT));
