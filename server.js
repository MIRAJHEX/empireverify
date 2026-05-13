/**
 * Empire Verify — Backend Server v2
 * ROOT level file for Railway deployment
 */
require("dotenv").config();
const express      = require("express");
const cors         = require("cors");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const crypto       = require("crypto");
const admin        = require("firebase-admin");
const axios        = require("axios");
const QRCode       = require("qrcode");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const notify       = require("./onesignal");

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── FIREBASE ADMIN ──────────────────────
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential:  admin.credential.cert(serviceAccount),
  databaseURL: "https://empirewin-store-default-rtdb.firebaseio.com",
});
const db = admin.database();

// ─── CLOUDFLARE R2 ───────────────────────
const _a = Buffer.from("M2QzYTk1YmZjOTE0M2E2ZmZhOGYzM2FlN2Q2NzczNGI=","base64").toString();
const _s = Buffer.from("MzkxYzA3MWUyNzJkYmJkODVjYmRlYzZkOTZiMGE0ZjY5MmM0NTE2MDNkMjY4ZDhmZjU4YjY0YjhhZTFmOTZhNw==","base64").toString();
const _e = Buffer.from("aHR0cHM6Ly9jMmU2Y2Q3MTM1ZDczMDk1MDhhMTJhNDMxNzQ1YWU2Yy5yMi5jbG91ZGZsYXJlc3RvcmFnZS5jb20=","base64").toString();

const r2 = new S3Client({
  region: "auto", endpoint: _e,
  credentials: { accessKeyId: _a, secretAccessKey: _s },
});
const R2_BUCKET     = "empirewin";
const R2_PUBLIC_URL = "https://pub-6cece415364e482cbd3f8657fdbb4c01.r2.dev";

// ─── MIDDLEWARE ──────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 300, standardHeaders: true }));

app.use((req, res, next) => {
  db.ref("adminLogs").push({ method: req.method, url: req.url, ip: req.ip, ts: Date.now() }).catch(()=>{});
  next();
});

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20 });

// ─── AUTH HELPERS ────────────────────────
async function verifyFirebaseToken(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try { req.user = await admin.auth().verifyIdToken(token); next(); }
  catch { return res.status(401).json({ error: "Invalid token" }); }
}

async function verifyApiKey(req, res, next) {
  const apiKey    = req.headers["x-api-key"];
  const secretKey = req.headers["x-secret-key"];
  if (!apiKey || !secretKey) return res.status(401).json({ error: "Missing API credentials" });
  try {
    const snap = await db.ref("merchantApiKeys").orderByChild("apiKey").equalTo(apiKey).once("value");
    if (!snap.exists()) return res.status(401).json({ error: "Invalid API key" });
    const merchantId = Object.keys(snap.val())[0];
    const data       = Object.values(snap.val())[0];
    const hashed     = crypto.createHash("sha256").update(secretKey + (process.env.SECRET_SALT||"emp_salt")).digest("hex");
    if (data.secretKeyHash !== hashed) return res.status(401).json({ error: "Invalid secret key" });
    if (data.status === "suspended")   return res.status(403).json({ error: "API key suspended" });
    req.merchantId   = merchantId;
    req.merchantData = data;
    next();
  } catch { return res.status(500).json({ error: "Auth error" }); }
}

async function verifyAdmin(req, res, next) {
  await verifyFirebaseToken(req, res, async () => {
    const snap = await db.ref(`users/${req.user.uid}/role`).once("value");
    if (snap.val() !== "admin") return res.status(403).json({ error: "Admin only" });
    next();
  });
}

// ─── UNIQUE AMOUNT ENGINE ────────────────
async function generateUniqueAmount(baseAmount, merchantId) {
  for (let i = 0; i < 50; i++) {
    const decimal = Math.floor(Math.random() * 99) + 1;
    const payable  = parseFloat((baseAmount + decimal / 100).toFixed(2));
    const resRef   = db.ref(`amountReservations/${merchantId}/${decimal}`);
    let reserved   = false;
    await resRef.transaction(cur => {
      if (!cur || cur.expiresAt < Date.now()) {
        reserved = true;
        return { amount: payable, decimal, reservedAt: Date.now(), expiresAt: Date.now() + 15*60*1000 };
      }
      return cur;
    });
    if (reserved) return { baseAmount, payableAmount: payable, decimalCode: decimal };
  }
  throw new Error("Could not generate unique amount");
}

// ─── R2 SIGNED UPLOAD ────────────────────
app.post("/api/upload/sign", verifyFirebaseToken, async (req, res) => {
  try {
    const { folder = "screenshots" } = req.body;
    const key = `${folder}/${req.user.uid}/${Date.now()}-${crypto.randomUUID()}.webp`;
    const url = await getSignedUrl(r2, new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, ContentType: "image/webp" }), { expiresIn: 120 });
    res.json({ uploadUrl: url, publicUrl: `${R2_PUBLIC_URL}/${key}`, key });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── WEBHOOK FIRE ────────────────────────
async function fireWebhook(merchantId, paymentId, event, session, amount, utrId) {
  try {
    const keysSnap = await db.ref(`merchantApiKeys/${merchantId}`).once("value");
    const keys     = keysSnap.val();
    const mSnap    = await db.ref(`merchants/${merchantId}`).once("value");
    const merchant = mSnap.val();
    if (!merchant?.webhookUrl || !keys) return;
    const payload   = { event:`payment.${event}`, paymentId, merchantId, amount, utrId, orderId:session.orderId, timestamp:Date.now() };
    const signature = crypto.createHmac("sha256", keys.webhookSecret).update(JSON.stringify(payload)).digest("hex");
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        await axios.post(merchant.webhookUrl, payload, { headers:{"X-EmpireVerify-Signature":signature,"Content-Type":"application/json"}, timeout:10000 });
        await db.ref(`webhookLogs/${merchantId}`).push({ paymentId, event:`payment.${event}`, status:"delivered", attempt, timestamp:Date.now() });
        return;
      } catch (err) {
        if (attempt===3) {
          await db.ref(`retryQueue/${paymentId}_${Date.now()}`).set({ merchantId, paymentId, payload, attempt, nextRetry:Date.now()+60000 });
        }
        await new Promise(r=>setTimeout(r, attempt*2000));
      }
    }
  } catch {}
}

// ─── MERCHANT SIGNUP ─────────────────────
app.post("/api/create-merchant", authLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const { gmailId, gmailAppPassword, upiId, merchantName, webhookUrl } = req.body;
    if (!gmailId||!gmailAppPassword||!upiId||!merchantName) return res.status(400).json({ error:"All fields required" });
    const uid = req.user.uid;
    if ((await db.ref(`merchants/${uid}`).once("value")).exists()) return res.status(400).json({ error:"Merchant already exists" });

    const encKey = crypto.scryptSync(process.env.ENCRYPTION_KEY||"empire_default_enc_key_32chars!!", "salt", 32);
    const iv     = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv);
    const enc    = Buffer.concat([cipher.update(gmailAppPassword), cipher.final()]);
    const encPw  = `${iv.toString("hex")}:${enc.toString("hex")}`;

    await db.ref(`merchants/${uid}`).set({ uid, merchantName, gmailId, upiId, gmailPasswordEncrypted:encPw, webhookUrl:webhookUrl||"", status:"pending", createdAt:admin.database.ServerValue.TIMESTAMP });

    const apiKey        = `ev_live_${crypto.randomBytes(16).toString("hex")}`;
    const secretKey     = `evs_${crypto.randomBytes(24).toString("hex")}`;
    const webhookSecret = `evwh_${crypto.randomBytes(16).toString("hex")}`;
    const hashedSecret  = crypto.createHash("sha256").update(secretKey+(process.env.SECRET_SALT||"emp_salt")).digest("hex");

    await db.ref(`merchantApiKeys/${uid}`).set({ apiKey, secretKeyHash:hashedSecret, webhookSecret, status:"active", createdAt:admin.database.ServerValue.TIMESTAMP });
    await db.ref(`users/${uid}`).update({ role:"merchant", merchantId:uid });
    await notify.newMerchant(merchantName, uid);

    res.json({ success:true, apiKey, secretKey, webhookSecret, message:"Merchant created. Awaiting approval." });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// ─── CREATE PAYMENT ──────────────────────
app.post("/api/create-payment", verifyApiKey, async (req, res) => {
  try {
    const { amount, orderId, customerName, customerEmail, redirectUrl } = req.body;
    if (!amount||isNaN(amount)||amount<=0) return res.status(400).json({ error:"Invalid amount" });
    const mSnap   = await db.ref(`merchants/${req.merchantId}`).once("value");
    const merchant = mSnap.val();
    if (!merchant||merchant.status!=="active") return res.status(403).json({ error:"Merchant not active" });

    const unique    = await generateUniqueAmount(parseFloat(amount), req.merchantId);
    const paymentId = `pay_${crypto.randomBytes(12).toString("hex")}`;
    const upiLink   = `upi://pay?pa=${merchant.upiId}&pn=${encodeURIComponent(merchant.merchantName)}&am=${unique.payableAmount}&cu=INR&tn=${paymentId}`;
    const qrCode    = await QRCode.toDataURL(upiLink, { width:256, margin:2 });

    const data = { paymentId, merchantId:req.merchantId, orderId:orderId||null, baseAmount:unique.baseAmount, payableAmount:unique.payableAmount, decimalCode:unique.decimalCode, upiId:merchant.upiId, merchantName:merchant.merchantName, customerName:customerName||null, customerEmail:customerEmail||null, status:"pending", redirectUrl:redirectUrl||null, qrCode, upiLink, createdAt:admin.database.ServerValue.TIMESTAMP, expiresAt:Date.now()+15*60*1000 };

    await db.ref(`paymentSessions/${paymentId}`).set(data);
    await db.ref(`merchantPayments/${req.merchantId}/${paymentId}`).set({ paymentId, status:"pending", amount:unique.payableAmount, createdAt:admin.database.ServerValue.TIMESTAMP });
    await db.ref(`verificationQueue/${paymentId}`).set({ paymentId, merchantId:req.merchantId, status:"awaiting", createdAt:Date.now() });

    res.json({ success:true, paymentId, payableAmount:unique.payableAmount, baseAmount:unique.baseAmount, qrCode, upiLink, checkoutUrl:`${process.env.FRONTEND_URL||""}/pay/${paymentId}`, expiresAt:Date.now()+15*60*1000 });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// ─── SUBMIT UTR ──────────────────────────
app.post("/api/submit-utr", async (req, res) => {
  try {
    const { paymentId, utrId, screenshotUrl } = req.body;
    if (!paymentId||!utrId) return res.status(400).json({ error:"paymentId and utrId required" });

    const dupSnap = await db.ref("transactions").orderByChild("utr").equalTo(utrId).once("value");
    if (dupSnap.exists()) {
      await db.ref(`fraudFlags/${paymentId}`).set({ reason:"duplicate_utr", utrId, timestamp:Date.now() });
      return res.status(400).json({ error:"UTR already used" });
    }

    const snap = await db.ref(`paymentSessions/${paymentId}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error:"Payment not found" });
    const session = snap.val();
    if (session.status!=="pending") return res.status(400).json({ error:`Payment is ${session.status}` });
    if (Date.now()>session.expiresAt) return res.status(400).json({ error:"Payment expired" });

    const ip     = req.ip;
    const ipKey  = `ipRetries/${Buffer.from(ip).toString("base64").replace(/=/g,"")}`;
    const ipSnap = await db.ref(ipKey).once("value");
    const retries = ipSnap.val()?.count||0;
    if (retries>10) {
      await db.ref(`fraudFlags/${paymentId}`).set({ reason:"ip_abuse", ip, timestamp:Date.now() });
      return res.status(429).json({ error:"Too many attempts" });
    }
    await db.ref(ipKey).set({ count:retries+1, lastAttempt:Date.now() });
    await db.ref(`paymentSessions/${paymentId}`).update({ utrId, screenshotUrl:screenshotUrl||null, utrSubmittedAt:Date.now(), status:"verifying" });
    await db.ref(`verificationQueue/${paymentId}`).update({ utrId, screenshotUrl:screenshotUrl||null, status:"queued", queuedAt:Date.now() });

    res.json({ success:true, message:"UTR submitted. Verifying payment..." });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// ─── PAYMENT STATUS ──────────────────────
app.get("/api/payment-status/:id", async (req, res) => {
  try {
    const snap = await db.ref(`paymentSessions/${req.params.id}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error:"Payment not found" });
    const { status, payableAmount, upiId, merchantName, createdAt, expiresAt, utrId, redirectUrl } = snap.val();
    res.json({ paymentId:req.params.id, status, payableAmount, upiId, merchantName, createdAt, expiresAt, utrId:utrId||null, redirectUrl:redirectUrl||null });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// ─── VERIFY (Python Worker calls this) ───
app.post("/api/verify-payment", async (req, res) => {
  if (req.headers["x-worker-secret"]!==process.env.WORKER_SECRET) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { paymentId, utrId, amount, senderName, matched } = req.body;
    const snap = await db.ref(`paymentSessions/${paymentId}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error:"Session not found" });
    const session   = snap.val();
    if (session.status==="success") return res.status(400).json({ error:"Already verified" });
    const newStatus = matched?"success":"failed";
    await db.ref(`paymentSessions/${paymentId}`).update({ status:newStatus, verifiedAt:Date.now(), verifiedAmount:amount, verifiedUtr:utrId, senderName:senderName||null });
    await db.ref(`merchantPayments/${session.merchantId}/${paymentId}`).update({ status:newStatus, verifiedAt:Date.now() });
    if (matched) {
      await db.ref(`transactions/${session.merchantId}/${paymentId}`).set({ paymentId, utr:utrId, amount, senderName, status:"success", merchantId:session.merchantId, timestamp:Date.now() });
      await db.ref(`amountReservations/${session.merchantId}/${session.decimalCode}`).remove();
      await db.ref(`analytics/${session.merchantId}`).transaction(cur=>({ totalSuccess:(cur?.totalSuccess||0)+1, totalVolume:(cur?.totalVolume||0)+amount, lastUpdated:Date.now() }));
      await notify.paymentSuccess(session.merchantId, amount, utrId, paymentId);
    } else {
      await notify.paymentFailed(session.merchantId, paymentId, "No matching email found");
    }
    await fireWebhook(session.merchantId, paymentId, newStatus, session, amount, utrId);
    res.json({ success:true, status:newStatus });
  } catch (err) { res.status(500).json({ error:err.message }); }
});

// ─── ADMIN ROUTES ────────────────────────
app.get("/api/admin/merchants", verifyAdmin, async (req,res)=>{
  try { const snap=await db.ref("merchants").once("value"); const list=[]; snap.forEach(c=>list.push({id:c.key,...c.val()})); res.json({merchants:list}); }
  catch(err){ res.status(500).json({error:err.message}); }
});
app.post("/api/admin/merchant/:id/status", verifyAdmin, async (req,res)=>{
  try {
    const {status}=req.body;
    if(!["active","suspended","banned"].includes(status)) return res.status(400).json({error:"Invalid status"});
    await db.ref(`merchants/${req.params.id}`).update({status,updatedAt:Date.now()});
    await db.ref(`merchantApiKeys/${req.params.id}`).update({status:status==="active"?"active":"suspended"});
    res.json({success:true});
  } catch(err){ res.status(500).json({error:err.message}); }
});
app.get("/api/admin/stats", verifyAdmin, async (req,res)=>{
  try {
    const [mS,fS,qS]=await Promise.all([db.ref("merchants").once("value"),db.ref("fraudFlags").once("value"),db.ref("verificationQueue").once("value")]);
    let total=0,active=0; mS.forEach(m=>{total++;if(m.val().status==="active")active++;});
    res.json({totalMerchants:total,activeMerchants:active,fraudFlags:fS.numChildren(),queueSize:qS.numChildren()});
  } catch(err){ res.status(500).json({error:err.message}); }
});
app.post("/api/admin/payment/:id/manual-approve", verifyAdmin, async (req,res)=>{
  try {
    const {merchantId}=req.body;
    await db.ref(`paymentSessions/${req.params.id}`).update({status:"success",manuallyApproved:true,approvedBy:req.user.uid,approvedAt:Date.now()});
    await db.ref(`merchantPayments/${merchantId}/${req.params.id}`).update({status:"success"});
    res.json({success:true});
  } catch(err){ res.status(500).json({error:err.message}); }
});

// ─── MERCHANT ROUTES ─────────────────────
app.get("/api/merchant/transactions", verifyFirebaseToken, async (req,res)=>{
  try { const snap=await db.ref(`merchantPayments/${req.user.uid}`).limitToLast(50).once("value"); const list=[]; snap.forEach(c=>list.push({id:c.key,...c.val()})); res.json({transactions:list.reverse()}); }
  catch(err){ res.status(500).json({error:err.message}); }
});
app.get("/api/merchant/analytics", verifyFirebaseToken, async (req,res)=>{
  try { const snap=await db.ref(`analytics/${req.user.uid}`).once("value"); res.json(snap.val()||{totalSuccess:0,totalVolume:0}); }
  catch(err){ res.status(500).json({error:err.message}); }
});
app.post("/api/merchant/webhook", verifyFirebaseToken, async (req,res)=>{
  try { await db.ref(`merchants/${req.user.uid}`).update({webhookUrl:req.body.webhookUrl,updatedAt:Date.now()}); res.json({success:true}); }
  catch(err){ res.status(500).json({error:err.message}); }
});
app.post("/api/regenerate-api-key", verifyApiKey, async (req,res)=>{
  try {
    const apiKey=`ev_live_${crypto.randomBytes(16).toString("hex")}`;
    const secretKey=`evs_${crypto.randomBytes(24).toString("hex")}`;
    const hashed=crypto.createHash("sha256").update(secretKey+(process.env.SECRET_SALT||"emp_salt")).digest("hex");
    await db.ref(`merchantApiKeys/${req.merchantId}`).update({apiKey,secretKeyHash:hashed,updatedAt:Date.now()});
    res.json({success:true,apiKey,secretKey});
  } catch(err){ res.status(500).json({error:err.message}); }
});

// ─── HEALTH ──────────────────────────────
app.get("/health",(req,res)=>res.json({status:"ok",timestamp:Date.now(),version:"2.0.0"}));
app.get("/",(req,res)=>res.json({name:"Empire Verify API",version:"2.0.0",status:"running"}));
app.use((err,req,res,next)=>{ console.error(err.stack); res.status(500).json({error:"Internal server error"}); });

app.listen(PORT,()=>console.log(`🚀 Empire Verify API running on port ${PORT}`));
module.exports = app;
