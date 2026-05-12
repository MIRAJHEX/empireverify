/**
 * Empire Verify — Backend Server
 * Node.js + Express.js + Firebase Admin + Cloudflare R2
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require("multer");
const sharp = require("sharp");
const admin = require("firebase-admin");
const axios = require("axios");
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const QRCode = require("qrcode");

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────
//  FIREBASE ADMIN INIT
// ─────────────────────────────────────────
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://empirewin-store-default-rtdb.firebaseio.com",
});
const db = admin.database();

// ─────────────────────────────────────────
//  CLOUDFLARE R2 CLIENT
// ─────────────────────────────────────────
const r2 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});
const R2_BUCKET = "empirewin";
const R2_PUBLIC_URL = "https://pub-6cece415364e482cbd3f8657fdbb4c01.r2.dev";

// ─────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || "*" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  message: { error: "Too many requests. Please try again later." },
});
app.use(globalLimiter);

// Strict rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many auth attempts." },
});

// Request logger
app.use((req, res, next) => {
  const log = { method: req.method, url: req.url, ip: req.ip, ts: Date.now() };
  db.ref("adminLogs").push(log).catch(() => {});
  next();
});

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
async function verifyFirebaseToken(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

async function verifyApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  const secretKey = req.headers["x-secret-key"];
  if (!apiKey || !secretKey) return res.status(401).json({ error: "Missing API credentials" });

  try {
    const snap = await db.ref("merchantApiKeys").orderByChild("apiKey").equalTo(apiKey).once("value");
    if (!snap.exists()) return res.status(401).json({ error: "Invalid API key" });

    const data = Object.values(snap.val())[0];
    const merchantId = Object.keys(snap.val())[0];

    const hashedSecret = crypto.createHash("sha256").update(secretKey + process.env.SECRET_SALT).digest("hex");
    if (data.secretKeyHash !== hashedSecret) return res.status(401).json({ error: "Invalid secret key" });
    if (data.status === "suspended") return res.status(403).json({ error: "API key suspended" });

    req.merchantId = merchantId;
    req.merchantData = data;
    next();
  } catch (err) {
    return res.status(500).json({ error: "Auth error" });
  }
}

async function verifyAdmin(req, res, next) {
  await verifyFirebaseToken(req, res, async () => {
    const snap = await db.ref(`users/${req.user.uid}/role`).once("value");
    if (snap.val() !== "admin") return res.status(403).json({ error: "Admin only" });
    next();
  });
}

// ─────────────────────────────────────────
//  UNIQUE AMOUNT ENGINE
// ─────────────────────────────────────────
async function generateUniqueAmount(baseAmount, merchantId) {
  const maxRetries = 50;
  for (let i = 0; i < maxRetries; i++) {
    const decimal = Math.floor(Math.random() * 99) + 1;
    const payableAmount = parseFloat((baseAmount + decimal / 100).toFixed(2));

    const reserveRef = db.ref(`amountReservations/${merchantId}/${decimal}`);
    let reserved = false;

    await reserveRef.transaction((current) => {
      if (!current || current.expiresAt < Date.now()) {
        reserved = true;
        return { amount: payableAmount, decimal, reservedAt: Date.now(), expiresAt: Date.now() + 15 * 60 * 1000 };
      }
      return current;
    });

    if (reserved) return { baseAmount, payableAmount, decimalCode: decimal };
  }
  throw new Error("Could not generate unique amount");
}

// ─────────────────────────────────────────
//  R2 UPLOAD UTILITY
// ─────────────────────────────────────────
async function uploadToR2(buffer, key, contentType = "image/webp") {
  await r2.send(new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    CacheControl: "public, max-age=31536000",
  }));
  return `${R2_PUBLIC_URL}/${key}`;
}

async function processAndUploadImage(fileBuffer, folder) {
  const webpBuffer = await sharp(fileBuffer)
    .resize({ width: 400, withoutEnlargement: true })
    .webp({ quality: 88 })
    .toBuffer();
  const key = `${folder}/${crypto.randomUUID()}.webp`;
  return uploadToR2(webpBuffer, key);
}

// Signed URL for direct upload
app.post("/api/upload/sign", verifyFirebaseToken, async (req, res) => {
  try {
    const { filename, folder = "screenshots" } = req.body;
    const key = `${folder}/${req.user.uid}/${Date.now()}-${crypto.randomUUID()}.webp`;
    const url = await getSignedUrl(r2, new PutObjectCommand({
      Bucket: R2_BUCKET, Key: key, ContentType: "image/webp",
    }), { expiresIn: 120 });
    res.json({ uploadUrl: url, publicUrl: `${R2_PUBLIC_URL}/${key}`, key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
//  MERCHANT ROUTES
// ─────────────────────────────────────────
app.post("/api/create-merchant", authLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const { gmailId, gmailAppPassword, upiId, merchantName, webhookUrl } = req.body;
    if (!gmailId || !gmailAppPassword || !upiId || !merchantName) {
      return res.status(400).json({ error: "All fields required" });
    }

    const uid = req.user.uid;
    const merchantRef = db.ref(`merchants/${uid}`);
    const existing = await merchantRef.once("value");
    if (existing.exists()) return res.status(400).json({ error: "Merchant already exists" });

    // Encrypt Gmail password
    const encKey = crypto.scryptSync(process.env.ENCRYPTION_KEY, "salt", 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv);
    const encrypted = Buffer.concat([cipher.update(gmailAppPassword), cipher.final()]);
    const encryptedPassword = `${iv.toString("hex")}:${encrypted.toString("hex")}`;

    const merchantData = {
      uid, merchantName, gmailId, upiId,
      gmailPasswordEncrypted: encryptedPassword,
      webhookUrl: webhookUrl || "",
      status: "pending",
      createdAt: admin.database.ServerValue.TIMESTAMP,
    };

    await merchantRef.set(merchantData);

    // Generate API keys
    const apiKey = `ev_live_${crypto.randomBytes(16).toString("hex")}`;
    const secretKey = `evs_${crypto.randomBytes(24).toString("hex")}`;
    const webhookSecret = `evwh_${crypto.randomBytes(16).toString("hex")}`;
    const hashedSecret = crypto.createHash("sha256").update(secretKey + process.env.SECRET_SALT).digest("hex");

    await db.ref(`merchantApiKeys/${uid}`).set({
      apiKey, secretKeyHash: hashedSecret, webhookSecret,
      status: "active", createdAt: admin.database.ServerValue.TIMESTAMP,
    });

    await db.ref(`users/${uid}`).update({ role: "merchant", merchantId: uid });

    res.json({ success: true, apiKey, secretKey, webhookSecret, message: "Merchant created. Awaiting approval." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/regenerate-api-key", verifyApiKey, async (req, res) => {
  try {
    const apiKey = `ev_live_${crypto.randomBytes(16).toString("hex")}`;
    const secretKey = `evs_${crypto.randomBytes(24).toString("hex")}`;
    const hashedSecret = crypto.createHash("sha256").update(secretKey + process.env.SECRET_SALT).digest("hex");

    await db.ref(`merchantApiKeys/${req.merchantId}`).update({ apiKey, secretKeyHash: hashedSecret, updatedAt: Date.now() });
    res.json({ success: true, apiKey, secretKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
//  PAYMENT ROUTES
// ─────────────────────────────────────────
app.post("/api/create-payment", verifyApiKey, async (req, res) => {
  try {
    const { amount, orderId, customerName, customerEmail, redirectUrl, callbackUrl } = req.body;
    if (!amount || isNaN(amount) || amount <= 0) return res.status(400).json({ error: "Invalid amount" });

    const merchantSnap = await db.ref(`merchants/${req.merchantId}`).once("value");
    const merchant = merchantSnap.val();
    if (!merchant || merchant.status !== "active") return res.status(403).json({ error: "Merchant not active" });

    const uniqueAmt = await generateUniqueAmount(parseFloat(amount), req.merchantId);
    const paymentId = `pay_${crypto.randomBytes(12).toString("hex")}`;

    // Generate UPI deep link & QR
    const upiLink = `upi://pay?pa=${merchant.upiId}&pn=${encodeURIComponent(merchant.merchantName)}&am=${uniqueAmt.payableAmount}&cu=INR&tn=${paymentId}`;
    const qrDataUrl = await QRCode.toDataURL(upiLink, { width: 256, margin: 2, color: { dark: "#000000", light: "#FFFFFF" } });

    const paymentData = {
      paymentId, merchantId: req.merchantId,
      orderId: orderId || null,
      baseAmount: uniqueAmt.baseAmount,
      payableAmount: uniqueAmt.payableAmount,
      decimalCode: uniqueAmt.decimalCode,
      upiId: merchant.upiId,
      merchantName: merchant.merchantName,
      customerName: customerName || null,
      customerEmail: customerEmail || null,
      status: "pending",
      redirectUrl: redirectUrl || null,
      callbackUrl: callbackUrl || null,
      qrCode: qrDataUrl,
      upiLink,
      createdAt: admin.database.ServerValue.TIMESTAMP,
      expiresAt: Date.now() + 15 * 60 * 1000,
    };

    await db.ref(`paymentSessions/${paymentId}`).set(paymentData);
    await db.ref(`merchantPayments/${req.merchantId}/${paymentId}`).set({ paymentId, status: "pending", amount: uniqueAmt.payableAmount, createdAt: admin.database.ServerValue.TIMESTAMP });
    await db.ref(`verificationQueue/${paymentId}`).set({ paymentId, merchantId: req.merchantId, status: "awaiting", createdAt: Date.now() });

    res.json({
      success: true,
      paymentId,
      payableAmount: uniqueAmt.payableAmount,
      baseAmount: uniqueAmt.baseAmount,
      qrCode: qrDataUrl,
      upiLink,
      checkoutUrl: `${process.env.FRONTEND_URL}/pay/${paymentId}`,
      expiresAt: Date.now() + 15 * 60 * 1000,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/submit-utr", async (req, res) => {
  try {
    const { paymentId, utrId, screenshotUrl } = req.body;
    if (!paymentId || !utrId) return res.status(400).json({ error: "paymentId and utrId required" });

    // Fraud: duplicate UTR check
    const dupSnap = await db.ref("transactions").orderByChild("utr").equalTo(utrId).once("value");
    if (dupSnap.exists()) {
      await db.ref(`fraudFlags/${paymentId}`).set({ reason: "duplicate_utr", utrId, timestamp: Date.now() });
      return res.status(400).json({ error: "UTR already used" });
    }

    const sessionSnap = await db.ref(`paymentSessions/${paymentId}`).once("value");
    if (!sessionSnap.exists()) return res.status(404).json({ error: "Payment not found" });

    const session = sessionSnap.val();
    if (session.status !== "pending") return res.status(400).json({ error: `Payment is ${session.status}` });
    if (Date.now() > session.expiresAt) return res.status(400).json({ error: "Payment expired" });

    // Count IP retries
    const ip = req.ip;
    const retryKey = `ipRetries/${Buffer.from(ip).toString("base64")}`;
    const retrySnap = await db.ref(retryKey).once("value");
    const retries = retrySnap.val()?.count || 0;
    if (retries > 10) {
      await db.ref(`fraudFlags/${paymentId}`).set({ reason: "ip_abuse", ip, timestamp: Date.now() });
      return res.status(429).json({ error: "Too many attempts from this IP" });
    }
    await db.ref(retryKey).set({ count: retries + 1, lastAttempt: Date.now() });

    await db.ref(`paymentSessions/${paymentId}`).update({ utrId, screenshotUrl: screenshotUrl || null, utrSubmittedAt: Date.now(), status: "verifying" });
    await db.ref(`verificationQueue/${paymentId}`).update({ utrId, screenshotUrl: screenshotUrl || null, status: "queued", queuedAt: Date.now() });

    res.json({ success: true, message: "UTR submitted. Verifying payment..." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/payment-status/:id", async (req, res) => {
  try {
    const snap = await db.ref(`paymentSessions/${req.params.id}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error: "Payment not found" });
    const { status, payableAmount, merchantName, createdAt, expiresAt, utrId } = snap.val();
    res.json({ paymentId: req.params.id, status, payableAmount, merchantName, createdAt, expiresAt, utrId: utrId || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Internal: called by Python worker after verification
app.post("/api/verify-payment", async (req, res) => {
  const workerSecret = req.headers["x-worker-secret"];
  if (workerSecret !== process.env.WORKER_SECRET) return res.status(401).json({ error: "Unauthorized worker" });

  try {
    const { paymentId, utrId, amount, senderName, timestamp, matched } = req.body;

    const sessionSnap = await db.ref(`paymentSessions/${paymentId}`).once("value");
    if (!sessionSnap.exists()) return res.status(404).json({ error: "Session not found" });

    const session = sessionSnap.val();
    const newStatus = matched ? "success" : "failed";

    // Replay attack prevention
    if (session.status === "success") return res.status(400).json({ error: "Already verified" });

    const updates = {
      status: newStatus, verifiedAt: Date.now(),
      verifiedAmount: amount, verifiedUtr: utrId,
      senderName: senderName || null, emailTimestamp: timestamp || null,
    };

    await db.ref(`paymentSessions/${paymentId}`).update(updates);
    await db.ref(`merchantPayments/${session.merchantId}/${paymentId}`).update({ status: newStatus, verifiedAt: Date.now() });

    if (matched) {
      await db.ref(`transactions/${session.merchantId}/${paymentId}`).set({
        paymentId, utr: utrId, amount, senderName, status: "success",
        merchantId: session.merchantId, timestamp: Date.now(),
      });

      // Release amount reservation
      await db.ref(`amountReservations/${session.merchantId}/${session.decimalCode}`).remove();

      // Analytics update
      await db.ref(`analytics/${session.merchantId}`).transaction((cur) => {
        if (!cur) return { totalSuccess: 1, totalVolume: amount, successRate: 100 };
        return {
          totalSuccess: (cur.totalSuccess || 0) + 1,
          totalVolume: (cur.totalVolume || 0) + amount,
          successRate: cur.successRate,
        };
      });
    }

    // Fire webhook
    await fireWebhook(session.merchantId, paymentId, newStatus, session, amount, utrId);

    res.json({ success: true, status: newStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
//  WEBHOOK SYSTEM
// ─────────────────────────────────────────
async function fireWebhook(merchantId, paymentId, event, session, amount, utrId) {
  const keysSnap = await db.ref(`merchantApiKeys/${merchantId}`).once("value");
  const keys = keysSnap.val();
  const merchantSnap = await db.ref(`merchants/${merchantId}`).once("value");
  const merchant = merchantSnap.val();

  const webhookUrl = merchant?.webhookUrl;
  if (!webhookUrl) return;

  const payload = {
    event: `payment.${event}`,
    paymentId, merchantId,
    amount, utrId,
    orderId: session.orderId,
    customerName: session.customerName,
    timestamp: Date.now(),
  };

  const signature = crypto.createHmac("sha256", keys.webhookSecret).update(JSON.stringify(payload)).digest("hex");

  const maxRetries = 3;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await axios.post(webhookUrl, payload, {
        headers: { "Content-Type": "application/json", "X-EmpireVerify-Signature": signature, "X-EmpireVerify-Event": `payment.${event}` },
        timeout: 10000,
      });

      await db.ref(`webhookLogs/${merchantId}`).push({
        paymentId, event: `payment.${event}`, status: "delivered",
        statusCode: response.status, attempt, timestamp: Date.now(),
      });
      return;
    } catch (err) {
      if (attempt === maxRetries) {
        await db.ref(`webhookLogs/${merchantId}`).push({
          paymentId, event: `payment.${event}`, status: "failed",
          error: err.message, attempt, timestamp: Date.now(),
        });
        await db.ref(`retryQueue/${paymentId}_${Date.now()}`).set({
          merchantId, paymentId, payload, attempt, nextRetry: Date.now() + 60000,
        });
      }
      await new Promise(r => setTimeout(r, attempt * 2000));
    }
  }
}

// ─────────────────────────────────────────
//  ADMIN ROUTES
// ─────────────────────────────────────────
app.get("/api/admin/merchants", verifyAdmin, async (req, res) => {
  try {
    const snap = await db.ref("merchants").once("value");
    const merchants = [];
    snap.forEach(child => merchants.push({ id: child.key, ...child.val() }));
    res.json({ merchants });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/merchant/:id/status", verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body; // active | suspended | banned
    if (!["active", "suspended", "banned"].includes(status)) return res.status(400).json({ error: "Invalid status" });
    await db.ref(`merchants/${req.params.id}`).update({ status, updatedAt: Date.now() });
    if (status !== "active") {
      await db.ref(`merchantApiKeys/${req.params.id}`).update({ status: "suspended" });
    } else {
      await db.ref(`merchantApiKeys/${req.params.id}`).update({ status: "active" });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/admin/payments", verifyAdmin, async (req, res) => {
  try {
    const snap = await db.ref("paymentSessions").limitToLast(100).once("value");
    const payments = [];
    snap.forEach(merchantSnap => {
      merchantSnap.forEach(p => payments.push({ id: p.key, ...p.val() }));
    });
    res.json({ payments: payments.reverse() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/payment/:id/manual-approve", verifyAdmin, async (req, res) => {
  try {
    const { merchantId } = req.body;
    await db.ref(`paymentSessions/${req.params.id}`).update({ status: "success", manuallyApproved: true, approvedBy: req.user.uid, approvedAt: Date.now() });
    await db.ref(`merchantPayments/${merchantId}/${req.params.id}`).update({ status: "success" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/admin/fraud-flags", verifyAdmin, async (req, res) => {
  try {
    const snap = await db.ref("fraudFlags").limitToLast(50).once("value");
    const flags = [];
    snap.forEach(child => flags.push({ id: child.key, ...child.val() }));
    res.json({ flags: flags.reverse() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/admin/stats", verifyAdmin, async (req, res) => {
  try {
    const [merchantsSnap, flagsSnap, queueSnap] = await Promise.all([
      db.ref("merchants").once("value"),
      db.ref("fraudFlags").once("value"),
      db.ref("verificationQueue").once("value"),
    ]);

    let totalMerchants = 0, activeMerchants = 0;
    merchantsSnap.forEach(m => { totalMerchants++; if (m.val().status === "active") activeMerchants++; });
    const fraudFlags = flagsSnap.numChildren();
    const queueSize = queueSnap.numChildren();

    res.json({ totalMerchants, activeMerchants, fraudFlags, queueSize });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
//  MERCHANT DASHBOARD ROUTES
// ─────────────────────────────────────────
app.get("/api/merchant/transactions", verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const snap = await db.ref(`merchantPayments/${uid}`).limitToLast(50).once("value");
    const txns = [];
    snap.forEach(child => txns.push({ id: child.key, ...child.val() }));
    res.json({ transactions: txns.reverse() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/merchant/analytics", verifyFirebaseToken, async (req, res) => {
  try {
    const snap = await db.ref(`analytics/${req.user.uid}`).once("value");
    res.json(snap.val() || { totalSuccess: 0, totalVolume: 0, successRate: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/merchant/webhook", verifyFirebaseToken, async (req, res) => {
  try {
    const { webhookUrl } = req.body;
    await db.ref(`merchants/${req.user.uid}`).update({ webhookUrl, updatedAt: Date.now() });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
//  HEALTH
// ─────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok", timestamp: Date.now(), version: "1.0.0" }));
app.get("/", (req, res) => res.json({ name: "Empire Verify API", version: "1.0.0" }));

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => console.log(`🚀 Empire Verify API running on port ${PORT}`));
module.exports = app;
