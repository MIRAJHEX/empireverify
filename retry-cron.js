/**
 * Empire Verify — Retry Queue Cron
 * Retries failed webhooks and unmatched payments every 60 seconds
 * Run via PM2 alongside main server
 */

require("dotenv").config();
const admin = require("firebase-admin");
const axios = require("axios");
const crypto = require("crypto");

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount), databaseURL: "https://empirewin-store-default-rtdb.firebaseio.com" });
}
const db = admin.database();

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:3000";
const WORKER_SECRET = process.env.WORKER_SECRET;
const MAX_WEBHOOK_RETRIES = 5;
const MAX_PAYMENT_RETRIES = 3;

// ── WEBHOOK RETRY ───────────────────────
async function retryWebhooks() {
  const snap = await db.ref("retryQueue").orderByChild("nextRetry").endAt(Date.now()).once("value");
  if (!snap.exists()) return;

  const retries = [];
  snap.forEach(child => retries.push({ key: child.key, ...child.val() }));
  console.log(`[RetryQueue] ${retries.length} webhook(s) to retry`);

  for (const item of retries) {
    if ((item.attempt || 1) >= MAX_WEBHOOK_RETRIES) {
      console.log(`[RetryQueue] Max retries reached for ${item.paymentId}. Dropping.`);
      await db.ref(`retryQueue/${item.key}`).remove();
      await db.ref(`webhookLogs/${item.merchantId}`).push({ paymentId: item.paymentId, status: "dropped", reason: "max_retries", timestamp: Date.now() });
      continue;
    }

    try {
      // Get webhook secret
      const keysSnap = await db.ref(`merchantApiKeys/${item.merchantId}`).once("value");
      const keys = keysSnap.val();
      if (!keys) { await db.ref(`retryQueue/${item.key}`).remove(); continue; }

      const signature = crypto.createHmac("sha256", keys.webhookSecret).update(JSON.stringify(item.payload)).digest("hex");

      const merchantSnap = await db.ref(`merchants/${item.merchantId}`).once("value");
      const merchant = merchantSnap.val();
      if (!merchant?.webhookUrl) { await db.ref(`retryQueue/${item.key}`).remove(); continue; }

      const response = await axios.post(merchant.webhookUrl, item.payload, {
        headers: { "Content-Type": "application/json", "X-EmpireVerify-Signature": signature },
        timeout: 10000,
      });

      // Success — remove from queue
      await db.ref(`retryQueue/${item.key}`).remove();
      await db.ref(`webhookLogs/${item.merchantId}`).push({
        paymentId: item.paymentId, status: "delivered", statusCode: response.status,
        attempt: (item.attempt || 1) + 1, retried: true, timestamp: Date.now(),
      });
      console.log(`[RetryQueue] ✅ Webhook delivered for ${item.paymentId}`);
    } catch (err) {
      // Exponential backoff
      const nextAttempt = (item.attempt || 1) + 1;
      const delay = Math.min(60000 * Math.pow(2, nextAttempt - 1), 3600000);
      await db.ref(`retryQueue/${item.key}`).update({ attempt: nextAttempt, nextRetry: Date.now() + delay, lastError: err.message });
      console.log(`[RetryQueue] ❌ Retry ${nextAttempt} failed for ${item.paymentId}. Next in ${delay / 1000}s`);
    }
  }
}

// ── EXPIRED PAYMENT CLEANUP ─────────────
async function cleanupExpiredPayments() {
  const snap = await db.ref("paymentSessions").once("value");
  if (!snap.exists()) return;

  const now = Date.now();
  const expiredIds = [];
  snap.forEach(child => {
    const session = child.val();
    if (session.status === "pending" && session.expiresAt && session.expiresAt < now) {
      expiredIds.push({ key: child.key, merchantId: session.merchantId, decimalCode: session.decimalCode });
    }
  });

  for (const { key, merchantId, decimalCode } of expiredIds) {
    await db.ref(`paymentSessions/${key}`).update({ status: "expired" });
    await db.ref(`merchantPayments/${merchantId}/${key}`).update({ status: "expired" });
    await db.ref(`verificationQueue/${key}`).update({ status: "expired" });
    if (decimalCode) await db.ref(`amountReservations/${merchantId}/${decimalCode}`).remove();
    console.log(`[Cleanup] Expired payment ${key}`);
  }
}

// ── IP RETRY COUNT RESET (daily) ────────
async function resetIpCounters() {
  const hour = new Date().getHours();
  if (hour !== 0) return; // Only at midnight
  await db.ref("ipRetries").remove();
  console.log("[Cleanup] IP retry counters reset");
}

// ── STALE AMOUNT RESERVATION CLEANUP ───
async function cleanupAmountReservations() {
  const snap = await db.ref("amountReservations").once("value");
  if (!snap.exists()) return;

  const now = Date.now();
  snap.forEach(merchantSnap => {
    merchantSnap.forEach(resSnap => {
      const res = resSnap.val();
      if (res?.expiresAt && res.expiresAt < now) {
        db.ref(`amountReservations/${merchantSnap.key}/${resSnap.key}`).remove();
      }
    });
  });
}

// ── MAIN LOOP ───────────────────────────
async function runCron() {
  console.log(`[RetryQueue] Cron tick — ${new Date().toISOString()}`);
  try { await retryWebhooks(); } catch (e) { console.error("[RetryQueue] Webhook retry error:", e.message); }
  try { await cleanupExpiredPayments(); } catch (e) { console.error("[Cleanup] Expired cleanup error:", e.message); }
  try { await cleanupAmountReservations(); } catch (e) { console.error("[Cleanup] Amount res error:", e.message); }
  try { await resetIpCounters(); } catch (e) { console.error("[Cleanup] IP reset error:", e.message); }
}

// Run immediately, then every 60 seconds
runCron();
setInterval(runCron, 60 * 1000);
console.log("🔁 Empire Verify Retry Cron started");
