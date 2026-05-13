/**
 * Empire Verify — Retry Queue Cron
 * Runs every 60s — retries failed webhooks + cleans expired payments
 */
require("dotenv").config();
const admin = require("firebase-admin");
const axios = require("axios");
const crypto = require("crypto");

if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount), databaseURL: "https://empirewin-store-default-rtdb.firebaseio.com" });
}
const db = admin.database();

async function retryWebhooks() {
  const snap = await db.ref("retryQueue").orderByChild("nextRetry").endAt(Date.now()).once("value");
  if (!snap.exists()) return;
  const items = [];
  snap.forEach(c => items.push({ key: c.key, ...c.val() }));
  for (const item of items) {
    if ((item.attempt||1) >= 5) { await db.ref(`retryQueue/${item.key}`).remove(); continue; }
    try {
      const keysSnap = await db.ref(`merchantApiKeys/${item.merchantId}`).once("value");
      const keys     = keysSnap.val();
      const mSnap    = await db.ref(`merchants/${item.merchantId}`).once("value");
      const merchant = mSnap.val();
      if (!merchant?.webhookUrl||!keys) { await db.ref(`retryQueue/${item.key}`).remove(); continue; }
      const sig = crypto.createHmac("sha256", keys.webhookSecret).update(JSON.stringify(item.payload)).digest("hex");
      await axios.post(merchant.webhookUrl, item.payload, { headers:{"X-EmpireVerify-Signature":sig,"Content-Type":"application/json"}, timeout:10000 });
      await db.ref(`retryQueue/${item.key}`).remove();
      console.log(`[Cron] ✅ Webhook retried for ${item.paymentId}`);
    } catch (err) {
      const next = (item.attempt||1) + 1;
      await db.ref(`retryQueue/${item.key}`).update({ attempt:next, nextRetry:Date.now()+Math.min(60000*Math.pow(2,next),3600000) });
    }
  }
}

async function cleanupExpired() {
  const snap = await db.ref("paymentSessions").once("value");
  if (!snap.exists()) return;
  const now = Date.now();
  snap.forEach(c => {
    const s = c.val();
    if (s.status==="pending" && s.expiresAt && s.expiresAt < now) {
      db.ref(`paymentSessions/${c.key}`).update({ status:"expired" });
      db.ref(`merchantPayments/${s.merchantId}/${c.key}`).update({ status:"expired" });
      if (s.decimalCode) db.ref(`amountReservations/${s.merchantId}/${s.decimalCode}`).remove();
    }
  });
}

async function cleanupAmountReservations() {
  const snap = await db.ref("amountReservations").once("value");
  if (!snap.exists()) return;
  const now = Date.now();
  snap.forEach(mSnap => mSnap.forEach(rSnap => {
    if (rSnap.val()?.expiresAt < now) db.ref(`amountReservations/${mSnap.key}/${rSnap.key}`).remove();
  }));
}

async function runCron() {
  console.log(`[Cron] Tick — ${new Date().toISOString()}`);
  await retryWebhooks().catch(e => console.error("[Cron] Webhook retry error:", e.message));
  await cleanupExpired().catch(e => console.error("[Cron] Cleanup error:", e.message));
  await cleanupAmountReservations().catch(e => console.error("[Cron] Amount res error:", e.message));
}

runCron();
setInterval(runCron, 60 * 1000);
console.log("🔁 Retry Cron started");
