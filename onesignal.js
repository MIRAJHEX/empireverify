/**
 * Empire Verify — OneSignal Push Helper
 * Exact cludeinfo.md credentials
 */
const axios = require("axios");

// Obfuscated keys (base64) — cludeinfo rule
const _appId  = Buffer.from("OGJiZWJhNGMtMGQzNi00OThkLWE4NTUtMmE1ZTIyOGIyYTEw","base64").toString();
const _apiKey = Buffer.from("b3NfdjJfYXBwX3JvN2x1dGFuZ3pleStrY3ZmanBjZmN6a2NjbGxoNW92d3ZydXBjNTVrcXh3eTVyamNveDNkejQzaGRqdnVsM3I1YnRybnJ3M3JlemVkNW1jNDc1bDJrZmR0NHFiNXRvdWthbm9mcHk=","base64").toString();

async function send(payload) {
  try {
    await axios.post("https://onesignal.com/api/v1/notifications", {
      app_id: _appId, ...payload
    }, {
      headers: { Authorization: `Basic ${_apiKey}`, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("[OneSignal] Push failed:", err.response?.data || err.message);
  }
}

async function paymentSuccess(merchantUid, amount, utr, paymentId) {
  await send({
    include_external_user_ids: [merchantUid],
    channel_for_external_user_ids: "push",
    headings: { en: "💸 Payment Received!" },
    contents: { en: `₹${amount} verified successfully. UTR: ${utr}` },
    data: { type: "payment_success", paymentId, amount, utr },
    android_accent_color: "ff6a00",
  });
}

async function paymentFailed(merchantUid, paymentId, reason) {
  await send({
    include_external_user_ids: [merchantUid],
    channel_for_external_user_ids: "push",
    headings: { en: "❌ Payment Verification Failed" },
    contents: { en: `Payment ${paymentId.slice(-8)} could not be verified.` },
    data: { type: "payment_failed", paymentId },
    android_accent_color: "ef4444",
  });
}

async function fraudAlert(reason, paymentId, merchantId) {
  await send({
    included_segments: ["All"],
    headings: { en: "🚨 Fraud Alert" },
    contents: { en: `${reason} — Payment: ${paymentId}` },
    data: { type: "fraud_alert", paymentId, merchantId, reason },
    priority: 10,
  });
}

async function newMerchant(merchantName, merchantId) {
  await send({
    included_segments: ["All"],
    headings: { en: "👤 New Merchant Registered" },
    contents: { en: `${merchantName} signed up. Pending approval.` },
    data: { type: "new_merchant", merchantId },
  });
}

async function workerDown(workerId) {
  await send({
    included_segments: ["All"],
    headings: { en: "⚠️ IMAP Worker Down" },
    contents: { en: `Worker ${workerId} not responding. Check Railway logs.` },
    priority: 10,
  });
}

module.exports = { paymentSuccess, paymentFailed, fraudAlert, newMerchant, workerDown };
