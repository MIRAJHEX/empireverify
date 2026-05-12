/**
 * Empire Verify — OneSignal Push Notification Helper
 * Usage: const notify = require('./onesignal');
 *        await notify.paymentSuccess(merchantId, amount, utr);
 */

const axios = require("axios");

const ONESIGNAL_APP_ID  = process.env.ONESIGNAL_APP_ID;
const ONESIGNAL_API_KEY = process.env.ONESIGNAL_REST_API_KEY;
const BASE_URL = "https://onesignal.com/api/v1/notifications";

async function send(payload) {
  if (!ONESIGNAL_APP_ID || !ONESIGNAL_API_KEY) return;
  try {
    await axios.post(BASE_URL, { app_id: ONESIGNAL_APP_ID, ...payload }, {
      headers: { Authorization: `Basic ${ONESIGNAL_API_KEY}`, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("[OneSignal] Push failed:", err.response?.data || err.message);
  }
}

// ── NOTIFICATION TEMPLATES ──────────────

/** Payment success — notify merchant by externalId (uid) */
async function paymentSuccess(merchantUid, amount, utr, paymentId) {
  await send({
    include_external_user_ids: [merchantUid],
    channel_for_external_user_ids: "push",
    headings: { en: "💸 Payment Received!" },
    contents: { en: `₹${amount} verified successfully. UTR: ${utr}` },
    data: { type: "payment_success", paymentId, amount, utr },
    android_accent_color: "FF6B00",
    ios_badge_type: "Increase",
    ios_badge_count: 1,
  });
}

/** Payment failed */
async function paymentFailed(merchantUid, paymentId, reason) {
  await send({
    include_external_user_ids: [merchantUid],
    channel_for_external_user_ids: "push",
    headings: { en: "❌ Payment Verification Failed" },
    contents: { en: `Payment ${paymentId.slice(-8)} could not be verified. ${reason || ""}` },
    data: { type: "payment_failed", paymentId },
    android_accent_color: "FF3D57",
  });
}

/** Fraud alert — notify admin segment */
async function fraudAlert(reason, paymentId, merchantId) {
  await send({
    included_segments: ["admin"],
    headings: { en: "🚨 Fraud Alert Detected" },
    contents: { en: `${reason} — Payment: ${paymentId} | Merchant: ${merchantId}` },
    data: { type: "fraud_alert", paymentId, merchantId, reason },
    android_accent_color: "FF3D57",
    priority: 10,
  });
}

/** Admin: new merchant registered */
async function newMerchant(merchantName, merchantId) {
  await send({
    included_segments: ["admin"],
    headings: { en: "👤 New Merchant Registered" },
    contents: { en: `${merchantName} has signed up and is pending approval.` },
    data: { type: "new_merchant", merchantId },
    android_accent_color: "FF6B00",
  });
}

/** Daily analytics summary to merchant */
async function dailySummary(merchantUid, totalSuccess, totalVolume, successRate) {
  await send({
    include_external_user_ids: [merchantUid],
    channel_for_external_user_ids: "push",
    headings: { en: "📊 Daily Payment Summary" },
    contents: { en: `${totalSuccess} payments · ₹${totalVolume.toLocaleString("en-IN")} · ${successRate}% success` },
    data: { type: "daily_summary" },
    android_accent_color: "00B0FF",
    delayed_option: "last-active",
  });
}

/** Worker health alert */
async function workerDown(workerId) {
  await send({
    included_segments: ["admin"],
    headings: { en: "⚠️ IMAP Worker Down" },
    contents: { en: `Worker ${workerId} has not pinged in over 5 minutes. Check PM2 logs.` },
    data: { type: "worker_down", workerId },
    android_accent_color: "FFB300",
    priority: 10,
  });
}

module.exports = { paymentSuccess, paymentFailed, fraudAlert, newMerchant, dailySummary, workerDown };
