const nodemailer = require("nodemailer");

// Gmail SMTP via an App Password (not your real Gmail password).
// Setup: Google Account → Security → 2-Step Verification (must be on)
//        → App Passwords → generate one for "Mail".
// Unlike Resend's free tier, this can send to ANY real recipient —
// no domain verification or "only your own email" restriction.
// Built on first use, not at import time. index.js requires this module on
// line 8 but only calls dotenv.config() on line 11, so reading process.env up
// here saw undefined credentials and silently disabled email for the whole
// process. It worked on Render purely because the platform injects env vars
// before Node starts — so local dev quietly never sent anything.
let transporter;

const getTransporter = () => {
  if (transporter !== undefined) return transporter;

  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    transporter = null;
    return transporter;
  }

  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
    // Without these, a host that silently drops outbound SMTP (Render's free
    // tier) leaves the socket open until the OS gives up — minutes, not
    // seconds. Fail fast and log instead.
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
  });
  return transporter;
};

const sendEmail = async ({ to, subject, html }) => {
  const tx = getTransporter();
  if (!tx) {
    console.log(`[email skipped - not configured] to=${to} subject="${subject}"`);
    return;
  }
  try {
    await tx.sendMail({
      from: `DocAppoint <${process.env.GMAIL_USER}>`,
      to,
      subject,
      html,
    });
  } catch (err) {
    console.error("Failed to send email:", err.message);
  }
};

module.exports = { sendEmail };
