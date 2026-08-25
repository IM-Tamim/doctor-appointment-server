const nodemailer = require("nodemailer");

// Gmail SMTP via an App Password (not your real Gmail password).
// Setup: Google Account → Security → 2-Step Verification (must be on)
//        → App Passwords → generate one for "Mail".
// Unlike Resend's free tier, this can send to ANY real recipient —
// no domain verification or "only your own email" restriction.
let transporter = null;

if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

// Fire-and-forget: never throw from a route because an email failed to send.
const sendEmail = async ({ to, subject, html }) => {
  if (!transporter) {
    console.log(`[email skipped - not configured] to=${to} subject="${subject}"`);
    return;
  }
  try {
    await transporter.sendMail({
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
