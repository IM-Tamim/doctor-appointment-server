const { sendEmail } = require("./email");

// notificationsCollection is passed in per-call to avoid a circular import
// with index.js, where all collections are created inside run().
const notify = async ({
  notificationsCollection,
  userId,
  type,
  message,
  email, // { to, subject, html } — optional, only sent if provided
}) => {
  try {
    await notificationsCollection.insertOne({
      userId,
      type,
      message,
      read: false,
      createdAt: new Date(),
    });
  } catch (err) {
    console.error("Failed to write notification:", err.message);
  }

  // Fire-and-forget on purpose. This used to be awaited, which meant the HTTP
  // response waited for Gmail's SMTP handshake — and on hosts that block
  // outbound SMTP (Render's free tier does) that hangs until the TCP timeout.
  // Measured effect: a booking took 121s to respond instead of ~1s, so the
  // spinner never stopped even though the appointment had already been saved.
  // A notification email is not worth blocking a user-facing write on.
  if (email) {
    sendEmail(email).catch((err) =>
      console.error("Background email failed:", err?.message || err)
    );
  }
};

module.exports = { notify };
