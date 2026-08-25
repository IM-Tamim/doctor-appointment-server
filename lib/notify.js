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

  if (email) {
    await sendEmail(email);
  }
};

module.exports = { notify };
