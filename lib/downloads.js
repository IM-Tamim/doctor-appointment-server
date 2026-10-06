// Short-lived download links for PDFs.
//
// The web app downloads receipts and prescriptions with fetch + a Bearer token
// and saves the blob. Android's WebView (the mobile app) can't save blobs, so
// the app instead asks for a one-off link and opens it in the system browser,
// which downloads the file normally. A link names one file, expires after a
// few minutes and carries no credentials of its own.
const crypto = require("crypto");

const LINK_MINUTES = 5;

const createDownloads = ({ app, db, serverUrl }) => {
  const tokens = db.collection("downloadTokens");
  tokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }).catch(() => {});

  const handlers = {};

  /** Registers how to stream one kind of file: `send(res, doc)`, doc = { id, lang }. */
  const register = (kind, send) => {
    handlers[kind] = send;
  };

  /** Creates a link for a file the caller has already been authorised to read. */
  const issue = async (kind, { id, lang }) => {
    const token = crypto.randomBytes(24).toString("hex");
    await tokens.insertOne({
      _id: token,
      kind,
      id: String(id),
      lang: lang === "bn" ? "bn" : "en",
      expiresAt: new Date(Date.now() + LINK_MINUTES * 60 * 1000),
    });
    return `${serverUrl()}/files/${token}`;
  };

  app.get("/files/:token", async (req, res) => {
    const doc = await tokens.findOne({ _id: String(req.params.token), expiresAt: { $gt: new Date() } });
    const send = doc && handlers[doc.kind];
    if (!send) return res.status(410).type("text/plain").send("This download link has expired. Go back to the app and try again.");
    await send(res, doc);
  });

  return { register, issue };
};

module.exports = { createDownloads };
