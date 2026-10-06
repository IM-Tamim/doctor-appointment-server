// AI assistant endpoint: classify symptoms, then recommend real doctors from
// the database. The API key never leaves the server.
const rateLimit = require("express-rate-limit");
const { triage } = require("../lib/triage");

// Each call costs money: a tight per-IP budget on top of the general limiter.
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You're sending messages quickly — please wait a minute and try again." },
});

const DISCLAIMER = {
  en: "This assistant only suggests which kind of doctor to see. It is not a diagnosis or medical advice.",
  bn: "এই সহকারী শুধু কোন ধরনের ডাক্তার দেখাবেন তা পরামর্শ দেয়। এটি রোগ নির্ণয় বা চিকিৎসা পরামর্শ নয়।",
};
const EMERGENCY = {
  en: "This may be an emergency. Call 999 or go to the nearest hospital emergency department now.",
  bn: "এটি জরুরি অবস্থা হতে পারে। এখনই ৯৯৯-এ কল করুন বা নিকটস্থ হাসপাতালের জরুরি বিভাগে যান।",
};

module.exports = function registerAssistantRoutes(app, ctx) {
  const { db } = ctx;
  const doctors = db.collection("doctors");

  app.post("/ai/triage", aiLimiter, async (req, res) => {
    const lang = req.body?.lang === "bn" ? "bn" : "en";
    const message = String(req.body?.message || "").trim().slice(0, 1000);
    if (!message) return res.status(400).json({ message: "Describe your symptoms first." });

    // Only plain text turns, newest last, capped — the client can't inject
    // other roles or unbounded context.
    const history = (Array.isArray(req.body?.history) ? req.body.history : [])
      .filter((h) => (h?.role === "user" || h?.role === "assistant") && typeof h.content === "string" && h.content.trim())
      .slice(-6)
      .map((h) => ({ role: h.role, content: h.content.slice(0, 1000) }));
    // The API needs alternating turns starting with the user.
    while (history.length && history[0].role !== "user") history.shift();
    if (history.length && history[history.length - 1].role === "user") history.pop();

    const result = await triage({ message, history, lang });

    const matches = await doctors
      .find(
        { approvalStatus: "approved", specialty: result.specialty },
        { projection: { name: 1, image: 1, specialty: 1, hospital: 1, hospitalId: 1, fee: 1, rating: 1, totalReviews: 1, consultationType: 1 } }
      )
      .sort({ rating: -1, totalReviews: -1 })
      .limit(3)
      .toArray();

    res.json({
      reply: result.reply,
      followUpQuestion: result.followUpQuestion || null,
      specialty: result.specialty,
      urgency: result.urgency,
      emergency: result.urgency === "emergency",
      emergencyMessage: result.urgency === "emergency" ? EMERGENCY[lang] : null,
      redFlags: result.redFlags,
      doctors: matches,
      disclaimer: DISCLAIMER[lang],
      source: result.source,
    });
  });
};
