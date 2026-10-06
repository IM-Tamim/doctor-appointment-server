// Per-account extras: saved doctors, family profiles and reviewable visits.
// Both lists live on the Better Auth `user` document and are always keyed by
// the id in the JWT — never by anything in the request body.
const { ObjectId } = require("mongodb");

const MAX_SAVED = 100;
const MAX_PROFILES = 10;
const RELATIONS = ["spouse", "child", "father", "mother", "sibling", "grandparent", "relative", "other"];
const GENDERS = ["Male", "Female", "Other"];

const PUBLIC_DOCTOR_FIELDS = {
  name: 1, image: 1, specialty: 1, hospital: 1, hospitalId: 1, fee: 1, rating: 1, totalReviews: 1,
  experience: 1, location: 1, availability: 1, maxPerHour: 1, consultationType: 1,
};

module.exports = function registerPatientRoutes(app, ctx) {
  const { db, verifyToken, writeLimiter } = ctx;
  const users = db.collection("user");
  const doctors = db.collection("doctors");
  const appointments = db.collection("appointments");
  const me = (req) => ({ _id: new ObjectId(req.user.id) });

  // ── Saved doctors ───────────────────────────────────────────────────────

  app.get("/me/saved-doctors", verifyToken, async (req, res) => {
    const user = await users.findOne(me(req), { projection: { savedDoctors: 1 } });
    const ids = (user?.savedDoctors || []).filter(ObjectId.isValid);
    if (req.query.ids === "1") return res.json(ids);
    // One $in query for the cards, in the order they were saved (newest first).
    const docs = await doctors
      .find({ _id: { $in: ids.map((id) => new ObjectId(id)) }, approvalStatus: "approved" }, { projection: PUBLIC_DOCTOR_FIELDS })
      .toArray();
    const byId = new Map(docs.map((d) => [d._id.toString(), d]));
    res.json([...ids].reverse().map((id) => byId.get(id)).filter(Boolean));
  });

  app.put("/me/saved-doctors/:doctorId", writeLimiter, verifyToken, async (req, res) => {
    const { doctorId } = req.params;
    if (!ObjectId.isValid(doctorId)) return res.status(400).json({ message: "Invalid doctor id." });
    const exists = await doctors.countDocuments({ _id: new ObjectId(doctorId), approvalStatus: "approved" });
    if (!exists) return res.status(404).json({ message: "Doctor not found." });
    const user = await users.findOne(me(req), { projection: { savedDoctors: 1 } });
    if ((user?.savedDoctors || []).length >= MAX_SAVED && !(user.savedDoctors || []).includes(doctorId)) {
      return res.status(400).json({ message: `You can save up to ${MAX_SAVED} doctors.` });
    }
    await users.updateOne(me(req), { $addToSet: { savedDoctors: doctorId } });
    res.json({ saved: true });
  });

  app.delete("/me/saved-doctors/:doctorId", verifyToken, async (req, res) => {
    await users.updateOne(me(req), { $pull: { savedDoctors: req.params.doctorId } });
    res.json({ saved: false });
  });

  // ── Family profiles ─────────────────────────────────────────────────────

  const parseProfile = (body, { partial = false } = {}) => {
    const out = {};
    if (body.name !== undefined || !partial) {
      const name = String(body.name || "").trim().slice(0, 80);
      if (!name) return { error: "Name is required." };
      out.name = name;
    }
    if (body.age !== undefined || !partial) {
      const age = Number(body.age);
      if (!Number.isFinite(age) || age < 0 || age > 120) return { error: "Age must be between 0 and 120." };
      out.age = Math.round(age);
    }
    if (body.gender !== undefined || !partial) {
      if (!GENDERS.includes(body.gender)) return { error: "Choose a gender." };
      out.gender = body.gender;
    }
    if (body.relation !== undefined || !partial) {
      if (!RELATIONS.includes(body.relation)) return { error: "Choose how this person is related to you." };
      out.relation = body.relation;
    }
    return { value: out };
  };

  app.get("/me/profiles", verifyToken, async (req, res) => {
    const user = await users.findOne(me(req), { projection: { profiles: 1 } });
    res.json(user?.profiles || []);
  });

  app.post("/me/profiles", writeLimiter, verifyToken, async (req, res) => {
    const { value, error } = parseProfile(req.body);
    if (error) return res.status(400).json({ message: error });
    const user = await users.findOne(me(req), { projection: { profiles: 1 } });
    if ((user?.profiles || []).length >= MAX_PROFILES) {
      return res.status(400).json({ message: `You can add up to ${MAX_PROFILES} family members.` });
    }
    const profile = { id: new ObjectId().toString(), ...value, createdAt: new Date() };
    await users.updateOne(me(req), { $push: { profiles: profile } });
    res.json(profile);
  });

  app.patch("/me/profiles/:pid", verifyToken, async (req, res) => {
    const { value, error } = parseProfile(req.body, { partial: true });
    if (error) return res.status(400).json({ message: error });
    const set = Object.fromEntries(Object.entries(value).map(([k, v]) => [`profiles.$.${k}`, v]));
    if (Object.keys(set).length === 0) return res.status(400).json({ message: "Nothing to update." });
    const result = await users.updateOne({ ...me(req), "profiles.id": req.params.pid }, { $set: set });
    if (result.matchedCount === 0) return res.status(404).json({ message: "Profile not found." });
    res.json({ acknowledged: true });
  });

  app.delete("/me/profiles/:pid", verifyToken, async (req, res) => {
    // Past appointments keep their name/age snapshot, so history stays intact.
    const upcoming = await appointments.countDocuments({
      userId: req.user.id,
      profileId: req.params.pid,
      isActive: true,
      status: { $in: ["pending", "confirmed"] },
    });
    if (upcoming > 0) {
      return res.status(409).json({ message: "This person has upcoming appointments. Cancel them first." });
    }
    await users.updateOne(me(req), { $pull: { profiles: { id: req.params.pid } } });
    res.json({ acknowledged: true });
  });

  // ── Reviews: completed, not-yet-reviewed visits with a doctor ───────────

  app.get("/me/reviewable", verifyToken, async (req, res) => {
    const filter = { userId: req.user.id, status: "completed", reviewed: { $ne: true } };
    if (req.query.doctorId) filter.doctorId = String(req.query.doctorId);
    const list = await appointments
      .find(filter, { projection: { doctorId: 1, doctorName: 1, appointmentDate: 1, appointmentTime: 1, patientName: 1 } })
      .sort({ appointmentDate: -1 })
      .limit(20)
      .toArray();
    res.json(list);
  });
};
