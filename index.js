const express = require("express");
require("express-async-errors");
const dotenv = require("dotenv");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");
const requireRole = require("./middleware/requireRole");
const { notify } = require("./lib/notify");
const rateLimit = require("express-rate-limit");

dotenv.config();

// Some Windows setups (extra VPN/virtual adapters) stop Node's c-ares resolver from
// reading the system DNS config; it then falls back to 127.0.0.1, where nothing is
// listening, and the mongodb+srv:// SRV lookup dies with ECONNREFUSED. Only kicks in
// when the resolver is loopback-only, so a healthy machine is left alone.
{
  const dns = require("dns");
  const loopbackOnly = dns
    .getServers()
    .every((s) => s.startsWith("127.") || s === "::1" || s === "[::1]");
  if (loopbackOnly) {
    const fallback = (process.env.DNS_SERVERS || "8.8.8.8,1.1.1.1")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    dns.setServers(fallback);
    console.warn(`[dns] system resolver unreadable; using ${fallback.join(", ")}`);
  }
}
const app = express();

// Origins are compared literally against the browser's Origin header, which
// never has a trailing slash. CLIENT_URL="https://site.app/" would silently
// match nothing, so normalise both sides.
const normaliseOrigin = (value) => (value || "").trim().replace(/\/+$/, "");

const allowedOrigins = [
  normaliseOrigin(process.env.CLIENT_URL),
  ...(process.env.EXTRA_ORIGINS || "").split(",").map(normaliseOrigin),
].filter(Boolean);

// Fail loudly at boot instead of silently rejecting every browser request.
// Without CLIENT_URL the allowlist is empty AND the JWKS URL below is
// "undefined/api/auth/jwks", so the whole app looks broken for two reasons at
// once — which is exactly the failure this guard is here to make obvious.
if (process.env.NODE_ENV === "production" && allowedOrigins.length === 0) {
  console.error(
    "[config] FATAL: CLIENT_URL is not set. In production every browser request " +
    "will be blocked by CORS and every JWT will fail to verify. Set CLIENT_URL " +
    "to your deployed frontend origin, e.g. https://your-site.netlify.app"
  );
}

app.use(cors({
  origin: (origin, cb) => {
    // Same-origin/curl/server-to-server requests send no Origin header.
    if (!origin) return cb(null, true);
    if (process.env.NODE_ENV !== "production") return cb(null, true);
    if (allowedOrigins.includes(normaliseOrigin(origin))) return cb(null, true);

    // Deny by *omitting* the CORS headers rather than throwing. Throwing here
    // turns a policy decision into an unhandled error, and the preflight comes
    // back as a 500 — which reads like the server crashed instead of "this
    // origin isn't on the list".
    console.warn(`[cors] blocked origin: ${origin} (allowed: ${allowedOrigins.join(", ") || "none"})`);
    return cb(null, false);
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Cap the body so a huge payload can't be used to exhaust memory.
app.use(express.json({ limit: "100kb" }));

// Booking and review endpoints write to the database on every call, so they get
// a tighter budget than plain reads.
const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please slow down and try again shortly." },
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again shortly." },
});

app.use(generalLimiter);
const port = process.env.PORT || 8000;
const uri = process.env.MONGO_URI;

// Public keys are fetched from the client app, so this URL is only valid if
// CLIENT_URL points at the deployed frontend.
const JWKS_URL = `${normaliseOrigin(process.env.CLIENT_URL)}/api/auth/jwks`;

// Built lazily and defensively. `new URL()` on a missing or malformed
// CLIENT_URL throws ERR_INVALID_URL at import time, which killed the whole
// process before it could serve even the public routes or /health — the worst
// possible way to report a one-line config mistake.
let JWKS = null;
try {
  JWKS = createRemoteJWKSet(new URL(JWKS_URL));
} catch (err) {
  console.error(
    `[auth] CLIENT_URL is missing or malformed, so JWKS is unavailable ` +
    `(tried "${JWKS_URL}"). Public routes still work; anything needing a login ` +
    `will return 503 until CLIENT_URL is set to the deployed frontend origin.`
  );
}

const verifyToken = async (req, res, next) => {
  const authHeader = req?.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const token = authHeader?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  if (!JWKS) {
    return res.status(503).json({
      message:
        "Auth is misconfigured on the server: CLIENT_URL is not set to a valid " +
        "frontend origin, so token signing keys can't be fetched.",
    });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload; // { id, email, name, role, status }
    next();
  } catch (error) {
    // A blanket 403 hid a config problem behind what looks like a rejected
    // login: if the JWKS endpoint is unreachable, EVERY token fails here no
    // matter how valid it is. Separate the two so the cause is visible.
    const isFetchProblem =
      error?.code === "ERR_JWKS_TIMEOUT" ||
      error?.code === "ERR_JWKS_NO_MATCHING_KEY" ||
      /fetch|network|ENOTFOUND|ECONNREFUSED|Invalid URL|failed to fetch/i.test(error?.message || "");

    if (isFetchProblem) {
      console.error(`[auth] cannot verify tokens — JWKS fetch failed from ${JWKS_URL}: ${error.message}`);
      return res.status(503).json({
        message:
          "Auth is misconfigured on the server: the token signing keys could not be fetched. " +
          "Check that CLIENT_URL matches the deployed frontend.",
      });
    }

    return res.status(403).json({ message: "Forbidden" });
  }
};

/**
 * Config probe. Deliberately reports only whether things are *set* and whether
 * the JWKS endpoint answers — never the values themselves.
 */
app.get("/health", async (req, res) => {
  let jwks = "unknown";
  try {
    // Generous: a cold serverless frontend can take several seconds to wake,
    // and a false "unreachable" here would send you chasing the wrong problem.
    const r = await fetch(JWKS_URL, { signal: AbortSignal.timeout(12000) });
    jwks = r.ok ? "reachable" : `HTTP ${r.status}`;
  } catch (err) {
    jwks = `unreachable (${err.message})`;
  }

  res.json({
    ok: allowedOrigins.length > 0 && jwks === "reachable",
    nodeEnv: process.env.NODE_ENV || "(unset)",
    clientUrlSet: Boolean(process.env.CLIENT_URL),
    allowedOrigins,
    jwksUrl: JWKS_URL,
    jwks,
    mongoUriSet: Boolean(process.env.MONGO_URI),
    emailConfigured: Boolean(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD),
  });
});

// ────────────────────────────────────────────────────────────
// Booking validation
// ────────────────────────────────────────────────────────────

const WEEKDAYS = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];

/**
 * A booking is only valid if the doctor actually works that weekday and
 * publishes that exact slot. The client shows a dropdown built from the same
 * data, but the dropdown is just UX — anyone can POST whatever they like, so
 * the real check has to live here.
 */
const validateSlot = (doctor, dateStr, timeStr) => {
  if (!dateStr || !timeStr) return "Appointment date and time are required.";

  const date = new Date(`${dateStr}T00:00:00`);
  if (Number.isNaN(date.getTime())) return "Invalid appointment date.";

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (date < today) return "Appointment date cannot be in the past.";

  // A one-off day off (holiday, leave, conference) beats the weekly pattern.
  if (Array.isArray(doctor.blockedDates) && doctor.blockedDates.includes(dateStr)) {
    return `${doctor.name} is not available on ${dateStr}.`;
  }

  const weekday = WEEKDAYS[date.getDay()];
  const availability = Array.isArray(doctor.availability) ? doctor.availability : [];
  const forDay = availability.find((a) => a.day === weekday);

  if (!forDay || !Array.isArray(forDay.slots) || forDay.slots.length === 0) {
    return `${doctor.name} does not consult on ${weekday}.`;
  }
  if (!forDay.slots.includes(timeStr)) {
    return `${timeStr} is not one of ${doctor.name}'s ${weekday} slots (${forDay.slots.join(", ")}).`;
  }
  return null;
};

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const db = client.db("DocAppoint");

    // Indexes are created once at boot and are no-ops if they already exist.
    // Without these, every "my appointments" read and every double-booking
    // check is a full collection scan.
    await Promise.all([
      db.collection("appointments").createIndex({ userEmail: 1, createdAt: -1 }),
      db.collection("appointments").createIndex({ doctorId: 1, appointmentDate: 1, appointmentTime: 1 }),
      db.collection("doctors").createIndex({ approvalStatus: 1 }),
      db.collection("doctors").createIndex({ userId: 1 }),
      db.collection("doctors").createIndex({ email: 1 }),
      db.collection("notifications").createIndex({ userId: 1, createdAt: -1 }),
    ]).catch((err) => console.warn("Index creation skipped:", err.message));
    const doctorCollection = db.collection("doctors");
    const appointmentsCollection = db.collection("appointments");
    const notificationsCollection = db.collection("notifications");
    const userCollection = db.collection("user"); // Better Auth's collection name

    // ────────────────────────────────────────────────────────────
    // PUBLIC: Doctors listing / details
    // ────────────────────────────────────────────────────────────

    app.get("/doctors", async (req, res) => {
      const result = await doctorCollection
        .find({ approvalStatus: "approved" })
        .toArray();
      res.json(result);
    });

    app.get("/doctors/my-application", verifyToken, async (req, res) => {
      const application = await doctorCollection.findOne({ userId: req.user.id });
      if (!application) return res.json(null);
      res.json({
        approvalStatus: application.approvalStatus,
        rejectionReason: application.rejectionReason || "",
        specialty: application.specialty,
        createdAt: application.createdAt,
      });
    });

    app.get("/doctors/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid doctor id." });
      }
      const result = await doctorCollection.findOne({ _id: new ObjectId(id) });
      res.json(result);
    });

    // ────────────────────────────────────────────────────────────
    // DOCTOR ONBOARDING (any logged-in user applies)
    // ────────────────────────────────────────────────────────────

    app.post("/doctors/apply", writeLimiter, verifyToken, async (req, res) => {
      const { degree, registrationNumber, hospital, specialty, credentialImageUrl, bio, fee, image, name, experience, location, phone } = req.body;

      const existing = await doctorCollection.findOne({ userId: req.user.id });

      // Only block if there's an active (pending) or already-successful
      // (approved) application. A rejected one can be resubmitted — we
      // update it in place rather than blocking or creating a duplicate.
      if (existing && existing.approvalStatus !== "rejected") {
        return res.status(400).json({
          message:
            existing.approvalStatus === "approved"
              ? "You're already an approved doctor."
              : "You already have a pending application.",
        });
      }

      // Credential document is mandatory — it's the only way an admin can
      // manually verify this is a real doctor before approving.
      if (!credentialImageUrl) {
        return res.status(400).json({ message: "A credential document is required to apply." });
      }
      if (!specialty || !degree || !registrationNumber || !hospital || !phone) {
        return res.status(400).json({ message: "Please fill in all required fields." });
      }

      const doctorFields = {
        userId: req.user.id,
        // Guaranteed non-null: a doctor doc with no name would crash any UI
        // that does doctor.name.toLowerCase() (e.g. the search page).
        name: name || req.user.name || req.user.email || "Unnamed Applicant",
        email: req.user.email,
        phone,
        specialty,
        degree,
        registrationNumber,
        hospital,
        location: location || "",
        experience: experience || "",
        credentialImageUrl,
        bio: bio || "",
        fee: fee || 0,
        image: image || "",
        approvalStatus: "pending",
        rejectionReason: "",
        createdAt: new Date(),
      };

      let result;
      if (existing) {
        // Resubmitting after rejection — update the same document instead
        // of creating a duplicate, but keep any existing rating/reviews.
        result = await doctorCollection.updateOne(
          { _id: existing._id },
          { $set: doctorFields }
        );
      } else {
        result = await doctorCollection.insertOne({
          ...doctorFields,
          rating: 0,
          totalReviews: 0,
          reviews: [],
          availability: [],
        });
      }

      await userCollection.updateOne(
        { _id: new ObjectId(req.user.id) },
        { $set: { status: "pending" } }
      );

      // Notify every admin so applications don't sit unnoticed.
      const admins = await userCollection.find({ role: "admin" }).toArray();
      for (const admin of admins) {
        await notify({
          notificationsCollection,
          userId: admin._id.toString(),
          type: "new_doctor_application",
          message: `${doctorFields.name} applied to become a doctor (${specialty}). Review their application.`,
          email: admin.email && {
            to: admin.email,
            subject: "New doctor application — DocAppoint",
            html: `<p><b>${doctorFields.name}</b> applied to become a doctor (${specialty}). Please review their credentials in the admin dashboard.</p>`,
          },
        });
      }

      res.json(result);
    });

    // ────────────────────────────────────────────────────────────
    // DOCTOR PANEL (requires role: doctor)
    // ────────────────────────────────────────────────────────────

    const getMyDoctorDoc = (userId) => doctorCollection.findOne({ userId });

    app.get("/doctor/profile", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });
      res.json(doctor);
    });

    app.patch("/doctor/profile", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

      const { bio, fee, image, specialty, hospital, experience, location } = req.body;
      const update = {};
      if (bio !== undefined) update.bio = bio;
      if (fee !== undefined) update.fee = fee;
      if (image !== undefined) update.image = image;
      if (specialty !== undefined) update.specialty = specialty;
      if (hospital !== undefined) update.hospital = hospital;
      if (experience !== undefined) update.experience = experience;
      if (location !== undefined) update.location = location;

      const result = await doctorCollection.updateOne({ _id: doctor._id }, { $set: update });
      res.json(result);
    });

    app.patch("/doctor/availability", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

      const { availability, blockedDates } = req.body;

      const update = {};

      if (availability !== undefined) {
        if (!Array.isArray(availability)) {
          return res.status(400).json({ message: "availability must be an array." });
        }
        // Normalise rather than trusting the shape — a malformed entry here
        // would silently break every booking validation later.
        update.availability = availability
          .filter((a) => a && WEEKDAYS.includes(a.day))
          .map((a) => ({
            day: a.day,
            slots: Array.isArray(a.slots)
              ? [...new Set(a.slots.filter((s) => /^\d{2}:\d{2}$/.test(s)))].sort()
              : [],
          }));
      }

      if (blockedDates !== undefined) {
        if (!Array.isArray(blockedDates)) {
          return res.status(400).json({ message: "blockedDates must be an array." });
        }
        update.blockedDates = [
          ...new Set(blockedDates.filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d))),
        ].sort();
      }

      if (Object.keys(update).length === 0) {
        return res.status(400).json({ message: "Nothing to update." });
      }

      const result = await doctorCollection.updateOne({ _id: doctor._id }, { $set: update });
      res.json(result);
    });

    app.get("/doctor/appointments", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

      const result = await appointmentsCollection
        .find({ doctorId: doctor._id.toString() })
        .sort({ appointmentDate: -1 })
        .toArray();
      res.json(result);
    });

    app.patch("/doctor/appointments/:id/status", verifyToken, requireRole("doctor"), async (req, res) => {
      const { id } = req.params;
      const { status } = req.body;

      if (!["confirmed", "cancelled", "completed"].includes(status)) {
        return res.status(400).json({ message: "Invalid status" });
      }

      const appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!appointment) return res.status(404).json({ message: "Appointment not found" });

      // requireRole("doctor") only proves the caller is *a* doctor. Without
      // this, any doctor could confirm, cancel or complete another doctor's
      // appointments just by knowing the id.
      const me = await getMyDoctorDoc(req.user.id);
      if (!me || appointment.doctorId !== me._id.toString()) {
        return res.status(403).json({ message: "This appointment is not yours." });
      }

      const result = await appointmentsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );

      const patient = await userCollection.findOne({ email: appointment.userEmail });
      if (patient) {
        await notify({
          notificationsCollection,
          userId: patient._id.toString(),
          type: `appointment_${status}`,
          message: `Your appointment on ${appointment.appointmentDate} at ${appointment.appointmentTime} was ${status}.`,
          email: {
            to: appointment.userEmail,
            subject: `Appointment ${status} — DocAppoint`,
            html: `<p>Your appointment on <b>${appointment.appointmentDate}</b> at <b>${appointment.appointmentTime}</b> has been <b>${status}</b>.</p>`,
          },
        });
      }

      res.json(result);
    });

    app.patch("/doctor/appointments/:id/prescription", verifyToken, requireRole("doctor"), async (req, res) => {
      const { id } = req.params;
      const { notes, fileUrl } = req.body;

      const appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!appointment) return res.status(404).json({ message: "Appointment not found" });

      // A prescription is medical data — only the treating doctor may attach one.
      const me = await getMyDoctorDoc(req.user.id);
      if (!me || appointment.doctorId !== me._id.toString()) {
        return res.status(403).json({ message: "This appointment is not yours." });
      }

      const result = await appointmentsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { prescription: { notes: notes || "", fileUrl: fileUrl || "", addedAt: new Date() } } }
      );
      res.json(result);
    });

    // ────────────────────────────────────────────────────────────
    // APPOINTMENTS (patient-facing)
    // ────────────────────────────────────────────────────────────

    app.post("/appointments", writeLimiter, verifyToken, async (req, res) => {
      const { doctorId, patientName, gender, phone, appointmentDate, appointmentTime, reason } = req.body;

      if (!doctorId || !ObjectId.isValid(doctorId)) {
        return res.status(400).json({ message: "A valid doctorId is required." });
      }

      const doctor = await doctorCollection.findOne({ _id: new ObjectId(doctorId) });
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });
      if (doctor.approvalStatus && doctor.approvalStatus !== "approved") {
        return res.status(403).json({ message: "This doctor is not accepting bookings yet." });
      }

      const slotError = validateSlot(doctor, appointmentDate, appointmentTime);
      if (slotError) return res.status(400).json({ message: slotError });

      // Don't let two patients hold the same slot.
      const clash = await appointmentsCollection.findOne({
        doctorId,
        appointmentDate,
        appointmentTime,
        status: { $ne: "cancelled" },
      });
      if (clash) {
        return res.status(409).json({ message: "That slot has just been taken. Please pick another." });
      }

      // Identity comes from the verified JWT, never from the request body —
      // otherwise a patient could book (and later read) under someone else's
      // email just by editing the payload.
      const appointment = {
        userEmail: req.user.email,
        userId: req.user.id,
        doctorId,
        doctorName: doctor.name,
        patientName: patientName || req.user.name,
        gender: gender || "",
        phone: phone || "",
        appointmentDate,
        appointmentTime,
        reason: reason || "",
        status: "pending",
        createdAt: new Date(),
      };

      const result = await appointmentsCollection.insertOne(appointment);

      if (doctor?.userId) {
        await notify({
          notificationsCollection,
          userId: doctor.userId,
          type: "new_booking",
          message: `New appointment booked by ${appointment.patientName || appointment.userEmail} on ${appointment.appointmentDate} at ${appointment.appointmentTime}.`,
          email: doctor.email && {
            to: doctor.email,
            subject: "New appointment booked — DocAppoint",
            html: `<p>You have a new booking from <b>${appointment.patientName || appointment.userEmail}</b> on <b>${appointment.appointmentDate}</b> at <b>${appointment.appointmentTime}</b>.</p>`,
          },
        });
      }

      res.json(result);
    });

    // Was unauthenticated and filtered by ?email= from the query string, so
    // anyone could read any patient's appointment history — medical data —
    // just by guessing an address. Now it only ever returns the caller's own.
    app.get("/appointments", verifyToken, async (req, res) => {
      const result = await appointmentsCollection
        .find({ userEmail: req.user.email })
        .sort({ createdAt: -1 })
        .toArray();
      res.json(result);
    });

    app.patch("/appointments/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const existing = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).json({ message: "Appointment not found" });

      // Patients may only edit/cancel while it's still pending — once a doctor
      // has acted on it (confirmed/completed/cancelled), it's locked on their side.
      // verifyToken only proves *who* you are. Without this, any signed-in user
      // could reschedule or cancel a stranger's appointment by guessing its id.
      if (existing.userEmail !== req.user.email && req.user.role !== "admin") {
        return res.status(403).json({ message: "This is not your appointment." });
      }

      if (existing.status && existing.status !== "pending") {
        return res.status(403).json({ message: "This appointment can no longer be edited." });
      }

      const allowed = {};
      const newDate = req.body.appointmentDate ?? existing.appointmentDate;
      const newTime = req.body.appointmentTime ?? existing.appointmentTime;

      if (req.body.appointmentDate !== undefined || req.body.appointmentTime !== undefined) {
        const doctor = await doctorCollection.findOne({ _id: new ObjectId(existing.doctorId) });
        if (!doctor) return res.status(404).json({ message: "Doctor not found." });

        // Rescheduling has to respect availability exactly like booking does.
        const slotError = validateSlot(doctor, newDate, newTime);
        if (slotError) return res.status(400).json({ message: slotError });

        const clash = await appointmentsCollection.findOne({
          _id: { $ne: new ObjectId(id) },
          doctorId: existing.doctorId,
          appointmentDate: newDate,
          appointmentTime: newTime,
          status: { $ne: "cancelled" },
        });
        if (clash) {
          return res.status(409).json({ message: "That slot is already taken. Please pick another." });
        }

        allowed.appointmentDate = newDate;
        allowed.appointmentTime = newTime;
      }

      if (req.body.status === "cancelled") allowed.status = "cancelled";

      const result = await appointmentsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: allowed }
      );
      res.json(result);
    });

    app.delete("/appointments/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const existing = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return res.status(404).json({ message: "Appointment not found" });

      if (existing.userEmail !== req.user.email && req.user.role !== "admin") {
        return res.status(403).json({ message: "This is not your appointment." });
      }

      if (existing.status && existing.status !== "pending") {
        return res.status(403).json({ message: "This appointment can no longer be deleted." });
      }

      const result = await appointmentsCollection.deleteOne({ _id: new ObjectId(id) });
      res.json(result);
    });

    app.patch("/doctors/:id/review", writeLimiter, verifyToken, async (req, res) => {
      const { id } = req.params;
      const { rating, comment } = req.body;

      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid doctor id." });

      const score = Number(rating);
      if (!Number.isInteger(score) || score < 1 || score > 5) {
        return res.status(400).json({ message: "Rating must be a whole number from 1 to 5." });
      }

      const doctor = await doctorCollection.findOne({ _id: new ObjectId(id) });
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });

      // Identity from the token, not the body — otherwise anyone could post a
      // review under another person's name and email.
      const userEmail = req.user.email;
      const userName = req.user.name || userEmail;

      // You may only review a doctor you've actually completed a visit with.
      const visited = await appointmentsCollection.findOne({
        doctorId: id,
        userEmail,
        status: "completed",
      });
      if (!visited) {
        return res.status(403).json({ message: "You can only review a doctor after a completed appointment." });
      }

      if ((doctor.reviews || []).some((r) => r.userEmail === userEmail)) {
        return res.status(409).json({ message: "You have already reviewed this doctor." });
      }

      // Proper running mean. The old formula was (current + new) / 2, which
      // weighted the newest review at 50% no matter how many came before —
      // one 1-star review could halve a long-standing 5.0.
      const prevTotal = doctor.totalReviews || 0;
      const prevRating = doctor.rating || 0;
      const newTotalReviews = prevTotal + 1;
      const newRating = parseFloat(
        (((prevRating * prevTotal) + score) / newTotalReviews).toFixed(1)
      );

      const result = await doctorCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: { rating: newRating, totalReviews: newTotalReviews },
          $push: {
            reviews: {
              userName,
              userEmail,
              rating: score,
              comment: (comment || "").slice(0, 1000),
              date: new Date().toISOString(),
            },
          },
        }
      );
      res.json(result);
    });

    // ────────────────────────────────────────────────────────────
    // ADMIN PANEL (requires role: admin)
    // ────────────────────────────────────────────────────────────

    app.get("/admin/doctors/pending", verifyToken, requireRole("admin"), async (req, res) => {
      const result = await doctorCollection.find({ approvalStatus: "pending" }).toArray();
      res.json(result);
    });

    app.patch("/admin/doctors/:id/approve", verifyToken, requireRole("admin"), async (req, res) => {
      const { id } = req.params;
      const doctor = await doctorCollection.findOne({ _id: new ObjectId(id) });
      if (!doctor) return res.status(404).json({ message: "Doctor application not found" });

      await doctorCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { approvalStatus: "approved" } }
      );

      const userUpdate = { role: "doctor", status: "active" };
      if (doctor.image) userUpdate.image = doctor.image;

      await userCollection.updateOne(
        { _id: new ObjectId(doctor.userId) },
        { $set: userUpdate }
      );

      await notify({
        notificationsCollection,
        userId: doctor.userId,
        type: "doctor_approved",
        message: "Congratulations! Your doctor application has been approved.",
        email: doctor.email && {
          to: doctor.email,
          subject: "You're approved — DocAppoint",
          html: `<p>Congratulations! Your doctor application has been <b>approved</b>. You can now log in to your doctor dashboard.</p>`,
        },
      });

      res.json({ success: true });
    });

    app.patch("/admin/doctors/:id/reject", verifyToken, requireRole("admin"), async (req, res) => {
      const { id } = req.params;
      const { reason } = req.body;
      const doctor = await doctorCollection.findOne({ _id: new ObjectId(id) });
      if (!doctor) return res.status(404).json({ message: "Doctor application not found" });

      await doctorCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { approvalStatus: "rejected", rejectionReason: reason || "" } }
      );

      await userCollection.updateOne(
        { _id: new ObjectId(doctor.userId) },
        { $set: { status: "active" } }
      );

      await notify({
        notificationsCollection,
        userId: doctor.userId,
        type: "doctor_rejected",
        message: `Your doctor application was rejected.${reason ? ` Reason: ${reason}` : ""}`,
        email: doctor.email && {
          to: doctor.email,
          subject: "Application update — DocAppoint",
          html: `<p>Your doctor application was <b>not approved</b>.${reason ? ` Reason: ${reason}` : ""}</p>`,
        },
      });

      res.json({ success: true });
    });

    app.get("/admin/users", verifyToken, requireRole("admin"), async (req, res) => {
      const { role } = req.query;
      const query = role ? { role } : {};
      const result = await userCollection
        .find(query, { projection: { name: 1, email: 1, role: 1, status: 1, createdAt: 1 } })
        .toArray();
      res.json(result);
    });

    app.patch("/admin/users/:id/suspend", verifyToken, requireRole("admin"), async (req, res) => {
      const { id } = req.params;
      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status: "suspended" } }
      );
      res.json(result);
    });

    app.patch("/admin/users/:id/reactivate", verifyToken, requireRole("admin"), async (req, res) => {
      const { id } = req.params;
      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status: "active" } }
      );
      res.json(result);
    });

    app.get("/admin/stats", verifyToken, requireRole("admin"), async (req, res) => {
      const [totalPatients, totalDoctors, pendingDoctors, totalAppointments] = await Promise.all([
        userCollection.countDocuments({ role: "patient" }),
        doctorCollection.countDocuments({ approvalStatus: "approved" }),
        doctorCollection.countDocuments({ approvalStatus: "pending" }),
        appointmentsCollection.countDocuments({}),
      ]);
      res.json({ totalPatients, totalDoctors, pendingDoctors, totalAppointments });
    });

    // ────────────────────────────────────────────────────────────
    // NOTIFICATIONS (any authenticated user, own notifications only)
    // ────────────────────────────────────────────────────────────

    app.get("/notifications", verifyToken, async (req, res) => {
      const result = await notificationsCollection
        .find({ userId: req.user.id })
        .sort({ createdAt: -1 })
        .limit(50)
        .toArray();
      res.json(result);
    });

    app.patch("/notifications/:id/read", verifyToken, async (req, res) => {
      const { id } = req.params;
      const result = await notificationsCollection.updateOne(
        { _id: new ObjectId(id), userId: req.user.id },
        { $set: { read: true } }
      );
      res.json(result);
    });

    app.patch("/notifications/read-all", verifyToken, async (req, res) => {
      const result = await notificationsCollection.updateMany(
        { userId: req.user.id, read: false },
        { $set: { read: true } }
      );
      res.json(result);
    });

    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("DocAppoint API is running.");
});

// Global error handler — MUST be registered last, after all routes.
// Anything that throws or rejects inside a route (bad ObjectId, DB hiccup,
// a bug we haven't found yet) lands here instead of crashing the whole
// server. This is the safety net; individual routes should still validate
// input where practical, but this guarantees a bad request degrades to a
// clean error response instead of taking down every other user's session.
app.use((err, req, res, next) => {
  console.error("Unhandled error on", req.method, req.originalUrl, ":", err.message);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({
    message: err.publicMessage || "Something went wrong on the server. Please try again.",
  });
});

app.listen(port, () => {
  console.log(`DocAppoint server listening on port ${port}`);
});
