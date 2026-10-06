const express = require("express");
require("express-async-errors");
const dotenv = require("dotenv");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");
const requireRole = require("./middleware/requireRole");
const { notify } = require("./lib/notify");
const { createAppointmentService } = require("./lib/appointments");
const { createDownloads } = require("./lib/downloads");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const {
  WEEKDAYS,
  PER_HOUR_OPTIONS,
  isDate,
  isTime,
  slotMinutesOf,
  perHourOf,
  weekdayOf,
  clinicNow,
  leaveDatesOf,
  daySlots,
  normalizeSessions,
  addDays,
} = require("./lib/schedule");
const crypto = require("crypto");

// Jitsi Meet needs no account or API key: an unguessable room name is the link.
const newMeetingUrl = () => `https://meet.jit.si/docappoint-${crypto.randomBytes(9).toString("hex")}`;

dotenv.config();

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

const normaliseOrigin = (value) => (value || "").trim().replace(/\/+$/, "");

const allowedOrigins = [
  normaliseOrigin(process.env.CLIENT_URL),
  ...(process.env.EXTRA_ORIGINS || "").split(",").map(normaliseOrigin),
].filter(Boolean);

if (process.env.NODE_ENV === "production" && allowedOrigins.length === 0) {
  console.error(
    "[config] FATAL: CLIENT_URL is not set. In production every browser request " +
    "will be blocked by CORS and every JWT will fail to verify. Set CLIENT_URL " +
    "to your deployed frontend origin, e.g. https://your-site.netlify.app"
  );
}

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (process.env.NODE_ENV !== "production") return cb(null, true);
    if (allowedOrigins.includes(normaliseOrigin(origin))) return cb(null, true);

    console.warn(`[cors] blocked origin: ${origin} (allowed: ${allowedOrigins.join(", ") || "none"})`);
    return cb(null, false);
  },
  // PUT is used by saved doctors and the donor profile.
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(compression());
app.use(express.json({ limit: "100kb" }));

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
// Overridable so a scratch database can be seeded/tested without touching real data.
const DB_NAME = process.env.DB_NAME || "DocAppoint";


const JWKS_URL = `${normaliseOrigin(process.env.CLIENT_URL)}/api/auth/jwks`;

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
    // Tokens minted before email verification existed carry no flag; only an
    // explicit false blocks.
    if (payload.emailVerified === false) {
      return res.status(403).json({ message: "Please verify your email address before continuing." });
    }
    req.user = payload; // { id, email, name, role, status, emailVerified }
    next();
  } catch (error) {
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

app.get("/health", async (req, res) => {
  let jwks = "unknown";
  try {
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

// Booking validation

/**
 * Checks a requested date + time against the doctor's sessions and leave days.
 * Returns { error } or { serial } — the slot's 1-based position in the day.
 * Whether the slot is already taken is left to the unique index.
 */
const validateSlot = (doctor, dateStr, timeStr) => {
  if (!dateStr || !timeStr) return { error: "Appointment date and time are required." };
  if (!isDate(dateStr)) return { error: "Invalid appointment date." };
  if (!isTime(timeStr)) return { error: "Invalid appointment time." };

  const now = clinicNow();
  if (dateStr < now.date) return { error: "Appointment date cannot be in the past." };

  if (leaveDatesOf(doctor).includes(dateStr)) {
    return { error: `${doctor.name} is on leave on ${dateStr}.` };
  }

  const weekday = weekdayOf(dateStr);
  const slots = daySlots(doctor, weekday);
  if (slots.length === 0) return { error: `${doctor.name} does not consult on ${weekday}.` };

  const slot = slots.find((s) => s.time === timeStr);
  if (!slot) return { error: `${timeStr} is not one of ${doctor.name}'s ${weekday} slots.` };
  if (dateStr === now.date && timeStr <= now.time) return { error: "That time has already passed today." };

  return { serial: slot.serial };
};

// Appointments that hold a slot. Cancelled ones (and expired payment holds)
// flip isActive to false, which frees the slot under the unique index.
const isDuplicateKey = (err) => err?.code === 11000;

// User input goes into RegExp constructors for search; escape it so "C++" or
// "(" can't throw or turn into a catastrophic pattern.
const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Public listings never need reviewer emails, credential scans or rejection
// notes — and dropping reviews keeps list payloads small.
const PUBLIC_DOCTOR_PROJECTION = {
  reviews: 0,
  credentialImageUrl: 0,
  rejectionReason: 0,
  email: 0,
};

const CONSULTATION_TYPES = ["in-person", "online", "both"];

// image = cover photo; imageCredit/imageSource = its author/licence and source page.
const HOSPITAL_TEXT_FIELDS = ["name", "city", "address", "phone", "logo", "emergencyPhone", "image", "imageCredit", "imageSource"];

const pickHospitalFields = (body = {}, { partial = false } = {}) => {
  const out = {};
  for (const key of HOSPITAL_TEXT_FIELDS) {
    if (body[key] !== undefined) out[key] = String(body[key] ?? "").trim().slice(0, 300);
    else if (!partial) out[key] = "";
  }
  if (body.departments !== undefined) {
    const list = Array.isArray(body.departments)
      ? body.departments
      : String(body.departments || "").split(",");
    out.departments = [...new Set(list.map((d) => String(d).trim()).filter(Boolean))].slice(0, 40);
  } else if (!partial) {
    out.departments = [];
  }
  return out;
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

    const db = client.db(DB_NAME);

    await Promise.all([
      db.collection("appointments").createIndex({ userEmail: 1, createdAt: -1 }),
      db.collection("appointments").createIndex({ doctorId: 1, appointmentDate: 1, appointmentTime: 1 }),
      db.collection("doctors").createIndex({ approvalStatus: 1 }),
      db.collection("doctors").createIndex({ userId: 1 }),
      db.collection("doctors").createIndex({ email: 1 }),
      db.collection("doctors").createIndex({ hospitalId: 1 }),
      // No text index on name/specialty: this client runs the Stable API in
      // strict mode, which can neither create nor query $text indexes. Search
      // uses a case-insensitive substring regex instead (see GET /doctors).
      db.collection("hospitals").createIndex({ city: 1 }),
      db.collection("notifications").createIndex({ userId: 1, createdAt: -1 }),
      db.collection("appointments").createIndex({ userId: 1, createdAt: -1 }),
      db.collection("appointments").createIndex({ holdExpiresAt: 1 }, { sparse: true }),
      db.collection("payments").createIndex({ appointmentId: 1 }),
      db.collection("payments").createIndex({ createdAt: -1 }),
    ]).catch((err) => console.warn("Index creation skipped:", err.message));
    const doctorCollection = db.collection("doctors");
    const appointmentsCollection = db.collection("appointments");
    const notificationsCollection = db.collection("notifications");
    const hospitalsCollection = db.collection("hospitals");
    const paymentsCollection = db.collection("payments");
    const settingsCollection = db.collection("settings");
    const userCollection = db.collection("user"); // Better Auth's collection name

    // No double booking: at most one *active* appointment per doctor/date/time.
    // Cancelling sets isActive=false, which takes the row out of the index and
    // frees the slot. (Partial filters can't use $ne, hence a boolean flag.)
    // Appointments created before the flag existed are backfilled first.
    await appointmentsCollection
      .updateMany({ isActive: { $exists: false } }, [
        { $set: { isActive: { $ne: ["$status", "cancelled"] } } },
      ])
      .catch((err) => console.warn("isActive backfill skipped:", err.message));
    await appointmentsCollection
      .createIndex(
        { doctorId: 1, appointmentDate: 1, appointmentTime: 1, isActive: 1 },
        { name: "uniq_active_slot", unique: true, partialFilterExpression: { isActive: true } }
      )
      .catch((err) => console.warn("Unique slot index not created:", err.message));

    const bookings = createAppointmentService({ db });
    setInterval(() => bookings.releaseExpiredHolds().catch(() => {}), 60 * 1000).unref();

    // Feature areas live in routes/*; they share these helpers.
    const routeContext = {
      db,
      verifyToken,
      requireRole,
      writeLimiter,
      bookings,
      newMeetingUrl,
      clientUrl: () => normaliseOrigin(process.env.CLIENT_URL),
      serverUrl: () => normaliseOrigin(process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`),
      // Defined further down in run(); resolved at request time.
      updateHospital: (...args) => updateHospital(...args),
    };
    routeContext.downloads = createDownloads({ app, db, serverUrl: routeContext.serverUrl });
    require("./routes/payments")(app, routeContext);
    require("./routes/ledger")(app, routeContext);
    require("./routes/prescriptions")(app, routeContext);
    require("./routes/patient")(app, routeContext);
    require("./routes/queue")(app, routeContext);
    require("./routes/analytics")(app, routeContext);
    require("./routes/emergency")(app, routeContext);
    require("./routes/hospitalAdmin")(app, routeContext);
    require("./routes/assistant")(app, routeContext);

    // HOSPITALS (public read, admin write)

    // hospitalId is stored on doctors as a string (same convention as doctorId
    // on appointments), so lookups compare against the stringified _id.
    const doctorsOfHospitalLookup = (as, extraStages) => ({
      $lookup: {
        from: "doctors",
        let: { hid: { $toString: "$_id" } },
        pipeline: [
          { $match: { $expr: { $eq: ["$hospitalId", "$$hid"] }, approvalStatus: "approved" } },
          ...extraStages,
        ],
        as,
      },
    });

    // Without ?page this returns the full array (dropdowns, admin list). With
    // ?page it returns one page plus the city list for the filter chips.
    app.get("/hospitals", async (req, res) => {
      const { city, q } = req.query;
      const match = {};
      if (city) match.city = new RegExp(`^${escapeRegex(city)}$`, "i");
      if (q && String(q).trim()) match.name = new RegExp(escapeRegex(String(q).trim()), "i");
      if (req.query.emergency === "1") match.emergencyPhone = { $nin: [null, ""] };

      const withCounts = [
        doctorsOfHospitalLookup("doctorCount", [{ $count: "n" }]),
        { $addFields: { doctorCount: { $ifNull: [{ $first: "$doctorCount.n" }, 0] } } },
      ];

      if (req.query.page === undefined) {
        const result = await hospitalsCollection.aggregate([{ $match: match }, { $sort: { name: 1 } }, ...withCounts]).toArray();
        return res.json(result);
      }

      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 9));
      const [[facet], cities] = await Promise.all([
        hospitalsCollection
          .aggregate([
            { $match: match },
            { $sort: { name: 1 } },
            {
              $facet: {
                hospitals: [{ $skip: (page - 1) * limit }, { $limit: limit }, ...withCounts],
                total: [{ $count: "n" }],
              },
            },
          ])
          .toArray(),
        // (distinct isn't allowed under the Stable API, so group instead)
        hospitalsCollection
          .aggregate([
            ...(req.query.emergency === "1" ? [{ $match: { emergencyPhone: { $nin: [null, ""] } } }] : []),
            { $group: { _id: "$city" } },
          ])
          .toArray()
          .then((rows) => rows.map((row) => row._id)),
      ]);
      const total = facet.total[0]?.n || 0;
      res.json({
        hospitals: facet.hospitals,
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit)),
        cities: cities.filter(Boolean).sort(),
      });
    });

    app.get("/hospitals/:id", async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid hospital id." });

      const [hospital] = await hospitalsCollection
        .aggregate([
          { $match: { _id: new ObjectId(id) } },
          doctorsOfHospitalLookup("doctors", [
            { $project: PUBLIC_DOCTOR_PROJECTION },
            { $sort: { rating: -1, _id: 1 } },
          ]),
        ])
        .toArray();
      if (!hospital) return res.status(404).json({ message: "Hospital not found." });
      res.json(hospital);
    });

    app.post("/admin/hospitals", writeLimiter, verifyToken, requireRole("admin"), async (req, res) => {
      const fields = pickHospitalFields(req.body);
      if (!fields.name || !fields.city) {
        return res.status(400).json({ message: "Hospital name and city are required." });
      }
      const result = await hospitalsCollection.insertOne({ ...fields, createdAt: new Date() });
      res.json(result);
    });

    // Shared by the admin and (later) the hospital manager, who may only touch
    // their own hospital.
    const updateHospital = async (id, body) => {
      const existing = await hospitalsCollection.findOne({ _id: new ObjectId(id) });
      if (!existing) return { status: 404, body: { message: "Hospital not found." } };

      const fields = pickHospitalFields(body, { partial: true });
      // A new cover photo doesn't inherit the old photo's credit.
      if (fields.image !== undefined && fields.image !== (existing.image || "") && body.imageCredit === undefined) {
        fields.imageCredit = "";
        fields.imageSource = "";
      }
      if (fields.name === "" || fields.city === "") {
        return { status: 400, body: { message: "Hospital name and city can't be empty." } };
      }
      if (Object.keys(fields).length === 0) {
        return { status: 400, body: { message: "Nothing to update." } };
      }

      const result = await hospitalsCollection.updateOne({ _id: existing._id }, { $set: fields });
      // Doctors carry the hospital name for display/search; keep it in step.
      if (fields.name && fields.name !== existing.name) {
        await doctorCollection.updateMany({ hospitalId: id }, { $set: { hospital: fields.name } });
      }
      return { status: 200, body: result };
    };

    app.patch("/admin/hospitals/:id", verifyToken, requireRole("admin"), async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ message: "Invalid hospital id." });
      const { status, body } = await updateHospital(req.params.id, req.body);
      res.status(status).json(body);
    });

    app.delete("/admin/hospitals/:id", verifyToken, requireRole("admin"), async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid hospital id." });

      const linked = await doctorCollection.countDocuments({ hospitalId: id });
      if (linked > 0) {
        return res.status(409).json({
          message: `${linked} doctor${linked === 1 ? " is" : "s are"} still linked to this hospital. Move them first.`,
        });
      }
      const result = await hospitalsCollection.deleteOne({ _id: new ObjectId(id) });
      res.json(result);
    });

    // Resolves a hospitalId from a form into { hospitalId, hospital } for the
    // doctor document. Empty means independent / online-only practice.
    const resolveHospital = async (hospitalId) => {
      if (!hospitalId) return { value: { hospitalId: null, hospital: "" } };
      if (!ObjectId.isValid(hospitalId)) return { error: "Invalid hospital selected." };
      const hospital = await hospitalsCollection.findOne({ _id: new ObjectId(hospitalId) });
      if (!hospital) return { error: "The selected hospital no longer exists." };
      return { value: { hospitalId: hospital._id.toString(), hospital: hospital.name } };
    };

    // PUBLIC: Doctors listing / details

    app.get("/doctors", async (req, res) => {
      const { q, hospital, specialty, sort } = req.query;
      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 12));

      const filter = { approvalStatus: "approved" };
      const term = typeof q === "string" ? q.trim() : "";
      if (term) {
        const rx = new RegExp(escapeRegex(term), "i");
        filter.$or = [{ name: rx }, { specialty: rx }, { hospital: rx }];
      }
      if (hospital === "independent") filter.hospitalId = null;
      else if (hospital) filter.hospitalId = String(hospital);
      if (specialty) filter.specialty = new RegExp(`^${escapeRegex(specialty)}$`, "i");
      if (req.query.type === "online") filter.consultationType = { $in: ["online", "both"] };
      if (req.query.type === "in-person") filter.consultationType = { $nin: ["online"] };

      const sortSpec = sort === "rating" ? { rating: -1, totalReviews: -1, _id: 1 } : { _id: 1 };

      const [doctors, total] = await Promise.all([
        doctorCollection
          .find(filter, { projection: PUBLIC_DOCTOR_PROJECTION })
          .sort(sortSpec)
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray(),
        doctorCollection.countDocuments(filter),
      ]);

      res.json({ doctors, total, page, limit, totalPages: Math.max(1, Math.ceil(total / limit)) });
    });

    // Homepage numbers + specialty list in one round trip, instead of shipping
    // every doctor to the browser just to count them.
    app.get("/doctors/stats", async (req, res) => {
      const [stats] = await doctorCollection
        .aggregate([
          { $match: { approvalStatus: "approved" } },
          {
            $facet: {
              totals: [
                {
                  $group: {
                    _id: null,
                    totalDoctors: { $sum: 1 },
                    totalReviews: { $sum: { $ifNull: ["$totalReviews", 0] } },
                    avgRating: { $avg: "$rating" },
                  },
                },
              ],
              specialties: [
                { $match: { specialty: { $nin: [null, ""] } } },
                { $group: { _id: "$specialty", count: { $sum: 1 } } },
                { $sort: { _id: 1 } },
              ],
              // 5-star quotes for the homepage carousel, minus reviewer emails.
              testimonials: [
                { $unwind: "$reviews" },
                { $match: { "reviews.rating": 5, "reviews.comment": { $nin: [null, ""] } } },
                { $sort: { "reviews.date": -1 } },
                { $limit: 12 },
                {
                  $project: {
                    _id: 0,
                    rating: "$reviews.rating",
                    comment: "$reviews.comment",
                    userName: "$reviews.userName",
                    doctorName: "$name",
                  },
                },
              ],
            },
          },
        ])
        .toArray();

      const totals = stats?.totals?.[0] || {};
      res.json({
        totalDoctors: totals.totalDoctors || 0,
        totalReviews: totals.totalReviews || 0,
        avgRating: totals.avgRating ? Number(totals.avgRating.toFixed(1)) : null,
        specialties: (stats?.specialties || []).map((s) => ({ name: s._id, count: s.count })),
        testimonials: stats?.testimonials || [],
      });
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
      const result = await doctorCollection.findOne({ _id: new ObjectId(id) }, { projection: { credentialImageUrl: 0 } });
      if (!result) return res.status(404).json({ message: "Doctor not found." });
      // Reviewer emails are for duplicate checks only, never for other users.
      result.reviews = (result.reviews || []).map(({ userEmail, ...review }) => review);
      res.json(result);
    });

    // Bookable slots for one date. Public (no patient data), never cached.
    app.get("/doctors/:id/slots", async (req, res) => {
      const { id } = req.params;
      const { date, exclude } = req.query;
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid doctor id." });
      if (!isDate(date)) return res.status(400).json({ message: "Pass ?date=YYYY-MM-DD." });

      const doctor = await doctorCollection.findOne(
        { _id: new ObjectId(id), approvalStatus: "approved" },
        { projection: { name: 1, availability: 1, maxPerHour: 1, leaveDates: 1, blockedDates: 1 } }
      );
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });

      res.set("Cache-Control", "no-store");
      const weekday = weekdayOf(date);
      const base = { date, weekday, slotMinutes: slotMinutesOf(doctor), slots: [] };
      const now = clinicNow();

      if (date < now.date) return res.json({ ...base, closedReason: "past" });
      if (leaveDatesOf(doctor).includes(date)) return res.json({ ...base, closedReason: "leave" });

      const slots = daySlots(doctor, weekday);
      if (slots.length === 0) return res.json({ ...base, closedReason: "not_consulting" });

      await bookings.releaseExpiredHolds();
      const taken = await appointmentsCollection
        .find(
          {
            doctorId: id,
            appointmentDate: date,
            isActive: true,
            // When rescheduling, the patient's own current slot shows as free.
            ...(exclude && ObjectId.isValid(exclude) ? { _id: { $ne: new ObjectId(exclude) } } : {}),
          },
          { projection: { appointmentTime: 1 } }
        )
        .toArray();
      const takenTimes = new Set(taken.map((a) => a.appointmentTime));

      res.json({
        ...base,
        slots: slots.map((s) => ({
          ...s,
          available: !takenTimes.has(s.time) && !(date === now.date && s.time <= now.time),
        })),
      });
    });


    // DOCTOR ONBOARDING (any logged-in user applies)

    app.post("/doctors/apply", writeLimiter, verifyToken, async (req, res) => {
      const { degree, registrationNumber, hospitalId, specialty, credentialImageUrl, bio, fee, image, name, experience, location, phone, consultationType } = req.body;

      const existing = await doctorCollection.findOne({ userId: req.user.id });

      if (existing && existing.approvalStatus !== "rejected") {
        return res.status(400).json({
          message:
            existing.approvalStatus === "approved"
              ? "You're already an approved doctor."
              : "You already have a pending application.",
        });
      }

      if (!credentialImageUrl) {
        return res.status(400).json({ message: "A credential document is required to apply." });
      }
      if (!specialty || !degree || !registrationNumber || !phone) {
        return res.status(400).json({ message: "Please fill in all required fields." });
      }

      const hospitalPick = await resolveHospital(hospitalId);
      if (hospitalPick.error) return res.status(400).json({ message: hospitalPick.error });

      const doctorFields = {
        userId: req.user.id,
        name: name || req.user.name || req.user.email || "Unnamed Applicant",
        email: req.user.email,
        phone,
        specialty,
        degree,
        registrationNumber,
        ...hospitalPick.value,
        consultationType: CONSULTATION_TYPES.includes(consultationType) ? consultationType : "in-person",
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
          maxPerHour: 2,
          leaveDates: [],
        });
      }

      await userCollection.updateOne(
        { _id: new ObjectId(req.user.id) },
        { $set: { status: "pending" } }
      );

      
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

    // DOCTOR PANEL (requires role: doctor)

    const getMyDoctorDoc = (userId) => doctorCollection.findOne({ userId });

    app.get("/doctor/profile", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });
      res.json(doctor);
    });

    app.patch("/doctor/profile", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

      const { bio, fee, image, specialty, hospitalId, experience, location, consultationType, followUpFeePercent } = req.body;
      const update = {};
      if (bio !== undefined) update.bio = bio;
      if (fee !== undefined) update.fee = fee;
      if (image !== undefined) update.image = image;
      if (specialty !== undefined) update.specialty = specialty;
      if (hospitalId !== undefined) {
        const hospitalPick = await resolveHospital(hospitalId);
        if (hospitalPick.error) return res.status(400).json({ message: hospitalPick.error });
        Object.assign(update, hospitalPick.value);
      }
      if (experience !== undefined) update.experience = experience;
      if (consultationType !== undefined) {
        if (!CONSULTATION_TYPES.includes(consultationType)) {
          return res.status(400).json({ message: "Consultation type must be in-person, online or both." });
        }
        update.consultationType = consultationType;
      }
      if (followUpFeePercent !== undefined) {
        const pct = Number(followUpFeePercent);
        if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
          return res.status(400).json({ message: "Follow-up fee must be between 0% and 100% of the regular fee." });
        }
        update.followUpFeePercent = Math.round(pct);
      }
      if (location !== undefined) update.location = location;

      const result = await doctorCollection.updateOne({ _id: doctor._id }, { $set: update });
      res.json(result);
    });

    app.patch("/doctor/availability", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

      // `blockedDates` is the old name for leave days; still accepted.
      const { availability, maxPerHour } = req.body;
      const leaveInput = req.body.leaveDates ?? req.body.blockedDates;

      const update = {};
      const unset = {};

      if (availability !== undefined) {
        if (!Array.isArray(availability)) {
          return res.status(400).json({ message: "availability must be an array." });
        }
        const days = [];
        for (const a of availability) {
          if (!a || !WEEKDAYS.includes(a.day)) continue;
          const { sessions, error } = normalizeSessions(a.sessions, a.day);
          if (error) return res.status(400).json({ message: error });
          days.push({ day: a.day, sessions });
        }
        update.availability = days;
      }

      if (maxPerHour !== undefined) {
        if (!PER_HOUR_OPTIONS.includes(Number(maxPerHour))) {
          return res.status(400).json({ message: `Patients per hour must be one of ${PER_HOUR_OPTIONS.join(", ")}.` });
        }
        update.maxPerHour = Number(maxPerHour);
      }

      let newLeaveDays = [];
      if (leaveInput !== undefined) {
        if (!Array.isArray(leaveInput)) {
          return res.status(400).json({ message: "leaveDates must be an array." });
        }
        update.leaveDates = [...new Set(leaveInput.filter(isDate))].sort();
        unset.blockedDates = "";
        const before = new Set(leaveDatesOf(doctor));
        const today = clinicNow().date;
        newLeaveDays = update.leaveDates.filter((d) => !before.has(d) && d >= today);
      }

      if (Object.keys(update).length === 0) {
        return res.status(400).json({ message: "Nothing to update." });
      }

      const result = await doctorCollection.updateOne(
        { _id: doctor._id },
        { $set: update, ...(Object.keys(unset).length ? { $unset: unset } : {}) }
      );

      // Leave over existing bookings: cancel them, refund in full, tell the patients.
      let cancelledCount = 0;
      if (newLeaveDays.length > 0) {
        const affected = await appointmentsCollection
          .find({
            doctorId: doctor._id.toString(),
            appointmentDate: { $in: newLeaveDays },
            isActive: true,
            status: { $in: ["pending", "confirmed"] },
          })
          .toArray();
        for (const appt of affected) {
          const { ok, refund } = await bookings.cancelAppointment(appt, {
            by: "doctor",
            reason: "Doctor on leave",
            refundPercent: 100,
          });
          if (!ok) continue;
          cancelledCount++;
          const refundText = refund > 0 ? ` Your payment of ৳${refund} will be refunded in full.` : "";
          await bookings.notifyPatient(appt, {
            type: "appointment_cancelled_leave",
            message: `${doctor.name} is on leave on ${appt.appointmentDate}, so your ${appt.appointmentTime} appointment was cancelled.${refundText} Please book another date.`,
            subject: "Appointment cancelled — doctor on leave",
          });
        }
      }

      res.json({ ...result, cancelledCount });
    });

    app.get("/doctor/appointments", verifyToken, requireRole("doctor"), async (req, res) => {
      const doctor = await getMyDoctorDoc(req.user.id);
      if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });

      await bookings.releaseExpiredHolds();
      const result = await appointmentsCollection
        .find({ doctorId: doctor._id.toString() }, { projection: { demoPayment: 0, gateway: 0 } })
        .sort({ appointmentDate: -1 })
        .toArray();
      res.json(result);
    });

    const DOCTOR_STATUS_TRANSITIONS = {
      confirmed: ["pending"],
      completed: ["confirmed"],
      cancelled: ["pending", "confirmed"],
      no_show: ["confirmed"],
    };

    app.patch("/doctor/appointments/:id/status", verifyToken, requireRole("doctor"), async (req, res) => {
      const { id } = req.params;
      const { status } = req.body;

      if (!DOCTOR_STATUS_TRANSITIONS[status]) {
        return res.status(400).json({ message: "Invalid status" });
      }
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid appointment id." });

      const appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!appointment) return res.status(404).json({ message: "Appointment not found" });

      const me = await getMyDoctorDoc(req.user.id);
      if (!me || appointment.doctorId !== me._id.toString()) {
        return res.status(403).json({ message: "This appointment is not yours." });
      }

      const current = appointment.status || "pending";
      if (!DOCTOR_STATUS_TRANSITIONS[status].includes(current)) {
        return res.status(400).json({ message: `A ${current} appointment can't be marked ${status.replace("_", "-")}.` });
      }
      if (status === "confirmed" && appointment.consultationMode === "online" && appointment.paymentStatus !== "paid") {
        return res.status(400).json({ message: "Online consultations can be confirmed once the patient has paid." });
      }
      if (status === "no_show" && bookings.hoursUntil(appointment) > 0) {
        return res.status(400).json({ message: "You can mark a no-show only after the appointment time." });
      }

      let refund = 0;
      if (status === "cancelled") {
        const outcome = await bookings.cancelAppointment(appointment, {
          by: "doctor",
          reason: (req.body.reason || "Cancelled by the doctor").slice(0, 200),
          refundPercent: (await bookings.getRefundPolicy()).doctorCancelPercent,
        });
        if (!outcome.ok) return res.status(409).json({ message: "This appointment was already cancelled." });
        refund = outcome.refund;
      } else {
        await appointmentsCollection.updateOne({ _id: appointment._id }, { $set: { status } });
      }

      const label = status === "no_show" ? "marked as a no-show" : status;
      const refundText = refund > 0 ? ` Your payment of ৳${refund} will be refunded in full.` : "";
      await bookings.notifyPatient(appointment, {
        type: `appointment_${status}`,
        message: `Your appointment with ${appointment.doctorName} on ${appointment.appointmentDate} at ${appointment.appointmentTime} was ${label}.${refundText}`,
        subject: `Appointment ${label} — DocAppoint`,
        html: `<p>Your appointment with <b>${appointment.doctorName}</b> on <b>${appointment.appointmentDate}</b> at <b>${appointment.appointmentTime}</b> has been <b>${label}</b>.${refundText}</p>`,
      });

      res.json({ acknowledged: true, status, refund });
    });

    app.patch("/doctor/appointments/:id/prescription", verifyToken, requireRole("doctor"), async (req, res) => {
      const { id } = req.params;
      const { notes, fileUrl } = req.body;

      const appointment = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!appointment) return res.status(404).json({ message: "Appointment not found" });

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

    // APPOINTMENTS (patient-facing)

    const PAYMENT_METHODS = ["sslcommerz", "demo_mobile", "cash"];
    const FOLLOW_UP_WINDOW_DAYS = 14;

    // DA-2026-000123: one counter per year, assigned when the booking is made.
    const nextReceiptNo = async () => {
      const year = clinicNow().date.slice(0, 4);
      const counter = await db
        .collection("counters")
        .findOneAndUpdate({ _id: `receipt-${year}` }, { $inc: { seq: 1 } }, { upsert: true, returnDocument: "after" });
      return `DA-${year}-${String(counter.seq).padStart(6, "0")}`;
    };

    /**
     * A follow-up must be for a completed visit of the same patient with the
     * same doctor that carries a prescription with a follow-up date. Patients
     * may book from today until 14 days after the visit, or until a week after
     * the doctor's suggested date if that's later.
     */
    const followUpContext = async (parentId, userId) => {
      if (!ObjectId.isValid(parentId)) return { error: "Invalid follow-up reference." };
      const parent = await appointmentsCollection.findOne({ _id: new ObjectId(parentId) });
      if (!parent || parent.userId !== userId) return { error: "Original appointment not found." };
      if (parent.status !== "completed") return { error: "Follow-ups can be booked after a completed visit." };

      const rx = await db.collection("prescriptions").findOne({ appointmentId: parentId });
      if (!rx?.followUpDate) return { error: "The doctor didn't ask for a follow-up on this visit." };

      const byVisit = addDays(parent.appointmentDate, FOLLOW_UP_WINDOW_DAYS);
      const byAdvice = addDays(rx.followUpDate, 7);
      const window = { start: clinicNow().date, end: byVisit > byAdvice ? byVisit : byAdvice };
      if (window.end < window.start) return { error: "The follow-up window for this visit has closed." };

      const existing = await appointmentsCollection.findOne({
        parentAppointmentId: parentId,
        isActive: true,
        status: { $in: ["pending", "confirmed"] },
      });
      return { parent, rx, window, existing };
    };

    const followUpFee = (doctor) => {
      const pct = Number.isFinite(Number(doctor.followUpFeePercent)) ? Number(doctor.followUpFeePercent) : 100;
      return Math.round(((doctor.fee || 0) * Math.max(0, Math.min(100, pct))) / 100);
    };

    // Who the appointment is for: the account holder, or one of their family
    // profiles (looked up server-side — never trusted from the request body).
    const resolvePatient = async (req) => {
      const { profileId, patientName, gender, age } = req.body;
      if (profileId) {
        const user = await userCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { profiles: 1 } }
        );
        const profile = (user?.profiles || []).find((p) => p.id === profileId);
        if (!profile) return { error: "That family profile doesn't exist." };
        return {
          value: {
            profileId,
            patientName: profile.name,
            gender: profile.gender || "",
            age: profile.age ?? null,
            relation: profile.relation || "",
          },
        };
      }
      const ageNum = Number(age);
      return {
        value: {
          profileId: null,
          patientName: String(patientName || req.user.name || "").slice(0, 100),
          gender: String(gender || "").slice(0, 20),
          age: Number.isFinite(ageNum) && ageNum > 0 && ageNum < 130 ? Math.round(ageNum) : null,
          relation: "self",
        },
      };
    };

    app.post("/appointments", writeLimiter, verifyToken, async (req, res) => {
      const { doctorId, phone, appointmentDate, appointmentTime, reason, parentAppointmentId } = req.body;

      if (!doctorId || !ObjectId.isValid(doctorId)) {
        return res.status(400).json({ message: "A valid doctorId is required." });
      }

      const doctor = await doctorCollection.findOne({ _id: new ObjectId(doctorId) });
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });
      if (doctor.approvalStatus && doctor.approvalStatus !== "approved") {
        return res.status(403).json({ message: "This doctor is not accepting bookings yet." });
      }
      if (doctor.userId === req.user.id) {
        return res.status(400).json({ message: "You can't book an appointment with yourself." });
      }

      // Visit mode: online-only doctors can't be visited in person and vice versa.
      const consultationType = doctor.consultationType || "in-person";
      const mode = req.body.consultationMode === "online" ? "online" : "in-person";
      if (consultationType !== "both" && consultationType !== mode) {
        return res.status(400).json({ message: `${doctor.name} only offers ${consultationType} consultations.` });
      }

      const paymentMethod = PAYMENT_METHODS.includes(req.body.paymentMethod) ? req.body.paymentMethod : null;
      if (!paymentMethod) return res.status(400).json({ message: "Choose how you'd like to pay." });
      if (paymentMethod === "cash" && mode === "online") {
        return res.status(400).json({ message: "Online consultations must be paid in advance." });
      }

      const slotCheck = validateSlot(doctor, appointmentDate, appointmentTime);
      if (slotCheck.error) return res.status(400).json({ message: slotCheck.error });

      let amount = doctor.fee || 0;
      let followUp = null;
      if (parentAppointmentId) {
        followUp = await followUpContext(parentAppointmentId, req.user.id);
        if (followUp.error) return res.status(400).json({ message: followUp.error });
        if (followUp.parent.doctorId !== doctorId) {
          return res.status(400).json({ message: "A follow-up has to be with the same doctor." });
        }
        if (followUp.existing) return res.status(409).json({ message: "You already have a follow-up booked for this visit." });
        if (appointmentDate < followUp.window.start || appointmentDate > followUp.window.end) {
          return res.status(400).json({ message: `Follow-up dates must be between ${followUp.window.start} and ${followUp.window.end}.` });
        }
        amount = followUpFee(doctor);
      }

      const patient = followUp
        ? {
            value: {
              profileId: followUp.parent.profileId || null,
              patientName: followUp.parent.patientName,
              gender: followUp.parent.gender || "",
              age: followUp.parent.age ?? null,
              relation: followUp.parent.relation || "self",
            },
          }
        : await resolvePatient(req);
      if (patient.error) return res.status(400).json({ message: patient.error });

      await bookings.releaseExpiredHolds();

      const free = amount <= 0;
      const online = paymentMethod !== "cash";
      const appointment = {
        userEmail: req.user.email,
        userId: req.user.id,
        ...patient.value,
        phone: String(phone || "").slice(0, 30),
        doctorId,
        doctorUserId: doctor.userId || null,
        doctorName: doctor.name,
        doctorSpecialty: doctor.specialty || "",
        hospitalId: doctor.hospitalId || null,
        hospitalName: doctor.hospital || "",
        appointmentDate,
        appointmentTime,
        serial: slotCheck.serial,
        slotMinutes: slotMinutesOf(doctor),
        consultationMode: mode,
        type: followUp ? "follow-up" : "regular",
        parentAppointmentId: followUp ? parentAppointmentId : null,
        reason: String(reason || "").slice(0, 500),
        status: "pending",
        isActive: true,
        amount,
        paymentMethod,
        paymentStatus: free ? "paid" : "unpaid",
        transactionId: "",
        refundedAmount: 0,
        // Unpaid online payments hold the slot briefly, then release it.
        holdExpiresAt: online && !free ? new Date(Date.now() + bookings.HOLD_MINUTES * 60 * 1000) : null,
        rescheduleCount: 0,
        receiptNo: "",
        meetingUrl: free && mode === "online" ? newMeetingUrl() : "",
        createdAt: new Date(),
      };

      let result;
      try {
        result = await appointmentsCollection.insertOne(appointment);
      } catch (err) {
        if (isDuplicateKey(err)) {
          return res.status(409).json({ message: "That slot has just been taken. Please pick another." });
        }
        throw err;
      }
      // Numbered only once the slot is secured, so rejected attempts leave no gaps.
      appointment.receiptNo = await nextReceiptNo();
      await appointmentsCollection.updateOne({ _id: result.insertedId }, { $set: { receiptNo: appointment.receiptNo } });

      if (doctor.userId) {
        await notify({
          notificationsCollection,
          userId: doctor.userId,
          type: "new_booking",
          message: `New ${appointment.type === "follow-up" ? "follow-up " : ""}booking: ${appointment.patientName} (serial #${appointment.serial}) on ${appointment.appointmentDate} at ${appointment.appointmentTime}.`,
          email: doctor.email && {
            to: doctor.email,
            subject: "New appointment booked — DocAppoint",
            html: `<p>You have a new booking from <b>${appointment.patientName}</b> (serial <b>#${appointment.serial}</b>) on <b>${appointment.appointmentDate}</b> at <b>${appointment.appointmentTime}</b>.</p>`,
          },
        });
      }

      res.json({
        acknowledged: true,
        insertedId: result.insertedId,
        serial: appointment.serial,
        receiptNo: appointment.receiptNo,
        amount,
        paymentMethod,
        paymentStatus: appointment.paymentStatus,
        holdExpiresAt: appointment.holdExpiresAt,
        needsPayment: online && !free,
      });
    });

    app.get("/appointments", verifyToken, async (req, res) => {
      await bookings.releaseExpiredHolds();
      const result = await appointmentsCollection
        .find({ $or: [{ userId: req.user.id }, { userEmail: req.user.email }] }, { projection: { demoPayment: 0, gateway: 0 } })
        .sort({ createdAt: -1 })
        .toArray();
      res.json(result);
    });

    const loadOwnAppointment = async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) {
        res.status(400).json({ message: "Invalid appointment id." });
        return null;
      }
      const appt = await appointmentsCollection.findOne({ _id: new ObjectId(id) });
      if (!appt) {
        res.status(404).json({ message: "Appointment not found" });
        return null;
      }
      const owns = appt.userId ? appt.userId === req.user.id : appt.userEmail === req.user.email;
      if (!owns && req.user.role !== "admin") {
        res.status(403).json({ message: "This is not your appointment." });
        return null;
      }
      return appt;
    };

    app.get("/appointments/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid appointment id." });
      await bookings.releaseExpiredHolds();
      const appt = await appointmentsCollection.findOne({ _id: new ObjectId(id) }, { projection: { demoPayment: 0, gateway: 0 } });
      if (!appt) return res.status(404).json({ message: "Appointment not found" });
      const isPatient = appt.userId ? appt.userId === req.user.id : appt.userEmail === req.user.email;
      const isDoctor = appt.doctorUserId && appt.doctorUserId === req.user.id;
      if (!isPatient && !isDoctor && req.user.role !== "admin") {
        return res.status(403).json({ message: "This is not your appointment." });
      }
      res.set("Cache-Control", "no-store");
      res.json(appt);
    });

    // Follow-up booking details for a completed visit (prefill + date window).
    app.get("/appointments/:id/follow-up", verifyToken, async (req, res) => {
      const ctx = await followUpContext(req.params.id, req.user.id);
      if (ctx.error) return res.status(400).json({ message: ctx.error });
      const doctor = await doctorCollection.findOne({ _id: new ObjectId(ctx.parent.doctorId) });
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });
      res.json({
        parentAppointmentId: req.params.id,
        doctorId: ctx.parent.doctorId,
        followUpDate: ctx.rx.followUpDate,
        window: ctx.window,
        fee: followUpFee(doctor),
        regularFee: doctor.fee || 0,
        alreadyBooked: Boolean(ctx.existing),
        patient: {
          profileId: ctx.parent.profileId || null,
          patientName: ctx.parent.patientName,
          gender: ctx.parent.gender || "",
          age: ctx.parent.age ?? null,
          phone: ctx.parent.phone || "",
        },
      });
    });

    // Reschedule: free once by default (keeps the payment), only before the
    // visit starts. The doctor has to confirm the new time again.
    app.patch("/appointments/:id", verifyToken, async (req, res) => {
      const existing = await loadOwnAppointment(req, res);
      if (!existing) return;

      if (req.body.status === "cancelled") {
        return res.status(400).json({ message: "Use the cancel action to cancel an appointment." });
      }
      if (!["pending", "confirmed"].includes(existing.status || "pending") || existing.isActive === false) {
        return res.status(403).json({ message: "This appointment can no longer be changed." });
      }
      if (bookings.hoursUntil(existing) <= 0) {
        return res.status(403).json({ message: "This appointment has already started." });
      }

      const newDate = req.body.appointmentDate ?? existing.appointmentDate;
      const newTime = req.body.appointmentTime ?? existing.appointmentTime;
      if (newDate === existing.appointmentDate && newTime === existing.appointmentTime) {
        return res.status(400).json({ message: "Pick a different date or time." });
      }

      const policy = await bookings.getRefundPolicy();
      if ((existing.rescheduleCount || 0) >= policy.freeReschedules && req.user.role !== "admin") {
        return res.status(403).json({
          message: `You've used your free reschedule${policy.freeReschedules === 1 ? "" : "s"}. Cancel and book again instead.`,
        });
      }

      const doctor = await doctorCollection.findOne({ _id: new ObjectId(existing.doctorId) });
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });

      const slotCheck = validateSlot(doctor, newDate, newTime);
      if (slotCheck.error) return res.status(400).json({ message: slotCheck.error });

      if (existing.type === "follow-up" && existing.parentAppointmentId) {
        const ctx = await followUpContext(existing.parentAppointmentId, existing.userId);
        if (!ctx.error && (newDate < ctx.window.start || newDate > ctx.window.end)) {
          return res.status(400).json({ message: `Follow-up dates must be between ${ctx.window.start} and ${ctx.window.end}.` });
        }
      }

      await bookings.releaseExpiredHolds();
      try {
        await appointmentsCollection.updateOne(
          { _id: existing._id },
          {
            $set: {
              appointmentDate: newDate,
              appointmentTime: newTime,
              serial: slotCheck.serial,
              slotMinutes: slotMinutesOf(doctor),
              status: "pending",
              queueNotified: false,
            },
            $inc: { rescheduleCount: 1 },
          }
        );
      } catch (err) {
        if (isDuplicateKey(err)) return res.status(409).json({ message: "That slot is already taken. Please pick another." });
        throw err;
      }

      await bookings.notifyDoctor(existing, {
        type: "appointment_rescheduled",
        message: `${existing.patientName} moved their appointment from ${existing.appointmentDate} ${existing.appointmentTime} to ${newDate} ${newTime} (serial #${slotCheck.serial}). Please confirm the new time.`,
      });

      res.json({ acknowledged: true, appointmentDate: newDate, appointmentTime: newTime, serial: slotCheck.serial });
    });

    // What cancelling now would refund — shown before the patient confirms.
    app.get("/appointments/:id/cancel-preview", verifyToken, async (req, res) => {
      const appt = await loadOwnAppointment(req, res);
      if (!appt) return;
      const policy = await bookings.getRefundPolicy();
      const by = req.user.role === "admin" ? "admin" : "patient";
      const percent = bookings.refundPercentFor(appt, by, policy);
      const refundable = bookings.refundableAmount(appt);
      res.json({
        refundPercent: percent,
        refundAmount: Math.min(refundable, Math.round(((appt.amount || 0) * percent) / 100)),
        paid: refundable,
        hoursUntil: Math.round(bookings.hoursUntil(appt) * 10) / 10,
        policy,
      });
    });

    app.post("/appointments/:id/cancel", writeLimiter, verifyToken, async (req, res) => {
      const appt = await loadOwnAppointment(req, res);
      if (!appt) return;
      if (!["pending", "confirmed"].includes(appt.status || "pending") || appt.isActive === false) {
        return res.status(400).json({ message: "Only upcoming appointments can be cancelled." });
      }

      const policy = await bookings.getRefundPolicy();
      const by = req.user.role === "admin" ? "admin" : "patient";
      const outcome = await bookings.cancelAppointment(appt, {
        by,
        reason: String(req.body.reason || "").slice(0, 200),
        refundPercent: bookings.refundPercentFor(appt, by, policy),
      });
      if (!outcome.ok) return res.status(409).json({ message: "This appointment was already cancelled." });

      await bookings.notifyDoctor(appt, {
        type: "appointment_cancelled",
        message: `${appt.patientName} cancelled their appointment on ${appt.appointmentDate} at ${appt.appointmentTime} (serial #${appt.serial ?? "—"}).`,
      });
      if (outcome.refund > 0) {
        await bookings.notifyPatient(appt, {
          type: "refund_issued",
          message: `৳${outcome.refund} (${outcome.percent}%) will be refunded for your cancelled appointment with ${appt.doctorName}.`,
          subject: "Refund issued — DocAppoint",
        });
      }
      res.json({ acknowledged: true, refund: outcome.refund, refundPercent: outcome.percent });
    });

    // Hard delete is only for bookings where no money ever moved; anything
    // paid goes through cancel so the ledger stays complete.
    app.delete("/appointments/:id", verifyToken, async (req, res) => {
      const existing = await loadOwnAppointment(req, res);
      if (!existing) return;

      if (existing.status && existing.status !== "pending") {
        return res.status(403).json({ message: "This appointment can no longer be deleted." });
      }
      if (["paid", "partially_refunded", "refunded", "pending"].includes(existing.paymentStatus)) {
        return res.status(403).json({ message: "Paid appointments can't be deleted — cancel it instead." });
      }

      const result = await appointmentsCollection.deleteOne({ _id: existing._id });
      res.json(result);
    });

    app.patch("/doctors/:id/review", writeLimiter, verifyToken, async (req, res) => {
      const { id } = req.params;
      const { rating, comment, appointmentId } = req.body;

      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid doctor id." });
      if (!appointmentId || !ObjectId.isValid(appointmentId)) {
        return res.status(400).json({ message: "Choose which visit you're reviewing." });
      }

      const score = Number(rating);
      if (!Number.isInteger(score) || score < 1 || score > 5) {
        return res.status(400).json({ message: "Rating must be a whole number from 1 to 5." });
      }

      const doctor = await doctorCollection.findOne({ _id: new ObjectId(id) });
      if (!doctor) return res.status(404).json({ message: "Doctor not found." });

      const userEmail = req.user.email;
      const userName = req.user.name || userEmail;

      // One review per appointment, and only for the patient's own completed visit
      // with this doctor. Claiming the appointment first makes double submits safe.
      const visit = await appointmentsCollection.findOneAndUpdate(
        {
          _id: new ObjectId(appointmentId),
          doctorId: id,
          userId: req.user.id,
          status: "completed",
          reviewed: { $ne: true },
        },
        { $set: { reviewed: true } }
      );
      if (!visit) {
        const existing = await appointmentsCollection.findOne({ _id: new ObjectId(appointmentId), userId: req.user.id });
        if (existing?.reviewed) return res.status(409).json({ message: "You've already reviewed this visit." });
        return res.status(403).json({ message: "You can only review a doctor after a completed appointment." });
      }

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
              appointmentId,
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

    // ADMIN PANEL (requires role: admin)    

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
        .find(query, { projection: { name: 1, email: 1, role: 1, status: 1, createdAt: 1, hospitalId: 1 } })
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

    // NOTIFICATIONS (any authenticated user, own notifications only)

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

    // Registered last so they sit after every route added above; Express only
    // hands errors to error middleware that comes later in the stack.
    app.use((req, res) => res.status(404).json({ message: "Not found." }));
    app.use((err, req, res, next) => {
      console.error("Unhandled error on", req.method, req.originalUrl, ":", err.message);
      if (res.headersSent) return next(err);
      res.status(err.status || 500).json({
        message: err.publicMessage || "Something went wrong on the server. Please try again.",
      });
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


app.listen(port, () => {
  console.log(`DocAppoint server listening on port ${port}`);
});
