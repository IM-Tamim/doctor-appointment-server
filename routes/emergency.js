// Blood donors, urgent blood requests and ambulances.
const { ObjectId } = require("mongodb");
const { notify } = require("../lib/notify");
const { isDate, clinicNow, addDays } = require("../lib/schedule");

const BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"];
const MIN_GAP_DAYS = 90; // whole-blood donations must be at least this far apart
const AMBULANCE_TYPES = ["Basic", "AC", "ICU", "Freezer"];
const MAX_REQUEST_NOTIFICATIONS = 50;

const escapeRegex = (v) => String(v).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const clean = (v, max = 120) => String(v ?? "").trim().slice(0, max);
const isPhone = (v) => /^\+?[\d\s-]{5,20}$/.test(String(v || ""));

/** Date a donor may give again (YYYY-MM-DD), or today if they've never donated. */
const eligibleFrom = (donor) =>
  donor.lastDonationDate ? addDays(donor.lastDonationDate, MIN_GAP_DAYS) : clinicNow().date;

module.exports = function registerEmergencyRoutes(app, ctx) {
  const { db, verifyToken, requireRole, writeLimiter } = ctx;
  const donors = db.collection("donors");
  const requests = db.collection("bloodRequests");
  const ambulances = db.collection("ambulances");
  const hospitals = db.collection("hospitals");
  const users = db.collection("user");
  const notificationsCollection = db.collection("notifications");

  donors.createIndex({ bloodGroup: 1, area: 1 }).catch(() => {});
  donors.createIndex({ userId: 1 }, { unique: true }).catch(() => {});
  requests.createIndex({ createdAt: -1 }).catch(() => {});
  ambulances.createIndex({ hospitalId: 1 }).catch(() => {});

  // Signed-in callers get donors' phone numbers; anonymous ones don't.
  const optionalAuth = (req, res, next) => (req.headers.authorization ? verifyToken(req, res, next) : next());

  // ── Donors ──────────────────────────────────────────────────────────────

  app.get("/donors", optionalAuth, async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 12));
    const cutoff = addDays(clinicNow().date, -MIN_GAP_DAYS);

    const filter = {
      available: true,
      $or: [{ lastDonationDate: null }, { lastDonationDate: { $lte: cutoff } }],
    };
    if (BLOOD_GROUPS.includes(req.query.bloodGroup)) filter.bloodGroup = req.query.bloodGroup;
    if (req.query.area && String(req.query.area).trim()) {
      filter.area = new RegExp(escapeRegex(String(req.query.area).trim()), "i");
    }

    const [list, total] = await Promise.all([
      donors.find(filter).sort({ lastDonationDate: 1, _id: 1 }).skip((page - 1) * limit).limit(limit).toArray(),
      donors.countDocuments(filter),
    ]);
    res.set("Cache-Control", "no-store");
    res.json({
      donors: list.map((d) => ({
        _id: d._id,
        name: d.name,
        bloodGroup: d.bloodGroup,
        area: d.area,
        lastDonationDate: d.lastDonationDate || null,
        phone: req.user ? d.phone : null,
      })),
      total,
      page,
      totalPages: Math.max(1, Math.ceil(total / limit)),
      phoneVisible: Boolean(req.user),
    });
  });

  app.get("/me/donor", verifyToken, async (req, res) => {
    const donor = await donors.findOne({ userId: req.user.id });
    res.json(donor ? { ...donor, eligibleFrom: eligibleFrom(donor) } : null);
  });

  app.put("/me/donor", writeLimiter, verifyToken, async (req, res) => {
    const { bloodGroup, area, phone, available, lastDonationDate } = req.body;
    if (!BLOOD_GROUPS.includes(bloodGroup)) return res.status(400).json({ message: "Choose a valid blood group." });
    if (!clean(area)) return res.status(400).json({ message: "Enter your area (e.g. Mirpur, Dhaka)." });
    if (!isPhone(phone)) return res.status(400).json({ message: "Enter a phone number donors can be reached on." });

    const today = clinicNow().date;
    let last = lastDonationDate || null;
    if (last && (!isDate(last) || last > today)) {
      return res.status(400).json({ message: "Last donation date can't be in the future." });
    }

    const existing = await donors.findOne({ userId: req.user.id });
    // A newer donation inside 90 days of the previous one isn't possible.
    if (existing?.lastDonationDate && last && last > existing.lastDonationDate && last < addDays(existing.lastDonationDate, MIN_GAP_DAYS)) {
      return res.status(400).json({
        message: `Donations must be at least ${MIN_GAP_DAYS} days apart — your previous donation was on ${existing.lastDonationDate}.`,
      });
    }

    const fields = {
      userId: req.user.id,
      name: req.user.name || "Donor",
      bloodGroup,
      area: clean(area, 80),
      phone: clean(phone, 20),
      available: available !== false,
      lastDonationDate: last,
      updatedAt: new Date(),
    };
    await donors.updateOne({ userId: req.user.id }, { $set: fields, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
    res.json({ ...fields, eligibleFrom: eligibleFrom(fields) });
  });

  app.delete("/me/donor", verifyToken, async (req, res) => {
    await donors.deleteOne({ userId: req.user.id });
    res.json({ acknowledged: true });
  });

  // ── Urgent blood requests (notify matching, eligible donors) ────────────

  app.post("/blood-requests", writeLimiter, verifyToken, async (req, res) => {
    const { bloodGroup, area, hospital, units, contactPhone, note, neededBy } = req.body;
    if (!BLOOD_GROUPS.includes(bloodGroup)) return res.status(400).json({ message: "Choose a valid blood group." });
    if (!clean(area)) return res.status(400).json({ message: "Enter the area where blood is needed." });
    if (!isPhone(contactPhone)) return res.status(400).json({ message: "Enter a contact phone number." });
    const unitCount = Math.max(1, Math.min(10, parseInt(units, 10) || 1));
    if (neededBy && (!isDate(neededBy) || neededBy < clinicNow().date)) {
      return res.status(400).json({ message: "The needed-by date can't be in the past." });
    }

    // One open request per person at a time keeps this from being used for spam.
    const open = await requests.countDocuments({ userId: req.user.id, status: "open" });
    if (open >= 2) return res.status(429).json({ message: "Close one of your open requests before posting another." });

    const doc = {
      userId: req.user.id,
      requesterName: req.user.name || "",
      bloodGroup,
      area: clean(area, 80),
      hospital: clean(hospital, 120),
      units: unitCount,
      contactPhone: clean(contactPhone, 20),
      note: clean(note, 300),
      neededBy: neededBy || null,
      status: "open",
      createdAt: new Date(),
    };
    const { insertedId } = await requests.insertOne(doc);

    const cutoff = addDays(clinicNow().date, -MIN_GAP_DAYS);
    const matches = await donors
      .find({
        bloodGroup,
        available: true,
        userId: { $ne: req.user.id },
        area: new RegExp(escapeRegex(doc.area.split(",")[0].trim()), "i"),
        $or: [{ lastDonationDate: null }, { lastDonationDate: { $lte: cutoff } }],
      })
      .limit(MAX_REQUEST_NOTIFICATIONS)
      .toArray();
    for (const donor of matches) {
      await notify({
        notificationsCollection,
        userId: donor.userId,
        type: "blood_request",
        message: `Urgent: ${unitCount} unit${unitCount > 1 ? "s" : ""} of ${bloodGroup} blood needed in ${doc.area}${doc.hospital ? ` at ${doc.hospital}` : ""}. Contact ${doc.contactPhone} if you can donate.`,
      });
    }
    await requests.updateOne({ _id: insertedId }, { $set: { notified: matches.length } });
    res.json({ acknowledged: true, insertedId, notified: matches.length });
  });

  app.get("/blood-requests", optionalAuth, async (req, res) => {
    const filter = { status: "open", createdAt: { $gte: new Date(Date.now() - 30 * 86400000) } };
    if (BLOOD_GROUPS.includes(req.query.bloodGroup)) filter.bloodGroup = req.query.bloodGroup;
    if (req.query.mine === "1" && req.user) {
      delete filter.status;
      filter.userId = req.user.id;
    }
    const list = await requests.find(filter).sort({ createdAt: -1 }).limit(30).toArray();
    res.set("Cache-Control", "no-store");
    res.json(list.map((r) => ({ ...r, contactPhone: req.user ? r.contactPhone : null })));
  });

  app.patch("/blood-requests/:id/close", verifyToken, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ message: "Invalid request id." });
    const result = await requests.updateOne(
      { _id: new ObjectId(req.params.id), userId: req.user.id },
      { $set: { status: "closed", closedAt: new Date() } }
    );
    if (result.matchedCount === 0) return res.status(404).json({ message: "Request not found." });
    res.json({ acknowledged: true });
  });

  // ── Ambulances ──────────────────────────────────────────────────────────

  app.get("/ambulances", async (req, res) => {
    const match = {};
    if (req.query.hospitalId) match.hospitalId = String(req.query.hospitalId);
    if (req.query.available === "1") match.available = true;
    const pipeline = [
      { $match: match },
      {
        $lookup: {
          from: "hospitals",
          let: { hid: { $toObjectId: "$hospitalId" } },
          pipeline: [{ $match: { $expr: { $eq: ["$_id", "$$hid"] } } }, { $project: { name: 1, city: 1, emergencyPhone: 1 } }],
          as: "hospital",
        },
      },
      { $addFields: { hospital: { $first: "$hospital" } } },
    ];
    if (req.query.city) pipeline.push({ $match: { "hospital.city": new RegExp(`^${escapeRegex(req.query.city)}$`, "i") } });
    pipeline.push({ $sort: { available: -1, "hospital.name": 1, type: 1 } });
    if (req.query.page === undefined) return res.json(await ambulances.aggregate(pipeline).toArray());

    // Paged form for the public emergency page.
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));
    pipeline.push({ $facet: { ambulances: [{ $skip: (page - 1) * limit }, { $limit: limit }], total: [{ $count: "n" }] } });
    const [facet] = await ambulances.aggregate(pipeline).toArray();
    const total = facet.total[0]?.n || 0;
    res.json({ ambulances: facet.ambulances, total, page, limit, totalPages: Math.max(1, Math.ceil(total / limit)) });
  });

  const parseAmbulance = (body, { partial = false } = {}) => {
    const out = {};
    if (body.type !== undefined || !partial) {
      if (!AMBULANCE_TYPES.includes(body.type)) return { error: `Type must be one of ${AMBULANCE_TYPES.join(", ")}.` };
      out.type = body.type;
    }
    if (body.phone !== undefined || !partial) {
      if (!isPhone(body.phone)) return { error: "Enter a valid phone number." };
      out.phone = clean(body.phone, 20);
    }
    if (body.available !== undefined) out.available = Boolean(body.available);
    else if (!partial) out.available = true;
    if (body.vehicleNo !== undefined) out.vehicleNo = clean(body.vehicleNo, 30);
    return { value: out };
  };

  /** Admins manage any hospital's ambulances; hospital managers only their own. */
  const ambulanceScope = async (req) => {
    if (req.user.role === "admin") return { hospitalId: req.body?.hospitalId ? String(req.body.hospitalId) : null };
    const me = await users.findOne({ _id: new ObjectId(req.user.id) }, { projection: { hospitalId: 1 } });
    return { hospitalId: me?.hospitalId || null, restricted: true };
  };

  app.post("/manage/ambulances", writeLimiter, verifyToken, requireRole("admin", "hospital_admin"), async (req, res) => {
    const scope = await ambulanceScope(req);
    if (!scope.hospitalId || !ObjectId.isValid(scope.hospitalId)) return res.status(400).json({ message: "Choose a hospital." });
    if (!(await hospitals.countDocuments({ _id: new ObjectId(scope.hospitalId) }))) {
      return res.status(404).json({ message: "Hospital not found." });
    }
    const { value, error } = parseAmbulance(req.body);
    if (error) return res.status(400).json({ message: error });
    const result = await ambulances.insertOne({ ...value, hospitalId: scope.hospitalId, createdAt: new Date() });
    res.json(result);
  });

  const ownedAmbulance = async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
      res.status(400).json({ message: "Invalid ambulance id." });
      return null;
    }
    const amb = await ambulances.findOne({ _id: new ObjectId(req.params.id) });
    if (!amb) {
      res.status(404).json({ message: "Ambulance not found." });
      return null;
    }
    const scope = await ambulanceScope(req);
    if (scope.restricted && amb.hospitalId !== scope.hospitalId) {
      res.status(403).json({ message: "This ambulance belongs to another hospital." });
      return null;
    }
    return amb;
  };

  app.patch("/manage/ambulances/:id", verifyToken, requireRole("admin", "hospital_admin"), async (req, res) => {
    const amb = await ownedAmbulance(req, res);
    if (!amb) return;
    const { value, error } = parseAmbulance(req.body, { partial: true });
    if (error) return res.status(400).json({ message: error });
    res.json(await ambulances.updateOne({ _id: amb._id }, { $set: value }));
  });

  app.delete("/manage/ambulances/:id", verifyToken, requireRole("admin", "hospital_admin"), async (req, res) => {
    const amb = await ownedAmbulance(req, res);
    if (!amb) return;
    res.json(await ambulances.deleteOne({ _id: amb._id }));
  });
};

module.exports.BLOOD_GROUPS = BLOOD_GROUPS;
