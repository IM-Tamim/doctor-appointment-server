// Digital prescriptions: written by the doctor on a completed appointment,
// downloadable as a PDF with a QR code that opens a public verify page, and
// optionally turned into medicine-reminder notifications.
const crypto = require("crypto");
const { ObjectId } = require("mongodb");
const { notify } = require("../lib/notify");
const { renderPrescription } = require("../lib/pdf");
const { isDate, clinicNow, addDays } = require("../lib/schedule");

const MAX_MEDICINES = 20;
const clean = (v, max = 200) => String(v ?? "").trim().slice(0, max);

// "1+0+1" style dose patterns map to morning / noon / night reminders.
const REMINDER_SLOTS = [
  { key: "morning", time: "08:00", label: "morning" },
  { key: "noon", time: "14:00", label: "afternoon" },
  { key: "night", time: "21:00", label: "night" },
];

/** "30 days" / "2 weeks" / "3 months" / "7" → days (capped at 90). */
const durationDays = (text) => {
  const m = /(\d+)\s*(day|days|d|week|weeks|w|month|months|m)?/i.exec(String(text || ""));
  if (!m) return 0;
  const n = Number(m[1]);
  const unit = (m[2] || "d").toLowerCase();
  const days = unit.startsWith("w") ? n * 7 : unit.startsWith("m") ? n * 30 : n;
  return Math.min(days, 90);
};

/** Which reminder slots a frequency like "1+0+1" asks for (empty if unparseable). */
const slotsForFrequency = (text) => {
  const m = /^\s*(\d)\s*\+\s*(\d)\s*\+\s*(\d)/.exec(String(text || ""));
  if (!m) return [];
  return REMINDER_SLOTS.filter((_, i) => Number(m[i + 1]) > 0);
};

const initials = (name) =>
  String(name || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => `${w[0]}${"*".repeat(Math.max(1, Math.min(4, w.length - 1)))}`)
    .join(" ");

module.exports = function registerPrescriptionRoutes(app, ctx) {
  const { db, verifyToken, requireRole, writeLimiter, bookings, clientUrl, downloads } = ctx;
  const prescriptions = db.collection("prescriptions");
  const appointments = db.collection("appointments");
  const doctors = db.collection("doctors");
  const notificationsCollection = db.collection("notifications");

  prescriptions.createIndex({ appointmentId: 1 }, { unique: true }).catch(() => {});
  prescriptions.createIndex({ "reminders.enabled": 1 }).catch(() => {});

  const verifyUrlFor = (rx) => `${clientUrl()}/verify/${rx._id}?code=${rx.verifyCode}`;

  const canRead = (rx, user) =>
    user.role === "admin" || rx.userId === user.id || rx.doctorUserId === user.id;

  app.post("/doctor/appointments/:id/digital-prescription", writeLimiter, verifyToken, requireRole("doctor"), async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid appointment id." });
    const appt = await appointments.findOne({ _id: new ObjectId(id) });
    if (!appt) return res.status(404).json({ message: "Appointment not found." });

    const doctor = await doctors.findOne({ userId: req.user.id });
    if (!doctor || appt.doctorId !== doctor._id.toString()) {
      return res.status(403).json({ message: "This appointment is not yours." });
    }
    if (appt.status !== "completed") {
      return res.status(400).json({ message: "Mark the appointment completed before writing the prescription." });
    }

    const medicines = (Array.isArray(req.body.medicines) ? req.body.medicines : [])
      .map((m) => ({
        name: clean(m?.name, 120),
        dose: clean(m?.dose, 60),
        frequency: clean(m?.frequency, 80),
        duration: clean(m?.duration, 60),
      }))
      .filter((m) => m.name)
      .slice(0, MAX_MEDICINES);
    const tests = (Array.isArray(req.body.tests) ? req.body.tests : String(req.body.tests || "").split(/\n|,/))
      .map((t) => clean(t, 120))
      .filter(Boolean)
      .slice(0, 20);
    const advice = clean(req.body.advice, 2000);
    const followUpDate = req.body.followUpDate ? String(req.body.followUpDate) : null;

    if (medicines.length === 0 && !advice && tests.length === 0) {
      return res.status(400).json({ message: "Add at least one medicine, test or piece of advice." });
    }
    if (followUpDate && (!isDate(followUpDate) || followUpDate <= appt.appointmentDate)) {
      return res.status(400).json({ message: "The follow-up date must be after the visit." });
    }

    const now = new Date();
    const fields = {
      appointmentId: id,
      userId: appt.userId || null,
      profileId: appt.profileId || null,
      doctorId: appt.doctorId,
      doctorUserId: req.user.id,
      doctorName: doctor.name,
      doctorDegree: doctor.degree || "",
      doctorSpecialty: doctor.specialty || "",
      doctorRegNo: doctor.registrationNumber || "",
      hospitalName: appt.consultationMode === "online" ? "" : appt.hospitalName || doctor.hospital || "",
      patientName: appt.patientName,
      patientAge: appt.age ?? null,
      patientGender: appt.gender || "",
      visitDate: appt.appointmentDate,
      medicines,
      tests,
      advice,
      followUpDate,
      updatedAt: now,
    };

    const result = await prescriptions.findOneAndUpdate(
      { appointmentId: id },
      { $set: fields, $setOnInsert: { createdAt: now, issuedAt: now, verifyCode: crypto.randomBytes(5).toString("hex").toUpperCase() } },
      { upsert: true, returnDocument: "after" }
    );
    await appointments.updateOne({ _id: appt._id }, { $set: { prescriptionId: result._id.toString() } });

    await bookings.notifyPatient(appt, {
      type: "prescription_ready",
      message: `${doctor.name} added your prescription for the ${appt.appointmentDate} visit.${followUpDate ? ` A follow-up is suggested around ${followUpDate} — you can book it from My Bookings.` : ""}`,
      subject: "Your prescription is ready — DocAppoint",
    });

    res.json({ acknowledged: true, prescriptionId: result._id, verifyUrl: verifyUrlFor(result) });
  });

  app.get("/appointments/:id/prescription", verifyToken, async (req, res) => {
    const rx = await prescriptions.findOne({ appointmentId: req.params.id });
    if (!rx) return res.status(404).json({ message: "No digital prescription for this appointment." });
    if (!canRead(rx, req.user)) return res.status(403).json({ message: "Not your prescription." });
    res.json({ ...rx, verifyUrl: verifyUrlFor(rx) });
  });

  /** The prescription if the caller may read it; otherwise sends the error and returns null. */
  const readablePrescription = async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return void res.status(400).json({ message: "Invalid prescription id." });
    const rx = await prescriptions.findOne({ _id: new ObjectId(req.params.id) });
    if (!rx) return void res.status(404).json({ message: "Prescription not found." });
    if (!canRead(rx, req.user)) return void res.status(403).json({ message: "Not your prescription." });
    return rx;
  };

  const sendPrescription = async (res, rx, lang) => {
    const doc = await renderPrescription(rx, { verifyUrl: verifyUrlFor(rx), lang: lang === "bn" ? "bn" : "en" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="prescription-${rx.visitDate}-${rx._id}.pdf"`);
    res.setHeader("Cache-Control", "no-store");
    doc.pipe(res);
    doc.end();
  };

  app.get("/prescriptions/:id/pdf", verifyToken, async (req, res) => {
    const rx = await readablePrescription(req, res);
    if (rx) await sendPrescription(res, rx, req.query.lang);
  });

  // For the mobile app, which can't save blob downloads (see lib/downloads.js).
  app.post("/prescriptions/:id/pdf-link", verifyToken, async (req, res) => {
    const rx = await readablePrescription(req, res);
    if (rx) res.json({ url: await downloads.issue("prescription", { id: rx._id, lang: req.body?.lang }) });
  });

  downloads.register("prescription", async (res, { id, lang }) => {
    const rx = await prescriptions.findOne({ _id: new ObjectId(id) });
    if (!rx) return res.status(404).type("text/plain").send("Prescription not found.");
    await sendPrescription(res, rx, lang);
  });

  /**
   * Public authenticity check behind the QR code. Anyone can confirm a
   * prescription exists and who issued it; the medicine list is only shown
   * with the code printed in the QR, so guessing ids reveals nothing medical.
   */
  app.get("/verify/prescriptions/:id", async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!ObjectId.isValid(req.params.id)) return res.json({ genuine: false });
    const rx = await prescriptions.findOne({ _id: new ObjectId(req.params.id) });
    if (!rx) return res.json({ genuine: false });

    const codeValid = Boolean(req.query.code) && String(req.query.code).toUpperCase() === rx.verifyCode;
    res.json({
      genuine: true,
      codeValid,
      id: rx._id,
      issuedAt: rx.issuedAt,
      updatedAt: rx.updatedAt,
      visitDate: rx.visitDate,
      doctorName: rx.doctorName,
      doctorDegree: rx.doctorDegree,
      doctorSpecialty: rx.doctorSpecialty,
      doctorRegNo: rx.doctorRegNo,
      hospitalName: rx.hospitalName,
      patient: codeValid ? rx.patientName : initials(rx.patientName),
      followUpDate: codeValid ? rx.followUpDate : null,
      medicines: codeValid ? rx.medicines : null,
      medicineCount: (rx.medicines || []).length,
    });
  });

  // ── Medicine reminders (opt-in by the patient) ──────────────────────────

  app.patch("/prescriptions/:id/reminders", verifyToken, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ message: "Invalid prescription id." });
    const rx = await prescriptions.findOne({ _id: new ObjectId(req.params.id) });
    if (!rx || rx.userId !== req.user.id) return res.status(404).json({ message: "Prescription not found." });

    const enabled = Boolean(req.body.enabled);
    const schedulable = (rx.medicines || []).filter((m) => slotsForFrequency(m.frequency).length > 0);
    if (enabled && schedulable.length === 0) {
      return res.status(400).json({ message: "None of the medicines use a 1+0+1 style schedule, so there's nothing to remind." });
    }
    // Doses whose time already passed today aren't reminded retroactively.
    const now = clinicNow();
    const alreadyPast = REMINDER_SLOTS.filter((s) => s.time <= now.time).map((s) => `${now.date}:${s.key}`);
    await prescriptions.updateOne(
      { _id: rx._id },
      { $set: { "reminders.enabled": enabled, "reminders.startDate": now.date, "reminders.sent": alreadyPast } }
    );
    res.json({ enabled, medicines: schedulable.length });
  });

  /** Runs every few minutes: one notification per dose slot that has come due today. */
  const sendDueReminders = async () => {
    const now = clinicNow();
    const due = REMINDER_SLOTS.filter((s) => s.time <= now.time);
    if (due.length === 0) return;
    const active = await prescriptions.find({ "reminders.enabled": true }).toArray();
    for (const rx of active) {
      // Only today's keys matter; drop older ones so the list stays tiny.
      const allSent = rx.reminders?.sent || [];
      const sent = new Set(allSent.filter((k) => k.startsWith(now.date)));
      if (sent.size !== allSent.length) {
        await prescriptions.updateOne({ _id: rx._id }, { $set: { "reminders.sent": [...sent] } });
      }
      for (const slot of due) {
        const key = `${now.date}:${slot.key}`;
        if (sent.has(key)) continue;
        const meds = (rx.medicines || []).filter((m) => {
          const days = durationDays(m.duration);
          const last = addDays(rx.reminders.startDate || rx.visitDate, Math.max(days, 1) - 1);
          return now.date <= last && slotsForFrequency(m.frequency).some((s) => s.key === slot.key);
        });
        // Mark the slot handled even when nothing is due, so it isn't re-checked.
        await prescriptions.updateOne({ _id: rx._id }, { $addToSet: { "reminders.sent": key } });
        if (meds.length === 0 || !rx.userId) continue;
        await notify({
          notificationsCollection,
          userId: rx.userId,
          type: "medicine_reminder",
          message: `Medicine reminder (${slot.label}): ${meds.map((m) => `${m.name}${m.dose ? ` — ${m.dose}` : ""}`).join(", ")}.`,
        });
      }
    }
  };
  setInterval(() => sendDueReminders().catch((e) => console.warn("[reminders]", e.message)), 5 * 60 * 1000).unref();

  return { sendDueReminders };
};
