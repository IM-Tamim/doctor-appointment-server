// Live queue: the doctor taps "Next patient" through the day's list and the
// server keeps the serial now being served per doctor/date. Patients poll
// their position; whoever is two away gets a heads-up notification.
const { ObjectId } = require("mongodb");
const { clinicNow, isDate } = require("../lib/schedule");

const WAITING = ["pending", "confirmed"];

module.exports = function registerQueueRoutes(app, ctx) {
  const { db, verifyToken, requireRole, writeLimiter, bookings } = ctx;
  const queues = db.collection("queues");
  const appointments = db.collection("appointments");
  const doctors = db.collection("doctors");

  const queueKey = (doctorId, date) => `${doctorId}:${date}`;
  const myDoctor = (userId) => doctors.findOne({ userId }, { projection: { _id: 1, name: 1, maxPerHour: 1 } });

  const dayList = (doctorId, date) =>
    appointments
      .find(
        { doctorId, appointmentDate: date, isActive: true, status: { $in: [...WAITING, "completed", "no_show"] } },
        { projection: { serial: 1, patientName: 1, status: 1, userId: 1, userEmail: 1, doctorName: 1, appointmentTime: 1, slotMinutes: 1, queueNotified: 1, appointmentDate: 1, doctorId: 1 } }
      )
      .sort({ serial: 1 })
      .toArray();

  const snapshot = async (doctorId, date) => {
    const [queue, list] = await Promise.all([queues.findOne({ _id: queueKey(doctorId, date) }), dayList(doctorId, date)]);
    return { date, currentSerial: queue?.currentSerial || 0, updatedAt: queue?.updatedAt || null, list };
  };

  app.get("/doctor/queue", verifyToken, requireRole("doctor"), async (req, res) => {
    const doctor = await myDoctor(req.user.id);
    if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });
    const date = isDate(req.query.date) ? req.query.date : clinicNow().date;
    res.set("Cache-Control", "no-store");
    res.json(await snapshot(doctor._id.toString(), date));
  });

  /** Advance to the next waiting serial (skipping empty slots), or set one explicitly. */
  app.post("/doctor/queue/next", writeLimiter, verifyToken, requireRole("doctor"), async (req, res) => {
    const doctor = await myDoctor(req.user.id);
    if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });
    const doctorId = doctor._id.toString();
    const date = clinicNow().date;
    const { currentSerial, list } = await snapshot(doctorId, date);

    const waiting = list.filter((a) => WAITING.includes(a.status));
    const target = req.body?.serial !== undefined
      ? waiting.find((a) => a.serial === Number(req.body.serial))
      : waiting.find((a) => a.serial > currentSerial);
    if (!target) return res.status(400).json({ message: "No more patients waiting today." });

    await queues.updateOne(
      { _id: queueKey(doctorId, date) },
      { $set: { doctorId, date, currentSerial: target.serial, updatedAt: new Date() } },
      { upsert: true }
    );

    await bookings.notifyPatient(target, {
      type: "queue_your_turn",
      message: `It's your turn with ${doctor.name} — serial #${target.serial}. Please go in.`,
    });

    // Heads-up for the patient two places behind the one now being served.
    const after = waiting.filter((a) => a.serial > target.serial);
    const twoAway = after[1];
    if (twoAway && !twoAway.queueNotified) {
      await appointments.updateOne({ _id: twoAway._id }, { $set: { queueNotified: true } });
      await bookings.notifyPatient(twoAway, {
        type: "queue_soon",
        message: `Now serving #${target.serial} for ${doctor.name}. You're #${twoAway.serial} — 2 patients ahead of you. Please be ready.`,
      });
    }

    res.json({ currentSerial: target.serial, patientName: target.patientName });
  });

  app.post("/doctor/queue/reset", verifyToken, requireRole("doctor"), async (req, res) => {
    const doctor = await myDoctor(req.user.id);
    if (!doctor) return res.status(404).json({ message: "Doctor profile not found" });
    await queues.deleteOne({ _id: queueKey(doctor._id.toString(), clinicNow().date) });
    res.json({ currentSerial: 0 });
  });

  /** Patient view: "Now serving #4, you are #6, about 25 min". */
  app.get("/queue/appointments/:id", verifyToken, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ message: "Invalid appointment id." });
    const appt = await appointments.findOne({ _id: new ObjectId(req.params.id) });
    const owns = appt && (appt.userId ? appt.userId === req.user.id : appt.userEmail === req.user.email);
    if (!owns) return res.status(404).json({ message: "Appointment not found." });

    res.set("Cache-Control", "no-store");
    const today = clinicNow().date;
    if (appt.appointmentDate !== today) return res.json({ state: "not_today", mySerial: appt.serial });

    const { currentSerial, list, updatedAt } = await snapshot(appt.doctorId, today);
    const slotMinutes = appt.slotMinutes || 30;
    const waitingAhead = list.filter(
      (a) => WAITING.includes(a.status) && a.serial < appt.serial && a.serial > currentSerial
    ).length;

    let state = "waiting";
    if (["completed", "no_show"].includes(appt.status)) state = "done";
    else if (appt.serial === currentSerial) state = "your_turn";
    else if (appt.serial < currentSerial) state = "passed";
    else if (currentSerial === 0) state = "not_started";

    // The patient being seen right now still has part of a slot to go.
    const ahead = waitingAhead + (currentSerial > 0 && state === "waiting" ? 1 : 0);
    res.json({
      state,
      currentSerial,
      mySerial: appt.serial,
      ahead,
      etaMinutes: ahead * slotMinutes,
      updatedAt,
    });
  });
};
