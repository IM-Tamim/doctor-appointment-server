// Shared appointment lifecycle: cancellation + refunds, payment-hold expiry,
// the refund policy and patient/doctor notifications. Used by the booking
// routes, leave days, payments and the admin tools so the rules live in one
// place.
const { ObjectId } = require("mongodb");
const { notify } = require("./notify");
const { slotInstant } = require("./schedule");

const DEFAULT_REFUND_POLICY = {
  fullRefundHours: 24, // cancelled more than this many hours ahead → 100%
  partialRefundHours: 2, // between this and fullRefundHours → partialRefundPercent
  partialRefundPercent: 50,
  doctorCancelPercent: 100, // doctor / admin / leave cancellations
  freeReschedules: 1,
};

// Unpaid online bookings hold their slot this long before being released.
const HOLD_MINUTES = 10;

const PAID_STATES = ["paid", "partially_refunded"];

const createAppointmentService = ({ db }) => {
  const appointments = db.collection("appointments");
  const payments = db.collection("payments");
  const settings = db.collection("settings");
  const users = db.collection("user");
  const notificationsCollection = db.collection("notifications");

  const getRefundPolicy = async () => {
    const doc = await settings.findOne({ _id: "refundPolicy" });
    return { ...DEFAULT_REFUND_POLICY, ...(doc?.value || {}) };
  };

  const hoursUntil = (appt) =>
    (slotInstant(appt.appointmentDate, appt.appointmentTime).getTime() - Date.now()) / 3600000;

  /** Refund percentage for a cancellation by `by` (patient | doctor | admin | system). */
  const refundPercentFor = (appt, by, policy) => {
    if (by !== "patient") return policy.doctorCancelPercent;
    const hours = hoursUntil(appt);
    if (hours > policy.fullRefundHours) return 100;
    if (hours >= policy.partialRefundHours) return policy.partialRefundPercent;
    return 0;
  };

  /** Amount still held by the platform for this appointment. */
  const refundableAmount = (appt) =>
    PAID_STATES.includes(appt.paymentStatus) ? Math.max(0, (appt.amount || 0) - (appt.refundedAmount || 0)) : 0;

  // Older appointments only stored the email; resolve the account id once.
  const patientUserId = async (appt) => {
    if (appt.userId) return appt.userId;
    const user = await users.findOne({ email: appt.userEmail }, { projection: { _id: 1 } });
    return user?._id?.toString() || null;
  };

  const notifyPatient = async (appt, { type, message, subject, html }) => {
    const userId = await patientUserId(appt);
    if (!userId) return;
    await notify({
      notificationsCollection,
      userId,
      type,
      message,
      email: subject && appt.userEmail ? { to: appt.userEmail, subject, html: html || `<p>${message}</p>` } : undefined,
    });
  };

  const notifyDoctor = async (appt, { type, message }) => {
    let doctorUserId = appt.doctorUserId;
    if (!doctorUserId && ObjectId.isValid(appt.doctorId)) {
      const doctor = await db.collection("doctors").findOne(
        { _id: new ObjectId(appt.doctorId) },
        { projection: { userId: 1 } }
      );
      doctorUserId = doctor?.userId;
    }
    if (doctorUserId) await notify({ notificationsCollection, userId: doctorUserId, type, message });
  };

  /** Ledger entry. Snapshots doctor/hospital so analytics never need a join. */
  const recordLedger = (appt, { type, amount, method, transactionId, note }) =>
    payments.insertOne({
      appointmentId: appt._id.toString(),
      type, // payment | refund
      amount,
      method: method || appt.paymentMethod || "",
      transactionId: transactionId || "",
      userId: appt.userId || null,
      doctorId: appt.doctorId,
      doctorName: appt.doctorName,
      hospitalId: appt.hospitalId || null,
      hospitalName: appt.hospitalName || "",
      specialty: appt.doctorSpecialty || "",
      note: note || "",
      createdAt: new Date(),
    });

  /**
   * Cancels an active appointment, frees its slot and refunds per policy.
   * The update is conditional on isActive, so a double click can't refund twice.
   * Returns { ok, refund } or { ok: false } if it was already cancelled.
   */
  const cancelAppointment = async (appt, { by, reason, refundPercent }) => {
    const percent = Math.max(0, Math.min(100, refundPercent ?? 0));
    const remaining = refundableAmount(appt);
    const refund = Math.min(remaining, Math.round(((appt.amount || 0) * percent) / 100));

    const set = {
      status: "cancelled",
      isActive: false,
      holdExpiresAt: null,
      cancelledBy: by,
      cancelReason: reason || "",
      cancelledAt: new Date(),
    };
    if (refund > 0) {
      set.refundedAmount = (appt.refundedAmount || 0) + refund;
      set.paymentStatus = refund >= remaining ? "refunded" : "partially_refunded";
    } else if (["unpaid", "pending"].includes(appt.paymentStatus) && appt.paymentMethod !== "cash") {
      set.paymentStatus = "failed";
    }

    const result = await appointments.updateOne({ _id: appt._id, isActive: true }, { $set: set });
    if (result.modifiedCount === 0) return { ok: false, refund: 0 };

    if (refund > 0) {
      await recordLedger(appt, {
        type: "refund",
        amount: refund,
        transactionId: `RF-${appt._id.toString().slice(-6).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`,
        note: `${percent}% refund — cancelled by ${by}${reason ? `: ${reason}` : ""}`,
      });
    }
    return { ok: true, refund, percent };
  };

  /**
   * Releases online bookings whose payment window lapsed. Called lazily before
   * anything that reads or claims slots (free-tier hosts sleep, so a timer
   * alone isn't reliable) and on a 1-minute interval while the process is up.
   */
  const releaseExpiredHolds = async () => {
    const expired = await appointments
      .find({ isActive: true, holdExpiresAt: { $lte: new Date() }, paymentStatus: { $in: ["unpaid", "pending"] } })
      .toArray();
    for (const appt of expired) {
      const { ok } = await cancelAppointment(appt, {
        by: "system",
        reason: "Payment not completed in time",
        refundPercent: 0,
      });
      if (ok) {
        await notifyPatient(appt, {
          type: "booking_expired",
          message: `Your held slot with ${appt.doctorName} on ${appt.appointmentDate} at ${appt.appointmentTime} was released because payment wasn't completed.`,
        });
      }
    }
    return expired.length;
  };

  return {
    HOLD_MINUTES,
    getRefundPolicy,
    refundPercentFor,
    refundableAmount,
    hoursUntil,
    recordLedger,
    cancelAppointment,
    releaseExpiredHolds,
    notifyPatient,
    notifyDoctor,
    patientUserId,
  };
};

module.exports = { createAppointmentService, DEFAULT_REFUND_POLICY, HOLD_MINUTES };
