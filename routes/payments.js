// Payments: SSLCommerz (sandbox or live), a clearly-labelled demo mobile
// banking flow, cash collected at the hospital, and PDF receipts.
//
// Every route that marks something paid funnels through markPaid(), which is
// idempotent and writes the ledger entry, so the gateway's browser redirect
// and its server-to-server IPN can both arrive without double counting.
const express = require("express");
const crypto = require("crypto");
const { ObjectId } = require("mongodb");
const { notify } = require("../lib/notify");
const { renderReceipt } = require("../lib/pdf");

const SSLCZ_BASE = () =>
  process.env.SSLCZ_IS_LIVE === "true" ? "https://securepay.sslcommerz.com" : "https://sandbox.sslcommerz.com";
const sslczConfigured = () => Boolean(process.env.SSLCZ_STORE_ID && process.env.SSLCZ_STORE_PASSWORD);

const DEMO_OTP_MINUTES = 5;

module.exports = function registerPaymentRoutes(app, ctx) {
  const { db, verifyToken, requireRole, writeLimiter, bookings, newMeetingUrl, clientUrl, serverUrl, downloads } = ctx;
  const appointments = db.collection("appointments");
  const notificationsCollection = db.collection("notifications");

  const urlencoded = express.urlencoded({ extended: false, limit: "50kb" });
  const clientResult = (status, appointmentId, extra = "") =>
    `${clientUrl()}/payment/result?status=${status}${appointmentId ? `&appointmentId=${appointmentId}` : ""}${extra}`;

  const loadOwnUnpaid = async (req, res) => {
    const { appointmentId } = req.body;
    if (!ObjectId.isValid(appointmentId)) {
      res.status(400).json({ message: "Invalid appointment id." });
      return null;
    }
    await bookings.releaseExpiredHolds();
    const appt = await appointments.findOne({ _id: new ObjectId(appointmentId) });
    if (!appt || appt.userId !== req.user.id) {
      res.status(404).json({ message: "Appointment not found." });
      return null;
    }
    if (appt.paymentStatus === "paid") {
      res.status(409).json({ message: "This appointment is already paid." });
      return null;
    }
    if (!appt.isActive || appt.status === "cancelled") {
      res.status(410).json({ message: "This booking has expired or was cancelled. Please book again." });
      return null;
    }
    return appt;
  };

  /**
   * Marks an appointment paid exactly once and records the ledger entry. If
   * the payment hold had already lapsed, the slot is reclaimed when still
   * free; otherwise the payment is recorded and refunded in full.
   */
  const markPaid = async (appt, { method, transactionId, amount, gateway = {} }) => {
    if (appt.paymentStatus === "paid") return { ok: true, already: true };

    const set = {
      paymentStatus: "paid",
      paidAt: new Date(),
      transactionId,
      paymentMethod: method,
      holdExpiresAt: null,
      gateway,
    };
    if (appt.consultationMode === "online" && !appt.meetingUrl) set.meetingUrl = newMeetingUrl();

    const claimed = await appointments.updateOne(
      { _id: appt._id, paymentStatus: { $in: ["unpaid", "pending", "failed"] } },
      { $set: set }
    );
    if (claimed.modifiedCount === 0) return { ok: true, already: true };

    const fresh = { ...appt, ...set };
    await bookings.recordLedger(fresh, { type: "payment", amount, method, transactionId, note: "Appointment fee" });

    // Paid after the hold lapsed: take the slot back if nobody else has it.
    if (appt.isActive === false) {
      try {
        await appointments.updateOne(
          { _id: appt._id, isActive: false },
          { $set: { isActive: true, status: "pending" }, $unset: { cancelledBy: "", cancelReason: "", cancelledAt: "" } }
        );
      } catch {
        // Slot was re-booked meanwhile (unique index) — refund in full.
        await appointments.updateOne(
          { _id: appt._id },
          { $set: { paymentStatus: "refunded", refundedAmount: amount } }
        );
        await bookings.recordLedger(fresh, {
          type: "refund",
          amount,
          method,
          transactionId: `RF-${transactionId}`,
          note: "Slot was released before the payment completed",
        });
        await bookings.notifyPatient(fresh, {
          type: "refund_issued",
          message: `Your payment of ৳${amount} arrived after your held slot with ${appt.doctorName} was released, so it will be refunded in full. Please book again.`,
          subject: "Payment refunded — DocAppoint",
        });
        return { ok: false, refunded: true };
      }
    }

    await bookings.notifyPatient(fresh, {
      type: "payment_received",
      message: `Payment of ৳${amount} received for your appointment with ${appt.doctorName} on ${appt.appointmentDate} at ${appt.appointmentTime} (serial #${appt.serial}).${set.meetingUrl ? " Your video call link is ready in your bookings." : ""}`,
      subject: "Payment received — DocAppoint",
    });
    await bookings.notifyDoctor(fresh, {
      type: "payment_received",
      message: `${appt.patientName} paid ৳${amount} for ${appt.appointmentDate} at ${appt.appointmentTime} (serial #${appt.serial}).`,
    });
    return { ok: true };
  };

  // ── SSLCommerz ─────────────────────────────────────────────────────────

  app.get("/payments/config", (req, res) => {
    res.json({ sslcommerz: sslczConfigured(), sandbox: process.env.SSLCZ_IS_LIVE !== "true" });
  });

  app.post("/payments/sslcommerz/init", writeLimiter, verifyToken, async (req, res) => {
    if (!sslczConfigured()) {
      return res.status(503).json({ message: "SSLCommerz isn't configured on this server. Use demo mobile banking instead." });
    }
    const appt = await loadOwnUnpaid(req, res);
    if (!appt) return;
    if (appt.paymentMethod === "cash") return res.status(400).json({ message: "This booking is set to pay at the hospital." });

    const tranId = `DA${appt._id.toString().slice(-8)}${Date.now().toString(36)}`.toUpperCase();
    const base = serverUrl();
    const params = new URLSearchParams({
      store_id: process.env.SSLCZ_STORE_ID,
      store_passwd: process.env.SSLCZ_STORE_PASSWORD,
      total_amount: String(appt.amount),
      currency: "BDT",
      tran_id: tranId,
      success_url: `${base}/payments/sslcommerz/success`,
      fail_url: `${base}/payments/sslcommerz/fail`,
      cancel_url: `${base}/payments/sslcommerz/cancel`,
      ipn_url: `${base}/payments/sslcommerz/ipn`,
      shipping_method: "NO",
      product_name: `Consultation — ${appt.doctorName}`.slice(0, 100),
      product_category: "Healthcare",
      product_profile: "non-physical-goods",
      cus_name: appt.patientName || req.user.name || "Patient",
      cus_email: req.user.email,
      cus_add1: appt.hospitalName || "Bangladesh",
      cus_city: "Dhaka",
      cus_postcode: "1000",
      cus_country: "Bangladesh",
      cus_phone: appt.phone || "01700000000",
      value_a: appt._id.toString(),
    });

    let data;
    try {
      const r = await fetch(`${SSLCZ_BASE()}/gwprocess/v4/api.php`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params,
        signal: AbortSignal.timeout(20000),
      });
      data = await r.json();
    } catch (err) {
      console.error("[sslcommerz] init failed:", err.message);
      return res.status(502).json({ message: "Couldn't reach the payment gateway. Please try again." });
    }
    if (data?.status !== "SUCCESS" || !data.GatewayPageURL) {
      return res.status(502).json({ message: data?.failedreason || "The payment gateway rejected the request." });
    }

    // Give the patient a fresh window to finish on the gateway page.
    await appointments.updateOne(
      { _id: appt._id },
      {
        $set: {
          paymentStatus: "pending",
          transactionId: tranId,
          holdExpiresAt: new Date(Date.now() + bookings.HOLD_MINUTES * 60 * 1000),
        },
      }
    );
    res.json({ url: data.GatewayPageURL });
  });

  /** Asks SSLCommerz whether a val_id is genuine. Never trust the callback body alone. */
  const validateWithGateway = async (valId) => {
    const q = new URLSearchParams({
      val_id: valId,
      store_id: process.env.SSLCZ_STORE_ID,
      store_passwd: process.env.SSLCZ_STORE_PASSWORD,
      v: "1",
      format: "json",
    });
    const r = await fetch(`${SSLCZ_BASE()}/validator/api/validationserverAPI.php?${q}`, {
      signal: AbortSignal.timeout(20000),
    });
    return r.json();
  };

  const settleFromGateway = async (body) => {
    const { val_id: valId, tran_id: tranId } = body || {};
    if (!valId || !tranId || !sslczConfigured()) return { status: "failed" };

    const appt = await appointments.findOne({ transactionId: tranId });
    if (!appt) return { status: "failed" };

    let v;
    try {
      v = await validateWithGateway(valId);
    } catch (err) {
      console.error("[sslcommerz] validation failed:", err.message);
      return { status: "failed", appt };
    }
    const valid =
      ["VALID", "VALIDATED"].includes(v?.status) &&
      v.tran_id === tranId &&
      v.currency_type === "BDT" &&
      Math.abs(Number(v.currency_amount ?? v.amount) - Number(appt.amount)) < 0.01;
    if (!valid) {
      console.warn(`[sslcommerz] rejected val_id ${valId} for ${tranId}: ${v?.status}`);
      return { status: "failed", appt };
    }

    const outcome = await markPaid(appt, {
      method: "sslcommerz",
      transactionId: tranId,
      amount: appt.amount,
      gateway: { valId, bankTranId: v.bank_tran_id || "", cardType: v.card_type || "" },
    });
    return { status: outcome.refunded ? "refunded" : "success", appt };
  };

  // The gateway POSTs the patient's browser to these, so they answer with a
  // redirect back to the web app rather than JSON.
  app.post("/payments/sslcommerz/success", urlencoded, async (req, res) => {
    const { status, appt } = await settleFromGateway(req.body);
    res.redirect(303, clientResult(status, appt?._id?.toString()));
  });

  const abandon = (status) => async (req, res) => {
    const appt = req.body?.tran_id ? await appointments.findOne({ transactionId: req.body.tran_id }) : null;
    if (appt && appt.paymentStatus === "pending") {
      // Back to unpaid so the patient can retry while the hold lasts.
      await appointments.updateOne({ _id: appt._id, paymentStatus: "pending" }, { $set: { paymentStatus: "unpaid" } });
    }
    res.redirect(303, clientResult(status, appt?._id?.toString()));
  };
  app.post("/payments/sslcommerz/fail", urlencoded, abandon("failed"));
  app.post("/payments/sslcommerz/cancel", urlencoded, abandon("cancelled"));

  // Server-to-server confirmation; covers patients who close the tab early.
  app.post("/payments/sslcommerz/ipn", urlencoded, async (req, res) => {
    const { status } = await settleFromGateway(req.body);
    res.json({ received: true, status });
  });

  // ── Demo mobile banking (simulation — no real money moves) ───────────────

  app.post("/payments/demo/start", writeLimiter, verifyToken, async (req, res) => {
    const appt = await loadOwnUnpaid(req, res);
    if (!appt) return;
    if (appt.paymentMethod === "cash") return res.status(400).json({ message: "This booking is set to pay at the hospital." });

    const phone = String(req.body.phone || "").replace(/\D/g, "");
    if (!/^01\d{9}$/.test(phone)) return res.status(400).json({ message: "Enter an 11-digit mobile number starting with 01." });

    const otp = String(crypto.randomInt(100000, 1000000));
    await appointments.updateOne(
      { _id: appt._id },
      {
        $set: {
          paymentMethod: "demo_mobile",
          paymentStatus: "pending",
          demoPayment: { phone, otp, attempts: 0, expiresAt: new Date(Date.now() + DEMO_OTP_MINUTES * 60 * 1000) },
          holdExpiresAt: new Date(Date.now() + bookings.HOLD_MINUTES * 60 * 1000),
        },
      }
    );
    // A real wallet would SMS this. The demo shows it on screen instead.
    res.json({ demoOtp: otp, amount: appt.amount, expiresInSeconds: DEMO_OTP_MINUTES * 60 });
  });

  app.post("/payments/demo/confirm", writeLimiter, verifyToken, async (req, res) => {
    const appt = await loadOwnUnpaid(req, res);
    if (!appt) return;
    const session = appt.demoPayment;
    if (!session) return res.status(400).json({ message: "Start the demo payment first." });
    if (new Date(session.expiresAt) < new Date()) return res.status(400).json({ message: "The demo code expired. Request a new one." });
    if (session.attempts >= 3) return res.status(429).json({ message: "Too many wrong codes. Request a new one." });

    const { otp, pin } = req.body;
    if (String(otp) !== session.otp) {
      await appointments.updateOne({ _id: appt._id }, { $inc: { "demoPayment.attempts": 1 } });
      return res.status(400).json({ message: "That code doesn't match." });
    }
    if (!/^\d{4,5}$/.test(String(pin || ""))) {
      return res.status(400).json({ message: "Enter your 4–5 digit demo PIN." });
    }

    const transactionId = `DEMO-${Date.now().toString(36).toUpperCase()}${crypto.randomBytes(2).toString("hex").toUpperCase()}`;
    const outcome = await markPaid(appt, { method: "demo_mobile", transactionId, amount: appt.amount });
    await appointments.updateOne({ _id: appt._id }, { $unset: { demoPayment: "" } });
    if (outcome.refunded) {
      return res.status(409).json({ message: "Your slot was released before payment completed, so the payment was refunded." });
    }
    res.json({ acknowledged: true, transactionId });
  });

  // ── Cash collected at the hospital ──────────────────────────────────────

  app.patch("/doctor/appointments/:id/cash-received", verifyToken, requireRole("doctor"), async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid appointment id." });
    const appt = await appointments.findOne({ _id: new ObjectId(id) });
    if (!appt) return res.status(404).json({ message: "Appointment not found." });
    const doctor = await db.collection("doctors").findOne({ userId: req.user.id }, { projection: { _id: 1 } });
    if (!doctor || appt.doctorId !== doctor._id.toString()) {
      return res.status(403).json({ message: "This appointment is not yours." });
    }
    if (appt.paymentMethod !== "cash" || appt.paymentStatus !== "unpaid") {
      return res.status(400).json({ message: "Only unpaid pay-at-hospital bookings can be marked as paid." });
    }
    if (!appt.isActive) return res.status(400).json({ message: "This appointment was cancelled." });

    const transactionId = `CASH-${appt.receiptNo || appt._id.toString().slice(-6).toUpperCase()}`;
    await markPaid(appt, { method: "cash", transactionId, amount: appt.amount });
    res.json({ acknowledged: true, transactionId });
  });

  // ── Receipt PDF ─────────────────────────────────────────────────────────

  /** The appointment if the caller may read its receipt; otherwise sends the error and returns null. */
  const readableReceipt = async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return void res.status(400).json({ message: "Invalid appointment id." });
    const appt = await appointments.findOne({ _id: new ObjectId(id) });
    if (!appt) return void res.status(404).json({ message: "Appointment not found." });

    const isPatient = appt.userId ? appt.userId === req.user.id : appt.userEmail === req.user.email;
    const isDoctor = appt.doctorUserId && appt.doctorUserId === req.user.id;
    if (!isPatient && !isDoctor && req.user.role !== "admin") {
      return void res.status(403).json({ message: "This is not your appointment." });
    }
    return appt;
  };

  const sendReceipt = async (res, appt, lang) => {
    const doc = await renderReceipt(appt, { lang: lang === "bn" ? "bn" : "en" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="receipt-${appt.receiptNo || appt._id}.pdf"`);
    res.setHeader("Cache-Control", "no-store");
    doc.pipe(res);
    doc.end();
  };

  app.get("/appointments/:id/receipt", verifyToken, async (req, res) => {
    const appt = await readableReceipt(req, res);
    if (appt) await sendReceipt(res, appt, req.query.lang);
  });

  // For the mobile app, which can't save blob downloads (see lib/downloads.js).
  app.post("/appointments/:id/receipt-link", verifyToken, async (req, res) => {
    const appt = await readableReceipt(req, res);
    if (appt) res.json({ url: await downloads.issue("receipt", { id: appt._id, lang: req.body?.lang }) });
  });

  downloads.register("receipt", async (res, { id, lang }) => {
    const appt = await appointments.findOne({ _id: new ObjectId(id) });
    if (!appt) return res.status(404).type("text/plain").send("Appointment not found.");
    await sendReceipt(res, appt, lang);
  });

  return { markPaid };
};
