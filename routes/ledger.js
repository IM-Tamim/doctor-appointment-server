// Payments ledger (admin) and the configurable refund policy.
const { DEFAULT_REFUND_POLICY } = require("../lib/appointments");

const POLICY_LIMITS = {
  fullRefundHours: [1, 24 * 14],
  partialRefundHours: [0, 24 * 14],
  partialRefundPercent: [0, 100],
  doctorCancelPercent: [0, 100],
  freeReschedules: [0, 5],
};

module.exports = function registerLedgerRoutes(app, ctx) {
  const { db, verifyToken, requireRole, bookings } = ctx;
  const payments = db.collection("payments");
  const settings = db.collection("settings");

  // Public, so patients can read the rules before they book or cancel.
  app.get("/settings/refund-policy", async (req, res) => {
    res.json(await bookings.getRefundPolicy());
  });

  app.patch("/admin/settings/refund-policy", verifyToken, requireRole("admin"), async (req, res) => {
    const current = await bookings.getRefundPolicy();
    const next = { ...current };
    for (const [key, [min, max]] of Object.entries(POLICY_LIMITS)) {
      if (req.body[key] === undefined) continue;
      const value = Number(req.body[key]);
      if (!Number.isFinite(value) || value < min || value > max) {
        return res.status(400).json({ message: `${key} must be between ${min} and ${max}.` });
      }
      next[key] = Math.round(value);
    }
    if (next.partialRefundHours >= next.fullRefundHours) {
      return res.status(400).json({ message: "The partial-refund cutoff must be earlier than the full-refund cutoff." });
    }
    await settings.updateOne({ _id: "refundPolicy" }, { $set: { value: next, updatedAt: new Date() } }, { upsert: true });
    res.json(next);
  });

  app.post("/admin/settings/refund-policy/reset", verifyToken, requireRole("admin"), async (req, res) => {
    await settings.deleteOne({ _id: "refundPolicy" });
    res.json(DEFAULT_REFUND_POLICY);
  });

  /**
   * Ledger page: one aggregation returns the page, the matching total and the
   * money totals, with each entry joined to its appointment ($lookup, not a
   * query per row).
   */
  app.get("/admin/payments", verifyToken, requireRole("admin"), async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const match = {};
    if (["payment", "refund"].includes(req.query.type)) match.type = req.query.type;
    if (["sslcommerz", "demo_mobile", "cash"].includes(req.query.method)) match.method = req.query.method;
    const range = {};
    if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.from || "")) range.$gte = new Date(`${req.query.from}T00:00:00+06:00`);
    if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.to || "")) range.$lt = new Date(new Date(`${req.query.to}T00:00:00+06:00`).getTime() + 86400000);
    if (Object.keys(range).length) match.createdAt = range;

    const [result] = await payments
      .aggregate([
        { $match: match },
        {
          $facet: {
            rows: [
              { $sort: { createdAt: -1 } },
              { $skip: (page - 1) * limit },
              { $limit: limit },
              {
                $lookup: {
                  from: "appointments",
                  let: { aid: { $toObjectId: "$appointmentId" } },
                  pipeline: [
                    { $match: { $expr: { $eq: ["$_id", "$$aid"] } } },
                    { $project: { receiptNo: 1, patientName: 1, appointmentDate: 1, appointmentTime: 1, status: 1 } },
                  ],
                  as: "appointment",
                },
              },
              { $addFields: { appointment: { $first: "$appointment" } } },
            ],
            count: [{ $count: "n" }],
            totals: [{ $group: { _id: "$type", amount: { $sum: "$amount" }, count: { $sum: 1 } } }],
          },
        },
      ])
      .toArray();

    const totals = Object.fromEntries((result?.totals || []).map((t) => [t._id, { amount: t.amount, count: t.count }]));
    const total = result?.count?.[0]?.n || 0;
    const collected = totals.payment?.amount || 0;
    const refunded = totals.refund?.amount || 0;
    res.json({
      entries: result?.rows || [],
      total,
      page,
      limit,
      totalPages: Math.max(1, Math.ceil(total / limit)),
      summary: { collected, refunded, net: collected - refunded, payments: totals.payment?.count || 0, refunds: totals.refund?.count || 0 },
    });
  });
};
