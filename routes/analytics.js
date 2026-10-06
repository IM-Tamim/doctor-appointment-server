// Admin analytics. Two aggregations per request — one over appointments,
// one over the payments ledger — each with $facet, never a query per row.
const { clinicNow, addDays } = require("../lib/schedule");

const RANGES = [7, 30, 90, 365];
const TZ = "Asia/Dhaka";

module.exports = function registerAnalyticsRoutes(app, ctx) {
  const { db, verifyToken, requireRole } = ctx;
  const appointments = db.collection("appointments");
  const payments = db.collection("payments");

  app.get("/admin/analytics", verifyToken, requireRole("admin"), async (req, res) => {
    const days = RANGES.includes(Number(req.query.days)) ? Number(req.query.days) : 30;
    const today = clinicNow().date;
    const from = addDays(today, -(days - 1));
    const fromInstant = new Date(`${from}T00:00:00+06:00`);

    const [apptStats] = await appointments
      .aggregate([
        { $match: { appointmentDate: { $gte: from, $lte: today } } },
        {
          // Older bookings didn't snapshot the specialty; join the doctor once.
          $lookup: {
            from: "doctors",
            let: { did: { $toObjectId: "$doctorId" } },
            pipeline: [{ $match: { $expr: { $eq: ["$_id", "$$did"] } } }, { $project: { specialty: 1, rating: 1, name: 1 } }],
            as: "doc",
          },
        },
        {
          $addFields: {
            specialty: { $ifNull: ["$doctorSpecialty", { $ifNull: [{ $first: "$doc.specialty" }, "Other"] }] },
            st: { $ifNull: ["$status", "pending"] },
          },
        },
        {
          $facet: {
            byStatus: [{ $group: { _id: "$st", n: { $sum: 1 } } }],
            bySpecialty: [
              { $match: { st: { $ne: "cancelled" } } },
              { $group: { _id: "$specialty", bookings: { $sum: 1 } } },
              { $sort: { bookings: -1 } },
              { $limit: 12 },
            ],
            byDay: [
              { $group: { _id: "$appointmentDate", bookings: { $sum: { $cond: [{ $eq: ["$st", "cancelled"] }, 0, 1] } }, cancelled: { $sum: { $cond: [{ $eq: ["$st", "cancelled"] }, 1, 0] } } } },
            ],
            topDoctors: [
              { $match: { st: { $ne: "cancelled" } } },
              {
                $group: {
                  _id: "$doctorId",
                  name: { $first: "$doctorName" },
                  specialty: { $first: "$specialty" },
                  rating: { $first: { $first: "$doc.rating" } },
                  bookings: { $sum: 1 },
                  completed: { $sum: { $cond: [{ $eq: ["$st", "completed"] }, 1, 0] } },
                },
              },
              { $sort: { bookings: -1, completed: -1 } },
              { $limit: 8 },
            ],
            modes: [{ $group: { _id: { $ifNull: ["$consultationMode", "in-person"] }, n: { $sum: 1 } } }],
          },
        },
      ])
      .toArray();

    const [money] = await payments
      .aggregate([
        { $match: { createdAt: { $gte: fromInstant } } },
        { $addFields: { signed: { $cond: [{ $eq: ["$type", "refund"] }, { $multiply: ["$amount", -1] }, "$amount"] } } },
        {
          $facet: {
            byDay: [
              {
                $group: {
                  _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt", timezone: TZ } },
                  collected: { $sum: { $cond: [{ $eq: ["$type", "payment"] }, "$amount", 0] } },
                  refunded: { $sum: { $cond: [{ $eq: ["$type", "refund"] }, "$amount", 0] } },
                },
              },
            ],
            byHospital: [
              { $group: { _id: { $cond: [{ $in: ["$hospitalName", [null, ""]] }, "Online / independent", "$hospitalName"] }, net: { $sum: "$signed" } } },
              { $sort: { net: -1 } },
              { $limit: 10 },
            ],
            byDoctor: [{ $group: { _id: "$doctorId", net: { $sum: "$signed" } } }],
            byMethod: [{ $match: { type: "payment" } }, { $group: { _id: "$method", amount: { $sum: "$amount" } } }],
            totals: [{ $group: { _id: null, net: { $sum: "$signed" }, refunded: { $sum: { $cond: [{ $eq: ["$type", "refund"] }, "$amount", 0] } } } }],
          },
        },
      ])
      .toArray();

    // Fill every day in the range so the charts don't skip empty days.
    const revenueByDay = new Map((money?.byDay || []).map((d) => [d._id, d]));
    const bookingsByDay = new Map((apptStats?.byDay || []).map((d) => [d._id, d]));
    const daily = [];
    for (let i = 0; i < days; i++) {
      const date = addDays(from, i);
      const r = revenueByDay.get(date);
      const b = bookingsByDay.get(date);
      daily.push({
        date,
        collected: r?.collected || 0,
        refunded: r?.refunded || 0,
        net: (r?.collected || 0) - (r?.refunded || 0),
        bookings: b?.bookings || 0,
        cancelled: b?.cancelled || 0,
      });
    }

    const status = Object.fromEntries((apptStats?.byStatus || []).map((s) => [s._id, s.n]));
    const total = Object.values(status).reduce((a, b) => a + b, 0);
    const attended = (status.completed || 0) + (status.no_show || 0);
    const revenueByDoctor = new Map((money?.byDoctor || []).map((d) => [d._id, d.net]));

    res.set("Cache-Control", "no-store");
    res.json({
      range: { from, to: today, days },
      totals: {
        bookings: total,
        revenue: money?.totals?.[0]?.net || 0,
        refunded: money?.totals?.[0]?.refunded || 0,
        cancellationRate: total ? (status.cancelled || 0) / total : 0,
        noShowRate: attended ? (status.no_show || 0) / attended : 0,
        status,
      },
      daily,
      revenueByHospital: (money?.byHospital || []).map((h) => ({ hospital: h._id, revenue: h.net })),
      bookingsBySpecialty: (apptStats?.bySpecialty || []).map((s) => ({ specialty: s._id, bookings: s.bookings })),
      paymentMethods: (money?.byMethod || []).map((m) => ({ method: m._id, amount: m.amount })),
      consultationModes: (apptStats?.modes || []).map((m) => ({ mode: m._id, count: m.n })),
      topDoctors: (apptStats?.topDoctors || []).map((d) => ({
        doctorId: d._id,
        name: d.name,
        specialty: d.specialty,
        rating: d.rating ?? null,
        bookings: d.bookings,
        completed: d.completed,
        revenue: revenueByDoctor.get(d._id) || 0,
      })),
    });
  });
};
