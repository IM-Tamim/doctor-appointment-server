// Hospital managers (role "hospital_admin") run one hospital: its contact
// details, which doctors are listed there, and its ambulances. Which hospital
// is read from the database on every request (by the user id in the JWT), so
// reassigning a manager takes effect immediately.
const { ObjectId } = require("mongodb");

const MANAGER_FIELDS = ["address", "phone", "emergencyPhone", "logo", "image", "departments"];

module.exports = function registerHospitalAdminRoutes(app, ctx) {
  const { db, verifyToken, requireRole, writeLimiter, updateHospital } = ctx;
  const users = db.collection("user");
  const hospitals = db.collection("hospitals");
  const doctors = db.collection("doctors");
  const ambulances = db.collection("ambulances");
  const manager = requireRole("hospital_admin");

  const myHospitalId = async (req) => {
    const me = await users.findOne({ _id: new ObjectId(req.user.id) }, { projection: { hospitalId: 1 } });
    return me?.hospitalId && ObjectId.isValid(me.hospitalId) ? me.hospitalId : null;
  };

  const requireHospital = async (req, res) => {
    const id = await myHospitalId(req);
    if (!id) {
      res.status(403).json({ message: "No hospital is assigned to your account yet. Ask an admin." });
      return null;
    }
    return id;
  };

  app.get("/hospital-admin/hospital", verifyToken, manager, async (req, res) => {
    const id = await requireHospital(req, res);
    if (!id) return;
    const [hospital, staff, fleet] = await Promise.all([
      hospitals.findOne({ _id: new ObjectId(id) }),
      doctors
        .find({ hospitalId: id }, { projection: { name: 1, specialty: 1, email: 1, image: 1, approvalStatus: 1, rating: 1, fee: 1, consultationType: 1 } })
        .sort({ name: 1 })
        .toArray(),
      ambulances.find({ hospitalId: id }).sort({ type: 1 }).toArray(),
    ]);
    if (!hospital) return res.status(404).json({ message: "Your hospital no longer exists." });
    res.json({ hospital, doctors: staff, ambulances: fleet });
  });

  // Name and city identify the hospital platform-wide, so only admins change them.
  app.patch("/hospital-admin/hospital", verifyToken, manager, async (req, res) => {
    const id = await requireHospital(req, res);
    if (!id) return;
    const body = Object.fromEntries(Object.entries(req.body || {}).filter(([k]) => MANAGER_FIELDS.includes(k)));
    const { status, body: result } = await updateHospital(id, body);
    res.status(status).json(result);
  });

  // List an existing approved doctor at this hospital (by their account email).
  app.post("/hospital-admin/doctors", writeLimiter, verifyToken, manager, async (req, res) => {
    const id = await requireHospital(req, res);
    if (!id) return;
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ message: "Enter the doctor's account email." });
    const doctor = await doctors.findOne({ email, approvalStatus: "approved" });
    if (!doctor) return res.status(404).json({ message: "No approved doctor uses that email." });
    if (doctor.hospitalId === id) return res.status(409).json({ message: `${doctor.name} is already listed here.` });
    if (doctor.hospitalId) {
      return res.status(409).json({ message: `${doctor.name} is listed at another hospital. They can change it from their profile.` });
    }
    const hospital = await hospitals.findOne({ _id: new ObjectId(id) }, { projection: { name: 1 } });
    await doctors.updateOne({ _id: doctor._id }, { $set: { hospitalId: id, hospital: hospital?.name || "" } });
    res.json({ acknowledged: true, name: doctor.name });
  });

  app.delete("/hospital-admin/doctors/:doctorId", verifyToken, manager, async (req, res) => {
    const id = await requireHospital(req, res);
    if (!id) return;
    if (!ObjectId.isValid(req.params.doctorId)) return res.status(400).json({ message: "Invalid doctor id." });
    const result = await doctors.updateOne(
      { _id: new ObjectId(req.params.doctorId), hospitalId: id },
      { $set: { hospitalId: null, hospital: "" } }
    );
    if (result.matchedCount === 0) return res.status(404).json({ message: "That doctor isn't listed at your hospital." });
    res.json({ acknowledged: true });
  });

  // ── Admin: assign / remove hospital managers ────────────────────────────

  app.patch("/admin/users/:id/hospital-manager", verifyToken, requireRole("admin"), async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid user id." });
    const user = await users.findOne({ _id: new ObjectId(id) });
    if (!user) return res.status(404).json({ message: "User not found." });
    if (!["patient", "hospital_admin"].includes(user.role || "patient")) {
      return res.status(400).json({ message: "Only patient accounts can be made hospital managers." });
    }

    const { hospitalId } = req.body;
    if (!hospitalId) {
      await users.updateOne({ _id: user._id }, { $set: { role: "patient" }, $unset: { hospitalId: "" } });
      return res.json({ role: "patient" });
    }
    if (!ObjectId.isValid(hospitalId) || !(await hospitals.countDocuments({ _id: new ObjectId(hospitalId) }))) {
      return res.status(404).json({ message: "Hospital not found." });
    }
    await users.updateOne({ _id: user._id }, { $set: { role: "hospital_admin", hospitalId: String(hospitalId) } });
    res.json({ role: "hospital_admin", hospitalId });
  });
};
