// One-time helper: promote an existing (already signed-up) user to admin.
// Usage:  node scripts/make-admin.js user@example.com
const { MongoClient } = require("mongodb");
const dotenv = require("dotenv");
dotenv.config();

const email = process.argv[2];
if (!email) {
  console.error("Usage: node scripts/make-admin.js <email>");
  process.exit(1);
}

(async () => {
  const client = new MongoClient(process.env.MONGO_URI);
  try {
    await client.connect();
    const db = client.db("DocAppoint");
    const result = await db.collection("user").updateOne(
      { email },
      { $set: { role: "admin", status: "active" } }
    );
    if (result.matchedCount === 0) {
      console.log(`No user found with email ${email}. Sign up normally first, then re-run this.`);
    } else {
      console.log(`${email} is now an admin.`);
    }
  } finally {
    await client.close();
  }
})();
