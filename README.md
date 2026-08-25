<div align="center">

# 🩺 DocAppoint — Server

### REST API powering the DocAppoint role-based appointment platform

[![Express](https://img.shields.io/badge/Express.js-black?logo=express)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-green?logo=mongodb)](https://www.mongodb.com/)
[![JWT](https://img.shields.io/badge/Auth-JWT%20%2F%20JWKS-error)](https://www.rfc-editor.org/rfc/rfc7519)

**[🌐 Live Client](#)** · **[💻 Client Repo](#)** · **[⚙️ Live Server](#)** · **[🗄️ Server Repo](#)**

</div>

---

## ✨ Overview

Express + MongoDB API for DocAppoint. Verifies requests via JWTs issued by the Next.js client's **Better Auth** instance (fetched through its JWKS endpoint — no shared secret needed), and enforces **role-based access control** (`patient` / `doctor` / `admin`) on top of that.

## 🔐 Auth Model

Every protected route runs through two middlewares:

1. **`verifyToken`** — verifies the JWT against the client's JWKS endpoint (`{CLIENT_URL}/api/auth/jwks`), attaches `req.user = { id, email, name, role, status }`.
2. **`requireRole(...roles)`** — 403s unless `req.user.role` is in the allowed list.

## 📡 API Overview

| Group | Example routes |
|---|---|
| **Public** | `GET /doctors` (approved only), `GET /` |
| **Patient (auth required)** | `POST /appointments`, `PATCH /appointments/:id`, `DELETE /appointments/:id`, `PATCH /doctors/:id/review`, `POST /doctors/apply` |
| **Doctor (role: doctor)** | `GET /doctor/appointments`, `PATCH /doctor/appointments/:id/status`, `PATCH /doctor/appointments/:id/prescription`, `PATCH /doctor/availability`, `GET|PATCH /doctor/profile` |
| **Admin (role: admin)** | `GET /admin/doctors/pending`, `PATCH /admin/doctors/:id/approve`, `PATCH /admin/doctors/:id/reject`, `GET /admin/users`, `PATCH /admin/users/:id/suspend`, `GET /admin/stats` |
| **Notifications (self)** | `GET /notifications`, `PATCH /notifications/:id/read` |

## 🗄️ Data Model (MongoDB, `DocAppoint` database)

- **`user`** — managed by Better Auth on the client side; extended with `role`, `status`, `phone`
- **`doctors`** — profile + credentials + `approvalStatus` (pending/approved/rejected) + `availability`
- **`appointments`** — booking details + `status` (pending/confirmed/completed/cancelled) + `prescription`
- **`notifications`** — per-user notification feed, mirrors emails sent via Gmail SMTP

## 🛠️ Tech Stack

Express.js · MongoDB (native driver) · `jose-cjs` (JWT/JWKS verification) · Nodemailer over Gmail SMTP (transactional email) · `express-rate-limit`

## ⚙️ Getting Started

```bash
git clone <this-repo>
cd docappoint-server
npm install
cp .env.example .env   # fill in MONGO_URI, CLIENT_URL, GMAIL_USER, GMAIL_APP_PASSWORD
npm run dev
```

### Bootstrapping your first admin

```bash
node scripts/make-admin.js you@example.com
```
(the user must have already signed up normally through the client first)

## 🧩 Related

This is the **server**. The Next.js frontend lives in the companion **[docappoint-client](#)** repo.

---

<div align="center">
Built as a full-stack ICT semester project — RUET, ETE Dept.
</div>
