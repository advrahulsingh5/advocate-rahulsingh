
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { SNSClient, PublishCommand } = require("@aws-sdk/client-sns");

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("Set a strong JWT_SECRET of at least 32 characters");
}

if (!process.env.FRONTEND_URL) {
  throw new Error("Set FRONTEND_URL in environment");
}

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ["GET", "POST"],
  credentials: true
}));
app.use(express.json({ limit: "20kb" }));

const db = new Database(process.env.DB_PATH || "advocates.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('CLIENT','ADVOCATE','ADMIN')),
  verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS otp_codes (
  phone TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS advocate_profiles (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  bar_council TEXT NOT NULL,
  enrollment_number TEXT NOT NULL,
  practice_area TEXT NOT NULL,
  verification_status TEXT NOT NULL DEFAULT 'PENDING'
);

CREATE TABLE IF NOT EXISTS enquiries (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES users(id),
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TEXT NOT NULL
);
`);

const sns = new SNSClient({
  region: process.env.AWS_REGION || "ap-southeast-2"
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
});

app.use("/api", apiLimiter);

function validPhone(phone) {
  return /^\+[1-9]\d{7,14}$/.test(phone);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Authentication required" });
  }
}

function allow(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "The Indian Advocates API"
  });
});

// Send OTP through AWS SNS.
// Configure AWS credentials and enable SMS before using this endpoint.
app.post("/api/auth/send-otp", otpLimiter, async (req, res) => {
  try {
    const phone = String(req.body.phone || "");

    if (!validPhone(phone)) {
      return res.status(400).json({
        error: "Phone must be in international format, e.g. +919876543210"
      });
    }

    const code = String(crypto.randomInt(100000, 1000000));
    const codeHash = await bcrypt.hash(code, 10);
    const expiresAt = Date.now() + 5 * 60 * 1000;

    await sns.send(new PublishCommand({
      PhoneNumber: phone,
      Message: `Your The Indian Advocates verification code is ${code}. It expires in 5 minutes.`
    }));

    db.prepare(`
      INSERT INTO otp_codes(phone, code_hash, expires_at, attempts)
      VALUES (?, ?, ?, 0)
      ON CONFLICT(phone) DO UPDATE SET
      code_hash=excluded.code_hash,
      expires_at=excluded.expires_at,
      attempts=0
    `).run(phone, codeHash, expiresAt);

    res.json({ message: "OTP sent if SMS delivery is enabled." });
  } catch (error) {
    console.error("OTP delivery failed:", error.message);
    res.status(503).json({
      error: "OTP service is not configured or SMS delivery failed."
    });
  }
});

// Verify OTP and create/login client or advocate account.
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const phone = String(req.body.phone || "");
    const code = String(req.body.code || "");
    const name = String(req.body.name || "").trim();
    const role = String(req.body.role || "CLIENT");

    if (!validPhone(phone) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Invalid phone or OTP format" });
    }

    if (!["CLIENT", "ADVOCATE"].includes(role)) {
      return res.status(400).json({ error: "Invalid account role" });
    }

    const record = db.prepare(
      "SELECT * FROM otp_codes WHERE phone=?"
    ).get(phone);

    if (!record || Date.now() > record.expires_at || record.attempts >= 5) {
      return res.status(400).json({ error: "OTP expired or unavailable" });
    }

    const valid = await bcrypt.compare(code, record.code_hash);

    if (!valid) {
      db.prepare(
        "UPDATE otp_codes SET attempts=attempts+1 WHERE phone=?"
      ).run(phone);
      return res.status(400).json({ error: "Incorrect OTP" });
    }

    if (!name || name.length > 100) {
      return res.status(400).json({ error: "Valid name is required" });
    }

    const existing = db.prepare(
      "SELECT * FROM users WHERE phone=?"
    ).get(phone);
if (existing && existing.role === "ADMIN") {
  return res.status(403).json({
    error: "Admin must use the secure Admin Login."
  });
}

if (existing && existing.role !== role) {
  return res.status(403).json({
    error: "This phone number is registered with a different account type."
  });
}
    let user;

    if (existing) {
      user = existing;
      db.prepare("UPDATE users SET verified=1 WHERE id=?").run(user.id);
    } else {
      const id = crypto.randomUUID();
      db.prepare(`
        INSERT INTO users(id,name,phone,role,verified,created_at)
        VALUES(?,?,?,?,1,?)
      `).run(id, name, phone, role, new Date().toISOString());

      user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    }

    db.prepare("DELETE FROM otp_codes WHERE phone=?").run(phone);

    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        verified: true
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Authentication failed" });
  }
});

// Advocate submits profile for admin verification.
app.post("/api/advocates/profile", auth, allow("ADVOCATE"), (req, res) => {
  const barCouncil = String(req.body.barCouncil || "").trim();
  const enrollmentNumber = String(req.body.enrollmentNumber || "").trim();
  const practiceArea = String(req.body.practiceArea || "").trim();

  if (!barCouncil || !enrollmentNumber || !practiceArea) {
    return res.status(400).json({ error: "All profile fields are required" });
  }

  db.prepare(`
    INSERT INTO advocate_profiles
    (user_id,bar_council,enrollment_number,practice_area,verification_status)
    VALUES(?,?,?,?, 'PENDING')
    ON CONFLICT(user_id) DO UPDATE SET
    bar_council=excluded.bar_council,
    enrollment_number=excluded.enrollment_number,
    practice_area=excluded.practice_area,
    verification_status='PENDING'
  `).run(req.user.sub, barCouncil, enrollmentNumber, practiceArea);

  res.status(201).json({ status: "PENDING" });
});

// Client submits an enquiry.
app.post("/api/enquiries", auth, allow("CLIENT"), (req, res) => {
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (!subject || !message || subject.length > 150 || message.length > 5000) {
    return res.status(400).json({ error: "Valid subject and message required" });
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO enquiries(id,client_id,subject,message,created_at)
    VALUES(?,?,?,?,?)
  `).run(id, req.user.sub, subject, message, new Date().toISOString());

  res.status(201).json({ id, status: "PENDING" });
});

// User can view only their own enquiries.
app.get("/api/enquiries", auth, allow("CLIENT"), (req, res) => {
  const rows = db.prepare(`
    SELECT id,subject,status,created_at
    FROM enquiries WHERE client_id=?
    ORDER BY created_at DESC
  `).all(req.user.sub);

  res.json(rows);
});

app.use((req, res) => {
  res.status(404).json({ error: "API route not found" });
});

app.listen(PORT, () => {
  console.log(`The Indian Advocates API listening on port ${PORT}`);
});
