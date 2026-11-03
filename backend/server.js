
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const OpenAI = require("openai");
const { SNSClient, PublishCommand } = require("@aws-sdk/client-sns");

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("Set a strong JWT_SECRET of at least 32 characters");
}

if (!process.env.FRONTEND_URL) {
  throw new Error("Set FRONTEND_URL in environment");
}

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

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

CREATE TABLE IF NOT EXISTS admin_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
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

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
});

const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", apiLimiter);

function validPhone(phone) {
  return /^\+[1-9]\d{7,14}$/.test(phone);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (!payload.sub || !payload.role) {
      return res.status(401).json({
        error: "Invalid authentication token"
      });
    }

    req.user = payload;
    next();
  } catch {
    return res.status(401).json({
      error: "Authentication required"
    });
  }
}

function allow(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Access denied"
      });
    }
    next();
  };
}

// SECURE ADMIN LOGIN
app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password || email.length > 254 || password.length > 200) {
      return res.status(400).json({
        error: "Valid email and password are required"
      });
    }

    const credentials = db.prepare(`
      SELECT user_id, email, password_hash
      FROM admin_credentials
      WHERE email = ?
    `).get(email);

    if (!credentials) {
      return res.status(401).json({
        error: "Invalid admin email or password"
      });
    }

    const valid = await bcrypt.compare(
      password,
      credentials.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid admin email or password"
      });
    }

    const admin = db.prepare(`
      SELECT id, name, phone, role, verified
      FROM users
      WHERE id = ?
    `).get(credentials.user_id);

    if (!admin || admin.role !== "ADMIN" || admin.verified !== 1) {
      return res.status(403).json({
        error: "Admin account is not authorized"
      });
    }

    const token = jwt.sign(
      { sub: admin.id, role: "ADMIN" },
      process.env.JWT_SECRET,
      { expiresIn: "30m" }
    );

    return res.json({
      message: "Admin login successful",
      token,
      admin: {
        id: admin.id,
        name: admin.name,
        email: credentials.email
      }
    });

  } catch (error) {
    console.error("Admin login error:", error);
    return res.status(500).json({
      error: "Admin login failed"
    });
  }
});

// ADMIN DASHBOARD SUMMARY
app.get("/api/admin/dashboard", auth, allow("ADMIN"), (req, res) => {
  try {
    const totalUsers = db.prepare(
      "SELECT COUNT(*) AS count FROM users"
    ).get().count;

    const totalClients = db.prepare(
      "SELECT COUNT(*) AS count FROM users WHERE role='CLIENT'"
    ).get().count;

    const totalAdvocates = db.prepare(
      "SELECT COUNT(*) AS count FROM users WHERE role='ADVOCATE'"
    ).get().count;

    const pendingAdvocates = db.prepare(
      "SELECT COUNT(*) AS count FROM advocate_profiles WHERE verification_status='PENDING'"
    ).get().count;

    const totalEnquiries = db.prepare(
      "SELECT COUNT(*) AS count FROM enquiries"
    ).get().count;

    const pendingEnquiries = db.prepare(
      "SELECT COUNT(*) AS count FROM enquiries WHERE status='PENDING'"
    ).get().count;

    res.json({
      totalUsers,
      totalClients,
      totalAdvocates,
      pendingAdvocates,
      totalEnquiries,
      pendingEnquiries
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).json({
      error: "Could not load dashboard"
    });
  }
});

// ADMIN: VIEW ADVOCATES
app.get("/api/admin/advocates", auth, allow("ADMIN"), (req, res) => {
  const status = String(req.query.status || "PENDING").toUpperCase();

  if (!["PENDING", "APPROVED", "REJECTED", "ALL"].includes(status)) {
    return res.status(400).json({
      error: "Invalid status filter"
    });
  }

  const rows = status === "ALL"
    ? db.prepare(`
        SELECT u.id, u.name, u.phone, p.bar_council,
        p.enrollment_number, p.practice_area, p.verification_status
        FROM advocate_profiles p
        JOIN users u ON u.id = p.user_id
        ORDER BY u.created_at DESC
      `).all()
    : db.prepare(`
        SELECT u.id, u.name, u.phone, p.bar_council,
        p.enrollment_number, p.practice_area, p.verification_status
        FROM advocate_profiles p
        JOIN users u ON u.id = p.user_id
        WHERE p.verification_status = ?
        ORDER BY u.created_at DESC
      `).all(status);

  res.json(rows);
});

// ADMIN: APPROVE OR REJECT ADVOCATE
app.post("/api/admin/advocates/:userId/decision", auth, allow("ADMIN"), (req, res) => {
  const status = String(req.body.status || "").toUpperCase();

  if (!["APPROVED", "REJECTED"].includes(status)) {
    return res.status(400).json({
      error: "Status must be APPROVED or REJECTED"
    });
  }

  const result = db.prepare(`
    UPDATE advocate_profiles
    SET verification_status = ?
    WHERE user_id = ?
  `).run(status, req.params.userId);

  if (result.changes === 0) {
    return res.status(404).json({
      error: "Advocate profile not found"
    });
  }

  res.json({
    message: "Advocate profile updated",
    status
  });
});

// ADMIN: VIEW ENQUIRIES
app.get("/api/admin/enquiries", auth, allow("ADMIN"), (req, res) => {
  const rows = db.prepare(`
    SELECT e.id, e.subject, e.message, e.status, e.created_at,
    u.name AS client_name, u.phone AS client_phone
    FROM enquiries e
    JOIN users u ON u.id = e.client_id
    ORDER BY e.created_at DESC
  `).all();

  res.json(rows);
});

// ADMIN: UPDATE ENQUIRY STATUS
app.post("/api/admin/enquiries/:id/status", auth, allow("ADMIN"), (req, res) => {
  const status = String(req.body.status || "").toUpperCase();

  if (!["PENDING", "IN_PROGRESS", "RESOLVED", "REJECTED"].includes(status)) {
    return res.status(400).json({
      error: "Invalid enquiry status"
    });
  }

  const result = db.prepare(`
    UPDATE enquiries SET status = ? WHERE id = ?
  `).run(status, req.params.id);

  if (result.changes === 0) {
    return res.status(404).json({
      error: "Enquiry not found"
    });
  }

  res.json({
    message: "Enquiry status updated",
    status
  });
});

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "The Indian Advocates API"
  });
});

// SEND OTP THROUGH AWS SNS
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

    res.json({
      message: "OTP sent if SMS delivery is enabled."
    });
  } catch (error) {
    console.error("OTP delivery failed:", error.message);
    res.status(503).json({
      error: "OTP service is not configured or SMS delivery failed."
    });
  }
});

// VERIFY OTP AND CREATE/LOGIN USER
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const phone = String(req.body.phone || "");
    const code = String(req.body.code || "");
    const name = String(req.body.name || "").trim();
    const role = String(req.body.role || "CLIENT");

    if (!validPhone(phone) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({
        error: "Invalid phone or OTP format"
      });
    }

    if (!["CLIENT", "ADVOCATE"].includes(role)) {
      return res.status(400).json({
        error: "Invalid account role"
      });
    }

    const record = db.prepare(
      "SELECT * FROM otp_codes WHERE phone=?"
    ).get(phone);

    if (!record || Date.now() > record.expires_at || record.attempts >= 5) {
      return res.status(400).json({
        error: "OTP expired or unavailable"
      });
    }

    const valid = await bcrypt.compare(code, record.code_hash);

    if (!valid) {
      db.prepare(
        "UPDATE otp_codes SET attempts=attempts+1 WHERE phone=?"
      ).run(phone);

      return res.status(400).json({
        error: "Incorrect OTP"
      });
    }

    if (!name || name.length > 100) {
      return res.status(400).json({
        error: "Valid name is required"
      });
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
      db.prepare(
        "UPDATE users SET verified=1 WHERE id=?"
      ).run(user.id);
    } else {
      const id = crypto.randomUUID();

      db.prepare(`
        INSERT INTO users(id,name,phone,role,verified,created_at)
        VALUES(?,?,?,?,1,?)
      `).run(id, name, phone, role, new Date().toISOString());

      user = db.prepare(
        "SELECT * FROM users WHERE id=?"
      ).get(id);
    }

    db.prepare(
      "DELETE FROM otp_codes WHERE phone=?"
    ).run(phone);

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
    console.error("OTP verification error:", error);
    res.status(500).json({
      error: "Authentication failed"
    });
  }
});

// ADVOCATE SUBMITS PROFILE
app.post("/api/advocates/profile", auth, allow("ADVOCATE"), (req, res) => {
  const barCouncil = String(req.body.barCouncil || "").trim();
  const enrollmentNumber = String(req.body.enrollmentNumber || "").trim();
  const practiceArea = String(req.body.practiceArea || "").trim();

  if (!barCouncil || !enrollmentNumber || !practiceArea ||
      barCouncil.length > 200 || enrollmentNumber.length > 100 ||
      practiceArea.length > 200) {
    return res.status(400).json({
      error: "Valid profile fields are required"
    });
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

  res.status(201).json({
    status: "PENDING"
  });
});

// CLIENT SUBMITS ENQUIRY
app.post("/api/enquiries", auth, allow("CLIENT"), (req, res) => {
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (!subject || !message || subject.length > 150 || message.length > 5000) {
    return res.status(400).json({
      error: "Valid subject and message required"
    });
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO enquiries(id,client_id,subject,message,created_at)
    VALUES(?,?,?,?,?)
  `).run(id, req.user.sub, subject, message, new Date().toISOString());

  res.status(201).json({
    id,
    status: "PENDING"
  });
});

// CLIENT VIEWS OWN ENQUIRIES
app.get("/api/enquiries", auth, allow("CLIENT"), (req, res) => {
  const rows = db.prepare(`
    SELECT id,subject,status,created_at
    FROM enquiries WHERE client_id=?
    ORDER BY created_at DESC
  `).all(req.user.sub);

  res.json(rows);
});

// ==========================================
// THE INDIAN ADVOCATES - OPENAI AI ASSISTANT
// ==========================================

app.post("/api/legal-assistant", aiLimiter, async (req, res) => {
  try {
    if (!openai) {
      return res.status(503).json({
        error: "AI service is not configured."
      });
    }

    const question = String(req.body.question || "").trim();

    if (!question || question.length > 3000) {
      return res.status(400).json({
        error: "Question is required and must be under 3000 characters."
      });
    }

    const response = await openai.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-5.5",

      instructions: `
You are the AI Legal Information Assistant for The Indian Advocates.

Your role:
1. Provide general legal information, not personalized legal advice.
2. Focus on Indian law when the question concerns India.
3. Explain legal concepts in simple English or Hindi, matching the user's language.
4. Never invent laws, section numbers, judgments, case citations or court decisions.
5. Mention when a law or legal position needs current verification.
6. Encourage users to consult a qualified advocate for case-specific advice.
7. Do not claim to be a lawyer or represent the user in court.
8. Do not request confidential information, passwords, OTPs or unnecessary personal details.
9. For urgent arrest, bail or safety matters, advise contacting a qualified local advocate or appropriate emergency services.
10. Clearly state when you are uncertain.
11. Do not treat your answer as a substitute for official legal sources.

Keep answers clear, useful and reasonably concise.
      `,

      input: question,
      max_output_tokens: 700
    });

    const answer = response.output_text;

    if (!answer) {
      return res.status(502).json({
        error: "AI could not generate an answer. Please try again."
      });
    }

    return res.json({ answer });

  } catch (error) {
    console.error(
      "AI Assistant request failed:",
      error.status || error.name || "Unknown error"
    );

    return res.status(500).json({
      error: "AI Assistant is temporarily unavailable. Please try again."
    });
  }
});

// 404 HANDLER
app.use((req, res) => {
  res.status(404).json({
    error: "API route not found"
  });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`The Indian Advocates API listening on port ${PORT}`);
});
