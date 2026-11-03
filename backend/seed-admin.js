
require("dotenv").config();

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

async function main() {
  const { DB_PATH, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_PHONE } = process.env;

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_PHONE) {
    throw new Error(
      "Set ADMIN_EMAIL, ADMIN_PASSWORD and ADMIN_PHONE in environment variables."
    );
  }

  if (ADMIN_PASSWORD.length < 14) {
    throw new Error("Admin password must be at least 14 characters.");
  }

  if (!/^\+[1-9]\d{7,14}$/.test(ADMIN_PHONE)) {
    throw new Error("ADMIN_PHONE must use international format, e.g. +919876543210");
  }

  const db = new Database(DB_PATH || "advocates.db");
  db.pragma("foreign_keys = ON");

  try {
    // Ensure the existing application tables have been initialized.
    const usersTable = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    ).get();

    if (!usersTable) {
      throw new Error("Users table not found. Start the backend once first.");
    }

    db.exec(`
      CREATE TABLE IF NOT EXISTS admin_credentials (
        user_id TEXT PRIMARY KEY REFERENCES users(id),
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);

    const email = ADMIN_EMAIL.trim().toLowerCase();
    const existingUser = db.prepare(
      "SELECT * FROM users WHERE phone = ?"
    ).get(ADMIN_PHONE);

    if (existingUser && existingUser.role !== "ADMIN") {
      throw new Error(
        "This phone number already belongs to a non-admin account. Use a separate admin phone."
      );
    }

    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    const now = new Date().toISOString();

    const createAdmin = db.transaction(() => {
      let userId;

      if (existingUser) {
        userId = existingUser.id;
      } else {
        userId = crypto.randomUUID();

        db.prepare(`
          INSERT INTO users (id, name, phone, role, verified, created_at)
          VALUES (?, ?, ?, 'ADMIN', 1, ?)
        `).run(userId, "Platform Administrator", ADMIN_PHONE, now);
      }

      db.prepare(`
        INSERT INTO admin_credentials (user_id, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          email = excluded.email,
          password_hash = excluded.password_hash
      `).run(userId, email, passwordHash, now);
    });

    createAdmin();

    console.log("Admin account created or updated successfully.");
    console.log("Admin email:", email);
    console.log("Do not share your admin password.");
  } finally {
    db.close();
  }
}

main().catch(error => {
  console.error("Admin setup failed:", error.message);
  process.exit(1);
});
