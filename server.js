// server.js (GitHub-backed state + multi-admin PINs)
import express from "express";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import crypto from "crypto";
import { Octokit } from "@octokit/rest";
import bcrypt from "bcryptjs";
import { nanoid } from "nanoid";

dotenv.config();

// ----- Paths -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----- App setup -----
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Simple in-memory session store
const sessions = new Map();
const SESSION_TTL_MS = 1000 * 60 * 60; // 1 hour

function setSession(res, userId) {
  const token = nanoid(32);
  const expiry = Date.now() + SESSION_TTL_MS;
  sessions.set(token, { userId, expiry });
  res.cookie?.("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // set true if behind HTTPS
    maxAge: SESSION_TTL_MS,
  });
  // Fallback if res.cookie isn't available (older Express without cookie-parser)
  res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Lax`);
}

function getSession(req) {
  const token = (req.headers.cookie || "")
    .split(";")
    .map(s => s.trim())
    .find(s => s.startsWith("session="));
  if (!token) return null;
  const val = token.split("=")[1];
  const sess = sessions.get(val);
  if (!sess) return null;
  if (Date.now() > sess.expiry) {
    sessions.delete(val);
    return null;
  }
  return { token: val, ...sess };
}

// ----- Crypto helpers (AES-256-GCM) -----
function getKey() {
  const passphrase = process.env.ENC_PASSPHRASE || "change-me";
  // derive a 32-byte key from passphrase
  return crypto.scryptSync(passphrase, "pin-server-salt", 32);
}
function encryptObject(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getKey(), iv);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // return hex blob: iv|ciphertext|tag
  return Buffer.concat([iv, ciphertext, tag]).toString("hex");
}
function decryptObject(hexBlob) {
  const buf = Buffer.from(hexBlob, "hex");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ciphertext = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", getKey(), iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

// ----- GitHub helpers -----
const GH_OWNER = process.env.GH_OWNER;
const GH_REPO = process.env.GH_REPO;
const GH_TOKEN = process.env.GH_TOKEN;
const INFO_PATH = process.env.INFO_PATH || "info.txt";
const CURRENT_PATH = process.env.CURRENT_PATH || "current.json";
const LOG_PATH = process.env.LOG_PATH || "log.json";
const ADMINS_PATH = process.env.ADMINS_PATH || "admins.json";

if (!GH_OWNER || !GH_REPO || !GH_TOKEN) {
  console.error("Missing GH_* env vars. Please set GH_OWNER, GH_REPO, GH_TOKEN.");
  process.exit(1);
}

const octokit = new Octokit({ auth: GH_TOKEN });

async function getFile(path) {
  try {
    const { data } = await octokit.repos.getContent({ owner: GH_OWNER, repo: GH_REPO, path });
    if (Array.isArray(data)) throw new Error(`${path} is a directory`);
    const content = Buffer.from(data.content || "", data.encoding || "base64").toString("utf8");
    return { sha: data.sha, content };
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
}

async function putFileText(path, text, message, actor = "pin-server") {
  const existing = await getFile(path);
  const content = Buffer.from(text, "utf8").toString("base64");
  const { data } = await octokit.repos.createOrUpdateFileContents({
    owner: GH_OWNER,
    repo: GH_REPO,
    path,
    message: message || `Update ${path}`,
    content,
    sha: existing?.sha || undefined,
    committer: { name: actor, email: "pin-server@example.com" },
    author: { name: actor, email: "pin-server@example.com" },
  });
  return data;
}

async function readJson(path, fallback) {
  const f = await getFile(path);
  if (!f) return fallback;
  try { return JSON.parse(f.content); } catch { return fallback; }
}
async function writeJson(path, data, message, actor = "pin-server") {
  const text = JSON.stringify(data, null, 2);
  return putFileText(path, text, message, actor);
}

async function appendLog(entry) {
  const log = await readJson(LOG_PATH, []);
  log.push(entry);
  await writeJson(LOG_PATH, log, "Append log entry");
}

async function ensureAdminsSeeded() {
  const existing = await getFile(ADMINS_PATH);
  if (existing) return;
  const raw = (process.env.ADMIN_PINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (raw.length === 0) {
    console.warn("No admins.json and no ADMIN_PINS provided; creating an example admin with PIN 1234 (please change!)");
    raw.push("1234");
  }
  const admins = raw.map((pin, i) => ({ id: nanoid(8), label: `admin-${i+1}`, pinHash: bcrypt.hashSync(pin, 10) }));
  await writeJson(ADMINS_PATH, admins, "Seed admins.json");
}

async function verifyPin(pin) {
  await ensureAdminsSeeded();
  const admins = await readJson(ADMINS_PATH, []);
  for (const a of admins) {
    if (bcrypt.compareSync(String(pin || ""), a.pinHash || "")) return a;
  }
  return null;
}

// ----- Auth routes -----
app.post("/api/login", async (req, res) => {
  try {
    const { pin } = req.body || {};
    const admin = await verifyPin(pin);
    if (!admin) return res.status(401).json({ error: "Invalid PIN" });
    setSession(res, admin.id);
    res.json({ ok: true, admin: { id: admin.id, label: admin.label } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
});

// ----- Middleware to require session for mutating routes -----
app.use((req, res, next) => {
  if (req.path.startsWith("/api/") && !["/api/status", "/api/login"].includes(req.path) && req.method !== "GET") {
    const sess = getSession(req);
    if (!sess) return res.status(401).json({ error: "Login required" });
    req.adminId = sess.userId;
  }
  next();
});

// ----- Status route (no auth required) -----
app.get("/api/status", async (_req, res) => {
  try {
    const current = await readJson(CURRENT_PATH, {});
    if (!current.encrypted) return res.json({ active: false });
    try {
      const decrypted = decryptObject(current.encrypted);
      res.json({ active: true, code: decrypted.code, why: decrypted.description, at: decrypted.timestamp });
    } catch {
      res.json({ active: false });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
});

// ----- Submit code -----
app.post("/api/submit", async (req, res) => {
  try {
    const { code, description } = req.body || {};
    const allowed = ["404S", "404G", "404F", "401"];
    if (!allowed.includes(code)) return res.status(400).json({ error: "Invalid code" });
    if (!description || String(description).trim().length < 3) return res.status(400).json({ error: "Description required" });

    const entry = {
      code,
      description: String(description).trim(),
      timestamp: new Date().toISOString(),
      actorIp: req.ip,
      adminId: req.adminId || "unknown",
    };

    // Write info.txt in GitHub
    const infoTxt = `CODE: ${entry.code}\nWHY: ${entry.description}\nWHEN: ${entry.timestamp}\n`;
    await putFileText(INFO_PATH, infoTxt, `Set ${code}`);

    // Store encrypted current in repo
    const encrypted = encryptObject({ code: entry.code, description: entry.description, timestamp: entry.timestamp });
    await writeJson(CURRENT_PATH, { encrypted }, "Set current.json");

    // Append to log in repo
    await appendLog({ action: "set", ...entry });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error" });
  }
});

// ----- Clear code (requires a reason) -----
app.post("/api/clear", async (req, res) => {
  try {
    const { reason } = req.body || {};
    if (!reason || String(reason).trim().length < 3) return res.status(400).json({ error: "Reason required" });

    const current = await readJson(CURRENT_PATH, {});
    let prev = null;
    if (current.encrypted) {
      try { prev = decryptObject(current.encrypted); } catch {}
    }

    // Empty info.txt in GitHub
    await putFileText(INFO_PATH, "", "Clear code");

    // Clear current.json in repo
    await writeJson(CURRENT_PATH, {}, "Clear current.json");

    // Log it
    await appendLog({
      action: "clear",
      reason: String(reason).trim(),
      timestamp: new Date().toISOString(),
      actorIp: req.ip,
      adminId: req.adminId || "unknown",
      previous: prev || null,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error" });
  }
});

// ----- Serve UI -----
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ----- Start server -----
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
