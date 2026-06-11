const crypto = require("crypto");

const { createClient } = require("@supabase/supabase-js");

const A2F_LOCKOUTS_TABLE = process.env.SUPABASE_A2F_LOCKOUTS_TABLE || "a2f_lockouts";
const A2F_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
let supabaseAdminClient = null;

function getSupabaseAdmin() {
  if (supabaseAdminClient) return supabaseAdminClient;

  const supabaseUrl = String(process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "").trim();
  const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();

  if (!supabaseUrl || !serviceRoleKey) {
    const err = new Error("ENV Supabase belum lengkap. Set SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di Vercel.");
    err.statusCode = 500;
    throw err;
  }

  supabaseAdminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });

  return supabaseAdminClient;
}

function getAdminUid() {
  const uid = String(process.env.A2F_ADMIN_UID || "").trim();

  if (!uid) {
    const err = new Error("A2F_ADMIN_UID belum diset");
    err.statusCode = 500;
    throw err;
  }

  return uid;
}

function normalizeLockRow(data) {
  const row = data && typeof data === "object" ? data : {};
  return {
    uid: String(row.uid || ""),
    email: String(row.email || ""),
    failedCount: Number(row.failed_count ?? row.failedCount ?? 0),
    lockUntilMs: Number(row.lock_until_ms ?? row.lockUntilMs ?? 0),
    permanentBan: row.permanent_ban === true || row.permanentBan === true,
    permanentBanReason: String(row.permanent_ban_reason || row.permanentBanReason || row.reason || row.last_reason || ""),
    lastFailedAtMs: Number(row.last_failed_at_ms ?? row.lastFailedAtMs ?? 0),
    bannedAtMs: Number(row.banned_at_ms ?? row.bannedAtMs ?? 0)
  };
}

async function readA2fLockRow(uid) {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from(A2F_LOCKOUTS_TABLE)
    .select("*")
    .eq("uid", uid)
    .maybeSingle();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  return normalizeLockRow(data || { uid });
}

async function saveA2fLockRow(row) {
  const supabase = getSupabaseAdmin();
  const payload = {
    uid: String(row.uid || getAdminUid()),
    email: String(row.email || process.env.A2F_ADMIN_EMAIL || ""),
    failed_count: Number(row.failedCount || 0),
    lock_until_ms: Number(row.lockUntilMs || 0),
    permanent_ban: row.permanentBan === true,
    permanent_ban_reason: row.permanentBanReason || null,
    last_failed_at_ms: Number(row.lastFailedAtMs || 0),
    banned_at_ms: row.bannedAtMs ? Number(row.bannedAtMs) : null,
    updated_at: new Date().toISOString()
  };

  const { data, error } = await supabase
    .from(A2F_LOCKOUTS_TABLE)
    .upsert(payload, { onConflict: "uid" })
    .select("*")
    .single();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  return normalizeLockRow(data || payload);
}

function getA2fLockDurationMs(failedCount) {
  const count = Number(failedCount || 0);
  if (count <= 1) return A2F_YEAR_MS;
  if (count === 2) return 10 * A2F_YEAR_MS;
  return 100 * A2F_YEAR_MS;
}

function getLockMessage(lockUntilMs) {
  const remainingMs = Math.max(0, Number(lockUntilMs || 0) - Date.now());
  const days = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));

  if (days >= 36500) return "A2F terkunci 100 tahun. Reset hanya bisa lewat Supabase/admin.";
  if (days >= 3650) return "A2F terkunci 10 tahun. Reset hanya bisa lewat Supabase/admin.";
  if (days >= 365) return "A2F terkunci 1 tahun. Reset hanya bisa lewat Supabase/admin.";
  if (days > 0) return `A2F terkunci. Coba lagi dalam ${days} hari.`;
  return "A2F terkunci. Reset lewat Supabase/admin.";
}

async function ensureA2fLockRow() {
  const uid = getAdminUid();
  let data = await readA2fLockRow(uid);

  if (!data.uid) {
    data = await saveA2fLockRow({
      uid,
      email: process.env.A2F_ADMIN_EMAIL || "",
      failedCount: 0,
      lockUntilMs: 0,
      permanentBan: false,
      lastFailedAtMs: 0
    });
  }

  return data;
}

async function checkA2fLock() {
  const data = await ensureA2fLockRow();

  if (data.permanentBan === true) {
    const err = new Error("A2F_PERMANENT_BAN");
    err.statusCode = 403;
    err.publicMessage = "A2F diblokir dari backend. Reset hanya bisa lewat Supabase/admin.";
    err.lockData = data;
    throw err;
  }

  const lockUntilMs = Number(data.lockUntilMs || 0);

  if (lockUntilMs > Date.now()) {
    const err = new Error("A2F_LOCKED");
    err.statusCode = 423;
    err.lockUntilMs = lockUntilMs;
    err.publicMessage = getLockMessage(lockUntilMs);
    err.lockData = data;
    throw err;
  }

  return data;
}

async function recordA2fFailure(reason = "wrong_code") {
  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const failedCount = Number(data.failedCount || 0) + 1;
  const now = Date.now();

  return saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || data.email || "",
    failedCount,
    lastFailedAtMs: now,
    permanentBan: false,
    permanentBanReason: reason,
    lockUntilMs: now + getA2fLockDurationMs(failedCount),
    bannedAtMs: failedCount >= 3 ? now : data.bannedAtMs || 0
  });
}

async function recordA2fTimeoutBlock(reason = "a2f_timeout") {
  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const now = Date.now();

  return saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || data.email || "",
    failedCount: Math.max(3, Number(data.failedCount || 0)),
    lastFailedAtMs: now,
    permanentBan: false,
    permanentBanReason: reason,
    lockUntilMs: now + 100 * A2F_YEAR_MS,
    bannedAtMs: now
  });
}

function lockJson(lockData, extra = {}) {
  const data = normalizeLockRow(lockData || {});
  const lockUntilMs = Number(data.lockUntilMs || 0);
  const locked = data.permanentBan === true || lockUntilMs > Date.now();

  return Object.assign({
    success: false,
    locked,
    permanentBan: data.permanentBan === true,
    failedCount: Number(data.failedCount || 0),
    lockUntilMs,
    uid: data.uid || getAdminUid(),
    email: data.email || process.env.A2F_ADMIN_EMAIL || "",
    error: locked ? getLockMessage(lockUntilMs) : "Kode verifikasi salah"
  }, extra);
}

function sendA2fLockError(res, error) {
  const data = error && error.lockData ? error.lockData : {};
  return res.status(error.statusCode || 423).json(lockJson(data, {
    success: false,
    error: error.publicMessage || error.message || "A2F terkunci dari backend."
  }));
}

async function sendWrongCodeResponse(res, reason) {
  const lockData = await recordA2fFailure(reason);
  return res.status(Number(lockData.failedCount || 0) >= 3 ? 403 : 401).json(lockJson(lockData, {
    success: false,
    error: getLockMessage(lockData.lockUntilMs)
  }));
}


function getAllowedOrigins() {
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return fromEnv.length ? fromEnv : [
    "https://diracgroup.store",
    "https://www.diracgroup.store",
    "https://companyprofilee-expk.vercel.app",
    "https://companyprofilee-ochre.vercel.app"
  ];
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return getAllowedOrigins().includes(origin);
}

function setCors(req, res) {
  const origin = String((req && req.headers && req.headers.origin) || "");
  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "https://diracgroup.store");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
  return isAllowedOrigin(origin);
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

  return crypto.timingSafeEqual(A, B);
}

module.exports = async function handler(req, res) {
  const corsOk = setCors(req, res);

  if (req.method === "OPTIONS") return res.status(corsOk ? 200 : 403).end();
  if (!corsOk) return res.status(403).json({ success: false, error: "Origin tidak diizinkan" });

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const { code } = req.body || {};

  if (!code) {
    return res.status(400).json({
      success: false,
      error: "Kode rahasia wajib diisi"
    });
  }

  const correctPin = process.env.A2F_PIN;

  if (!correctPin) {
    return res.status(500).json({
      success: false,
      error: "A2F_PIN belum diset di Vercel"
    });
  }

  const inputCode = String(code).trim();
  const savedCode = String(correctPin).trim();

  try {
    await checkA2fLock();
  } catch (error) {
    return sendA2fLockError(res, error);
  }

  if (!safeEqual(inputCode, savedCode)) {
    return sendWrongCodeResponse(res, "pin_wrong_code");
  }

  return res.status(200).json({
    success: true,
    message: "Kode rahasia benar"
  });
};
