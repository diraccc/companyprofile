const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const A2F_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const A2F_LOCK_TABLE = process.env.SUPABASE_A2F_LOCKS_TABLE || process.env.SUPABASE_A2F_LOCKOUTS_TABLE || "a2f_locks";
const A2F_DEFAULT_SUPABASE_URL = "https://aqvzzfijlomcznotyigx.supabase.co";
const A2F_DEFAULT_SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFxdnp6ZmlqbG9tY3pub3R5aWd4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzk5OTE3OTIsImV4cCI6MjA5NTU2Nzc5Mn0.Azp6CBvS3amdzCX0ujsz_RgjNak6OrLHa5FsDJWXxF0";
let a2fSupabaseClient = null;

function getA2fSupabaseClient() {
  if (a2fSupabaseClient) return a2fSupabaseClient;

  const supabaseUrl = String(
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    A2F_DEFAULT_SUPABASE_URL ||
    ""
  ).trim();

  const supabaseKey = String(
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    A2F_DEFAULT_SUPABASE_ANON_KEY ||
    ""
  ).trim();

  if (!supabaseUrl || !supabaseKey) {
    const error = new Error("Supabase A2F lock belum siap");
    error.statusCode = 500;
    throw error;
  }

  a2fSupabaseClient = createClient(supabaseUrl, supabaseKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });

  return a2fSupabaseClient;
}

function decodeA2fJwtPayload(token) {
  const rawToken = String(token || "").trim();
  const payloadPart = rawToken.split(".")[1];
  if (!payloadPart) return {};

  try {
    const normalized = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, "=");
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8")) || {};
  } catch (_error) {
    return {};
  }
}

function getA2fIdentity(req) {
  const body = req && req.body && typeof req.body === "object" ? req.body : {};
  const tokenPayload = decodeA2fJwtPayload(body.idToken);
  const email = String(tokenPayload.email || process.env.A2F_ADMIN_EMAIL || "").trim();
  const uid = String(
    tokenPayload.user_id ||
    tokenPayload.sub ||
    process.env.A2F_ADMIN_UID ||
    email ||
    "dirac-admin-a2f"
  ).trim();

  return {
    uid: uid || email || "dirac-admin-a2f",
    email
  };
}

function normalizeA2fLockRow(row, identity) {
  const source = row && typeof row === "object" ? row : {};
  const fallback = identity && typeof identity === "object" ? identity : {};
  const failedCount = Math.max(0, Number(source.failed_count ?? source.failedCount ?? 0));
  const lockUntilMs = Math.max(0, Number(source.lock_until_ms ?? source.lockUntilMs ?? 0));
  const permanentBan = source.permanent_ban === true || source.permanentBan === true;
  const locked = source.locked === true || permanentBan || lockUntilMs > Date.now();

  return {
    success: false,
    provider: "supabase",
    uid: String(source.uid || fallback.uid || ""),
    email: String(source.email || fallback.email || ""),
    failedCount,
    lockUntilMs,
    locked,
    permanentBan,
    lastReason: String(source.last_reason || source.lastReason || "")
  };
}

function getA2fCooldownYears(failedCount) {
  if (failedCount <= 1) return 1;
  if (failedCount === 2) return 10;
  return 100;
}

function getA2fCooldownLabel(years) {
  return years + " tahun";
}

function getA2fLockMessage(lockUntilMs) {
  const remainingMs = Math.max(0, Number(lockUntilMs || 0) - Date.now());
  const oneDayMs = 24 * 60 * 60 * 1000;
  const days = Math.ceil(remainingMs / oneDayMs);

  if (days >= 36500) return "A2F terkunci. Coba lagi sekitar 100 tahun.";
  if (days >= 3650) return "A2F terkunci. Coba lagi sekitar 10 tahun.";
  if (days >= 365) return "A2F terkunci. Coba lagi sekitar 1 tahun.";
  if (days > 1) return "A2F terkunci. Coba lagi dalam " + days + " hari.";
  return "A2F terkunci. Coba lagi setelah cooldown selesai.";
}

async function readA2fLockRow(identity) {
  const supabase = getA2fSupabaseClient();
  const { data, error } = await supabase
    .from(A2F_LOCK_TABLE)
    .select("*")
    .eq("uid", identity.uid)
    .maybeSingle();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  return normalizeA2fLockRow(data || {}, identity);
}

async function saveA2fLockRow(row) {
  const supabase = getA2fSupabaseClient();
  const payload = {
    uid: String(row.uid || "dirac-admin-a2f"),
    email: String(row.email || ""),
    failed_count: Math.max(0, Number(row.failedCount || 0)),
    locked: row.locked === true,
    permanent_ban: row.permanentBan === true,
    lock_until_ms: Math.max(0, Number(row.lockUntilMs || 0)),
    last_action: String(row.lastAction || ""),
    last_reason: String(row.lastReason || ""),
    client_time_ms: Date.now(),
    payload: row.payload && typeof row.payload === "object" ? row.payload : {}
  };

  const { data, error } = await supabase
    .from(A2F_LOCK_TABLE)
    .upsert(payload, { onConflict: "uid" })
    .select("*")
    .maybeSingle();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  return normalizeA2fLockRow(data || payload, payload);
}

async function checkA2fLock(req) {
  const identity = getA2fIdentity(req);
  const row = await readA2fLockRow(identity);

  if (row.permanentBan === true || Number(row.lockUntilMs || 0) > Date.now()) {
    const error = new Error(row.lastReason || getA2fLockMessage(row.lockUntilMs));
    error.statusCode = 423;
    error.lockState = Object.assign({}, row, {
      success: false,
      error: row.lastReason || getA2fLockMessage(row.lockUntilMs)
    });
    throw error;
  }

  if (row.locked === true && Number(row.lockUntilMs || 0) <= Date.now() && row.permanentBan !== true) {
    await saveA2fLockRow(Object.assign({}, row, {
      locked: false,
      lockUntilMs: 0,
      lastAction: "unlock-expired",
      lastReason: "Cooldown A2F selesai."
    }));
  }
}

async function recordA2fFailure(req, label) {
  const identity = getA2fIdentity(req);
  const current = await readA2fLockRow(identity);
  const failedCount = Math.max(0, Number(current.failedCount || 0)) + 1;
  const cooldownYears = getA2fCooldownYears(failedCount);
  const lockUntilMs = Date.now() + cooldownYears * A2F_YEAR_MS;
  const lastReason = String(label || "Kode A2F salah") + ". Cooldown " + getA2fCooldownLabel(cooldownYears) + ".";

  const saved = await saveA2fLockRow({
    uid: identity.uid,
    email: identity.email || current.email || "",
    failedCount,
    locked: true,
    permanentBan: false,
    lockUntilMs,
    lastAction: "fail",
    lastReason,
    payload: {
      cooldownYears,
      failedCount
    }
  });

  return Object.assign({}, saved, {
    success: false,
    error: lastReason,
    cooldownYears,
    cooldownLabel: getA2fCooldownLabel(cooldownYears)
  });
}

async function resetA2fFailure(req) {
  const identity = getA2fIdentity(req);
  return saveA2fLockRow({
    uid: identity.uid,
    email: identity.email,
    failedCount: 0,
    locked: false,
    permanentBan: false,
    lockUntilMs: 0,
    lastAction: "success-reset",
    lastReason: "A2F berhasil. Counter salah direset.",
    payload: {}
  });
}

function sendA2fError(res, error) {
  const statusCode = Number(error && error.statusCode || 500);
  const lockState = error && error.lockState && typeof error.lockState === "object" ? error.lockState : null;
  if (lockState) {
    return res.status(statusCode).json(lockState);
  }

  return res.status(statusCode).json({
    success: false,
    error: error && error.message ? error.message : "A2F lock gagal diproses"
  });
}


function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));

  if (A.length !== B.length) return false;

  return crypto.timingSafeEqual(A, B);
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

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
    await checkA2fLock(req);
  } catch (error) {
    return sendA2fError(res, error);
  }

  if (!safeEqual(inputCode, savedCode)) {
    try {
      const lockData = await recordA2fFailure(req, "Kode rahasia salah");
      return res.status(423).json(lockData);
    } catch (error) {
      return sendA2fError(res, error);
    }
  }

  try {
    await resetA2fFailure(req);
  } catch (error) {
    return sendA2fError(res, error);
  }

  return res.status(200).json({
    success: true,
    message: "Kode rahasia benar"
  });
};
