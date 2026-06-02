const crypto = require("crypto");

const { createClient } = require("@supabase/supabase-js");

const A2F_LOCKOUTS_TABLE = process.env.SUPABASE_A2F_LOCKOUTS_TABLE || "a2f_lockouts";
const PUBLIC_TOTP_TABLE = process.env.SUPABASE_PUBLIC_TOTP_TABLE || "user_totp_mfa";
const A2F_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const PUBLIC_LOCK_MS = Number(process.env.PUBLIC_TOTP_LOCK_MS || 10 * 60 * 1000);
const PUBLIC_MAX_FAILED = Number(process.env.PUBLIC_TOTP_MAX_FAILED || 5);
const TOTP_ISSUER = process.env.TOTP_ISSUER || "Dirac Group";
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

function lockJson(lockData, extra = {}) {
  const data = normalizeLockRow(lockData || {});
  const lockUntilMs = Number(data.lockUntilMs || 0);
  const locked = data.permanentBan === true || lockUntilMs > Date.now();

  return Object.assign({
    success: false,
    ok: false,
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
    ok: false,
    error: error.publicMessage || error.message || "A2F terkunci dari backend."
  }));
}

async function sendWrongCodeResponse(res, reason) {
  const lockData = await recordA2fFailure(reason);
  return res.status(Number(lockData.failedCount || 0) >= 3 ? 403 : 401).json(lockJson(lockData, {
    success: false,
    ok: false,
    error: getLockMessage(lockData.lockUntilMs)
  }));
}

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const bytes = [];

  base32 = String(base32).replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();

  for (const char of base32) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error("Konfigurasi verifikasi tidak valid");
    bits += val.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateTotp(secret, offset = 0) {
  const key = base32Decode(secret);
  const timeStep = Math.floor(Date.now() / 1000 / 30) + offset;

  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(timeStep, 4);

  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const hOffset = hmac[hmac.length - 1] & 0xf;

  const code =
    ((hmac[hOffset] & 0x7f) << 24) |
    ((hmac[hOffset + 1] & 0xff) << 16) |
    ((hmac[hOffset + 2] & 0xff) << 8) |
    (hmac[hOffset + 3] & 0xff);

  return String(code % 1000000).padStart(6, "0");
}

function normalizeIdentifier(value) {
  return String(value || "").trim().toLowerCase().slice(0, 180);
}

function randomBase32(length = 32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  while (out.length < length) {
    out += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return out;
}

function getEncryptionSecret() {
  const secret = String(process.env.A2F_SECRET || process.env.TOTP_ENCRYPTION_SECRET || "").trim();
  if (!secret || secret.length < 32) {
    const err = new Error("A2F_SECRET/TOTP_ENCRYPTION_SECRET wajib minimal 32 karakter acak untuk MFA publik.");
    err.statusCode = 500;
    throw err;
  }
  return secret;
}

function deriveEncryptionKey(secret) {
  return crypto.createHash("sha256").update(`dirac-public-totp-v1:${secret}`).digest();
}

function encryptSecret(base32Secret) {
  const key = deriveEncryptionKey(getEncryptionSecret());
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(base32Secret), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: "aes-256-gcm",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    data: encrypted.toString("base64url")
  };
}

function decryptSecret(payload) {
  if (typeof payload === "string" && /^[A-Z2-7]+=*$/i.test(payload.replace(/\s+/g, ""))) {
    return payload.replace(/\s+/g, "").toUpperCase();
  }
  const row = payload && typeof payload === "object" ? payload : {};
  if (row.v !== 1 || row.alg !== "aes-256-gcm" || !row.iv || !row.tag || !row.data) {
    const err = new Error("Secret Authenticator tidak valid atau belum disiapkan.");
    err.statusCode = 400;
    throw err;
  }
  const key = deriveEncryptionKey(getEncryptionSecret());
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(String(row.iv), "base64url"));
  decipher.setAuthTag(Buffer.from(String(row.tag), "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(String(row.data), "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function otpauthUrl(identifier, secret) {
  const label = `${TOTP_ISSUER}:${identifier}`;
  const params = new URLSearchParams({
    secret,
    issuer: TOTP_ISSUER,
    algorithm: "SHA1",
    digits: "6",
    period: "30"
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

async function makeQrCodeDataUrl(uri) {
  try {
    // Optional dependency. If package "qrcode" is not installed, the frontend still shows manualKey.
    const QRCode = require("qrcode");
    return await QRCode.toDataURL(uri, { margin: 1, width: 220 });
  } catch (_error) {
    return "";
  }
}

function makeRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    const a = crypto.randomBytes(4).toString("hex").toUpperCase();
    const b = crypto.randomBytes(4).toString("hex").toUpperCase();
    codes.push(`DRC-${a}-${b}`);
  }
  return codes;
}

function hashRecoveryCodes(codes) {
  const secret = getEncryptionSecret();
  return codes.map((code) => crypto.createHmac("sha256", secret).update(String(code)).digest("hex"));
}

function publicLockMessage(lockUntilMs) {
  const remainingMs = Math.max(0, Number(lockUntilMs || 0) - Date.now());
  const minutes = Math.ceil(remainingMs / 60000);
  return minutes > 0 ? `Terlalu banyak percobaan. Coba lagi dalam ${minutes} menit.` : "Terlalu banyak percobaan. Coba lagi nanti.";
}

async function readPublicMfa(identifier) {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from(PUBLIC_TOTP_TABLE)
    .select("*")
    .eq("identifier", identifier)
    .maybeSingle();
  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }
  return data || null;
}

async function savePublicMfa(payload) {
  const supabase = getSupabaseAdmin();
  const now = new Date().toISOString();
  const identifier = normalizeIdentifier(payload && payload.identifier);

  if (!identifier) {
    const err = new Error("Identifier pengguna wajib ada untuk menyimpan MFA.");
    err.statusCode = 400;
    throw err;
  }

  const row = Object.assign({}, payload, {
    identifier,
    updated_at: now
  });

  // Hindari upsert ON CONFLICT karena beberapa project Supabase sering gagal 400
  // jika schema cache/constraint belum sinkron. Alur manual ini lebih stabil:
  // 1) cek row, 2) update jika ada, 3) insert jika belum ada.
  const existing = await readPublicMfa(identifier);

  if (existing) {
    delete row.created_at;
    const { data, error } = await supabase
      .from(PUBLIC_TOTP_TABLE)
      .update(row)
      .eq("identifier", identifier)
      .select("*")
      .single();

    if (error) {
      console.error("Gagal update user_totp_mfa:", {
        message: error.message,
        details: error.details,
        hint: error.hint,
        code: error.code
      });
      error.statusCode = error.status || 500;
      throw error;
    }

    return data || row;
  }

  if (!row.created_at) row.created_at = now;

  const { data, error } = await supabase
    .from(PUBLIC_TOTP_TABLE)
    .insert(row)
    .select("*")
    .single();

  if (error) {
    console.error("Gagal insert user_totp_mfa:", {
      message: error.message,
      details: error.details,
      hint: error.hint,
      code: error.code
    });
    error.statusCode = error.status || 500;
    throw error;
  }

  return data || row;
}

function getRowSecret(row) {
  if (!row) return "";
  return decryptSecret(row.secret_enc || row.secretEnc || row.totp_secret || row.secret || "");
}

async function setupPublicAuthenticator(identifier) {
  const existing = await readPublicMfa(identifier);
  const secret = existing ? getRowSecret(existing) : randomBase32(32);
  const uri = otpauthUrl(identifier, secret);
  const qrCodeDataUrl = await makeQrCodeDataUrl(uri);

  await savePublicMfa({
    identifier,
    secret_enc: encryptSecret(secret),
    enabled: existing && existing.enabled === true,
    failed_count: 0,
    lock_until_ms: 0
  });

  return {
    success: true,
    ok: true,
    method: "authenticator",
    qrCodeDataUrl,
    manualKey: secret,
    otpauthUrl: uri,
    message: "Scan QR atau masukkan setup key di aplikasi Authenticator, lalu verifikasi kode 6 digit."
  };
}

async function verifyPublicAuthenticator(identifier, code) {
  const row = await readPublicMfa(identifier);
  if (!row) {
    return { status: 400, body: { success: false, ok: false, error: "Authenticator belum disiapkan untuk akun ini." } };
  }

  const lockUntilMs = Number(row.lock_until_ms ?? row.lockUntilMs ?? 0);
  if (lockUntilMs > Date.now()) {
    return { status: 423, body: { success: false, ok: false, locked: true, lockUntilMs, error: publicLockMessage(lockUntilMs) } };
  }

  const inputCode = String(code || "").replace(/\s+/g, "");
  const secret = getRowSecret(row);
  const validCodes = [generateTotp(secret, -1), generateTotp(secret, 0), generateTotp(secret, 1)];

  if (!validCodes.some((validCode) => safeEqual(inputCode, validCode))) {
    const failedCount = Number(row.failed_count ?? row.failedCount ?? 0) + 1;
    const nextLockUntilMs = failedCount >= PUBLIC_MAX_FAILED ? Date.now() + PUBLIC_LOCK_MS : 0;
    await savePublicMfa({
      identifier,
      secret_enc: row.secret_enc || row.secretEnc || encryptSecret(secret),
      enabled: row.enabled === true,
      failed_count: failedCount,
      lock_until_ms: nextLockUntilMs,
      last_failed_at: new Date().toISOString()
    });
    return {
      status: nextLockUntilMs ? 423 : 401,
      body: {
        success: false,
        ok: false,
        locked: Boolean(nextLockUntilMs),
        failedCount,
        lockUntilMs: nextLockUntilMs,
        error: nextLockUntilMs ? publicLockMessage(nextLockUntilMs) : "Kode verifikasi salah."
      }
    };
  }

  const recoveryCodes = makeRecoveryCodes(8);
  await savePublicMfa({
    identifier,
    secret_enc: row.secret_enc || row.secretEnc || encryptSecret(secret),
    enabled: true,
    failed_count: 0,
    lock_until_ms: 0,
    verified_at: new Date().toISOString(),
    recovery_hashes: hashRecoveryCodes(recoveryCodes)
  });

  return {
    status: 200,
    body: {
      success: true,
      ok: true,
      verified: true,
      method: "authenticator",
      recoveryCodes,
      message: "Kode verifikasi benar"
    }
  };
}

async function legacyAdminVerify(code, action, method) {
  if (action === "setup" || action === "resend") {
    try {
      await checkA2fLock();
    } catch (error) {
      return { lockedError: error };
    }
    return {
      status: 200,
      body: {
        success: true,
        ok: true,
        method: method || "authenticator",
        message: "Authenticator admin siap. Masukkan kode 6 digit dari aplikasi Authenticator."
      }
    };
  }

  if (!code) {
    return { status: 400, body: { success: false, ok: false, error: "Kode wajib diisi" } };
  }

  const secret = process.env.TOTP_SECRET;
  if (!secret) {
    return { status: 500, body: { success: false, ok: false, error: "Konfigurasi verifikasi belum lengkap" } };
  }

  const inputCode = String(code).replace(/\s+/g, "");
  const validCodes = [generateTotp(secret, -1), generateTotp(secret, 0), generateTotp(secret, 1)];

  try {
    await checkA2fLock();
  } catch (error) {
    return { lockedError: error };
  }

  if (!validCodes.some((validCode) => safeEqual(inputCode, validCode))) {
    return { wrongCode: true };
  }

  return {
    status: 200,
    body: {
      success: true,
      ok: true,
      verified: true,
      method: "authenticator",
      message: "Kode verifikasi benar"
    }
  };
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      ok: false,
      error: "Method tidak diizinkan"
    });
  }

  const body = req.body || {};
  const action = String(body.action || (body.code ? "verify" : "setup")).trim().toLowerCase();
  const method = String(body.method || "authenticator").trim().toLowerCase();
  const code = body.code;
  const identifier = normalizeIdentifier(body.identifier || body.email || body.username || body.userId || "");

  try {
    if (method && method !== "authenticator") {
      return res.status(400).json({
        success: false,
        ok: false,
        error: "Endpoint ini khusus Authenticator. Pilih metode Authenticator."
      });
    }

    if (identifier) {
      if (action === "setup" || action === "resend") {
        const data = await setupPublicAuthenticator(identifier);
        return res.status(200).json(data);
      }

      if (!code) {
        return res.status(400).json({ success: false, ok: false, error: "Kode wajib diisi" });
      }

      const result = await verifyPublicAuthenticator(identifier, code);
      return res.status(result.status).json(result.body);
    }

    const legacy = await legacyAdminVerify(code, action, method);
    if (legacy.lockedError) return sendA2fLockError(res, legacy.lockedError);
    if (legacy.wrongCode) return sendWrongCodeResponse(res, "totp_wrong_code");
    return res.status(legacy.status).json(legacy.body);
  } catch (error) {
    const status = error.statusCode || error.status || 500;
    return res.status(status).json({
      success: false,
      ok: false,
      error: error.message || "Gagal memproses A2F Authenticator"
    });
  }
};
