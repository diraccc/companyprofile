const crypto = require("crypto");
const admin = require("firebase-admin");
const argon2 = require("argon2");
const nodemailer = require("nodemailer");
const { createClient } = require("@supabase/supabase-js");
const { verifyRegistrationResponse, verifyAuthenticationResponse } = require("@simplewebauthn/server");

const ONE_TIME_RECOVERY_CODE_COUNT = 3;
const ONE_TIME_RECOVERY_CODE_LENGTH = 1000;
const ONE_TIME_RECOVERY_DIGITS = "0123456789";
const ONE_TIME_RECOVERY_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ONE_TIME_RECOVERY_SYMBOLS = "!@#$%^&*_=+[]{}:,.?";
const ONE_TIME_RECOVERY_ALPHABET = ONE_TIME_RECOVERY_DIGITS + ONE_TIME_RECOVERY_LETTERS + ONE_TIME_RECOVERY_SYMBOLS;
const ONE_TIME_RECOVERY_CODE_FORMAT = "MIXED-1000-V1";
const ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32
});
const STEP6_EMAIL_CODE_DIGITS = 1000;
const STEP6_EMAIL_CODE_TTL_MS = 60 * 1000;
const STEP6_COPY_TOKEN_BYTES = 48;
const STEP6_CODE_ENCRYPTION_ALG = "aes-256-gcm";
const STEP6_GENERIC_LINK_ERROR = "Link tidak valid, sudah expired, atau sudah dipakai.";
const STEP6_CONFIRM_PHRASE = "SETUJU";
const STEP6_DENY_PHRASE = "TOLAK";

const A2F_LOCKOUTS_TABLE = process.env.SUPABASE_A2F_LOCKOUTS_TABLE || "a2f_lockouts";
const CLIPBOARD_SECURITY_TABLE = process.env.SUPABASE_CLIPBOARD_SECURITY_TABLE || "admin_clipboard_security";
const CLIPBOARD_OTP_CHALLENGES_TABLE = process.env.SUPABASE_CLIPBOARD_OTP_CHALLENGES_TABLE || "admin_clipboard_otp_challenges";
const CLIPBOARD_UNLOCK_PURPOSE = "clipboard_unlock_5m";
const CLIPBOARD_OTP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CLIPBOARD_OTP_LENGTH = 15;
const CLIPBOARD_OTP_TTL_MS = 90 * 1000;
const CLIPBOARD_UNLOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_TRUSTED_BYPASS_MS = CLIPBOARD_UNLOCK_MS;
const A2F_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const CLIPBOARD_UNLOCK_FIRST_WRONG_LOCK_MS = A2F_YEAR_MS;
const CLIPBOARD_UNLOCK_SECOND_WRONG_LOCK_MS = 100 * A2F_YEAR_MS;
const CLIPBOARD_BAN_META_PREFIX = "clipboard_unlock_ban_v1:";
const CLIPBOARD_ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32
});
let supabaseAdminClient = null;
let domainSupabaseAdminClient = null;

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


function getDomainSupabaseAdmin() {
  if (domainSupabaseAdminClient) return domainSupabaseAdminClient;

  const supabaseUrl = String(
    process.env.DOMAIN_SUPABASE_URL ||
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    ""
  ).trim();

  const serviceRoleKey = String(
    process.env.DOMAIN_SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    ""
  ).trim();

  if (!supabaseUrl || !serviceRoleKey) {
    const err = new Error("ENV Supabase domain belum lengkap. Set DOMAIN_SUPABASE_URL dan DOMAIN_SUPABASE_SERVICE_ROLE_KEY di Vercel.");
    err.statusCode = 500;
    throw err;
  }

  domainSupabaseAdminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false }
  });

  return domainSupabaseAdminClient;
}

function normalizeLockRow(data) {
  const row = data && typeof data === "object" ? data : {};
  return {
    uid: String(row.uid || ""),
    email: String(row.email || ""),
    failedCount: Number(row.failed_count ?? row.failedCount ?? 0),
    lockUntilMs: Number(row.lock_until_ms ?? row.lockUntilMs ?? 0),
    permanentBan: row.permanent_ban === true || row.permanentBan === true,
    permanentBanReason: String(row.permanent_ban_reason || row.permanentBanReason || row.reason || ""),
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

function getAllowedOrigins() {
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  if (fromEnv.length) return fromEnv;

  return [
    "https://diracgroup.store",
    "https://www.diracgroup.store",
    "https://companyprofilee-expk.vercel.app"
  ];
}

function setCors(reqOrRes, maybeRes) {
  const req = maybeRes ? reqOrRes : null;
  const res = maybeRes || reqOrRes;
  const origin = req && req.headers ? String(req.headers.origin || "") : "";
  const allowedOrigins = getAllowedOrigins();

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

function hashCode(code, secret) {
  return crypto.createHmac("sha256", secret).update(String(code)).digest("hex");
}

function hashStep6ActionToken(purpose, { requestId, uid, createdAtMs, expiresAtMs, token }, secret) {
  return hashCode(
    [
      "step6-action-token-v2",
      String(purpose || ""),
      String(requestId || ""),
      String(uid || ""),
      String(createdAtMs || 0),
      String(expiresAtMs || 0),
      String(token || "")
    ].join(":"),
    secret
  );
}

function verifyStep6ActionToken(purpose, data, requestId, token, secret) {
  const row = data && typeof data === "object" ? data : {};
  const fieldName = `${purpose}TokenHash`;
  const storedHash = String(row[fieldName] || "");
  if (!storedHash || !token) return false;
  const expectedHash = hashStep6ActionToken(
    purpose,
    {
      requestId,
      uid: row.uid || "",
      createdAtMs: row.createdAtMs || 0,
      expiresAtMs: row.expiresAtMs || 0,
      token
    },
    secret
  );
  return safeEqual(expectedHash, storedHash);
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function randomId(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function randomDigitCode(length = STEP6_EMAIL_CODE_DIGITS) {
  let out = "";
  while (out.length < length) {
    out += String(crypto.randomInt(0, 10));
  }
  return out;
}

function deriveStep6CodeEncryptionKey(secret) {
  return crypto
    .createHash("sha256")
    .update(`dirac-step6-code-encryption-v1:${String(secret || "")}`)
    .digest();
}

function encryptStep6Code(code, secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(STEP6_CODE_ENCRYPTION_ALG, deriveStep6CodeEncryptionKey(secret), iv);
  const encrypted = Buffer.concat([
    cipher.update(String(code || ""), "utf8"),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return {
    v: 1,
    alg: STEP6_CODE_ENCRYPTION_ALG,
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    data: encrypted.toString("base64url")
  };
}

function decryptStep6Code(payload, secret) {
  const row = payload && typeof payload === "object" ? payload : {};

  if (row.v !== 1 || row.alg !== STEP6_CODE_ENCRYPTION_ALG || !row.iv || !row.tag || !row.data) {
    const err = new Error("Data kode salin tidak valid atau sudah hangus.");
    err.statusCode = 410;
    throw err;
  }

  const decipher = crypto.createDecipheriv(
    STEP6_CODE_ENCRYPTION_ALG,
    deriveStep6CodeEncryptionKey(secret),
    Buffer.from(String(row.iv), "base64url")
  );
  decipher.setAuthTag(Buffer.from(String(row.tag), "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(String(row.data), "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function setNoStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "clipboard-read=(), clipboard-write=(self), camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  );
}

function makeHttpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function getA2fSecret() {
  const secret = String(process.env.A2F_SECRET || "").trim();

  if (!secret) {
    const err = new Error("A2F_SECRET belum diset di Environment Variables backend.");
    err.statusCode = 500;
    throw err;
  }

  if (secret === "rahasia-test") {
    const err = new Error("A2F_SECRET masih memakai nilai testing. Ganti dengan secret production yang panjang dan acak.");
    err.statusCode = 500;
    throw err;
  }

  if (secret.length < 32) {
    const err = new Error("A2F_SECRET terlalu pendek. Gunakan minimal 32 karakter acak.");
    err.statusCode = 500;
    throw err;
  }

  return secret;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlPage(title, bodyHtml) {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#050814;color:#f8fbff;display:grid;place-items:center;min-height:100vh;margin:0;padding:18px}
    .card{width:min(560px,100%);border:1px solid rgba(96,165,250,.36);background:#0b1222;border-radius:24px;padding:22px;box-shadow:0 24px 70px rgba(0,0,0,.38)}
    h1{margin:0 0 12px;font-size:1.35rem}
    p{color:#cbd5e1;line-height:1.55}
    label{display:block;font-weight:800;margin:14px 0 6px}
    input{width:100%;box-sizing:border-box;border:1px solid rgba(255,255,255,.16);background:#111827;color:#fff;border-radius:14px;padding:13px;font-size:1rem}
    button{width:100%;border:0;border-radius:999px;background:#60a5fa;color:#07101e;font-weight:900;padding:13px 18px;margin-top:12px;font-size:1rem}
    .danger{background:#dc2626;color:#fff}
    .warn{border:1px solid rgba(250,204,21,.45);background:rgba(250,204,21,.10);color:#fef08a;border-radius:16px;padding:12px;margin:12px 0}
    .codehint{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;color:#dbeafe}
  </style>
</head>
<body><div class="card"><h1>${escapeHtml(title)}</h1>${bodyHtml}</div></body>
</html>`;
}

function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let bytes = [];

  base32 = String(base32).replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();

  for (const char of base32) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error("Kode verifikasi belum siap");
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

function verifyRecoveryTotp(code) {
  const secret = process.env.A2F_RECOVERY_TOTP_SECRET_2;

  if (!secret) {
    throw new Error("Kode verifikasi belum siap");
  }

  const inputCode = String(code || "").replace(/\s+/g, "");
  const validCodes = [
    generateTotp(secret, -1),
    generateTotp(secret, 0),
    generateTotp(secret, 1)
  ];

  return validCodes.some((validCode) => safeEqual(inputCode, validCode));
}

function getFirebaseDb() {
  if (!admin.apps.length) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");

    if (!projectId || !clientEmail || !privateKey) {
      throw new Error("ENV Firebase Admin belum lengkap");
    }

    admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey
      })
    });
  }

  return admin.firestore();
}

function getAdminUid() {
  const uid = String(process.env.A2F_ADMIN_UID || "").trim();

  if (!uid) {
    throw new Error("A2F_ADMIN_UID belum diset");
  }

  return uid;
}


async function verifyAdminIdToken(idToken) {
  const token = String(idToken || "").trim();

  if (!token) {
    throw new Error("ID token admin wajib dikirim");
  }

  getFirebaseDb();
  const decoded = await admin.auth().verifyIdToken(token);
  const expectedUid = getAdminUid();

  if (decoded.uid !== expectedUid) {
    throw new Error("Akun ini tidak diizinkan memakai recovery code");
  }

  return decoded;
}

function normalizeOneTimeRecoveryCode(code) {
  return String(code || "").trim().toUpperCase().replace(/[\s-]+/g, "");
}

function isValidOneTimeRecoveryCode(code) {
  const normalized = normalizeOneTimeRecoveryCode(code);

  if (normalized.length !== ONE_TIME_RECOVERY_CODE_LENGTH) return false;

  for (const char of normalized) {
    if (!ONE_TIME_RECOVERY_ALPHABET.includes(char)) return false;
  }

  return true;
}

async function hashOneTimeRecoveryCodeArgon2id(code) {
  return argon2.hash(normalizeOneTimeRecoveryCode(code), ARGON2ID_OPTIONS);
}

async function verifyOneTimeRecoveryArgon2id(inputCode, storedHash) {
  const normalized = normalizeOneTimeRecoveryCode(inputCode);

  if (!storedHash || typeof storedHash !== "string") {
    return false;
  }

  try {
    return await argon2.verify(storedHash, normalized);
  } catch (_error) {
    return false;
  }
}

async function verifyStep6Argon2idCode(inputCode, storedHash) {
  const normalized = String(inputCode || "").replace(/\D+/g, "");

  if (!storedHash || typeof storedHash !== "string") {
    return false;
  }

  try {
    return await argon2.verify(storedHash, normalized);
  } catch (_error) {
    return false;
  }
}

function normalizeClipboardOtpCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, "");
}

function randomClipboardOtp(length = CLIPBOARD_OTP_LENGTH) {
  let out = "";

  while (out.length < length) {
    const index = crypto.randomInt(0, CLIPBOARD_OTP_ALPHABET.length);
    out += CLIPBOARD_OTP_ALPHABET[index];
  }

  return out;
}

async function hashClipboardOtpCode(code) {
  return argon2.hash(normalizeClipboardOtpCode(code), CLIPBOARD_ARGON2ID_OPTIONS);
}

async function verifyClipboardOtpCode(inputCode, storedHash) {
  const normalized = normalizeClipboardOtpCode(inputCode);

  if (!storedHash || typeof storedHash !== "string") {
    return false;
  }

  if (!new RegExp(`^[${CLIPBOARD_OTP_ALPHABET}]{${CLIPBOARD_OTP_LENGTH}}$`).test(normalized)) {
    return false;
  }

  try {
    return await argon2.verify(storedHash, normalized);
  } catch (_error) {
    return false;
  }
}

async function consumeOneTimeRecoveryCode(code, _secret, idToken) {
  const normalized = normalizeOneTimeRecoveryCode(code);

  if (!isValidOneTimeRecoveryCode(normalized)) {
    return { ok: false, reason: "format" };
  }

  const decoded = await verifyAdminIdToken(idToken);
  const db = getFirebaseDb();
  const now = Date.now();
  const snapshot = await db.collection("a2fRecoveryCodes").where("uid", "==", decoded.uid).get();
  const candidates = [];

  snapshot.forEach((doc) => {
    const data = doc.data() || {};

    if (
      data.active === true &&
      data.used !== true &&
      data.revoked !== true &&
      data.hashType === "argon2id" &&
      data.purpose === "face_recovery_step_5" &&
      data.codeFormat === ONE_TIME_RECOVERY_CODE_FORMAT &&
      Number(data.codeLength || 0) === ONE_TIME_RECOVERY_CODE_LENGTH &&
      typeof data.argon2Hash === "string"
    ) {
      candidates.push({ ref: doc.ref, data });
    }
  });

  if (!candidates.length) {
    return { ok: false, reason: "not-found" };
  }

  for (const candidate of candidates) {
    const firstRead = candidate.data;

    if (!(await verifyOneTimeRecoveryArgon2id(normalized, firstRead.argon2Hash))) {
      continue;
    }

    let result = { ok: false, reason: "not-found" };

    await db.runTransaction(async (tx) => {
      const txSnap = await tx.get(candidate.ref);

      if (!txSnap.exists) {
        result = { ok: false, reason: "not-found" };
        return;
      }

      const data = txSnap.data() || {};

      if (data.revoked === true || data.active !== true) {
        result = { ok: false, reason: "revoked" };
        return;
      }

      if (data.used === true) {
        result = { ok: false, reason: "used" };
        return;
      }

      if (
        data.hashType !== "argon2id" ||
        data.purpose !== "face_recovery_step_5" ||
        data.codeFormat !== ONE_TIME_RECOVERY_CODE_FORMAT ||
        Number(data.codeLength || 0) !== ONE_TIME_RECOVERY_CODE_LENGTH ||
        data.argon2Hash !== firstRead.argon2Hash
      ) {
        result = { ok: false, reason: "not-found" };
        return;
      }

      tx.set(candidate.ref, {
        used: true,
        active: false,
        usedAtMs: now,
        usedAt: admin.firestore.FieldValue.serverTimestamp(),
        usedByUid: decoded.uid,
        usedByEmail: decoded.email || process.env.A2F_ADMIN_EMAIL || ""
      }, { merge: true });

      result = { ok: true };
    });

    return result;
  }

  return { ok: false, reason: "not-found" };
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

async function checkA2fLock() {
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

  if (data.permanentBan === true) {
    const err = new Error("A2F_PERMANENT_BAN");
    err.statusCode = 403;
    err.publicMessage = "A2F diblokir permanen dari backend. Reset hanya bisa lewat secret admin.";
    throw err;
  }

  const lockUntilMs = Number(data.lockUntilMs || 0);

  if (lockUntilMs > Date.now()) {
    const err = new Error("A2F_TEMP_LOCKED");
    err.statusCode = 423;
    err.lockUntilMs = lockUntilMs;
    err.publicMessage = getLockMessage(lockUntilMs);
    throw err;
  }
}

async function recordA2fFailure() {
  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const failedCount = Number(data.failedCount || 0) + 1;
  const now = Date.now();

  const nextData = {
    uid,
    email: process.env.A2F_ADMIN_EMAIL || data.email || "",
    failedCount,
    lastFailedAtMs: now,
    permanentBan: false,
    permanentBanReason: failedCount >= 3 ? "wrong_code_100_year_lock" : "wrong_code_cooldown",
    lockUntilMs: now + getA2fLockDurationMs(failedCount),
    bannedAtMs: failedCount >= 3 ? now : data.bannedAtMs || 0
  };

  return saveA2fLockRow(nextData);
}

async function resetA2fFailure() {
  const uid = getAdminUid();

  await saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 0,
    lockUntilMs: 0,
    permanentBan: false,
    lastFailedAtMs: 0,
    permanentBanReason: null,
    bannedAtMs: null
  });
}


async function recordPermanentBan(reason) {
  const uid = getAdminUid();
  const now = Date.now();

  await saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 999,
    lockUntilMs: 0,
    permanentBan: true,
    permanentBanReason: reason,
    bannedAtMs: now,
    lastFailedAtMs: now
  });
}

async function recordA2fTimeoutBlock(reason = "a2f_timeout") {
  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const now = Date.now();
  const reasonText = String(reason || "a2f_timeout");
  const isStep6Timeout = /step6|step_6|1000|60/i.test(reasonText);

  return saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || data.email || "",
    failedCount: isStep6Timeout ? 999 : Math.max(3, Number(data.failedCount || 0)),
    lockUntilMs: isStep6Timeout ? 0 : now + 100 * A2F_YEAR_MS,
    permanentBan: isStep6Timeout,
    permanentBanReason: reasonText,
    bannedAtMs: now,
    lastFailedAtMs: now
  });
}

async function sendWrongCodeResponse(res) {
  const lockData = await recordA2fFailure();

  return res.status(Number(lockData.failedCount || 0) >= 3 ? 403 : 401).json({
    success: false,
    locked: Number(lockData.lockUntilMs || 0) > Date.now(),
    permanentBan: lockData.permanentBan === true,
    error: getLockMessage(lockData.lockUntilMs),
    failedCount: lockData.failedCount,
    lockUntilMs: lockData.lockUntilMs,
    uid: lockData.uid || getAdminUid(),
    email: lockData.email || process.env.A2F_ADMIN_EMAIL || ""
  });
}


function cleanMetaString(value, maxLength = 420) {
  const text = String(value === undefined || value === null ? "" : value).replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return text.length > maxLength ? text.slice(0, maxLength) + "..." : text;
}

function cleanMetaNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function getHeaderValue(req, name) {
  const raw = req && req.headers ? req.headers[String(name || "").toLowerCase()] : "";
  if (Array.isArray(raw)) return cleanMetaString(raw[0] || "");
  return cleanMetaString(raw || "");
}

function decodeHeaderText(value) {
  const text = cleanMetaString(value, 260);
  if (!text) return "";
  try { return decodeURIComponent(text); } catch (_error) { return text; }
}

function getRequestIpInfo(req) {
  const candidates = [
    ["x-forwarded-for", getHeaderValue(req, "x-forwarded-for")],
    ["x-real-ip", getHeaderValue(req, "x-real-ip")],
    ["cf-connecting-ip", getHeaderValue(req, "cf-connecting-ip")],
    ["x-client-ip", getHeaderValue(req, "x-client-ip")],
    ["x-vercel-forwarded-for", getHeaderValue(req, "x-vercel-forwarded-for")]
  ];

  for (const [source, value] of candidates) {
    if (!value) continue;
    const firstIp = cleanMetaString(String(value).split(",")[0], 120);
    if (firstIp) {
      return {
        ip: firstIp,
        source,
        rawForwardedFor: source === "x-forwarded-for" ? cleanMetaString(value, 300) : ""
      };
    }
  }

  const socketIp = req && req.socket && req.socket.remoteAddress ? cleanMetaString(req.socket.remoteAddress, 120) : "";
  return {
    ip: socketIp || "Tidak tersedia",
    source: socketIp ? "socket.remoteAddress" : "not-available",
    rawForwardedFor: ""
  };
}

function getGeoInfoFromHeaders(req) {
  return {
    country: getHeaderValue(req, "x-vercel-ip-country") || "Tidak tersedia",
    region: getHeaderValue(req, "x-vercel-ip-country-region") || "Tidak tersedia",
    city: decodeHeaderText(getHeaderValue(req, "x-vercel-ip-city")) || "Tidak tersedia",
    latitude: getHeaderValue(req, "x-vercel-ip-latitude") || "Tidak tersedia",
    longitude: getHeaderValue(req, "x-vercel-ip-longitude") || "Tidak tersedia",
    timezone: getHeaderValue(req, "x-vercel-ip-timezone") || "Tidak tersedia",
    asn: getHeaderValue(req, "x-vercel-ip-as-number") || getHeaderValue(req, "x-asn") || "Tidak tersedia",
    isp: getHeaderValue(req, "x-vercel-ip-isp") || getHeaderValue(req, "x-isp") || "Tidak tersedia"
  };
}

function parseBrowserName(userAgent) {
  const ua = String(userAgent || "");
  if (/CriOS/i.test(ua)) return "Chrome iOS";
  if (/FxiOS/i.test(ua)) return "Firefox iOS";
  if (/EdgiOS/i.test(ua)) return "Edge iOS";
  if (/OPiOS/i.test(ua)) return "Opera iOS";
  if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) return "Chrome";
  if (/Edg\//i.test(ua)) return "Edge";
  if (/Firefox\//i.test(ua)) return "Firefox";
  if (/Safari\//i.test(ua) && /Version\//i.test(ua)) return "Safari";
  return "Tidak terdeteksi";
}

function parseOsName(userAgent) {
  const ua = String(userAgent || "");
  const iosMatch = ua.match(/OS\s([0-9_]+)\s+like\s+Mac\s+OS\s+X/i);
  if (/iPhone|iPad|iPod/i.test(ua)) return iosMatch ? `iOS ${iosMatch[1].replace(/_/g, ".")}` : "iOS";
  const androidMatch = ua.match(/Android\s+([0-9.]+)/i);
  if (androidMatch) return `Android ${androidMatch[1]}`;
  if (/Windows NT/i.test(ua)) return "Windows";
  if (/Mac OS X/i.test(ua)) return "macOS";
  if (/Linux/i.test(ua)) return "Linux";
  return "Tidak terdeteksi";
}

function parseDeviceType(userAgent, clientContext) {
  const ua = String(userAgent || "");
  const platform = String((clientContext && clientContext.platform) || "");
  if (/iPhone/i.test(ua) || /iPhone/i.test(platform)) return "iPhone";
  if (/iPad/i.test(ua) || /iPad/i.test(platform)) return "iPad";
  if (/Android/i.test(ua)) return /Mobile/i.test(ua) ? "Android Phone" : "Android Tablet";
  if (/Macintosh|MacIntel/i.test(ua + " " + platform)) return "Mac";
  if (/Windows/i.test(ua + " " + platform)) return "Windows PC";
  return "Desktop / Browser";
}

function estimateIphoneModel(clientContext, deviceType) {
  if (deviceType !== "iPhone") return "Tidak berlaku";
  const width = Math.round(cleanMetaNumber(clientContext && clientContext.screenWidth));
  const height = Math.round(cleanMetaNumber(clientContext && clientContext.screenHeight));
  const dpr = Math.round(cleanMetaNumber(clientContext && clientContext.pixelRatio));
  const min = Math.min(width, height);
  const max = Math.max(width, height);
  const key = `${min}x${max}@${dpr}`;
  const map = {
    "320x568@2": "iPhone 5 / 5s / SE generasi 1 (perkiraan)",
    "375x667@2": "iPhone 6 / 6s / 7 / 8 / SE generasi 2-3 (perkiraan)",
    "414x736@3": "iPhone 6 Plus / 6s Plus / 7 Plus / 8 Plus (perkiraan)",
    "375x812@3": "iPhone X / XS / 11 Pro / 12 mini / 13 mini (perkiraan)",
    "360x780@3": "iPhone 12 mini / 13 mini (perkiraan)",
    "414x896@2": "iPhone XR / iPhone 11 (perkiraan)",
    "414x896@3": "iPhone XS Max / iPhone 11 Pro Max (perkiraan)",
    "390x844@3": "iPhone 12 / 12 Pro / 13 / 13 Pro / 14 / 15 / 16e (perkiraan)",
    "393x852@3": "iPhone 14 Pro / 15 / 15 Pro / 16 (perkiraan)",
    "402x874@3": "iPhone 16 Pro (perkiraan)",
    "428x926@3": "iPhone 12 Pro Max / 13 Pro Max / 14 Plus (perkiraan)",
    "430x932@3": "iPhone 14 Pro Max / 15 Plus / 15 Pro Max / 16 Plus (perkiraan)",
    "440x956@3": "iPhone 16 Pro Max (perkiraan)"
  };
  return map[key] || `iPhone, model tidak pasti dari browser (${key})`;
}

function normalizeClientContext(raw) {
  const input = raw && typeof raw === "object" ? raw : {};
  return {
    deviceId: cleanMetaString(input.deviceId, 200),
    deviceName: cleanMetaString(input.deviceName, 120) || "Belum diberi nama",
    userAgent: cleanMetaString(input.userAgent, 700),
    language: cleanMetaString(input.language, 80),
    languages: Array.isArray(input.languages) ? input.languages.slice(0, 8).map(v => cleanMetaString(v, 40)).filter(Boolean) : [],
    timezone: cleanMetaString(input.timezone, 120),
    screenWidth: cleanMetaNumber(input.screenWidth),
    screenHeight: cleanMetaNumber(input.screenHeight),
    availWidth: cleanMetaNumber(input.availWidth),
    availHeight: cleanMetaNumber(input.availHeight),
    pixelRatio: cleanMetaNumber(input.pixelRatio),
    colorDepth: cleanMetaNumber(input.colorDepth),
    touchSupport: input.touchSupport === true,
    maxTouchPoints: cleanMetaNumber(input.maxTouchPoints),
    platform: cleanMetaString(input.platform, 120),
    vendor: cleanMetaString(input.vendor, 140),
    hardwareConcurrency: cleanMetaNumber(input.hardwareConcurrency),
    deviceMemory: cleanMetaNumber(input.deviceMemory),
    online: input.online === true,
    cookieEnabled: input.cookieEnabled === true,
    mode: cleanMetaString(input.mode, 80),
    browserName: cleanMetaString(input.browserName, 80),
    connectionType: cleanMetaString(input.connectionType, 60),
    effectiveType: cleanMetaString(input.effectiveType, 60),
    downlink: cleanMetaString(input.downlink, 40),
    rtt: cleanMetaString(input.rtt, 40),
    pageUrl: cleanMetaString(input.pageUrl, 300),
    referrer: cleanMetaString(input.referrer, 300)
  };
}

function compactHash(hash) {
  const text = cleanMetaString(hash, 120);
  if (!text) return "Tidak tersedia";
  if (text.length <= 18) return text;
  return `${text.slice(0, 10)}...${text.slice(-6)}`;
}

function deriveRiskLevel(reasons) {
  const count = Array.isArray(reasons) ? reasons.length : 0;
  if (count >= 2) return "tinggi";
  if (count === 1) return "sedang";
  return "rendah";
}

async function buildStep6LoginContext({ req, db, decoded, clientContext, secret }) {
  const normalizedClient = normalizeClientContext(clientContext);
  const ipInfo = getRequestIpInfo(req);
  const geo = getGeoInfoFromHeaders(req);
  const headerUa = getHeaderValue(req, "user-agent");
  const userAgent = normalizedClient.userAgent || headerUa || "Tidak tersedia";
  const browser = normalizedClient.browserName || parseBrowserName(userAgent);
  const os = parseOsName(userAgent);
  const deviceType = parseDeviceType(userAgent, normalizedClient);
  const estimatedModel = estimateIphoneModel(normalizedClient, deviceType);
  const deviceIdHash = normalizedClient.deviceId
    ? crypto.createHmac("sha256", secret).update(`a2f-device:${normalizedClient.deviceId}`).digest("hex")
    : "";

  let knownDevice = false;
  let previous = {};
  if (deviceIdHash) {
    try {
      const knownRef = db.collection("a2fKnownDevices").doc(`${decoded.uid}_${deviceIdHash}`);
      const knownSnap = await knownRef.get();
      knownDevice = knownSnap.exists;
      previous = knownSnap.exists ? knownSnap.data() || {} : {};
    } catch (_error) {
      knownDevice = false;
      previous = {};
    }
  }

  const reasons = [];
  if (!knownDevice) reasons.push("device baru");
  if (knownDevice && previous.lastIp && previous.lastIp !== ipInfo.ip) reasons.push("IP berubah");
  if (knownDevice && previous.browserName && previous.browserName !== browser) reasons.push("browser berubah");
  if (knownDevice && previous.timezone && normalizedClient.timezone && previous.timezone !== normalizedClient.timezone) reasons.push("timezone berubah");
  if (knownDevice && previous.deviceType && previous.deviceType !== deviceType) reasons.push("tipe perangkat berubah");

  const now = new Date();

  return {
    account: {
      email: decoded.email || process.env.A2F_ADMIN_EMAIL || "Tidak tersedia",
      uid: decoded.uid,
      serverTimeIso: now.toISOString(),
      requestId: ""
    },
    network: {
      ip: ipInfo.ip,
      ipSource: ipInfo.source,
      rawForwardedFor: ipInfo.rawForwardedFor,
      country: geo.country,
      region: geo.region,
      city: geo.city,
      latitude: geo.latitude,
      longitude: geo.longitude,
      timezone: geo.timezone,
      isp: geo.isp,
      asn: geo.asn
    },
    device: {
      name: normalizedClient.deviceName,
      idHash: deviceIdHash,
      idHashShort: compactHash(deviceIdHash),
      type: deviceType,
      estimatedModel,
      os,
      browser,
      userAgent,
      platform: normalizedClient.platform,
      vendor: normalizedClient.vendor
    },
    browser: {
      language: normalizedClient.language || "Tidak tersedia",
      languages: normalizedClient.languages.join(", ") || "Tidak tersedia",
      timezone: normalizedClient.timezone || "Tidak tersedia",
      screen: normalizedClient.screenWidth && normalizedClient.screenHeight ? `${normalizedClient.screenWidth} x ${normalizedClient.screenHeight}` : "Tidak tersedia",
      availableScreen: normalizedClient.availWidth && normalizedClient.availHeight ? `${normalizedClient.availWidth} x ${normalizedClient.availHeight}` : "Tidak tersedia",
      pixelRatio: normalizedClient.pixelRatio || "Tidak tersedia",
      colorDepth: normalizedClient.colorDepth || "Tidak tersedia",
      touchSupport: normalizedClient.touchSupport ? "Ya" : "Tidak",
      maxTouchPoints: normalizedClient.maxTouchPoints || 0,
      hardwareConcurrency: normalizedClient.hardwareConcurrency || "Tidak tersedia",
      deviceMemory: normalizedClient.deviceMemory ? `${normalizedClient.deviceMemory} GB` : "Tidak tersedia",
      online: normalizedClient.online ? "Online" : "Offline / tidak terdeteksi",
      cookieEnabled: normalizedClient.cookieEnabled ? "Ya" : "Tidak",
      mode: normalizedClient.mode || "Web browser",
      connectionType: normalizedClient.connectionType || "Tidak tersedia",
      effectiveType: normalizedClient.effectiveType || "Tidak tersedia",
      downlink: normalizedClient.downlink || "Tidak tersedia",
      rtt: normalizedClient.rtt || "Tidak tersedia"
    },
    security: {
      deviceStatus: knownDevice ? "dikenal" : "baru",
      a2fStatus: "menunggu approval",
      risk: deriveRiskLevel(reasons),
      reasons: reasons.length ? reasons.join(", ") : "tidak ada perubahan besar",
      previousIp: previous.lastIp || "Tidak tersedia",
      previousSeenAtMs: previous.lastSeenAtMs || 0
    }
  };
}

async function rememberStep6KnownDevice(db, approvalData) {
  const ctx = approvalData && approvalData.loginContext ? approvalData.loginContext : null;
  if (!ctx || !ctx.device || !ctx.device.idHash || !approvalData.uid) return;
  const now = Date.now();
  const ref = db.collection("a2fKnownDevices").doc(`${approvalData.uid}_${ctx.device.idHash}`);
  const previousSnap = await ref.get().catch(() => null);
  const previousData = previousSnap && previousSnap.exists ? (previousSnap.data() || {}) : {};
  await ref.set({
    uid: approvalData.uid,
    email: approvalData.email || "",
    deviceIdHash: ctx.device.idHash,
    deviceName: ctx.device.name || "Belum diberi nama",
    deviceType: ctx.device.type || "Tidak tersedia",
    estimatedModel: ctx.device.estimatedModel || "Tidak tersedia",
    os: ctx.device.os || "Tidak tersedia",
    browserName: ctx.device.browser || "Tidak tersedia",
    platform: ctx.device.platform || "Tidak tersedia",
    timezone: ctx.browser && ctx.browser.timezone ? ctx.browser.timezone : "Tidak tersedia",
    firstSeenAtMs: previousData.firstSeenAtMs || approvalData.createdAtMs || now,
    lastSeenAtMs: now,
    lastIp: ctx.network && ctx.network.ip ? ctx.network.ip : "Tidak tersedia",
    lastCountry: ctx.network && ctx.network.country ? ctx.network.country : "Tidak tersedia",
    lastCity: ctx.network && ctx.network.city ? ctx.network.city : "Tidak tersedia",
    lastUserAgent: ctx.device.userAgent || "",
    revoked: previousData.revoked === true ? false : false,
    revokedAtMs: null,
    clipboardTrusted: previousData.clipboardTrusted === false ? false : true,
    trustedSource: previousData.trustedSource || "a2f_step6_approved",
    lastTrustedAtMs: previousData.lastTrustedAtMs || now,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
}


function oneTimeRecoveryCodeHasRequiredCategories(code) {
  const value = String(code || "");
  return (
    [...ONE_TIME_RECOVERY_DIGITS].some((char) => value.includes(char)) &&
    [...ONE_TIME_RECOVERY_LETTERS].some((char) => value.includes(char)) &&
    [...ONE_TIME_RECOVERY_SYMBOLS].some((char) => value.includes(char))
  );
}

function createOneTimeRecoveryCode(length = ONE_TIME_RECOVERY_CODE_LENGTH) {
  let out = "";

  do {
    out = "";
    while (out.length < length) {
      const index = crypto.randomInt(0, ONE_TIME_RECOVERY_ALPHABET.length);
      out += ONE_TIME_RECOVERY_ALPHABET[index];
    }
  } while (!oneTimeRecoveryCodeHasRequiredCategories(out));

  return out;
}

async function revokeExistingOneTimeRecoveryCodes(db, decoded, now, reason = "rotated_by_new_1000_char_recovery_codes") {
  const refs = new Map();

  async function collect(field) {
    const snap = await db.collection("a2fRecoveryCodes").where(field, "==", decoded.uid).get();
    snap.forEach((doc) => {
      const data = doc.data() || {};
      if (data.used === true || data.revoked === true) return;
      refs.set(doc.ref.path, doc.ref);
    });
  }

  await collect("uid");
  await collect("createdByUid");

  const allRefs = Array.from(refs.values());

  for (let index = 0; index < allRefs.length; index += 450) {
    const batch = db.batch();
    for (const ref of allRefs.slice(index, index + 450)) {
      batch.set(ref, {
        active: false,
        revoked: true,
        revokedAtMs: now,
        revokedAt: admin.firestore.FieldValue.serverTimestamp(),
        revokedReason: reason,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }
    await batch.commit();
  }

  return allRefs.length;
}

function getDeviceIdHashFromClientContext(clientContext, secret) {
  const normalizedClient = normalizeClientContext(clientContext);
  if (!normalizedClient.deviceId) return "";
  return crypto.createHmac("sha256", secret).update(`a2f-device:${normalizedClient.deviceId}`).digest("hex");
}

function sanitizeDeviceForClient(id, row, currentDeviceHash) {
  const data = row && typeof row === "object" ? row : {};
  const hash = String(data.deviceIdHash || data.device_id_hash || "");
  const revoked = data.revoked === true;
  const trusted = !revoked && data.clipboardTrusted !== false;
  return {
    id: String(id || ""),
    uid: String(data.uid || ""),
    email: String(data.email || ""),
    deviceIdHash: hash,
    deviceIdHashShort: compactHash(hash),
    deviceName: String(data.deviceName || "Belum diberi nama"),
    deviceType: String(data.deviceType || "Tidak tersedia"),
    estimatedModel: String(data.estimatedModel || "Tidak tersedia"),
    os: String(data.os || "Tidak tersedia"),
    browserName: String(data.browserName || "Tidak tersedia"),
    platform: String(data.platform || "Tidak tersedia"),
    timezone: String(data.timezone || "Tidak tersedia"),
    lastIp: String(data.lastIp || "Tidak tersedia"),
    lastCountry: String(data.lastCountry || "Tidak tersedia"),
    lastCity: String(data.lastCity || "Tidak tersedia"),
    lastUserAgent: String(data.lastUserAgent || ""),
    firstSeenAtMs: Number(data.firstSeenAtMs || 0),
    lastSeenAtMs: Number(data.lastSeenAtMs || 0),
    revoked,
    clipboardTrusted: trusted,
    trustedSource: String(data.trustedSource || ""),
    isCurrent: Boolean(currentDeviceHash && hash && safeEqual(hash, currentDeviceHash))
  };
}

async function getCurrentTrustedDeviceState({ db, decoded, clientContext, secret }) {
  const deviceIdHash = getDeviceIdHashFromClientContext(clientContext, secret);
  if (!deviceIdHash) {
    return { known: false, trusted: false, revoked: false, deviceIdHash: "", deviceIdHashShort: "Tidak tersedia" };
  }

  const ref = db.collection("a2fKnownDevices").doc(`${decoded.uid}_${deviceIdHash}`);
  const snap = await ref.get();
  const data = snap.exists ? (snap.data() || {}) : {};
  const revoked = data.revoked === true;
  const trusted = snap.exists && !revoked && data.clipboardTrusted !== false;
  return {
    known: snap.exists,
    trusted,
    revoked,
    deviceIdHash,
    deviceIdHashShort: compactHash(deviceIdHash),
    deviceName: String(data.deviceName || "Perangkat ini"),
    deviceType: String(data.deviceType || "Tidak tersedia"),
    os: String(data.os || "Tidak tersedia"),
    browserName: String(data.browserName || "Tidak tersedia"),
    lastSeenAtMs: Number(data.lastSeenAtMs || 0)
  };
}

function applyTrustedClipboardBypass(status, trustedState) {
  if (!trustedState || trustedState.trusted !== true || status.permanentBan === true || status.protectionEnabled === false) return status;
  const untilMs = Date.now() + CLIPBOARD_TRUSTED_BYPASS_MS;
  return {
    ...status,
    success: true,
    clipboardUnlocked: true,
    clipboardUnlockedUntil: new Date(untilMs).toISOString(),
    clipboardUnlockedUntilMs: untilMs,
    trustedDeviceBypass: true,
    trustedDevice: {
      deviceIdHashShort: trustedState.deviceIdHashShort,
      deviceName: trustedState.deviceName,
      deviceType: trustedState.deviceType,
      os: trustedState.os,
      browserName: trustedState.browserName
    },
    message: "Perangkat terpercaya. Verifikasi copy-paste dilewati untuk sesi ini."
  };
}

async function writeBackendSecurityLog(action, detail, level, decoded, extra = {}) {
  try {
    const db = getFirebaseDb();
    const now = Date.now();
    await db.collection("securityLogs").doc(`${now}-${randomId(6)}`).set({
      action: String(action || "security.event"),
      detail: String(detail || ""),
      level: String(level || "info"),
      adminUid: decoded && decoded.uid ? decoded.uid : "",
      adminEmail: decoded && decoded.email ? decoded.email : "",
      role: "backend",
      createdAtMs: now,
      createdAtText: new Date(now).toLocaleString("id-ID"),
      backend: true,
      ...extra,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.warn("Backend security log gagal:", error && error.message ? error.message : error);
  }
}

function hashStep6AuditValue(value) {
  const secretPart = String(process.env.A2F_SECRET || "step6-audit");
  return crypto
    .createHash("sha256")
    .update(`step6-url-audit-v1:${secretPart}:${String(value || "")}`)
    .digest("hex")
    .slice(0, 32);
}

async function writeStep6UrlAuditLog(action, detail, level, req, requestId, ok = true, extra = {}) {
  try {
    const db = getFirebaseDb();
    const now = Date.now();
    const ipInfo = getRequestIpInfo(req || {});
    const userAgent = getHeaderValue(req, "user-agent");
    const origin = getHeaderValue(req, "origin");
    await db.collection("securityLogs").doc(`${now}-step6-url-${randomId(6)}`).set({
      action: `auth.step6_url.${String(action || "event")}`,
      detail: String(detail || ""),
      level: String(level || (ok ? "info" : "warn")),
      role: "backend",
      backend: true,
      step: 6,
      requestId: String(requestId || ""),
      ok: Boolean(ok),
      ipHash: hashStep6AuditValue(ipInfo.ip || ""),
      ipSource: ipInfo.source || "",
      userAgentHash: hashStep6AuditValue(userAgent),
      origin: origin || "",
      createdAtMs: now,
      createdAtText: new Date(now).toLocaleString("id-ID"),
      ...extra,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.warn("Step 6 URL audit log gagal:", error && error.message ? error.message : error);
  }
}

function assertAllowedStep6PostOrigin(req) {
  const origin = String((req && req.headers && req.headers.origin) || "").trim();
  if (!origin || !getAllowedOrigins().includes(origin)) {
    const err = makeHttpError(403, STEP6_GENERIC_LINK_ERROR);
    err.publicMessage = STEP6_GENERIC_LINK_ERROR;
    throw err;
  }
  return origin;
}

function step6ExpiredBanFields(now, reason = "step6_60s_expired") {
  return {
    status: "permanent_ban_timeout",
    screenCodeArgon2Hash: null,
    encryptedScreenCode: null,
    approveTokenHash: null,
    denyTokenHash: null,
    copyTokenHash: null,
    permanentBanReason: reason,
    expiredAtMs: now,
    bannedAtMs: now,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };
}

function makeStep6TimeoutBanError(message = "Waktu step 6 60 detik habis. A2F diblokir permanen.") {
  const err = makeHttpError(403, message);
  err.step6PermanentBan = true;
  err.permanentBanReason = "step6_60_seconds_expired";
  err.publicMessage = "Waktu step 6 60 detik habis. A2F diblokir permanen dari backend.";
  return err;
}

async function generateOneTimeRecoveryCodes(req, res) {
  const { idToken, sensitiveTotpCode } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);
  const requestedCount = ONE_TIME_RECOVERY_CODE_COUNT;

  if (!verifyRecoveryTotp(sensitiveTotpCode)) {
    return res.status(403).json({ success: false, error: "Kode A2F utama salah. Recovery code tidak dibuat." });
  }

  const db = getFirebaseDb();
  const batch = db.batch();
  const now = Date.now();
  const codes = [];
  const revokedCount = await revokeExistingOneTimeRecoveryCodes(db, decoded, now);

  for (let i = 0; i < requestedCount; i += 1) {
    const code = createOneTimeRecoveryCode();
    const argon2Hash = await hashOneTimeRecoveryCodeArgon2id(code);
    codes.push(code);
    batch.set(db.collection("a2fRecoveryCodes").doc(randomId(24)), {
      uid: decoded.uid,
      email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      hashType: "argon2id",
      argon2Hash,
      active: true,
      used: false,
      revoked: false,
      createdAtMs: now,
      createdByUid: decoded.uid,
      createdByEmail: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      codeLength: ONE_TIME_RECOVERY_CODE_LENGTH,
      codeFormat: ONE_TIME_RECOVERY_CODE_FORMAT,
      alphabetVersion: "numbers-uppercase-symbols-v1",
      randomMethod: "crypto.randomInt",
      lookupType: "argon2id-active-candidate-scan",
      purpose: "face_recovery_step_5",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      usedAtMs: null,
      usedAt: null,
      usedByUid: null,
      usedByEmail: null,
      revokedAtMs: null,
      revokedAt: null,
      revokedReason: null
    }, { merge: false });
  }

  await batch.commit();
  await writeBackendSecurityLog("auth.recovery_codes_generated", `${requestedCount} recovery code sekali pakai 1000 karakter dibuat untuk Recovery Face ID tahap 5. Kode lama direvoke: ${revokedCount}.`, "warn", decoded, { count: requestedCount, revokedCount, codeLength: ONE_TIME_RECOVERY_CODE_LENGTH, codeFormat: ONE_TIME_RECOVERY_CODE_FORMAT });

  return res.status(200).json({
    success: true,
    count: requestedCount,
    codes,
    revokedCount,
    codeLength: ONE_TIME_RECOVERY_CODE_LENGTH,
    codeFormat: ONE_TIME_RECOVERY_CODE_FORMAT,
    message: "Recovery code sekali pakai berhasil dibuat. Kode asli hanya tampil sekali."
  });
}

async function listAdminSecurityCenter(req, res) {
  const { idToken, clientContext } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);
  const db = getFirebaseDb();
  const secret = getA2fSecret();
  const currentDeviceHash = getDeviceIdHashFromClientContext(clientContext, secret);
  const currentContext = await buildStep6LoginContext({ req, db, decoded, clientContext, secret }).catch(() => null);

  const devicesSnap = await db.collection("a2fKnownDevices").where("uid", "==", decoded.uid).get();
  const devices = [];
  devicesSnap.forEach((docSnap) => devices.push(sanitizeDeviceForClient(docSnap.id, docSnap.data() || {}, currentDeviceHash)));
  devices.sort((a, b) => Number(b.lastSeenAtMs || 0) - Number(a.lastSeenAtMs || 0));

  let approvals = [];
  try {
    const approvalsSnap = await db.collection("a2fEmailApprovals").where("uid", "==", decoded.uid).limit(60).get();
    approvalsSnap.forEach((docSnap) => {
      const data = docSnap.data() || {};
      const ctx = data.loginContext || {};
      approvals.push({
        id: docSnap.id,
        email: String(data.email || decoded.email || ""),
        status: String(data.status || "unknown"),
        createdAtMs: Number(data.createdAtMs || 0),
        expiresAtMs: Number(data.expiresAtMs || 0),
        approvedAtMs: Number(data.emailApprovedAtMs || data.approvedAtMs || 0),
        deniedAtMs: Number(data.deniedAtMs || 0),
        deviceName: String((ctx.device && ctx.device.name) || "Tidak tersedia"),
        deviceType: String((ctx.device && ctx.device.type) || "Tidak tersedia"),
        browserName: String((ctx.device && ctx.device.browser) || "Tidak tersedia"),
        os: String((ctx.device && ctx.device.os) || "Tidak tersedia"),
        ip: String((ctx.network && ctx.network.ip) || "Tidak tersedia"),
        city: String((ctx.network && ctx.network.city) || "Tidak tersedia"),
        country: String((ctx.network && ctx.network.country) || "Tidak tersedia"),
        risk: String((ctx.security && ctx.security.risk) || "Tidak tersedia"),
        reasons: String((ctx.security && ctx.security.reasons) || "Tidak tersedia")
      });
    });
    approvals.sort((a, b) => Number(b.createdAtMs || 0) - Number(a.createdAtMs || 0));
    approvals = approvals.slice(0, 30);
  } catch (error) {
    approvals = [{ id: "error", status: "error", email: decoded.email || "", createdAtMs: Date.now(), deviceName: "Gagal membaca riwayat approval", reasons: error.message || "" }];
  }

  let logs = [];
  try {
    const logsSnap = await db.collection("securityLogs").limit(120).get();
    logsSnap.forEach((docSnap) => {
      const data = docSnap.data() || {};
      logs.push({
        id: docSnap.id,
        action: String(data.action || "-"),
        detail: String(data.detail || "-"),
        level: String(data.level || "info"),
        adminEmail: String(data.adminEmail || ""),
        role: String(data.role || ""),
        createdAtMs: Number(data.createdAtMs || 0),
        createdAtText: String(data.createdAtText || "")
      });
    });
    logs.sort((a, b) => Number(b.createdAtMs || 0) - Number(a.createdAtMs || 0));
    logs = logs.slice(0, 50);
  } catch (_error) {
    logs = [];
  }

  const a2fLock = await readA2fLockRow(getAdminUid()).catch(() => null);
  const clipboardRow = await ensureClipboardSecurityRow().catch(() => null);
  const trustedState = await getCurrentTrustedDeviceState({ db, decoded, clientContext, secret }).catch(() => ({ trusted: false }));
  const clipboard = clipboardRow ? applyTrustedClipboardBypass(normalizeClipboardSecurityStatus(clipboardRow), trustedState) : null;

  return res.status(200).json({
    success: true,
    serverTimeMs: Date.now(),
    account: { uid: decoded.uid, email: decoded.email || process.env.A2F_ADMIN_EMAIL || "" },
    currentDevice: {
      ...(currentContext ? {
        deviceName: currentContext.device.name,
        deviceType: currentContext.device.type,
        estimatedModel: currentContext.device.estimatedModel,
        os: currentContext.device.os,
        browserName: currentContext.device.browser,
        platform: currentContext.device.platform,
        timezone: currentContext.browser.timezone,
        ip: currentContext.network.ip,
        city: currentContext.network.city,
        country: currentContext.network.country,
        risk: currentContext.security.risk,
        reasons: currentContext.security.reasons
      } : {}),
      deviceIdHash: currentDeviceHash,
      deviceIdHashShort: compactHash(currentDeviceHash),
      trusted: trustedState.trusted === true,
      known: trustedState.known === true,
      revoked: trustedState.revoked === true
    },
    devices,
    approvals,
    logs,
    a2fLock,
    clipboard,
    health: {
      firebaseAdmin: true,
      supabaseAdmin: Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
      smtpConfigured: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
      recoveryTotpReady: Boolean(process.env.A2F_RECOVERY_TOTP_SECRET_2),
      a2fSecretReady: Boolean(process.env.A2F_SECRET)
    }
  });
}

async function updateTrustedDevice(req, res) {
  const { idToken, deviceIdHash, mode } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);
  const hash = String(deviceIdHash || "").trim();
  const action = String(mode || "").trim();

  if (!/^[a-f0-9]{64}$/i.test(hash)) {
    return res.status(400).json({ success: false, error: "Device hash tidak valid." });
  }

  if (!["trust", "untrust", "revoke", "kick"].includes(action)) {
    return res.status(400).json({ success: false, error: "Mode perangkat tidak valid." });
  }

  const db = getFirebaseDb();
  const ref = db.collection("a2fKnownDevices").doc(`${decoded.uid}_${hash}`);
  const snap = await ref.get();
  if (!snap.exists) return res.status(404).json({ success: false, error: "Perangkat tidak ditemukan." });

  const now = Date.now();
  let update = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
  let detail = "";
  if (action === "trust") {
    update = { ...update, revoked: false, revokedAtMs: null, clipboardTrusted: true, lastTrustedAtMs: now, trustedSource: "manual_security_center" };
    detail = "Perangkat ditandai terpercaya untuk bypass verifikasi copy-paste.";
  } else if (action === "untrust") {
    update = { ...update, clipboardTrusted: false, lastUntrustedAtMs: now };
    detail = "Status perangkat terpercaya untuk copy-paste dicabut.";
  } else {
    update = { ...update, revoked: true, clipboardTrusted: false, revokedAtMs: now, lastKickedAtMs: now };
    detail = "Perangkat dikeluarkan dan dicabut dari daftar perangkat terpercaya.";
  }

  await ref.set(update, { merge: true });
  await writeBackendSecurityLog("security.device_" + action, detail + " Hash: " + compactHash(hash), action === "trust" ? "good" : "danger", decoded, { deviceIdHashShort: compactHash(hash) });

  return res.status(200).json({ success: true, mode: action, deviceIdHash: hash, deviceIdHashShort: compactHash(hash), message: detail });
}

async function checkCurrentDeviceSecurity(req, res) {
  const { idToken, clientContext } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);
  const db = getFirebaseDb();
  const secret = getA2fSecret();
  const state = await getCurrentTrustedDeviceState({ db, decoded, clientContext, secret });
  return res.status(200).json({
    success: true,
    known: state.known === true,
    trusted: state.trusted === true,
    revoked: state.revoked === true,
    shouldSignOut: state.revoked === true,
    deviceIdHashShort: state.deviceIdHashShort,
    message: state.revoked === true ? "Perangkat ini sudah dikeluarkan dari Security Center." : "Perangkat aktif."
  });
}

function renderEmailRow(label, value) {
  return `<tr><td style="padding:7px 10px;border-bottom:1px solid #e5e7eb;color:#475569;width:150px;vertical-align:top"><b>${escapeHtml(label)}</b></td><td style="padding:7px 10px;border-bottom:1px solid #e5e7eb;color:#0f172a;vertical-align:top;word-break:break-word">${escapeHtml(value || "Tidak tersedia")}</td></tr>`;
}

function renderEmailSection(title, rows) {
  return `<h3 style="margin:18px 0 8px;color:#0f172a">${escapeHtml(title)}</h3><table role="presentation" style="width:100%;border-collapse:collapse;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">${rows.join("")}</table>`;
}

function contextLine(label, value) {
  return `- ${label}: ${value || "Tidak tersedia"}`;
}

function getSmtpTransporter() {
  const host = String(process.env.SMTP_HOST || "");
  const port = Number(process.env.SMTP_PORT || 465);
  const user = String(process.env.SMTP_USER || "");
  const pass = String(process.env.SMTP_PASS || "");

  if (!host || !user || !pass) {
    throw new Error("ENV SMTP belum lengkap");
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });
}

async function sendStep6Email({ requestId, approveToken, denyToken, copyToken, emailCode, email, loginContext }) {
  const baseUrl = String(process.env.A2F_PUBLIC_BASE_URL || "").replace(/\/+$/, "");

  if (!baseUrl) {
    throw new Error("A2F_PUBLIC_BASE_URL belum diset");
  }

  const to = String(process.env.A2F_APPROVAL_EMAIL || process.env.A2F_ADMIN_EMAIL || email || "").trim();
  const fromEmail = String(process.env.SMTP_USER || "").trim();
  const fromName = String(process.env.SMTP_FROM_NAME || "Dirac Security").trim();

  if (!to || !fromEmail) {
    throw new Error("Email approval belum lengkap");
  }

  const approveUrl =
    `${baseUrl}/api/2fa/verify-step?action=approveStep6` +
    `&requestId=${encodeURIComponent(requestId)}` +
    `#t=${encodeURIComponent(approveToken)}`;

  const denyUrl =
    `${baseUrl}/api/2fa/verify-step?action=denyStep6` +
    `&requestId=${encodeURIComponent(requestId)}` +
    `#t=${encodeURIComponent(denyToken)}`;

  const copyUrl =
    `${baseUrl}/api/2fa/verify-step?action=copyStep6Code` +
    `&requestId=${encodeURIComponent(requestId)}` +
    `#t=${encodeURIComponent(copyToken)}`;

  const step6TtlSeconds = Math.floor(STEP6_EMAIL_CODE_TTL_MS / 1000);

  const ctx = loginContext || {};
  const account = ctx.account || {};
  const network = ctx.network || {};
  const device = ctx.device || {};
  const browser = ctx.browser || {};
  const security = ctx.security || {};
  const subject = `SETUJUI Login Admin Dirac - Risiko ${security.risk || "tidak diketahui"}`;

  const text =
`Percobaan Login Admin Dirac

Akun login:
${contextLine("Email", account.email)}
${contextLine("UID Firebase", account.uid)}
${contextLine("Waktu server", account.serverTimeIso)}
${contextLine("Request ID", requestId)}

Jaringan:
${contextLine("IP login", network.ip)}
${contextLine("IP source", network.ipSource)}
${contextLine("Negara", network.country)}
${contextLine("Region", network.region)}
${contextLine("Kota", network.city)}
${contextLine("Koordinat", network.latitude && network.longitude ? `${network.latitude}, ${network.longitude}` : "Tidak tersedia")}
${contextLine("Timezone IP", network.timezone)}
${contextLine("ISP/ASN", `${network.isp || "Tidak tersedia"} / ${network.asn || "Tidak tersedia"}`)}

Perangkat:
${contextLine("Nama perangkat", device.name)}
${contextLine("Device ID hash", device.idHashShort || device.idHash)}
${contextLine("Tipe", device.type)}
${contextLine("Perkiraan model", device.estimatedModel)}
${contextLine("OS", device.os)}
${contextLine("Browser", device.browser)}
${contextLine("Platform", device.platform)}
${contextLine("Vendor", device.vendor)}
${contextLine("User-Agent", device.userAgent)}

Detail browser:
${contextLine("Bahasa", browser.language)}
${contextLine("Semua bahasa", browser.languages)}
${contextLine("Timezone", browser.timezone)}
${contextLine("Ukuran layar", browser.screen)}
${contextLine("Available screen", browser.availableScreen)}
${contextLine("Pixel ratio", browser.pixelRatio)}
${contextLine("Color depth", browser.colorDepth)}
${contextLine("Touch support", browser.touchSupport)}
${contextLine("Max touch points", browser.maxTouchPoints)}
${contextLine("CPU thread", browser.hardwareConcurrency)}
${contextLine("Device memory", browser.deviceMemory)}
${contextLine("Online status", browser.online)}
${contextLine("Cookie enabled", browser.cookieEnabled)}
${contextLine("Mode", browser.mode)}
${contextLine("Koneksi", `${browser.connectionType || "Tidak tersedia"} / ${browser.effectiveType || "Tidak tersedia"}`)}

Keamanan:
${contextLine("Status device", security.deviceStatus)}
${contextLine("Status A2F", security.a2fStatus)}
${contextLine("Risiko", security.risk)}
${contextLine("Alasan risiko", security.reasons)}
${contextLine("IP sebelumnya", security.previousIp)}

LANGKAH 1 - klik SETUJUI dulu:
${approveUrl}

LANGKAH 2 - klik BUKA HALAMAN SALIN KODE 1000 DIGIT:
${copyUrl}

Kode 1000 digit hanya bisa dibuka 1x, hanya berlaku ${step6TtlSeconds} detik, dan akan hangus setelah dipakai.
Salah 1x akan membuat A2F diblokir permanen.

Jika ini bukan kamu, klik TOLAK & BAN PERMANEN:
${denyUrl}`;

  const html =
`<div style="font-family:Arial,sans-serif;line-height:1.5;color:#111;background:#f8fafc;padding:18px">
  <div style="max-width:760px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:20px">
    <h2 style="margin:0 0 8px;color:#0f172a">Percobaan Login Admin Dirac</h2>
    <p style="margin:0 0 14px;color:#475569">Periksa detail di bawah sebelum menyetujui login.</p>
    <div style="display:inline-block;padding:7px 12px;border-radius:999px;background:${security.risk === "tinggi" ? "#fee2e2;color:#991b1b" : security.risk === "sedang" ? "#fef3c7;color:#92400e" : "#dcfce7;color:#166534"};font-weight:800">Risiko: ${escapeHtml(security.risk || "tidak diketahui")}</div>

    ${renderEmailSection("Akun login", [
      renderEmailRow("Email", account.email),
      renderEmailRow("UID Firebase", account.uid),
      renderEmailRow("Waktu server", account.serverTimeIso),
      renderEmailRow("Request ID", requestId)
    ])}

    ${renderEmailSection("Jaringan", [
      renderEmailRow("IP login", network.ip),
      renderEmailRow("IP source", network.ipSource),
      renderEmailRow("Raw forwarded", network.rawForwardedFor),
      renderEmailRow("Negara", network.country),
      renderEmailRow("Region", network.region),
      renderEmailRow("Kota", network.city),
      renderEmailRow("Koordinat", network.latitude && network.longitude ? `${network.latitude}, ${network.longitude}` : "Tidak tersedia"),
      renderEmailRow("Timezone IP", network.timezone),
      renderEmailRow("ISP/ASN", `${network.isp || "Tidak tersedia"} / ${network.asn || "Tidak tersedia"}`)
    ])}

    ${renderEmailSection("Perangkat", [
      renderEmailRow("Nama perangkat", device.name),
      renderEmailRow("Device ID hash", device.idHashShort || device.idHash),
      renderEmailRow("Tipe", device.type),
      renderEmailRow("Perkiraan model", device.estimatedModel),
      renderEmailRow("OS", device.os),
      renderEmailRow("Browser", device.browser),
      renderEmailRow("Platform", device.platform),
      renderEmailRow("Vendor", device.vendor),
      renderEmailRow("User-Agent", device.userAgent)
    ])}

    ${renderEmailSection("Detail browser", [
      renderEmailRow("Bahasa", browser.language),
      renderEmailRow("Semua bahasa", browser.languages),
      renderEmailRow("Timezone", browser.timezone),
      renderEmailRow("Ukuran layar", browser.screen),
      renderEmailRow("Available screen", browser.availableScreen),
      renderEmailRow("Pixel ratio", browser.pixelRatio),
      renderEmailRow("Color depth", browser.colorDepth),
      renderEmailRow("Touch support", browser.touchSupport),
      renderEmailRow("Max touch points", browser.maxTouchPoints),
      renderEmailRow("CPU thread", browser.hardwareConcurrency),
      renderEmailRow("Device memory", browser.deviceMemory),
      renderEmailRow("Online status", browser.online),
      renderEmailRow("Cookie enabled", browser.cookieEnabled),
      renderEmailRow("Mode", browser.mode),
      renderEmailRow("Koneksi", `${browser.connectionType || "Tidak tersedia"} / ${browser.effectiveType || "Tidak tersedia"}`)
    ])}

    ${renderEmailSection("Keamanan", [
      renderEmailRow("Status device", security.deviceStatus),
      renderEmailRow("Status A2F", security.a2fStatus),
      renderEmailRow("Risiko", security.risk),
      renderEmailRow("Alasan risiko", security.reasons),
      renderEmailRow("IP sebelumnya", security.previousIp)
    ])}

    <div style="margin:18px 0;padding:14px;border-radius:14px;background:#eff6ff;border:1px solid #bfdbfe">
      <b>Langkah 1:</b> klik SETUJUI dulu. Setelah itu buka halaman salin kode dan masukkan kode 1000 digit ke dashboard admin.
    </div>
    <p>
      <a href="${approveUrl}" style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;padding:13px 20px;border-radius:999px;font-weight:700">SETUJUI LOGIN</a>
    </p>
    <div style="margin:18px 0;padding:14px;border-radius:14px;background:#f8fafc;border:1px solid #cbd5e1">
      <p style="margin:0 0 10px;color:#334155"><b>Kode 1000 digit tidak ditulis di email.</b> Kode hanya bisa dibuka 1x melalui halaman HTTPS di bawah, berlaku ${step6TtlSeconds} detik, lalu hangus permanen.</p>
      <a href="${copyUrl}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:13px 20px;border-radius:999px;font-weight:700">BUKA HALAMAN SALIN KODE 1000 DIGIT</a>
    </div>
    <p style="padding:12px;border-radius:12px;background:#fff7ed;color:#9a3412"><b>Penting:</b> salah 1x akan membuat A2F diblokir permanen. Link salin hanya bisa dipakai setelah login disetujui.</p>
    <p>
      <a href="${denyUrl}" style="display:inline-block;background:#dc2626;color:#fff;text-decoration:none;padding:12px 18px;border-radius:999px;font-weight:700">TOLAK & BAN PERMANEN</a>
    </p>
    <p style="color:#64748b;font-size:13px">Catatan: model iPhone adalah estimasi dari data browser. Nama perangkat dan Device ID hash lebih akurat untuk membedakan perangkat company.</p>
  </div>
</div>`;

  const transporter = getSmtpTransporter();

  await transporter.sendMail({
    from: `"${fromName}" <${fromEmail}>`,
    to,
    subject,
    text,
    html
  });
}

async function sendClipboardUnlockEmail({ code, email, expiresAtMs }) {
  const to = String(process.env.A2F_APPROVAL_EMAIL || process.env.A2F_ADMIN_EMAIL || email || "").trim();
  const fromEmail = String(process.env.SMTP_USER || "").trim();
  const fromName = String(process.env.SMTP_FROM_NAME || "Dirac Security").trim();

  if (!to || !fromEmail) {
    throw new Error("Email clipboard unlock belum lengkap");
  }

  const expiresAtIso = new Date(Number(expiresAtMs || Date.now())).toISOString();
  const subject = "Kode Izinkan Copy-Paste 5 Menit - Dirac Admin";
  const safeCode = escapeHtml(code);

  const text = `Kode izin copy-paste 5 menit Dirac Admin\n\nKode: ${code}\nExpired: ${expiresAtIso}\n\nJangan berikan kode ini ke siapa pun. Salah input kode SMTP/Authenticator 1x memblokir izin copy-paste 1 tahun; salah ke-2 memblokir 100 tahun. Semua ban dicatat lewat backend Supabase.`;

  const html =
`<div style="font-family:Arial,sans-serif;line-height:1.5;color:#111;background:#f8fafc;padding:18px">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:20px">
    <h2 style="margin:0 0 8px;color:#0f172a">Kode Izinkan Copy-Paste 5 Menit</h2>
    <p style="margin:0 0 14px;color:#475569">Masukkan kode berikut di dashboard admin, lalu lanjutkan dengan Authenticator/TOTP.</p>
    <div style="font-size:26px;font-weight:900;letter-spacing:3px;line-height:1.7;padding:14px 18px;background:#eef6ff;border-radius:12px;word-break:break-all;color:#0f172a">${safeCode}</div>
    <p style="margin:14px 0 0;color:#475569">Expired: <b>${escapeHtml(expiresAtIso)}</b></p>
    <p style="padding:12px;border-radius:12px;background:#fff7ed;color:#9a3412"><b>Penting:</b> salah input kode SMTP/Authenticator 1x = ban izin copy-paste 1 tahun; salah ke-2 = 100 tahun. Semua ban dicatat lewat backend Supabase.</p>
  </div>
</div>`;

  const transporter = getSmtpTransporter();
  await transporter.sendMail({
    from: `"${fromName}" <${fromEmail}>`,
    to,
    subject,
    text,
    html
  });
}

async function startStep6EmailApproval(req, res) {
  await checkA2fLock();

  const { idToken, clientContext } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const secret = getA2fSecret();
  const requestId = randomId(18);
  const approveToken = randomId(32);
  const denyToken = randomId(32);
  const copyToken = randomId(STEP6_COPY_TOKEN_BYTES);
  const screenCode = randomDigitCode(STEP6_EMAIL_CODE_DIGITS);
  const screenCodeArgon2Hash = await argon2.hash(screenCode, ARGON2ID_OPTIONS);
  const encryptedScreenCode = encryptStep6Code(screenCode, secret);
  const now = Date.now();
  const expiresAtMs = now + STEP6_EMAIL_CODE_TTL_MS;

  const ref = db.collection("a2fEmailApprovals").doc(requestId);
  const loginContext = await buildStep6LoginContext({ req, db, decoded, clientContext, secret });
  loginContext.account.requestId = requestId;

  await ref.set({
    uid: decoded.uid,
    email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
    status: "pending_email_approval",
    screenCodeDigits: STEP6_EMAIL_CODE_DIGITS,
    screenCodeTtlMs: STEP6_EMAIL_CODE_TTL_MS,
    screenCodeHashType: "argon2id",
    screenCodeArgon2Hash,
    encryptedScreenCode,
    approveTokenHash: hashStep6ActionToken("approve", { requestId, uid: decoded.uid, createdAtMs: now, expiresAtMs, token: approveToken }, secret),
    denyTokenHash: hashStep6ActionToken("deny", { requestId, uid: decoded.uid, createdAtMs: now, expiresAtMs, token: denyToken }, secret),
    copyTokenHash: hashStep6ActionToken("copy", { requestId, uid: decoded.uid, createdAtMs: now, expiresAtMs, token: copyToken }, secret),
    copyTokenUsedAtMs: 0,
    copyRevealedAtMs: 0,
    codeConsumedAtMs: 0,
    failedCodeCount: 0,
    loginContext,
    createdAtMs: now,
    expiresAtMs,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: false });

  await sendStep6Email({
    requestId,
    approveToken,
    denyToken,
    copyToken,
    emailCode: screenCode,
    email: decoded.email || "",
    loginContext
  });

  return res.status(200).json({
    success: true,
    requestId,
    status: "pending_email_approval",
    expiresAtMs,
    codeDigits: STEP6_EMAIL_CODE_DIGITS,
    ttlSeconds: Math.floor(STEP6_EMAIL_CODE_TTL_MS / 1000),
    message: "Email approval step 6 sudah dikirim. Klik SETUJUI di email, buka halaman salin kode, lalu masukkan kode 1000 digit."
  });
}

async function checkStep6EmailApproval(req, res) {
  await checkA2fLock();

  const { idToken, requestId } = req.body || {};
  await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const snap = await db.collection("a2fEmailApprovals").doc(String(requestId || "")).get();

  if (!snap.exists) {
    return res.status(404).json({
      success: false,
      error: "Request approval tidak ditemukan"
    });
  }

  const data = snap.data() || {};
  const status = String(data.status || "unknown");

  if (Date.now() > Number(data.expiresAtMs || 0) && status !== "consumed") {
    await expireStep6Approval(snap.ref, "step6_60_seconds_expired_poll", req);

    return res.status(403).json({
      success: false,
      status: "permanent_ban_timeout",
      permanentBan: true,
      error: "Waktu step 6 60 detik habis. A2F diblokir permanen dari backend."
    });
  }

  if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) {
    return res.status(403).json({
      success: false,
      status: data.status,
      permanentBan: true,
      error: "Step 6 ditolak. A2F diblokir permanen."
    });
  }

  return res.status(200).json({
    success: true,
    status,
    codeDigits: Number(data.screenCodeDigits || STEP6_EMAIL_CODE_DIGITS),
    ttlSeconds: Math.floor(Number(data.screenCodeTtlMs || STEP6_EMAIL_CODE_TTL_MS) / 1000),
    expiresAtMs: data.expiresAtMs || 0
  });
}

async function submitStep6ScreenCode(req, res) {
  await checkA2fLock();

  const { idToken, requestId, code } = req.body || {};
  await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const ref = db.collection("a2fEmailApprovals").doc(String(requestId || ""));
  const snap = await ref.get();

  if (!snap.exists) {
    return res.status(404).json({
      success: false,
      error: "Request approval tidak ditemukan"
    });
  }

  const data = snap.data() || {};
  const status = String(data.status || "");

  if (Date.now() > Number(data.expiresAtMs || 0)) {
    await expireStep6Approval(ref, "step6_60_seconds_expired_submit", req);

    return res.status(403).json({
      success: false,
      status: "permanent_ban_timeout",
      permanentBan: true,
      error: "Waktu step 6 60 detik habis. A2F diblokir permanen dari backend."
    });
  }

  if (status === "consumed" || status === "approved") {
    return res.status(410).json({
      success: false,
      status: "consumed",
      error: "Kode step 6 sudah pernah dipakai dan sudah hangus. Login ulang."
    });
  }

  if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) {
    return res.status(403).json({
      success: false,
      status: data.status,
      permanentBan: true,
      error: "Step 6 ditolak. A2F diblokir permanen."
    });
  }

  if (status !== "approved_waiting_code") {
    return res.status(409).json({
      success: false,
      status: data.status || "unknown",
      error: "Klik SETUJUI di email dulu, buka halaman salin kode, baru masukkan kode 1000 digit."
    });
  }

  const inputCode = String(code || "").replace(/\D+/g, "");

  if (!inputCode) {
    return res.status(400).json({
      success: false,
      error: "Kode 1000 digit wajib diisi."
    });
  }

  const step6CodeOk = inputCode.length === STEP6_EMAIL_CODE_DIGITS && await verifyStep6Argon2idCode(inputCode, data.screenCodeArgon2Hash);

  if (!step6CodeOk) {
    await ref.set({
      status: "permanent_ban_wrong_code",
      failedCodeCount: Number(data.failedCodeCount || 0) + 1,
      wrongCodeAtMs: Date.now(),
      screenCodeArgon2Hash: null,
      encryptedScreenCode: null,
      approveTokenHash: null,
      denyTokenHash: null,
      copyTokenHash: null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await recordPermanentBan("step6_wrong_1000_digit_email_code_argon2id");

    return res.status(403).json({
      success: false,
      status: "permanent_ban_wrong_code",
      permanentBan: true,
      error: "Kode step 6 salah. A2F diblokir permanen."
    });
  }

  await ref.set({
    status: "consumed",
    approvedFinalAtMs: Date.now(),
    codeConsumedAtMs: Date.now(),
    screenCodeArgon2Hash: null,
    encryptedScreenCode: null,
    approveTokenHash: null,
    denyTokenHash: null,
    copyTokenHash: null,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  await rememberStep6KnownDevice(db, data);
  await resetA2fFailure();

  return res.status(200).json({
    success: true,
    status: "consumed",
    message: "Kode 1000 digit benar. Kode sudah hangus permanen dan dashboard boleh dibuka.",
    nextStep: 7
  });
}

async function expireStep6Approval(ref, reason = "step6_60_seconds_expired", req = null) {
  const now = Date.now();
  await ref.set(step6ExpiredBanFields(now, reason), { merge: true });
  await recordPermanentBan(reason);
  if (req) {
    await writeStep6UrlAuditLog("expired_ban", "Step 6 expired 60 detik dan A2F diblokir permanen.", "danger", req, ref.id, false, { reason });
  }
}

function genericStep6Html(title = "Link tidak valid") {
  return htmlPage(title, `<p>${escapeHtml(STEP6_GENERIC_LINK_ERROR)}</p>`);
}

function renderStep6FragmentActionPage({ title, requestId, action, buttonText, danger = false, warning = "", phrase = "" }) {
  const requestIdJson = JSON.stringify(String(requestId || "")).replace(/</g, "\\u003c");
  const actionJson = JSON.stringify(String(action || "")).replace(/</g, "\\u003c");
  const phraseJson = JSON.stringify(String(phrase || "")).replace(/</g, "\\u003c");
  const buttonTextSafe = escapeHtml(buttonText || "Konfirmasi");
  const phraseHtml = phrase
    ? `<label for="confirmPhrase">Ketik <span class="codehint">${escapeHtml(phrase)}</span> untuk melanjutkan</label><input id="confirmPhrase" autocomplete="off" inputmode="text" placeholder="${escapeHtml(phrase)}">`
    : "";

  return htmlPage(
    title,
    `<p>Token rahasia dibaca dari bagian <span class="codehint">#t=...</span> di link email, lalu langsung dihapus dari address bar. Aksi penting baru berjalan setelah tombol konfirmasi ditekan.</p>
     ${warning ? `<div class="warn">${escapeHtml(warning)}</div>` : ""}
     ${phraseHtml}
     <button id="confirmStep6ActionBtn" class="${danger ? "danger" : ""}" type="button">${buttonTextSafe}</button>
     <p id="step6ActionStatus" class="codehint">Siap menunggu konfirmasi manual.</p>
     <script>
     (() => {
       const requestId = ${requestIdJson};
       const action = ${actionJson};
       const requiredPhrase = ${phraseJson};
       const button = document.getElementById('confirmStep6ActionBtn');
       const statusBox = document.getElementById('step6ActionStatus');
       const phraseInput = document.getElementById('confirmPhrase');
       const hashParams = new URLSearchParams(String(location.hash || '').replace(/^#/, ''));
       const token = hashParams.get('t') || '';
       try {
         history.replaceState(null, document.title, location.pathname + '?action=' + encodeURIComponent(new URLSearchParams(location.search).get('action') || '') + '&requestId=' + encodeURIComponent(requestId));
       } catch (_error) {}
       function setStatus(message) { if (statusBox) statusBox.textContent = message; }
       if (!token) {
         button.disabled = true;
         setStatus('Token tidak ditemukan. Buka link asli dari email approval.');
         return;
       }
       button.addEventListener('click', async () => {
         const confirmText = phraseInput ? String(phraseInput.value || '').trim().toUpperCase() : '';
         if (requiredPhrase && confirmText !== requiredPhrase) {
           setStatus('Ketik ' + requiredPhrase + ' dengan benar dulu.');
           if (phraseInput) phraseInput.focus();
           return;
         }
         button.disabled = true;
         setStatus('Memproses konfirmasi aman...');
         try {
           const response = await fetch(location.pathname, {
             method: 'POST',
             headers: { 'Content-Type': 'application/json' },
             cache: 'no-store',
             credentials: 'omit',
             body: JSON.stringify({ action, requestId, token, confirmText })
           });
           const data = await response.json().catch(() => ({}));
           if (!response.ok || !data.success) throw new Error(data.error || '${STEP6_GENERIC_LINK_ERROR}');
           setStatus(data.message || 'Berhasil.');
         } catch (error) {
           setStatus(error.message || '${STEP6_GENERIC_LINK_ERROR}');
         }
       });
     })();
     </script>`
  );
}

async function readStep6RequestOrShowGeneric(req, res, requestId, actionName) {
  const db = getFirebaseDb();
  const ref = db.collection("a2fEmailApprovals").doc(String(requestId || ""));
  const snap = await ref.get();
  if (!snap.exists) {
    await writeStep6UrlAuditLog(actionName || "missing_request", STEP6_GENERIC_LINK_ERROR, "warn", req, requestId, false);
    res.status(404).send(genericStep6Html());
    return null;
  }
  return { db, ref, data: snap.data() || {} };
}

async function approveStep6FromEmail(req, res) {
  setNoStore(res);
  try {
    await checkA2fLock();
    const requestId = String((req.query && req.query.requestId) || "").trim();
    if (!requestId) {
      await writeStep6UrlAuditLog("approve_page_invalid", "Request ID approve kosong.", "warn", req, "", false);
      return res.status(400).send(genericStep6Html());
    }

    const loaded = await readStep6RequestOrShowGeneric(req, res, requestId, "approve_page_missing");
    if (!loaded) return;
    const { ref, data } = loaded;
    const status = String(data.status || "");

    if (Date.now() > Number(data.expiresAtMs || 0) && status !== "consumed") {
      await expireStep6Approval(ref, "step6_60_seconds_expired_approve_page", req);
      return res.status(403).send(htmlPage("A2F diblokir permanen", "<p>Waktu step 6 60 detik habis. A2F diblokir permanen dari backend.</p>"));
    }

    await writeStep6UrlAuditLog("approve_page_opened", "Halaman konfirmasi approve dibuka.", "info", req, requestId, true);
    return res.status(200).send(renderStep6FragmentActionPage({
      title: "Konfirmasi Setujui Login",
      requestId,
      action: "confirmApproveStep6",
      buttonText: "KONFIRMASI SETUJUI LOGIN",
      warning: "Halaman ini mencegah scanner email menyetujui login otomatis. Semua proses step 6 hanya berlaku 60 detik."
    }));
  } catch (error) {
    await writeStep6UrlAuditLog("approve_page_error", error.message || STEP6_GENERIC_LINK_ERROR, "danger", req, req.query && req.query.requestId, false);
    return res.status(error.statusCode || 500).send(genericStep6Html("Approval gagal"));
  }
}

async function confirmApproveStep6FromEmail(req, res) {
  setNoStore(res);
  let requestId = "";
  try {
    await checkA2fLock();
    assertAllowedStep6PostOrigin(req);
    requestId = String((req.body && req.body.requestId) || "").trim();
    const token = String((req.body && req.body.token) || "").trim();
    const secret = getA2fSecret();

    if (!requestId || !token) throw makeHttpError(400, STEP6_GENERIC_LINK_ERROR);

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();
    if (!snap.exists) throw makeHttpError(404, STEP6_GENERIC_LINK_ERROR);

    const data = snap.data() || {};
    const status = String(data.status || "");

    if (Date.now() > Number(data.expiresAtMs || 0) && status !== "consumed") {
      await expireStep6Approval(ref, "step6_60_seconds_expired_approve_confirm", req);
      throw makeStep6TimeoutBanError();
    }

    if (!verifyStep6ActionToken("approve", data, requestId, token, secret)) {
      await writeStep6UrlAuditLog("invalid_token", "Token approve tidak valid.", "danger", req, requestId, false, { purpose: "approve" });
      throw makeHttpError(403, STEP6_GENERIC_LINK_ERROR);
    }

    if (status === "consumed" || status === "approved") throw makeHttpError(410, STEP6_GENERIC_LINK_ERROR);
    if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) throw makeHttpError(403, STEP6_GENERIC_LINK_ERROR);
    if (status !== "pending_email_approval" && status !== "approved_waiting_code") throw makeHttpError(409, STEP6_GENERIC_LINK_ERROR);

    await ref.set({
      status: "approved_waiting_code",
      emailApprovedAtMs: Date.now(),
      approveTokenUsedAtMs: data.approveTokenUsedAtMs || Date.now(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await writeStep6UrlAuditLog("approve_confirmed", "Login step 6 disetujui via POST manual.", "good", req, requestId, true);
    return res.status(200).json({
      success: true,
      status: "approved_waiting_code",
      message: "Login disetujui. Sekarang buka halaman salin kode, salin 1000 digit, lalu paste ke dashboard sebelum 60 detik habis."
    });
  } catch (error) {
    if (error.step6PermanentBan) {
      await writeStep6UrlAuditLog("expired_token", error.publicMessage || STEP6_GENERIC_LINK_ERROR, "danger", req, requestId, false);
    }
    return res.status(error.statusCode || 500).json({
      success: false,
      permanentBan: error.step6PermanentBan === true,
      error: error.publicMessage || STEP6_GENERIC_LINK_ERROR
    });
  }
}

function renderStep6CopyCodePage(req, res) {
  setNoStore(res);
  const requestId = String((req.query && req.query.requestId) || "").trim();
  if (!requestId) {
    writeStep6UrlAuditLog("copy_page_invalid", "Request ID copy kosong.", "warn", req, "", false).catch(() => {});
    return res.status(400).send(genericStep6Html("Request tidak valid"));
  }

  writeStep6UrlAuditLog("copy_page_opened", "Halaman salin kode dibuka.", "info", req, requestId, true).catch(() => {});
  const requestIdJson = JSON.stringify(requestId).replace(/</g, "\\u003c");
  const ttlSeconds = Math.floor(STEP6_EMAIL_CODE_TTL_MS / 1000);

  return res.status(200).send(htmlPage(
    "Salin Kode Step 6",
    `<p>Halaman ini hanya bisa membuka kode <b>${STEP6_EMAIL_CODE_DIGITS} digit</b> satu kali. Token rahasia dibaca dari bagian <span class="codehint">#t=...</span> di link email dan tidak dikirim lewat URL HTTP.</p>
     <div class="warn">Wajib klik <b>SETUJUI LOGIN</b> di email dulu. Setelah kode tersalin, link salin langsung hangus. Semua proses hanya berlaku ${ttlSeconds} detik. Lewat waktu ini A2F diblokir permanen dari backend.</div>
     <label for="confirmRevealText">Ketik <span class="codehint">${STEP6_CONFIRM_PHRASE}</span> sebelum membuka kode</label>
     <input id="confirmRevealText" autocomplete="off" inputmode="text" placeholder="${STEP6_CONFIRM_PHRASE}">
     <button id="revealCopyBtn" type="button">Salin Semua ${STEP6_EMAIL_CODE_DIGITS} Digit</button>
     <textarea id="manualCodeBox" readonly spellcheck="false" style="display:none;width:100%;min-height:180px;box-sizing:border-box;margin-top:12px;border:1px solid rgba(255,255,255,.16);background:#020617;color:#e0f2fe;border-radius:14px;padding:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem;line-height:1.5"></textarea>
     <p id="copyStatus" class="codehint">Siap. Ketik ${STEP6_CONFIRM_PHRASE}, lalu tekan tombol sekali saja.</p>
     <script>
     (() => {
       const requestId = ${requestIdJson};
       const button = document.getElementById('revealCopyBtn');
       const statusBox = document.getElementById('copyStatus');
       const manualBox = document.getElementById('manualCodeBox');
       const confirmBox = document.getElementById('confirmRevealText');
       const hashParams = new URLSearchParams(String(location.hash || '').replace(/^#/, ''));
       const copyToken = hashParams.get('t') || '';
       try {
         history.replaceState(null, document.title, location.pathname + '?action=copyStep6Code&requestId=' + encodeURIComponent(requestId));
       } catch (_error) {}
       function setStatus(message) { if (statusBox) statusBox.textContent = message; }
       async function copyText(text) {
         if (navigator.clipboard && window.isSecureContext) {
           await navigator.clipboard.writeText(text);
           return true;
         }
         const ta = document.createElement('textarea');
         ta.value = text;
         ta.setAttribute('readonly', '');
         ta.style.position = 'fixed';
         ta.style.left = '-9999px';
         ta.style.top = '0';
         document.body.appendChild(ta);
         ta.focus();
         ta.select();
         const ok = document.execCommand('copy');
         document.body.removeChild(ta);
         if (!ok) throw new Error('Clipboard browser menolak salin otomatis.');
         return true;
       }
       if (!copyToken) {
         button.disabled = true;
         setStatus('Token salin tidak ditemukan. Buka link asli dari email approval.');
         return;
       }
       button.addEventListener('click', async () => {
         const confirmText = String(confirmBox && confirmBox.value || '').trim().toUpperCase();
         if (confirmText !== '${STEP6_CONFIRM_PHRASE}') {
           setStatus('Ketik ${STEP6_CONFIRM_PHRASE} dengan benar dulu.');
           if (confirmBox) confirmBox.focus();
           return;
         }
         button.disabled = true;
         setStatus('Membuka kode terenkripsi satu kali...');
         try {
           const response = await fetch(location.pathname, {
             method: 'POST',
             headers: { 'Content-Type': 'application/json' },
             cache: 'no-store',
             credentials: 'omit',
             body: JSON.stringify({ action: 'revealStep6CopyCode', requestId, copyToken, confirmText })
           });
           const data = await response.json().catch(() => ({}));
           if (!response.ok || !data.success || !data.code) throw new Error(data.error || '${STEP6_GENERIC_LINK_ERROR}');
           try {
             await copyText(String(data.code));
             setStatus('Kode 1000 digit berhasil disalin. Link salin sudah hangus. Segera paste ke dashboard admin.');
           } catch (copyError) {
             manualBox.value = String(data.code);
             manualBox.style.display = 'block';
             manualBox.focus();
             manualBox.select();
             setStatus((copyError && copyError.message ? copyError.message + ' ' : '') + 'Kode ditampilkan sekali di kotak ini. Salin manual sekarang; refresh tidak akan menampilkan ulang.');
           }
         } catch (error) {
           setStatus(error.message || '${STEP6_GENERIC_LINK_ERROR}');
         } finally {
           setTimeout(() => { manualBox.value = ''; }, 60000);
         }
       });
     })();
     </script>`
  ));
}

async function revealStep6CopyCode(req, res) {
  setNoStore(res);
  await checkA2fLock();

  const requestId = String((req.body && req.body.requestId) || "").trim();
  const copyToken = String((req.body && req.body.copyToken) || "").trim();
  const confirmText = String((req.body && req.body.confirmText) || "").trim().toUpperCase();

  try {
    assertAllowedStep6PostOrigin(req);
    if (!requestId || !copyToken || confirmText !== STEP6_CONFIRM_PHRASE) {
      throw makeHttpError(400, STEP6_GENERIC_LINK_ERROR);
    }

    const db = getFirebaseDb();
    const secret = getA2fSecret();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    let revealedCode = "";
    let expiresAtMs = 0;

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) throw makeHttpError(404, STEP6_GENERIC_LINK_ERROR);
      const data = snap.data() || {};
      const status = String(data.status || "");
      expiresAtMs = Number(data.expiresAtMs || 0);
      const now = Date.now();

      if (now > expiresAtMs) throw makeStep6TimeoutBanError();
      if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) throw makeHttpError(403, STEP6_GENERIC_LINK_ERROR);
      if (status === "consumed" || status === "approved") throw makeHttpError(410, STEP6_GENERIC_LINK_ERROR);
      if (status !== "approved_waiting_code") throw makeHttpError(409, "Klik SETUJUI LOGIN di email dulu, lalu tekan tombol salin lagi.");
      if (Number(data.copyTokenUsedAtMs || 0) || !data.copyTokenHash || !data.encryptedScreenCode) throw makeHttpError(410, STEP6_GENERIC_LINK_ERROR);
      if (!verifyStep6ActionToken("copy", data, requestId, copyToken, secret)) {
        const err = makeHttpError(403, STEP6_GENERIC_LINK_ERROR);
        err.step6AuditAction = "invalid_token";
        err.step6AuditPurpose = "copy";
        throw err;
      }

      const code = decryptStep6Code(data.encryptedScreenCode, secret);
      if (!new RegExp(`^\\d{${STEP6_EMAIL_CODE_DIGITS}}$`).test(code)) throw makeHttpError(500, STEP6_GENERIC_LINK_ERROR);
      revealedCode = code;
      tx.set(ref, {
        copyTokenUsedAtMs: now,
        copyRevealedAtMs: now,
        encryptedScreenCode: null,
        copyTokenHash: null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    });

    await writeStep6UrlAuditLog("copy_revealed", "Kode 1000 digit berhasil dibuka 1x.", "good", req, requestId, true);
    return res.status(200).json({
      success: true,
      code: revealedCode,
      codeDigits: STEP6_EMAIL_CODE_DIGITS,
      expiresAtMs,
      message: "Kode 1000 digit dibuka satu kali. Link salin sekarang hangus."
    });
  } catch (error) {
    if (error.step6PermanentBan) {
      const db = getFirebaseDb();
      const ref = db.collection("a2fEmailApprovals").doc(requestId);
      await expireStep6Approval(ref, error.permanentBanReason || "step6_60_seconds_expired_reveal", req);
    } else {
      await writeStep6UrlAuditLog(error.step6AuditAction || "copy_reveal_failed", error.publicMessage || error.message || STEP6_GENERIC_LINK_ERROR, "warn", req, requestId, false, error.step6AuditPurpose ? { purpose: error.step6AuditPurpose } : {});
    }
    return res.status(error.statusCode || 500).json({
      success: false,
      permanentBan: error.step6PermanentBan === true,
      error: error.publicMessage || STEP6_GENERIC_LINK_ERROR
    });
  }
}

async function denyStep6FromEmail(req, res) {
  setNoStore(res);
  try {
    const requestId = String((req.query && req.query.requestId) || "").trim();
    if (!requestId) {
      await writeStep6UrlAuditLog("deny_page_invalid", "Request ID deny kosong.", "warn", req, "", false);
      return res.status(400).send(genericStep6Html());
    }

    const loaded = await readStep6RequestOrShowGeneric(req, res, requestId, "deny_page_missing");
    if (!loaded) return;
    const { ref, data } = loaded;
    const status = String(data.status || "");

    if (Date.now() > Number(data.expiresAtMs || 0) && status !== "consumed") {
      await expireStep6Approval(ref, "step6_60_seconds_expired_deny_page", req);
      return res.status(403).send(htmlPage("A2F diblokir permanen", "<p>Waktu step 6 60 detik habis. A2F diblokir permanen dari backend.</p>"));
    }

    await writeStep6UrlAuditLog("deny_page_opened", "Halaman konfirmasi deny dibuka.", "warn", req, requestId, true);
    return res.status(200).send(renderStep6FragmentActionPage({
      title: "Konfirmasi Tolak Login",
      requestId,
      action: "confirmDenyStep6",
      buttonText: "KONFIRMASI TOLAK & BAN PERMANEN",
      danger: true,
      phrase: STEP6_DENY_PHRASE,
      warning: "Konfirmasi ini akan membuat A2F diblokir permanen. Halaman ini mencegah scanner email mem-ban akun otomatis."
    }));
  } catch (error) {
    await writeStep6UrlAuditLog("deny_page_error", error.message || STEP6_GENERIC_LINK_ERROR, "danger", req, req.query && req.query.requestId, false);
    return res.status(error.statusCode || 500).send(genericStep6Html("Penolakan gagal"));
  }
}

async function confirmDenyStep6FromEmail(req, res) {
  setNoStore(res);
  let requestId = "";
  try {
    assertAllowedStep6PostOrigin(req);
    requestId = String((req.body && req.body.requestId) || "").trim();
    const token = String((req.body && req.body.token) || "").trim();
    const confirmText = String((req.body && req.body.confirmText) || "").trim().toUpperCase();
    const secret = getA2fSecret();
    if (!requestId || !token || confirmText !== STEP6_DENY_PHRASE) throw makeHttpError(400, STEP6_GENERIC_LINK_ERROR);

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();
    if (!snap.exists) throw makeHttpError(404, STEP6_GENERIC_LINK_ERROR);

    const data = snap.data() || {};
    const status = String(data.status || "");

    if (Date.now() > Number(data.expiresAtMs || 0) && status !== "consumed") {
      await expireStep6Approval(ref, "step6_60_seconds_expired_deny_confirm", req);
      throw makeStep6TimeoutBanError();
    }

    if (!verifyStep6ActionToken("deny", data, requestId, token, secret)) {
      await writeStep6UrlAuditLog("invalid_token", "Token deny tidak valid.", "danger", req, requestId, false, { purpose: "deny" });
      throw makeHttpError(403, STEP6_GENERIC_LINK_ERROR);
    }

    if (status === "consumed" || status === "approved") throw makeHttpError(410, STEP6_GENERIC_LINK_ERROR);
    if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) throw makeHttpError(403, STEP6_GENERIC_LINK_ERROR);

    await ref.set({
      status: "denied_permanent_ban",
      deniedAtMs: Date.now(),
      denyTokenUsedAtMs: data.denyTokenUsedAtMs || Date.now(),
      approveTokenHash: null,
      denyTokenHash: null,
      copyTokenHash: null,
      encryptedScreenCode: null,
      screenCodeArgon2Hash: null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await recordPermanentBan("step6_email_denied_confirmed");
    await writeStep6UrlAuditLog("deny_confirmed", "Login ditolak dan A2F diblokir permanen via POST manual.", "danger", req, requestId, true);
    return res.status(200).json({
      success: true,
      permanentBan: true,
      status: "denied_permanent_ban",
      message: "Login ditolak. A2F diblokir permanen dari backend."
    });
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      success: false,
      permanentBan: error.step6PermanentBan === true,
      error: error.publicMessage || STEP6_GENERIC_LINK_ERROR
    });
  }
}


async function checkA2fBanStatus(req, res) {
  const { idToken } = req.body || {};
  await verifyAdminIdToken(idToken);

  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const lockUntilMs = Number(data.lockUntilMs || 0);
  const permanentBan = data.permanentBan === true;
  const locked = permanentBan || lockUntilMs > Date.now();

  return res.status(200).json({
    success: true,
    locked,
    permanentBan,
    failedCount: Number(data.failedCount || 0),
    lockUntilMs,
    permanentBanReason: data.permanentBanReason || "",
    error: permanentBan
      ? "A2F diblokir permanen dari backend."
      : (lockUntilMs > Date.now() ? getLockMessage(lockUntilMs) : "")
  });
}


function parseClipboardBanMeta(reason) {
  const raw = String(reason || "").trim();

  if (!raw.startsWith(CLIPBOARD_BAN_META_PREFIX)) {
    return {
      version: 0,
      active: false,
      failedCount: 0,
      banUntilMs: 0,
      reasonCode: raw
    };
  }

  try {
    const parsed = JSON.parse(raw.slice(CLIPBOARD_BAN_META_PREFIX.length));
    return {
      version: 1,
      active: parsed.active !== false,
      failedCount: Math.max(0, Number(parsed.failedCount || 0)),
      banUntilMs: Math.max(0, Number(parsed.banUntilMs || 0)),
      reasonCode: String(parsed.reasonCode || "clipboard_unlock_wrong_code")
    };
  } catch (_error) {
    return {
      version: 1,
      active: true,
      failedCount: 0,
      banUntilMs: 0,
      reasonCode: "clipboard_unlock_ban_meta_corrupt"
    };
  }
}

function buildClipboardBanMeta({ active = true, failedCount = 0, banUntilMs = 0, reasonCode = "clipboard_unlock_wrong_code" } = {}) {
  return CLIPBOARD_BAN_META_PREFIX + JSON.stringify({
    active: active === true,
    failedCount: Math.max(0, Number(failedCount || 0)),
    banUntilMs: Math.max(0, Number(banUntilMs || 0)),
    reasonCode: String(reasonCode || "clipboard_unlock_wrong_code")
  });
}

function getClipboardUnlockFailureCountFromRow(row) {
  const data = row && typeof row === "object" ? row : {};
  const meta = parseClipboardBanMeta(data.clipboard_ban_reason || "");
  return Math.max(0, Number(meta.failedCount || 0));
}

function getClipboardUnlockBanDurationMs(failedCount) {
  return Number(failedCount || 0) >= 2
    ? CLIPBOARD_UNLOCK_SECOND_WRONG_LOCK_MS
    : CLIPBOARD_UNLOCK_FIRST_WRONG_LOCK_MS;
}

function getClipboardUnlockBanLabel(failedCount) {
  return Number(failedCount || 0) >= 2 ? "100 tahun" : "1 tahun";
}

function getClipboardUnlockBanMessage(failedCount, banUntilMs, reasonCode) {
  const until = banUntilMs ? new Date(banUntilMs).toLocaleString("id-ID", {
    timeZone: "Asia/Jakarta",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }) : "waktu backend";
  const label = getClipboardUnlockBanLabel(failedCount);
  const codeText = String(reasonCode || "").includes("totp") ? "Authenticator" : "SMTP";

  return `Kode ${codeText} salah. Fitur izin copy-paste diblokir ${label} lewat backend Supabase sampai ${until}.`;
}

function isExpiredClipboardTimedBan(row) {
  const data = row && typeof row === "object" ? row : {};
  const meta = parseClipboardBanMeta(data.clipboard_ban_reason || "");
  return Boolean(data.clipboard_permanent_ban === true && meta.version === 1 && meta.banUntilMs && meta.banUntilMs <= Date.now());
}

async function clearExpiredClipboardTimedBan(row) {
  if (!isExpiredClipboardTimedBan(row)) return row;

  const supabase = getSupabaseAdmin();
  const meta = parseClipboardBanMeta(row.clipboard_ban_reason || "");
  const { data, error } = await supabase
    .from(CLIPBOARD_SECURITY_TABLE)
    .upsert({
      id: "global",
      protection_enabled: true,
      clipboard_unlocked_until: null,
      clipboard_permanent_ban: false,
      clipboard_ban_reason: buildClipboardBanMeta({
        active: false,
        failedCount: meta.failedCount,
        banUntilMs: meta.banUntilMs,
        reasonCode: meta.reasonCode || "clipboard_unlock_ban_expired"
      }),
      updated_at: new Date().toISOString()
    }, { onConflict: "id" })
    .select("*")
    .single();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  return data || row;
}

function normalizeClipboardSecurityStatus(row) {
  const data = row && typeof row === "object" ? row : {};
  const unlockedUntilMs = data.clipboard_unlocked_until
    ? Date.parse(data.clipboard_unlocked_until)
    : 0;
  const safeUnlockedUntilMs = Number.isFinite(unlockedUntilMs) ? unlockedUntilMs : 0;
  const clipboardUnlocked = Boolean(safeUnlockedUntilMs && safeUnlockedUntilMs > Date.now());
  const meta = parseClipboardBanMeta(data.clipboard_ban_reason || "");
  const timedBanActive = Boolean(data.clipboard_permanent_ban === true && meta.version === 1 && meta.banUntilMs && meta.banUntilMs > Date.now());
  const legacyPermanentBan = Boolean(data.clipboard_permanent_ban === true && meta.version !== 1);
  const permanentBan = legacyPermanentBan || timedBanActive;
  const banUntilMs = timedBanActive ? meta.banUntilMs : 0;
  const failedCount = Math.max(0, Number(meta.failedCount || 0));
  const banReason = permanentBan
    ? (timedBanActive
      ? getClipboardUnlockBanMessage(failedCount, banUntilMs, meta.reasonCode)
      : String(data.clipboard_ban_reason || "Fitur izin copy-paste diblokir permanen."))
    : String(data.clipboard_ban_reason || "");

  return {
    success: true,
    protectionEnabled: data.protection_enabled !== false,
    clipboardUnlocked,
    clipboardUnlockedUntil: clipboardUnlocked ? data.clipboard_unlocked_until : null,
    clipboardUnlockedUntilMs: clipboardUnlocked ? safeUnlockedUntilMs : 0,
    permanentBan,
    banReason,
    clipboardBanUntilMs: banUntilMs,
    lockUntilMs: banUntilMs,
    clipboardUnlockFailedCount: failedCount,
    updatedAt: data.updated_at || null
  };
}

async function ensureClipboardSecurityRow() {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from(CLIPBOARD_SECURITY_TABLE)
    .select("*")
    .eq("id", "global")
    .maybeSingle();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  if (data) return clearExpiredClipboardTimedBan(data);

  const { data: inserted, error: insertError } = await supabase
    .from(CLIPBOARD_SECURITY_TABLE)
    .insert({
      id: "global",
      protection_enabled: true,
      clipboard_unlocked_until: null,
      clipboard_permanent_ban: false
    })
    .select("*")
    .single();

  if (insertError) {
    insertError.statusCode = insertError.status || 500;
    throw insertError;
  }

  return inserted;
}

async function checkClipboardSecurityStatus(req, res) {
  const { idToken, clientContext } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);

  try {
    const row = await ensureClipboardSecurityRow();
    const status = normalizeClipboardSecurityStatus(row);
    const db = getFirebaseDb();
    const trustedState = await getCurrentTrustedDeviceState({
      db,
      decoded,
      clientContext,
      secret: getA2fSecret()
    }).catch(() => ({ trusted: false }));
    return res.status(200).json(applyTrustedClipboardBypass(status, trustedState));
  } catch (error) {
    console.error("checkClipboardSecurityStatus error:", error);
    return res.status(500).json({
      success: false,
      protectionEnabled: true,
      clipboardUnlocked: false,
      clipboardUnlockedUntil: null,
      clipboardUnlockedUntilMs: 0,
      permanentBan: false,
      banReason: "",
      error: "Gagal membaca status proteksi. Default aman: ON."
    });
  }
}


async function startClipboardUnlockOtp(req, res) {
  await checkA2fLock();

  const { idToken, clientContext } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);
  const row = await ensureClipboardSecurityRow();
  const status = normalizeClipboardSecurityStatus(row);
  const trustedState = await getCurrentTrustedDeviceState({
    db: getFirebaseDb(),
    decoded,
    clientContext,
    secret: getA2fSecret()
  }).catch(() => ({ trusted: false }));
  const trustedBypassStatus = applyTrustedClipboardBypass(status, trustedState);
  if (trustedBypassStatus.trustedDeviceBypass === true) {
    await writeBackendSecurityLog("clipboard.trusted_bypass", "Verifikasi copy-paste dilewati karena perangkat terpercaya.", "good", decoded, { deviceIdHashShort: trustedState.deviceIdHashShort || "" });
    return res.status(200).json(trustedBypassStatus);
  }

  if (status.permanentBan) {
    return res.status(403).json({
      ...status,
      success: false,
      permanentBan: true,
      error: status.banReason || "Fitur izin copy-paste sedang diblokir dari backend Supabase."
    });
  }

  const now = Date.now();
  const expiresAtMs = now + CLIPBOARD_OTP_TTL_MS;
  const code = randomClipboardOtp();
  const otpHash = await hashClipboardOtpCode(code);
  const supabase = getSupabaseAdmin();

  const { data, error } = await supabase
    .from(CLIPBOARD_OTP_CHALLENGES_TABLE)
    .insert({
      purpose: CLIPBOARD_UNLOCK_PURPOSE,
      uid: decoded.uid,
      email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      otp_hash: otpHash,
      otp_hash_algorithm: "argon2id",
      expires_at: new Date(expiresAtMs).toISOString(),
      failed_count: 0,
      permanently_failed: false
    })
    .select("id, expires_at")
    .single();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  await sendClipboardUnlockEmail({
    code,
    email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
    expiresAtMs
  });

  return res.status(200).json({
    success: true,
    challengeId: data.id,
    expiresAt: data.expires_at,
    expiresAtMs,
    message: "Kode SMTP untuk izin copy-paste 5 menit sudah dikirim. Kode SMTP expired dalam 90 detik."
  });
}

async function banClipboardUnlockForWrongCode({ uid, email, reasonCode, challengeId, currentRow }) {
  const supabase = getSupabaseAdmin();
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const previousFailedCount = getClipboardUnlockFailureCountFromRow(currentRow);
  const failedCount = previousFailedCount + 1;
  const banUntilMs = now + getClipboardUnlockBanDurationMs(failedCount);
  const reason = buildClipboardBanMeta({
    active: true,
    failedCount,
    banUntilMs,
    reasonCode: reasonCode || "clipboard_unlock_wrong_code"
  });

  if (challengeId) {
    await supabase
      .from(CLIPBOARD_OTP_CHALLENGES_TABLE)
      .update({
        failed_count: failedCount,
        permanently_failed: true,
        failed_reason: reasonCode || "clipboard_unlock_wrong_code",
        updated_at: nowIso
      })
      .eq("id", String(challengeId));
  }

  const { data, error } = await supabase
    .from(CLIPBOARD_SECURITY_TABLE)
    .upsert({
      id: "global",
      protection_enabled: true,
      clipboard_unlocked_until: null,
      clipboard_permanent_ban: true,
      clipboard_ban_reason: reason,
      updated_by_uid: uid || "",
      updated_by_email: email || "",
      updated_at: nowIso
    }, { onConflict: "id" })
    .select("*")
    .single();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  return data;
}

async function verifyClipboardUnlockOtp(req, res) {
  await checkA2fLock();

  const { idToken, challengeId, smtpCode, totpCode } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);
  const currentRow = await ensureClipboardSecurityRow();
  const currentStatus = normalizeClipboardSecurityStatus(currentRow);

  if (currentStatus.permanentBan) {
    return res.status(403).json({
      ...currentStatus,
      success: false,
      permanentBan: true,
      error: currentStatus.banReason || "Fitur izin copy-paste sedang diblokir dari backend Supabase."
    });
  }

  if (!verifyRecoveryTotp(totpCode)) {
    const bannedRow = await banClipboardUnlockForWrongCode({
      uid: decoded.uid,
      email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      reasonCode: "clipboard_unlock_totp_wrong",
      challengeId: String(challengeId || ""),
      currentRow
    });
    const bannedStatus = normalizeClipboardSecurityStatus(bannedRow);

    return res.status(403).json({
      ...bannedStatus,
      success: false,
      permanentBan: true,
      error: bannedStatus.banReason || "Kode Authenticator salah. Fitur izin copy-paste diblokir lewat backend Supabase."
    });
  }

  const supabase = getSupabaseAdmin();
  const { data: challenge, error } = await supabase
    .from(CLIPBOARD_OTP_CHALLENGES_TABLE)
    .select("*")
    .eq("id", String(challengeId || ""))
    .eq("uid", decoded.uid)
    .eq("purpose", CLIPBOARD_UNLOCK_PURPOSE)
    .is("used_at", null)
    .maybeSingle();

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }

  if (!challenge) {
    return res.status(404).json({
      success: false,
      error: "Request SMTP OTP tidak ditemukan atau sudah dipakai."
    });
  }

  if (challenge.permanently_failed === true) {
    return res.status(403).json({
      success: false,
      permanentBan: true,
      error: "Request ini sudah gagal dan sudah dicatat backend Supabase."
    });
  }

  if (Date.parse(challenge.expires_at) <= Date.now()) {
    return res.status(408).json({
      success: false,
      error: "Kode SMTP OTP sudah expired. Minta kode baru."
    });
  }

  const otpOk = await verifyClipboardOtpCode(smtpCode, challenge.otp_hash);

  if (!otpOk) {
    const bannedRow = await banClipboardUnlockForWrongCode({
      uid: decoded.uid,
      email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      reasonCode: "clipboard_unlock_smtp_wrong",
      challengeId: challenge.id,
      currentRow
    });
    const bannedStatus = normalizeClipboardSecurityStatus(bannedRow);

    return res.status(403).json({
      ...bannedStatus,
      success: false,
      permanentBan: true,
      error: bannedStatus.banReason || "Kode SMTP salah. Fitur izin copy-paste diblokir lewat backend Supabase."
    });
  }

  const nowIso = new Date().toISOString();
  const unlockedUntilMs = Date.now() + CLIPBOARD_UNLOCK_MS;
  const unlockedUntilIso = new Date(unlockedUntilMs).toISOString();
  const historyCount = getClipboardUnlockFailureCountFromRow(currentRow);

  await supabase
    .from(CLIPBOARD_OTP_CHALLENGES_TABLE)
    .update({
      used_at: nowIso,
      updated_at: nowIso
    })
    .eq("id", challenge.id);

  const { data: updatedRow, error: updateError } = await supabase
    .from(CLIPBOARD_SECURITY_TABLE)
    .upsert({
      id: "global",
      protection_enabled: true,
      clipboard_unlocked_until: unlockedUntilIso,
      clipboard_permanent_ban: false,
      clipboard_ban_reason: historyCount > 0 ? buildClipboardBanMeta({
        active: false,
        failedCount: historyCount,
        banUntilMs: 0,
        reasonCode: "clipboard_unlock_success_after_previous_failure"
      }) : null,
      updated_by_uid: decoded.uid,
      updated_by_email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      updated_at: nowIso
    }, { onConflict: "id" })
    .select("*")
    .single();

  if (updateError) {
    updateError.statusCode = updateError.status || 500;
    throw updateError;
  }

  return res.status(200).json({
    ...normalizeClipboardSecurityStatus(updatedRow),
    success: true,
    message: "Copy-paste diizinkan selama maksimal 5 menit.",
    clipboardUnlockedUntil: unlockedUntilIso,
    clipboardUnlockedUntilMs: unlockedUntilMs
  });
}



/* =========================================================
   Dirac customer login MFA API bridge for masuk.html
   Additive only: does not alter legacy admin A2F step/hash/login flow.
   Supported frontend payload:
   - POST /api/2fa/verify-step { action:"verify", method:"passkey"|"email"|"authenticator", identifier/email, code/setupToken/credential }
   ========================================================= */
const DIRAC_CUSTOMER_MFA_TOKEN_TYPE = "dirac-customer-login-mfa-v1";
const DIRAC_CUSTOMER_MFA_RECOVERY_COUNT = Number(process.env.DIRAC_CUSTOMER_MFA_RECOVERY_COUNT || 8);
const DIRAC_CUSTOMER_MFA_RECOVERY_COLLECTION = process.env.DIRAC_CUSTOMER_MFA_RECOVERY_COLLECTION || "diracCustomerMfaProfiles";
const DIRAC_CUSTOMER_MFA_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const DIRAC_CUSTOMER_MFA_COOKIE = process.env.DIRAC_CUSTOMER_MFA_COOKIE || "dirac_customer_mfa_session";
// PATCH 3C: customer dashboard MFA proof is stored only as HttpOnly Secure cookie. No frontend proof token is returned.
const DIRAC_CUSTOMER_MFA_SESSION_TYPE = "dirac-customer-mfa-session-v1";
const DIRAC_CUSTOMER_MFA_DASHBOARD_TTL_MS = Number(process.env.DIRAC_CUSTOMER_MFA_DASHBOARD_TTL_MS || 6 * 60 * 60 * 1000);
const DIRAC_PASSWORD_RESET_TOKEN_TYPE = "dirac-password-reset-v1";
const DIRAC_PASSWORD_RESET_CODE_DIGITS = 8;
const DIRAC_CUSTOMER_MFA_ATTEMPT_COLLECTION = process.env.DIRAC_CUSTOMER_MFA_ATTEMPT_COLLECTION || "diracCustomerMfaVerifyAttempts";
const DIRAC_CUSTOMER_MFA_MAX_FAILED = Math.max(3, Number(process.env.DIRAC_CUSTOMER_MFA_MAX_FAILED || 5));
const DIRAC_CUSTOMER_MFA_LOCK_MS = Math.max(60 * 1000, Number(process.env.DIRAC_CUSTOMER_MFA_LOCK_MS || 10 * 60 * 1000));
const DIRAC_PASSWORD_RESET_CHALLENGE_COLLECTION = process.env.DIRAC_PASSWORD_RESET_CHALLENGE_COLLECTION || "diracPasswordResetChallenges";
const DIRAC_PASSWORD_RESET_MAX_FAILED = Math.max(3, Number(process.env.DIRAC_PASSWORD_RESET_MAX_FAILED || 5));
const DIRAC_PASSWORD_RESET_LOCK_MS = Math.max(5 * 60 * 1000, Number(process.env.DIRAC_PASSWORD_RESET_LOCK_MS || 60 * 60 * 1000));

function diracGetCustomerMfaSecret() {
  const secret = String(process.env.DIRAC_MFA_SECRET || process.env.A2F_SECRET || "").trim();

  if (!secret) {
    const err = new Error("DIRAC_MFA_SECRET atau A2F_SECRET belum diset di Environment Variables backend.");
    err.statusCode = 500;
    throw err;
  }

  if (secret === "rahasia-test" || secret.length < 32) {
    const err = new Error("Secret MFA production belum aman. Gunakan DIRAC_MFA_SECRET minimal 32 karakter acak.");
    err.statusCode = 500;
    throw err;
  }

  return secret;
}

function diracNormalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function diracAssertEmail(value) {
  const email = diracNormalizeEmail(value);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    const err = new Error("Email akun wajib valid.");
    err.statusCode = 400;
    throw err;
  }
  return email;
}

function diracNormalizeMfaMethod(value) {
  const method = String(value || "").trim().toLowerCase();
  if (method === "authen" || method === "totp" || method === "authenticator") return "authenticator";
  if (method === "mail" || method === "otp-email" || method === "email") return "email";
  if (method === "paskey" || method === "pass-key" || method === "webauthn" || method === "passkey") return "passkey";
  const err = new Error("Metode A2F harus passkey, email, atau authenticator.");
  err.statusCode = 400;
  throw err;
}

function diracHashCustomerMfaCode({ method, email, code, nonce }) {
  return hashCode([
    "dirac-customer-login-mfa-code-v1",
    String(method || ""),
    diracNormalizeEmail(email),
    String(nonce || ""),
    String(code || "")
  ].join(":"), diracGetCustomerMfaSecret());
}

function diracDecodeCustomerMfaToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2) {
    const err = new Error("Token A2F tidak valid. Minta kode/challenge baru.");
    err.statusCode = 400;
    throw err;
  }

  const payloadBase64 = parts[0];
  const signature = parts[1];
  const expectedSignature = sign(payloadBase64, diracGetCustomerMfaSecret());

  if (!safeEqual(signature, expectedSignature)) {
    const err = new Error("Token A2F tidak valid atau sudah dimodifikasi.");
    err.statusCode = 401;
    throw err;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
  } catch (_error) {
    const err = new Error("Data token A2F rusak. Minta kode/challenge baru.");
    err.statusCode = 400;
    throw err;
  }

  if (!payload || payload.tokenType !== DIRAC_CUSTOMER_MFA_TOKEN_TYPE) {
    const err = new Error("Token A2F bukan untuk login pelanggan.");
    err.statusCode = 400;
    throw err;
  }

  if (!payload.expiresAtMs || Date.now() > Number(payload.expiresAtMs)) {
    const err = new Error("Kode/challenge A2F sudah expired. Kirim ulang kode.");
    err.statusCode = 410;
    throw err;
  }

  return payload;
}


/* =========================================================
   PATCH 3F - Customer MFA verify must be bound to backend login cookie.
   The frontend setup token/code is not trusted by itself. Verification only
   succeeds when the current HttpOnly login cookie belongs to the same user
   that started the A2F challenge.
   ========================================================= */
const DIRAC_DOMAIN_ACCESS_COOKIE = process.env.DOMAIN_SESSION_COOKIE || "dirac_domain_session";
const DIRAC_DOMAIN_REFRESH_COOKIE = process.env.DOMAIN_REFRESH_COOKIE || "dirac_domain_refresh";

function diracParseRequestCookies(req) {
  const header = String((req && req.headers && (req.headers.cookie || req.headers.Cookie)) || "");
  const cookies = {};
  header.split(";").map((item) => item.trim()).filter(Boolean).forEach((item) => {
    const index = item.indexOf("=");
    if (index < 0) {
      cookies[item] = "";
      return;
    }
    const key = item.slice(0, index);
    const rawValue = item.slice(index + 1);
    try {
      cookies[key] = decodeURIComponent(rawValue);
    } catch (_) {
      cookies[key] = rawValue;
    }
  });
  return cookies;
}

function diracDomainSupabaseUrl() {
  const url = String(
    process.env.DOMAIN_SUPABASE_URL ||
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    ""
  ).trim().replace(/\/$/, "");
  if (!url) {
    const err = new Error("ENV Supabase domain belum lengkap. Set DOMAIN_SUPABASE_URL/SUPABASE_URL.");
    err.statusCode = 500;
    throw err;
  }
  return url;
}

function diracDomainSupabaseAnonKey() {
  const key = String(
    process.env.DOMAIN_SUPABASE_ANON_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.DOMAIN_SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    ""
  ).trim();
  if (!key) {
    const err = new Error("ENV Supabase domain belum lengkap. Set DOMAIN_SUPABASE_ANON_KEY.");
    err.statusCode = 500;
    throw err;
  }
  return key;
}

async function diracFetchSupabaseAuth(path, options = {}) {
  const key = diracDomainSupabaseAnonKey();
  const headers = {
    apikey: key,
    Authorization: `Bearer ${options.bearer || key}`,
    "Content-Type": "application/json"
  };
  const fetchOptions = { method: options.method || "GET", headers };
  if (options.body !== undefined) fetchOptions.body = JSON.stringify(options.body);
  const response = await fetch(`${diracDomainSupabaseUrl()}${path}`, fetchOptions);
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
  return { ok: response.ok, status: response.status, data };
}

async function diracReadSupabaseUserFromAccessToken(accessToken) {
  const token = String(accessToken || "").trim();
  if (!token) return null;
  const result = await diracFetchSupabaseAuth("/auth/v1/user", { method: "GET", bearer: token });
  if (result.ok && result.data && result.data.id) return result.data;
  return null;
}

function diracNormalizeCookieDomain(value) {
  const clean = String(value || "").trim().toLowerCase().replace(/^\./, "");
  if (!clean || /^(none|false|off|host-only|host_only)$/i.test(clean)) return "";
  if (/^localhost$|^127\.|^0\.0\.0\.0$/.test(clean)) return "";
  return clean;
}

function diracDomainCookieCandidates() {
  const out = [];
  const add = (value) => {
    const domain = diracNormalizeCookieDomain(value);
    if (domain && !out.includes(domain)) out.push(domain);
  };
  add(process.env.DOMAIN_COOKIE_DOMAIN);
  add(process.env.DOMAIN_SITE_URL ? (() => { try { return new URL(process.env.DOMAIN_SITE_URL).hostname; } catch (_) { return ""; } })() : "");
  add(process.env.SITE_URL ? (() => { try { return new URL(process.env.SITE_URL).hostname; } catch (_) { return ""; } })() : "");
  add("diracgroup.store");
  return out;
}

function diracMakeDomainLoginCookie(name, value, options = {}) {
  const rawSameSite = String(process.env.DOMAIN_COOKIE_SAMESITE || "Lax").trim().toLowerCase();
  const sameSite = rawSameSite === "strict" ? "Strict" : rawSameSite === "none" ? "None" : "Lax";
  const parts = [
    `${name}=${encodeURIComponent(value || "")}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${sameSite}`
  ];
  if (sameSite.toLowerCase() === "none" || process.env.NODE_ENV !== "development") parts.push("Secure");
  parts.push("Priority=High");
  const cookieDomain = Object.prototype.hasOwnProperty.call(options, "domain") ? diracNormalizeCookieDomain(options.domain) : diracNormalizeCookieDomain(process.env.DOMAIN_COOKIE_DOMAIN || "");
  if (cookieDomain) parts.push(`Domain=${cookieDomain}`);
  if (options.maxAge !== undefined) {
    const maxAge = Number(options.maxAge) || 0;
    parts.push(`Max-Age=${maxAge}`);
    if (maxAge <= 0) parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  }
  return parts.join("; ");
}

function diracMakeDomainLoginCookieVariants(name, value, options = {}) {
  const cookies = [];
  const preferred = diracNormalizeCookieDomain(process.env.DOMAIN_COOKIE_DOMAIN || "");
  cookies.push(diracMakeDomainLoginCookie(name, value, Object.assign({}, options, { domain: preferred || "" })));
  diracDomainCookieCandidates().forEach((domain) => {
    if (domain !== preferred) cookies.push(diracMakeDomainLoginCookie(name, value, Object.assign({}, options, { domain })));
  });
  return cookies;
}

const DIRAC_DOMAIN_COOKIE_CHUNK_SIZE = 3400;
const DIRAC_DOMAIN_COOKIE_MAX_CHUNKS = 12;

function diracMakeClearDomainLoginTokenCookieChunks(name) {
  const cookies = [];
  const preferred = diracNormalizeCookieDomain(process.env.DOMAIN_COOKIE_DOMAIN || "");
  for (let index = 0; index < DIRAC_DOMAIN_COOKIE_MAX_CHUNKS; index += 1) {
    cookies.push(diracMakeDomainLoginCookie(`${name}__${index}`, "", { maxAge: 0, domain: preferred || "" }));
  }
  return cookies;
}

function diracMakeClearDomainLoginTokenCookieSet(name) {
  return [
    ...diracMakeDomainLoginCookieVariants(name, "", { maxAge: 0 }),
    ...diracMakeClearDomainLoginTokenCookieChunks(name)
  ];
}

function diracMakeDomainLoginTokenCookieSet(name, value, options = {}) {
  const token = String(value || "");
  const preferred = diracNormalizeCookieDomain(process.env.DOMAIN_COOKIE_DOMAIN || "");
  const cookies = [...diracMakeDomainLoginCookieVariants(name, "", { maxAge: 0 })];
  if (!token) return cookies;
  if (token.length <= DIRAC_DOMAIN_COOKIE_CHUNK_SIZE) {
    cookies.push(diracMakeDomainLoginCookie(name, token, Object.assign({}, options, { domain: preferred || "" })));
    return cookies;
  }
  cookies.push(...diracMakeClearDomainLoginTokenCookieChunks(name));
  const chunks = [];
  for (let index = 0; index < token.length; index += DIRAC_DOMAIN_COOKIE_CHUNK_SIZE) {
    chunks.push(token.slice(index, index + DIRAC_DOMAIN_COOKIE_CHUNK_SIZE));
  }
  if (chunks.length > DIRAC_DOMAIN_COOKIE_MAX_CHUNKS) return cookies;
  cookies.push(diracMakeDomainLoginCookie(name, `__chunked_${chunks.length}`, Object.assign({}, options, { domain: preferred || "" })));
  chunks.forEach((chunk, index) => {
    cookies.push(diracMakeDomainLoginCookie(`${name}__${index}`, chunk, Object.assign({}, options, { domain: preferred || "" })));
  });
  return cookies;
}

function diracReadDomainLoginCookieToken(cookies, name) {
  const jar = cookies && typeof cookies === "object" ? cookies : {};
  const marker = String(jar[name] || "");
  const chunkMatch = marker.match(/^__chunked_(\d+)$/);
  if (chunkMatch) {
    const count = Math.max(0, Math.min(DIRAC_DOMAIN_COOKIE_MAX_CHUNKS, Number(chunkMatch[1]) || 0));
    let token = "";
    for (let index = 0; index < count; index += 1) {
      const chunk = jar[`${name}__${index}`];
      if (!chunk) return "";
      token += String(chunk);
    }
    return token;
  }
  if (marker) return marker;
  if (jar[`${name}__0`]) {
    let token = "";
    for (let index = 0; index < DIRAC_DOMAIN_COOKIE_MAX_CHUNKS; index += 1) {
      const chunk = jar[`${name}__${index}`];
      if (!chunk) break;
      token += String(chunk);
    }
    return token;
  }
  return "";
}

function diracSetRefreshedDomainLoginCookies(res, session) {
  const data = session && typeof session === "object" ? session : {};
  if (!data.access_token || !data.refresh_token) return;
  const maxAge = 60 * 60 * 24 * 7;
  [
    ...diracMakeDomainLoginTokenCookieSet(DIRAC_DOMAIN_ACCESS_COOKIE, data.access_token, { maxAge }),
    ...diracMakeDomainLoginTokenCookieSet(DIRAC_DOMAIN_REFRESH_COOKIE, data.refresh_token, { maxAge })
  ].forEach((cookie) => diracAppendSetCookie(res, cookie));
}

async function diracRefreshDomainLoginSession(refreshToken, res) {
  const token = String(refreshToken || "").trim();
  if (!token) return null;
  const result = await diracFetchSupabaseAuth("/auth/v1/token?grant_type=refresh_token", {
    method: "POST",
    body: { refresh_token: token }
  });
  if (result.ok && result.data && result.data.access_token && result.data.user) {
    diracSetRefreshedDomainLoginCookies(res, result.data);
    return result.data.user;
  }
  return null;
}

function diracCustomerLoginUserIdHash(user) {
  const id = String((user && (user.id || user.sub || user.uid)) || "").trim();
  if (!id) return "";
  return hashCode(`dirac-customer-login-user-v1:${id}`, diracGetCustomerMfaSecret());
}

function diracRequestBaseUrl(req) {
  const headers = (req && req.headers) || {};
  const origin = String(headers.origin || '').trim();
  if (origin && /^https?:\/\//i.test(origin)) return origin.replace(/\/+$/, '');

  const host = String(headers['x-forwarded-host'] || headers.host || '').split(',')[0].trim();
  const proto = String(headers['x-forwarded-proto'] || '').split(',')[0].trim() || (host && !/^localhost(?::|$)|^127\./i.test(host) ? 'https' : 'http');
  if (host) return `${proto}://${host}`.replace(/\/+$/, '');

  const site = String(process.env.DOMAIN_SITE_URL || process.env.SITE_URL || 'https://diracgroup.store').trim();
  return site.replace(/\/+$/, '');
}

function diracUniqueBaseUrls(values) {
  const out = [];
  (Array.isArray(values) ? values : [values]).forEach((value) => {
    const raw = String(value || '').trim();
    if (!raw || !/^https?:\/\//i.test(raw)) return;
    const clean = raw.replace(/\/+$/, '');
    if (!out.includes(clean)) out.push(clean);
  });
  return out;
}

function diracDomainMeBaseUrlCandidates(req) {
  const headers = (req && req.headers) || {};
  const origin = String(headers.origin || '').trim();
  const host = String(headers['x-forwarded-host'] || headers.host || '').split(',')[0].trim();
  const proto = String(headers['x-forwarded-proto'] || '').split(',')[0].trim() || 'https';
  const site = String(process.env.DOMAIN_SITE_URL || process.env.SITE_URL || '').trim();
  return diracUniqueBaseUrls([
    diracRequestBaseUrl(req),
    origin,
    host ? `${proto}://${host}` : '',
    site,
    'https://diracgroup.store',
    'https://www.diracgroup.store'
  ]);
}

function diracAppendSetCookieFromHeader(res, setCookieValue) {
  const raw = String(setCookieValue || '').trim();
  if (!raw) return;
  if (/dirac_domain_session|dirac_domain_refresh|dirac_customer_mfa_session/i.test(raw)) {
    diracAppendSetCookieHeader(res, raw);
  }
}

function diracMaybeForwardDomainMeCookies(response, res) {
  if (!response || !response.headers || !res) return;
  try {
    if (typeof response.headers.getSetCookie === 'function') {
      response.headers.getSetCookie().forEach((item) => diracAppendSetCookieFromHeader(res, item));
      return;
    }
  } catch (_) {}
  try {
    const single = response.headers.get('set-cookie');
    if (single) diracAppendSetCookieFromHeader(res, single);
  } catch (_) {}
}

async function diracReadLoggedInCustomerViaHealth(req, res) {
  const headers = (req && req.headers) || {};
  const cookieHeader = String(headers.cookie || headers.Cookie || '').trim();
  if (!cookieHeader) return null;

  const bases = diracDomainMeBaseUrlCandidates(req);
  if (!bases.length) return null;

  for (const base of bases) {
    try {
      const response = await fetch(`${base}/api/health?action=domain_me`, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Cookie: cookieHeader,
          'User-Agent': String(headers['user-agent'] || headers['User-Agent'] || 'Dirac-A2F-Backend-Session-Check'),
          'X-Dirac-A2F-Session-Check': '1'
        }
      });
      diracMaybeForwardDomainMeCookies(response, res);
      const data = await response.json().catch(() => null);
      const user = data && data.ok !== false && data.user && typeof data.user === 'object' ? data.user : null;
      if (response.ok && user && user.id && diracNormalizeEmail(user.email)) return user;
    } catch (_) {
      // Coba kandidat base URL berikutnya. Tidak bocorkan detail internal ke user.
    }
  }
  return null;
}

async function diracRequireLoggedInCustomer(req, res) {
  const cookies = diracParseRequestCookies(req);
  const accessToken = String(diracReadDomainLoginCookieToken(cookies, DIRAC_DOMAIN_ACCESS_COOKIE) || '').trim();
  const refreshToken = String(diracReadDomainLoginCookieToken(cookies, DIRAC_DOMAIN_REFRESH_COOKIE) || '').trim();

  let user = await diracReadSupabaseUserFromAccessToken(accessToken);
  if (!user && refreshToken) user = await diracRefreshDomainLoginSession(refreshToken, res);

  // PATCH v4: health?action=domain_me sudah terbukti ok:true di browser.
  // Jika validasi lokal A2F gagal karena ENV/anon-key/cookie parser route berbeda,
  // pakai domain_me sebagai sumber kebenaran backend dengan Cookie header yang sama.
  if (!user || !user.id || !diracNormalizeEmail(user.email)) {
    user = await diracReadLoggedInCustomerViaHealth(req, res);
  }

  if (!user || !user.id || !diracNormalizeEmail(user.email)) {
    const err = new Error('Belum login atau sesi login backend sudah habis. Login ulang terlebih dahulu.');
    err.statusCode = 401;
    throw err;
  }

  return user;
}

async function diracAssertCustomerMfaRequestMatchesLogin(req, res) {
  const user = await diracRequireLoggedInCustomer(req, res);
  const loginEmail = diracAssertEmail(user.email || "");
  const requestedRaw = req && req.body ? (req.body.identifier || req.body.email || "") : "";
  const requestedEmail = diracNormalizeEmail(requestedRaw);

  if (requestedEmail && requestedEmail !== loginEmail) {
    const err = new Error("Email A2F tidak cocok dengan sesi login backend.");
    err.statusCode = 403;
    throw err;
  }

  const userIdHash = diracCustomerLoginUserIdHash(user);
  if (!userIdHash) {
    const err = new Error("Sesi login backend tidak valid untuk A2F.");
    err.statusCode = 401;
    throw err;
  }

  return { user, email: loginEmail, userIdHash };
}

function diracClientIpHash(req) {
  const headers = (req && req.headers) || {};
  const ip = String(headers["x-forwarded-for"] || headers["x-real-ip"] || "").split(",")[0].trim();
  return hashCode(`ip:${ip}`, diracGetCustomerMfaSecret());
}

function diracMfaAttemptDocId({ userIdHash, email, method }) {
  return hashCode([
    "dirac-customer-mfa-attempt-v1",
    String(userIdHash || ""),
    diracNormalizeEmail(email),
    String(method || "")
  ].join(":"), diracGetCustomerMfaSecret());
}

async function diracReadCustomerMfaAttempt({ login, method }) {
  const db = getFirebaseDb();
  const docId = diracMfaAttemptDocId({ userIdHash: login.userIdHash, email: login.email, method });
  const ref = db.collection(DIRAC_CUSTOMER_MFA_ATTEMPT_COLLECTION).doc(docId);
  const snap = await ref.get();
  return { ref, data: snap.exists ? (snap.data() || {}) : {} };
}

async function diracAssertCustomerMfaAttemptAllowed({ login, method }) {
  const { data } = await diracReadCustomerMfaAttempt({ login, method });
  const lockedUntilMs = Number(data.lockedUntilMs || 0);
  if (lockedUntilMs > Date.now()) {
    const err = new Error("Terlalu banyak kode A2F salah. Coba lagi setelah jeda keamanan selesai.");
    err.statusCode = 429;
    err.retryAfterSeconds = Math.max(1, Math.ceil((lockedUntilMs - Date.now()) / 1000));
    throw err;
  }
}

async function diracRecordCustomerMfaFailure({ req, login, method }) {
  const now = Date.now();
  const { ref, data } = await diracReadCustomerMfaAttempt({ login, method });
  const failedCount = Number(data.failedCount || 0) + 1;
  const lockedUntilMs = failedCount >= DIRAC_CUSTOMER_MFA_MAX_FAILED ? now + DIRAC_CUSTOMER_MFA_LOCK_MS : 0;
  const payload = {
    emailHash: diracMfaProfileId(login.email),
    userIdHash: String(login.userIdHash || ""),
    method: String(method || ""),
    failedCount,
    maxFailed: DIRAC_CUSTOMER_MFA_MAX_FAILED,
    lockedUntilMs,
    lastFailedAtMs: now,
    ipHash: diracClientIpHash(req),
    uaHash: diracMfaBindingHash("ua", diracRequestUserAgent(req)),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };
  await ref.set(payload, { merge: true });
  return {
    failedCount,
    attemptsRemaining: Math.max(0, DIRAC_CUSTOMER_MFA_MAX_FAILED - failedCount),
    lockedUntilMs,
    retryAfterSeconds: lockedUntilMs > now ? Math.max(1, Math.ceil((lockedUntilMs - now) / 1000)) : 0
  };
}

async function diracClearCustomerMfaFailures({ login, method }) {
  const { ref } = await diracReadCustomerMfaAttempt({ login, method });
  await ref.set({
    failedCount: 0,
    lockedUntilMs: 0,
    clearedAtMs: Date.now(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
}


function diracBase64UrlToBuffer(value) {
  let input = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  while (input.length % 4) input += "=";
  return Buffer.from(input, "base64");
}

function diracJsonFromBase64Url(value) {
  return JSON.parse(diracBase64UrlToBuffer(value).toString("utf8"));
}

function diracBufferToBase64Url(value) {
  return Buffer.from(value || Buffer.alloc(0)).toString("base64url");
}

function diracGenerateRecoveryCode() {
  let out = "";
  while (out.length < 12) {
    out += DIRAC_CUSTOMER_MFA_RECOVERY_ALPHABET[crypto.randomInt(0, DIRAC_CUSTOMER_MFA_RECOVERY_ALPHABET.length)];
  }
  return `${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}`;
}

function diracMfaProfileId(email) {
  return hashCode(`dirac-customer-mfa-profile-v1:${diracNormalizeEmail(email)}`, diracGetCustomerMfaSecret());
}

function diracAppendSetCookie(res, cookie) {
  const current = res.getHeader && res.getHeader("Set-Cookie");
  if (!current) return res.setHeader("Set-Cookie", cookie);
  const list = Array.isArray(current) ? current.slice() : [String(current)];
  list.push(cookie);
  return res.setHeader("Set-Cookie", list);
}

function diracMakeCookie(name, value, options = {}) {
  // PATCH 3D: default Lax lebih ketat dan lebih stabil untuk same-origin Safari/Chrome.
  // Env DIRAC_CUSTOMER_MFA_COOKIE_SAMESITE tetap bisa override jika benar-benar dibutuhkan.
  const sameSite = String(process.env.DIRAC_CUSTOMER_MFA_COOKIE_SAMESITE || "Lax").trim();
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${sameSite}`
  ];

  if (sameSite.toLowerCase() === "none" || process.env.NODE_ENV !== "development") parts.push("Secure");
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Number(options.maxAge) || 0}`);
  return parts.join("; ");
}

function diracMfaBindingHash(kind, value) {
  const text = String(value || "").trim();
  if (!text) return "";
  return hashCode(`dirac-customer-mfa-binding-v2:${kind}:${text}`, diracGetCustomerMfaSecret());
}

function diracNormalizeRequestOrigin(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    return new URL(raw).origin;
  } catch (_) {
    return raw.replace(/\/+$/, "");
  }
}

function diracRequestOrigin(req) {
  const headers = (req && req.headers) || {};
  return diracNormalizeRequestOrigin(headers.origin) || diracNormalizeRequestOrigin(headers.referer);
}

function diracRequestUserAgent(req) {
  return String((req && req.headers && req.headers["user-agent"]) || "").trim().slice(0, 512);
}

function diracMakeCustomerMfaDashboardToken({ email, method, req }) {
  const now = Date.now();
  const expiresAtMs = now + DIRAC_CUSTOMER_MFA_DASHBOARD_TTL_MS;
  const origin = diracRequestOrigin(req);
  const userAgent = diracRequestUserAgent(req);
  const payload = {
    type: DIRAC_CUSTOMER_MFA_SESSION_TYPE,
    emailHash: diracMfaProfileId(email),
    method: String(method || ""),
    verifiedAtMs: now,
    expiresAtMs,
    nonce: randomId(18),
    bindingVersion: 2,
    originHash: diracMfaBindingHash("origin", origin),
    uaHash: diracMfaBindingHash("ua", userAgent)
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return {
    token: `${payloadBase64}.${sign(payloadBase64, diracGetCustomerMfaSecret())}`,
    verifiedAtMs: now,
    expiresAtMs,
    bindingVersion: 2
  };
}

function diracSetCustomerMfaDashboardCookie(req, res, { email, method }) {
  const session = diracMakeCustomerMfaDashboardToken({ email, method, req });
  const maxAge = Math.max(1, Math.floor((session.expiresAtMs - Date.now()) / 1000));
  diracAppendSetCookie(res, diracMakeCookie(DIRAC_CUSTOMER_MFA_COOKIE, session.token, { maxAge }));
  return session;
}

function diracTotpEncryptionKey() {
  return crypto.createHash("sha256").update(`dirac-customer-totp-secret-v1:${diracGetCustomerMfaSecret()}`).digest();
}

function diracEncryptTotpSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", diracTotpEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(secret || ""), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: "aes-256-gcm",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    data: encrypted.toString("base64url")
  };
}

function diracDecryptTotpSecret(payload) {
  const row = payload && typeof payload === "object" ? payload : {};
  if (row.v !== 1 || row.alg !== "aes-256-gcm" || !row.iv || !row.tag || !row.data) {
    const err = new Error("Authenticator belum tersimpan aman untuk akun ini. Setup ulang setelah email OTP.");
    err.statusCode = 409;
    throw err;
  }
  const decipher = crypto.createDecipheriv("aes-256-gcm", diracTotpEncryptionKey(), Buffer.from(String(row.iv), "base64url"));
  decipher.setAuthTag(Buffer.from(String(row.tag), "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(String(row.data), "base64url")),
    decipher.final()
  ]).toString("utf8");
}

async function diracReadCustomerMfaProfile(email) {
  const db = getFirebaseDb();
  const snap = await db.collection(DIRAC_CUSTOMER_MFA_RECOVERY_COLLECTION).doc(diracMfaProfileId(email)).get();
  if (!snap.exists) return null;
  return { id: snap.id, ...(snap.data() || {}) };
}

async function diracGetStoredTotpSecret(email) {
  const profile = await diracReadCustomerMfaProfile(email);
  if (!profile || profile.enabled !== true || !profile.totpSecretEncrypted) {
    const err = new Error("Authenticator belum terdaftar untuk akun ini. Verifikasi email OTP dulu untuk setup Authenticator.");
    err.statusCode = 409;
    throw err;
  }
  return diracDecryptTotpSecret(profile.totpSecretEncrypted);
}


async function diracPersistVerifiedCustomerMfa({ email, method, credential, passkeyRegistrationInfo, passkeyAuthenticationInfo, totpSecret }) {
  const db = getFirebaseDb();
  const profileRef = db.collection(DIRAC_CUSTOMER_MFA_RECOVERY_COLLECTION).doc(diracMfaProfileId(email));
  const now = Date.now();
  const payload = {
    emailHash: diracMfaProfileId(email),
    method,
    enabled: true,
    verifiedAtMs: now,
    verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
    recoveryCodeCount: 0,
    recoveryCodeHashes: [],
    recoveryHashType: "disabled-for-customer-login",
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };

  if (method === "passkey" && passkeyRegistrationInfo) {
    const info = passkeyRegistrationInfo || {};
    const savedCredential = info.credential || {};
    const credentialId = String(savedCredential.id || (credential && (credential.id || credential.rawId)) || info.credentialID || "").trim();
    const publicKey = savedCredential.publicKey || info.credentialPublicKey;
    if (!credentialId || !publicKey) {
      const err = new Error("Registrasi passkey belum menghasilkan credential yang bisa disimpan.");
      err.statusCode = 500;
      throw err;
    }
    payload.passkeyCredentialId = credentialId;
    payload.passkeyPublicKey = diracBufferToBase64Url(publicKey);
    payload.passkeyCounter = Number(savedCredential.counter ?? info.counter ?? 0);
    payload.passkeyTransports = credential && credential.response && Array.isArray(credential.response.transports) ? credential.response.transports : [];
    payload.passkeyDeviceType = String(info.credentialDeviceType || "");
    payload.passkeyBackedUp = info.credentialBackedUp === true;
    payload.passkeyRegisteredAtMs = now;
  }

  if (method === "passkey" && passkeyAuthenticationInfo) {
    const info = passkeyAuthenticationInfo || {};
    if (Number.isFinite(Number(info.newCounter))) payload.passkeyCounter = Number(info.newCounter);
    payload.passkeyLastAuthenticatedAtMs = now;
  }

  if (method === "authenticator" && totpSecret) {
    payload.totpSecretEncrypted = diracEncryptTotpSecret(totpSecret);
    payload.totpSecretVersion = 1;
    payload.totpRegisteredAtMs = now;
  }

  await profileRef.set(payload, { merge: true });
  return [];
}

function diracVerifyTotpCode(secret, inputCode) {
  const code = String(inputCode || "").replace(/\D+/g, "");
  if (!/^\d{6}$/.test(code)) return false;
  const validCodes = [generateTotp(secret, -1), generateTotp(secret, 0), generateTotp(secret, 1)];
  return validCodes.some((validCode) => safeEqual(validCode, code));
}

function diracAllowedOriginsFromPayload(payload) {
  const fromPayload = Array.isArray(payload && payload.allowedOrigins) ? payload.allowedOrigins : [];
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const defaults = ["https://diracgroup.store", "https://www.diracgroup.store", "https://companyprofilee-expk.vercel.app"];
  return Array.from(new Set([...fromPayload, ...fromEnv, ...defaults].filter(Boolean)));
}

async function diracVerifyPasskeyCredential({ payload, credential, email }) {
  const item = credential && typeof credential === "object" ? credential : null;
  if (!item || item.type !== "public-key" || !item.id || !item.response || !item.response.clientDataJSON) {
    const err = new Error("Data passkey dari browser tidak lengkap.");
    err.statusCode = 400;
    throw err;
  }

  const rpID = String(payload.rpId || process.env.WEBAUTHN_RP_ID || "diracgroup.store").trim();
  const expectedOrigin = diracAllowedOriginsFromPayload(payload);
  const purpose = String(payload.purpose || "");

  if (purpose === "passkey-authentication-login-mfa") {
    const db = getFirebaseDb();
    const snap = await db.collection(DIRAC_CUSTOMER_MFA_RECOVERY_COLLECTION).doc(diracMfaProfileId(email)).get();
    const profile = snap.exists ? (snap.data() || {}) : null;
    const credentialId = String(profile && profile.passkeyCredentialId || "").trim();
    const publicKey = String(profile && profile.passkeyPublicKey || "").trim();

    if (!profile || profile.enabled !== true || !credentialId || !publicKey) {
      const err = new Error("Passkey belum tersimpan untuk akun ini. Daftarkan passkey terlebih dahulu.");
      err.statusCode = 404;
      throw err;
    }

    const verification = await verifyAuthenticationResponse({
      response: item,
      expectedChallenge: String(payload.challenge || ""),
      expectedOrigin,
      expectedRPID: rpID,
      credential: {
        id: credentialId,
        publicKey: Buffer.from(publicKey, "base64url"),
        counter: Number(profile.passkeyCounter || 0),
        transports: Array.isArray(profile.passkeyTransports) ? profile.passkeyTransports : []
      }
    });

    return {
      verified: verification.verified === true,
      mode: "authentication",
      authenticationInfo: verification.authenticationInfo || null
    };
  }

  const verification = await verifyRegistrationResponse({
    response: item,
    expectedChallenge: String(payload.challenge || ""),
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false
  });

  return {
    verified: verification.verified === true,
    mode: "registration",
    registrationInfo: verification.registrationInfo || null
  };
}

function diracHashPasswordResetCode({ email, userId, code, nonce }) {
  return hashCode([
    "dirac-password-reset-code-v1",
    diracNormalizeEmail(email),
    String(userId || ""),
    String(nonce || ""),
    String(code || "")
  ].join(":"), diracGetCustomerMfaSecret());
}

function diracDecodePasswordResetToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2) {
    const err = new Error("Token reset tidak valid. Kirim kode reset lagi.");
    err.statusCode = 400;
    throw err;
  }

  const payloadBase64 = parts[0];
  const signature = parts[1];
  const expectedSignature = sign(payloadBase64, diracGetCustomerMfaSecret());

  if (!safeEqual(signature, expectedSignature)) {
    const err = new Error("Token reset tidak valid atau sudah dimodifikasi.");
    err.statusCode = 401;
    throw err;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
  } catch (_error) {
    const err = new Error("Data token reset rusak. Kirim kode reset lagi.");
    err.statusCode = 400;
    throw err;
  }

  if (!payload || payload.tokenType !== DIRAC_PASSWORD_RESET_TOKEN_TYPE || payload.purpose !== "password-reset") {
    const err = new Error("Token reset bukan untuk reset password.");
    err.statusCode = 400;
    throw err;
  }

  if (!payload.expiresAtMs || Date.now() > Number(payload.expiresAtMs)) {
    const err = new Error("Kode reset sudah expired. Kirim kode reset lagi.");
    err.statusCode = 410;
    throw err;
  }

  return payload;
}


function diracPasswordResetUserIdHash(userId) {
  return hashCode(`dirac-password-reset-user-v1:${String(userId || "")}`, diracGetCustomerMfaSecret());
}

async function diracReadPasswordResetChallenge(challengeId) {
  const id = String(challengeId || "").trim();
  if (!id) {
    const err = new Error("Challenge reset tidak ada. Kirim kode reset lagi.");
    err.statusCode = 400;
    throw err;
  }
  const db = getFirebaseDb();
  const ref = db.collection(DIRAC_PASSWORD_RESET_CHALLENGE_COLLECTION).doc(id);
  const snap = await ref.get();
  if (!snap.exists) {
    const err = new Error("Challenge reset tidak ditemukan atau sudah hangus. Kirim kode reset lagi.");
    err.statusCode = 410;
    throw err;
  }
  return { ref, data: snap.data() || {} };
}

async function diracAssertPasswordResetChallengeReady({ payload, email }) {
  const { ref, data } = await diracReadPasswordResetChallenge(payload.challengeId);
  const now = Date.now();
  if (data.usedAtMs) {
    const err = new Error("Kode reset sudah dipakai. Kirim kode reset baru.");
    err.statusCode = 410;
    throw err;
  }
  if (Number(data.expiresAtMs || 0) <= now || Number(payload.expiresAtMs || 0) <= now) {
    const err = new Error("Kode reset sudah expired. Kirim kode reset lagi.");
    err.statusCode = 410;
    throw err;
  }
  if (Number(data.lockedUntilMs || 0) > now) {
    const err = new Error("Reset password terkunci sementara karena kode salah berulang.");
    err.statusCode = 429;
    err.retryAfterSeconds = Math.max(1, Math.ceil((Number(data.lockedUntilMs || 0) - now) / 1000));
    throw err;
  }
  if (!safeEqual(String(data.emailHash || ""), diracMfaProfileId(email))) {
    const err = new Error("Challenge reset tidak sesuai dengan email akun.");
    err.statusCode = 403;
    throw err;
  }
  if (!safeEqual(String(data.userIdHash || ""), diracPasswordResetUserIdHash(payload.userId))) {
    const err = new Error("Challenge reset tidak sesuai dengan user akun.");
    err.statusCode = 403;
    throw err;
  }
  return { ref, data };
}

async function diracRecordPasswordResetFailure(ref, data) {
  const now = Date.now();
  const attempts = Number(data.attempts || 0) + 1;
  const lockedUntilMs = attempts >= DIRAC_PASSWORD_RESET_MAX_FAILED ? now + DIRAC_PASSWORD_RESET_LOCK_MS : 0;
  await ref.set({
    attempts,
    maxAttempts: DIRAC_PASSWORD_RESET_MAX_FAILED,
    lockedUntilMs,
    lastFailedAtMs: now,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
  const err = new Error(lockedUntilMs ? "Kode reset salah berulang. Reset password terkunci sementara." : "Kode reset salah.");
  err.statusCode = lockedUntilMs ? 429 : 401;
  err.retryAfterSeconds = lockedUntilMs ? Math.max(1, Math.ceil((lockedUntilMs - now) / 1000)) : 0;
  throw err;
}

function diracValidateNewPassword(password, email) {
  const pass = String(password || "");
  const normalizedEmail = diracNormalizeEmail(email);
  const local = String(normalizedEmail.split("@")[0] || "").toLowerCase();

  if (pass.length < 12) {
    const err = new Error("Password baru minimal 12 karakter.");
    err.statusCode = 400;
    throw err;
  }

  if (!/[a-z]/.test(pass) || !/[A-Z]/.test(pass) || !/\d/.test(pass) || !/[^A-Za-z0-9]/.test(pass)) {
    const err = new Error("Password baru wajib berisi huruf besar, huruf kecil, angka, dan simbol.");
    err.statusCode = 400;
    throw err;
  }

  if (/password|qwerty|123456|dirac|admin|welcome/i.test(pass)) {
    const err = new Error("Password baru terlalu mudah ditebak.");
    err.statusCode = 400;
    throw err;
  }

  if (local.length >= 3 && pass.toLowerCase().includes(local)) {
    const err = new Error("Password baru tidak boleh mengandung nama/email akun.");
    err.statusCode = 400;
    throw err;
  }

  return pass;
}

async function diracHandleConfirmPasswordReset(req, res) {
  try {
    const email = diracAssertEmail((req.body && (req.body.email || req.body.identifier)) || "");
    const code = String((req.body && req.body.code) || "").replace(/\D+/g, "");
    const resetToken = String((req.body && (req.body.resetToken || req.body.token)) || "").trim();
    const newPassword = String((req.body && req.body.newPassword) || "");
    const confirmPassword = String((req.body && req.body.confirmPassword) || "");

    if (!/^\d{8}$/.test(code)) {
      const err = new Error("Kode reset harus 8 digit.");
      err.statusCode = 400;
      throw err;
    }

    if (!resetToken) {
      const err = new Error("Token reset belum ada. Kirim kode reset lagi.");
      err.statusCode = 400;
      throw err;
    }

    if (newPassword !== confirmPassword) {
      const err = new Error("Konfirmasi password baru belum sama.");
      err.statusCode = 400;
      throw err;
    }

    diracValidateNewPassword(newPassword, email);

    const payload = diracDecodePasswordResetToken(resetToken);
    if (diracNormalizeEmail(payload.email) !== email || !payload.userId) {
      const err = new Error("Token reset tidak sesuai dengan email akun.");
      err.statusCode = 400;
      throw err;
    }

    if (!payload.challengeId) {
      const err = new Error("Token reset lama tidak lagi diterima. Kirim kode reset baru.");
      err.statusCode = 410;
      throw err;
    }

    const challenge = await diracAssertPasswordResetChallengeReady({ payload, email });
    const expectedHash = diracHashPasswordResetCode({
      email,
      userId: payload.userId,
      code,
      nonce: challenge.data.nonce || payload.nonce
    });

    if (!safeEqual(expectedHash, String(challenge.data.codeHash || ""))) {
      await diracRecordPasswordResetFailure(challenge.ref, challenge.data);
    }

    await challenge.ref.set({
      usedAtMs: Date.now(),
      attempts: Number(challenge.data.attempts || 0),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    const supabase = getDomainSupabaseAdmin();
    const { data, error } = await supabase.auth.admin.updateUserById(String(payload.userId), {
      password: newPassword
    });

    if (error) {
      error.statusCode = error.status || 500;
      throw error;
    }

    return res.status(200).json({
      ok: true,
      success: true,
      updated: true,
      provider: "supabase",
      user: data && data.user ? { id: data.user.id, email: data.user.email } : null,
      message: "Password berhasil diganti. Silakan login memakai password baru."
    });
  } catch (error) {
    if (error && error.retryAfterSeconds) res.setHeader("Retry-After", String(error.retryAfterSeconds));
    return res.status(error.statusCode || error.status || 500).json({
      ok: false,
      success: false,
      updated: false,
      provider: "supabase",
      retryAfterSeconds: error && error.retryAfterSeconds ? error.retryAfterSeconds : 0,
      error: error.message || "Reset password gagal."
    });
  }
}

async function diracHandleCustomerMfaVerify(req, res) {
  try {
    const method = diracNormalizeMfaMethod(req.body && req.body.method);
    const login = await diracAssertCustomerMfaRequestMatchesLogin(req, res);
    const email = login.email;
    const setupToken = String((req.body && (req.body.setupToken || req.body.mfaSetupToken || req.body.token)) || "").trim();
    const payload = diracDecodeCustomerMfaToken(setupToken);

    if (!payload.userIdHash || !safeEqual(String(payload.userIdHash || ""), String(login.userIdHash || ""))) {
      return res.status(401).json({
        ok: false,
        success: false,
        verified: false,
        error: "Token A2F tidak cocok dengan sesi login backend. Kirim ulang kode dari halaman masuk."
      });
    }

    if (payload.method !== method || diracNormalizeEmail(payload.email) !== email) {
      return res.status(400).json({
        ok: false,
        success: false,
        verified: false,
        error: "Token A2F tidak sesuai dengan email/metode login."
      });
    }

    await diracAssertCustomerMfaAttemptAllowed({ login, method });

    let verified = false;
    let credential = null;
    let verifiedTotpSecret = "";

    if (method === "email") {
      const code = String((req.body && req.body.code) || "").replace(/\D+/g, "");
      verified = /^\d{6}$/.test(code) && safeEqual(
        diracHashCustomerMfaCode({ method, email, code, nonce: payload.nonce }),
        String(payload.codeHash || "")
      );
    } else if (method === "authenticator") {
      if (payload.purpose === "authenticator-authentication-login-mfa") {
        verifiedTotpSecret = await diracGetStoredTotpSecret(email);
      } else if (payload.purpose === "authenticator-setup-login-mfa" && payload.totpSecret) {
        verifiedTotpSecret = String(payload.totpSecret || "");
      } else {
        const err = new Error("Token Authenticator tidak valid. Mulai ulang verifikasi A2F.");
        err.statusCode = 400;
        throw err;
      }
      verified = diracVerifyTotpCode(verifiedTotpSecret, req.body && req.body.code);
    } else {
      credential = req.body && req.body.credential;
      const passkeyResult = await diracVerifyPasskeyCredential({ payload, credential, email });
      verified = passkeyResult && passkeyResult.verified === true;
      if (passkeyResult && passkeyResult.registrationInfo) req.__diracPasskeyRegistrationInfo = passkeyResult.registrationInfo;
      if (passkeyResult && passkeyResult.authenticationInfo) req.__diracPasskeyAuthenticationInfo = passkeyResult.authenticationInfo;
    }

    if (!verified) {
      const failure = await diracRecordCustomerMfaFailure({ req, login, method });
      if (failure.retryAfterSeconds) res.setHeader("Retry-After", String(failure.retryAfterSeconds));
      return res.status(failure.lockedUntilMs ? 429 : 401).json({
        ok: false,
        success: false,
        verified: false,
        attemptsRemaining: failure.attemptsRemaining,
        retryAfterSeconds: failure.retryAfterSeconds,
        error: failure.lockedUntilMs ? "Terlalu banyak kode A2F salah. Coba lagi nanti." : "Kode/verifikasi A2F salah."
      });
    }

    await diracClearCustomerMfaFailures({ login, method });

    const recoveryCodes = await diracPersistVerifiedCustomerMfa({
      email,
      method,
      credential,
      passkeyRegistrationInfo: req.__diracPasskeyRegistrationInfo,
      passkeyAuthenticationInfo: req.__diracPasskeyAuthenticationInfo,
      totpSecret: payload.purpose === "authenticator-setup-login-mfa" ? verifiedTotpSecret : ""
    });
    const dashboardSession = diracSetCustomerMfaDashboardCookie(req, res, { email, method });

    return res.status(200).json({
      ok: true,
      success: true,
      verified: true,
      method,
      recoveryCodes,
      dashboardSession: {
        verified: true,
        expiresAtMs: dashboardSession.expiresAtMs,
        transport: "httponly-secure-cookie-only"
      },
      message: "A2F berhasil diverifikasi oleh backend."
    });
  } catch (error) {
    if (error && error.retryAfterSeconds) res.setHeader("Retry-After", String(error.retryAfterSeconds));
    return res.status(error.statusCode || 500).json({
      ok: false,
      success: false,
      verified: false,
      error: error.message || "Gagal memverifikasi A2F login."
    });
  }
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method === "GET") {
    const action = String((req.query && req.query.action) || "");

    setNoStore(res);
    if (action === "approveStep6") return approveStep6FromEmail(req, res);
    if (action === "copyStep6Code") return renderStep6CopyCodePage(req, res);
    if (action === "denyStep6") return denyStep6FromEmail(req, res);

    return res.status(405).send(htmlPage("Method tidak diizinkan", "<p>Endpoint ini hanya menerima link approval/salin A2F.</p>"));
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  try {
    const action = String((req.body && req.body.action) || "").trim();

    if (action.toLowerCase() === "confirm-password-reset") return diracHandleConfirmPasswordReset(req, res);

    if (action.toLowerCase() === "verify" && req.body && req.body.method) return diracHandleCustomerMfaVerify(req, res);

    if (action === "confirmApproveStep6") return confirmApproveStep6FromEmail(req, res);
    if (action === "confirmDenyStep6") return confirmDenyStep6FromEmail(req, res);
    if (action === "checkA2fBanStatus") return checkA2fBanStatus(req, res);
    if (action === "generate-recovery-codes") return generateOneTimeRecoveryCodes(req, res);
    if (action === "listAdminSecurityCenter") return listAdminSecurityCenter(req, res);
    if (action === "updateTrustedDevice") return updateTrustedDevice(req, res);
    if (action === "checkCurrentDeviceSecurity") return checkCurrentDeviceSecurity(req, res);
    if (action === "checkClipboardSecurityStatus") return checkClipboardSecurityStatus(req, res);
    if (action === "startClipboardUnlockOtp") return startClipboardUnlockOtp(req, res);
    if (action === "verifyClipboardUnlockOtp") return verifyClipboardUnlockOtp(req, res);
    if (action === "recordA2fFailure") {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const data = await recordA2fFailure();
      return res.status(200).json({
        success: true,
        locked: Number(data.lockUntilMs || 0) > Date.now(),
        permanentBan: data.permanentBan === true,
        failedCount: Number(data.failedCount || 0),
        lockUntilMs: Number(data.lockUntilMs || 0),
        permanentBanReason: data.permanentBanReason || "wrong_code_cooldown",
        error: data.permanentBan === true ? "A2F diblokir permanen dari backend." : getLockMessage(data.lockUntilMs)
      });
    }
    if (action === "recordA2fTimeoutMarker") {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const uid = getAdminUid();
      const data = await readA2fLockRow(uid);
      return res.status(200).json({
        success: true,
        locked: Number(data.lockUntilMs || 0) > Date.now() || data.permanentBan === true,
        permanentBan: data.permanentBan === true,
        failedCount: Number(data.failedCount || 0),
        lockUntilMs: Number(data.lockUntilMs || 0),
        permanentBanReason: data.permanentBanReason || "",
        error: Number(data.lockUntilMs || 0) > Date.now() ? getLockMessage(data.lockUntilMs) : ""
      });
    }
    if (action === "recordA2fTimeoutBlock") {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const data = await recordA2fTimeoutBlock(String((req.body && req.body.reason) || "a2f_timeout"));
      return res.status(200).json({
        success: true,
        locked: true,
        permanentBan: data.permanentBan === true,
        failedCount: Number(data.failedCount || 0),
        lockUntilMs: Number(data.lockUntilMs || 0),
        permanentBanReason: data.permanentBanReason || "a2f_timeout",
        error: data.permanentBan === true ? "A2F diblokir permanen dari backend." : getLockMessage(data.lockUntilMs)
      });
    }

    if (action === "startStep6EmailApproval") return startStep6EmailApproval(req, res);
    if (action === "checkStep6EmailApproval") return checkStep6EmailApproval(req, res);
    if (action === "revealStep6CopyCode") return revealStep6CopyCode(req, res);
    if (action === "submitStep6ScreenCode") return submitStep6ScreenCode(req, res);

    await checkA2fLock();

    const { sessionId, code, step, idToken } = req.body || {};
    const stepNumber = Number(step);

    if (!sessionId || !code || ![2, 3, 6, 7, 8, 9, 10].includes(stepNumber)) {
      return res.status(400).json({
        success: false,
        error: "Session, kode, dan step wajib benar"
      });
    }

    const secret = getA2fSecret();
    const parts = String(sessionId).split(".");

    if (parts.length !== 2) {
      return res.status(400).json({
        success: false,
        error: "Session A2F tidak valid"
      });
    }

    const payloadBase64 = parts[0];
    const signature = parts[1];
    const expectedSignature = sign(payloadBase64, secret);

    if (!safeEqual(signature, expectedSignature)) {
      return res.status(401).json({
        success: false,
        error: "Session A2F palsu"
      });
    }

    let payload;

    try {
      payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: "Data session rusak"
      });
    }

    if (payload.step !== stepNumber) {
      return res.status(400).json({
        success: false,
        error: "Step tidak sesuai"
      });
    }

    if (Date.now() > payload.expiresAt) {
      return res.status(400).json({
        success: false,
        error: "Kode sudah expired"
      });
    }

    if (stepNumber === 7) {
      if (payload.flow !== "face-recovery") {
        return res.status(400).json({
          success: false,
          error: "Session recovery tidak valid"
        });
      }

      if (!verifyRecoveryTotp(code)) {
        return sendWrongCodeResponse(res);
      }

      await resetA2fFailure();

      return res.status(200).json({
        success: true,
        message: "Kode verifikasi benar",
        recoveryStep: 2,
        nextStep: 8
      });
    }

    if (stepNumber === 10) {
      if (payload.flow !== "face-recovery") {
        return res.status(400).json({
          success: false,
          error: "Session recovery tidak valid"
        });
      }

      const oneTimeResult = await consumeOneTimeRecoveryCode(code, secret, idToken);

      if (!oneTimeResult.ok) {
        return sendWrongCodeResponse(res);
      }

      await resetA2fFailure();

      return res.status(200).json({
        success: true,
        message: "Kode verifikasi benar.",
        recoveryStep: 5,
        nextStep: 11
      });
    }

    const inputHash = hashCode(`${stepNumber}:${code}`, secret);

    if (!safeEqual(inputHash, payload.codeHash)) {
      return sendWrongCodeResponse(res);
    }

    await resetA2fFailure();

    return res.status(200).json({
      success: true,
      message: "Kode verifikasi benar",
      recoveryStep: stepNumber >= 6 ? stepNumber - 5 : undefined,
      nextStep: stepNumber + 1
    });
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      success: false,
      error: error.publicMessage || error.message || "Server A2F error"
    });
  }
};
