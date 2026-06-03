const crypto = require("crypto");
const dns = require("dns").promises;
const admin = require("firebase-admin");
const argon2 = require("argon2");
const { createClient } = require("@supabase/supabase-js");

const ONE_TIME_RECOVERY_CODE_COUNT = 3;
const ONE_TIME_RECOVERY_CODE_LENGTH = 1000;
const ONE_TIME_RECOVERY_DIGITS = "0123456789";
const ONE_TIME_RECOVERY_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ONE_TIME_RECOVERY_SYMBOLS = "!@#$%^&*_=+[]{}:,.?";
const ONE_TIME_RECOVERY_ALPHABET = ONE_TIME_RECOVERY_DIGITS + ONE_TIME_RECOVERY_LETTERS + ONE_TIME_RECOVERY_SYMBOLS;
const ONE_TIME_RECOVERY_CODE_FORMAT = "MIXED-1000-V1";
const ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: Number(process.env.ARGON2_MEMORY_COST || 65536),
  timeCost: Number(process.env.ARGON2_TIME_COST || 3),
  parallelism: 1,
  hashLength: 32
});

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
    auth: { persistSession: false, autoRefreshToken: false }
  });

  return supabaseAdminClient;
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

function formatLockStatus(data) {
  const row = normalizeLockRow(data || {});
  const lockUntilMs = Number(row.lockUntilMs || 0);
  const locked = row.permanentBan === true || lockUntilMs > Date.now();
  return {
    success: true,
    locked,
    permanentBan: row.permanentBan === true,
    failedCount: Number(row.failedCount || 0),
    lockUntilMs,
    uid: row.uid || getAdminUid(),
    email: row.email || process.env.A2F_ADMIN_EMAIL || "",
    permanentBanReason: row.permanentBanReason || "",
    error: locked ? (row.permanentBanReason || getLockMessage(lockUntilMs)) : ""
  };
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
  const status = formatLockStatus(data);

  if (status.locked) {
    const err = new Error(status.error || "A2F terkunci dari backend.");
    err.statusCode = status.permanentBan ? 403 : 423;
    err.lockStatus = status;
    throw err;
  }

  return data;
}

async function recordA2fFailure(reason = "wrong_code") {
  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const now = Date.now();
  const failedCount = Number(data.failedCount || 0) + 1;
  const saved = await saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || data.email || "",
    failedCount,
    lastFailedAtMs: now,
    permanentBan: false,
    permanentBanReason: reason,
    lockUntilMs: now + getA2fLockDurationMs(failedCount),
    bannedAtMs: failedCount >= 3 ? now : data.bannedAtMs || 0
  });
  return formatLockStatus(saved);
}

async function recordA2fTimeoutBlock(reason = "a2f_timeout") {
  const uid = getAdminUid();
  const data = await readA2fLockRow(uid);
  const now = Date.now();
  const saved = await saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || data.email || "",
    failedCount: Math.max(3, Number(data.failedCount || 0)),
    lastFailedAtMs: now,
    permanentBan: false,
    permanentBanReason: reason,
    lockUntilMs: now + 100 * A2F_YEAR_MS,
    bannedAtMs: now
  });
  return formatLockStatus(saved);
}

async function resetA2fFailure() {
  const uid = getAdminUid();
  const saved = await saveA2fLockRow({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 0,
    lockUntilMs: 0,
    permanentBan: false,
    permanentBanReason: null,
    lastFailedAtMs: 0,
    bannedAtMs: null
  });
  return formatLockStatus(saved);
}


function setCors(res) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

function hashCode(code, secret) {
  return crypto.createHmac("sha256", secret).update(String(code)).digest("hex");
}

function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const bytes = [];

  base32 = String(base32).replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();

  for (const char of base32) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error("Secret A2F utama tidak valid");
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

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));

  if (A.length !== B.length) return false;

  return crypto.timingSafeEqual(A, B);
}

function verifySensitiveTotpCode(code) {
  const secret = process.env.TOTP_SECRET;
  const inputCode = String(code || "").replace(/\s+/g, "");

  if (!secret) {
    throw new Error("A2F utama belum siap");
  }

  if (!inputCode) {
    throw new Error("Kode A2F utama wajib diisi");
  }

  const validCodes = [
    generateTotp(secret, -1),
    generateTotp(secret, 0),
    generateTotp(secret, 1)
  ];

  if (!validCodes.some((validCode) => safeEqual(inputCode, validCode))) {
    throw new Error("Kode A2F utama salah");
  }
}

function verifyRecentAdminAuth(decoded) {
  const maxAgeMs = Number(process.env.A2F_SENSITIVE_REAUTH_MAX_MS || 5 * 60 * 1000);
  const authTimeMs = Number(decoded && decoded.auth_time || 0) * 1000;

  if (!authTimeMs || Date.now() - authTimeMs > maxAgeMs) {
    throw new Error("Verifikasi password admin sudah kedaluwarsa. Login/verifikasi ulang dulu.");
  }
}

function makeSession(payload, secret) {
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(payloadBase64, secret);
  return `${payloadBase64}.${signature}`;
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
  const decoded = await admin.auth().verifyIdToken(token, true);
  const expectedUid = getAdminUid();

  if (decoded.uid !== expectedUid) {
    throw new Error("Akun ini tidak diizinkan membuat recovery code");
  }

  return decoded;
}

function normalizeOneTimeRecoveryCode(code) {
  return String(code || "").trim().toUpperCase().replace(/[\s-]+/g, "");
}

function getA2fSecretForRecoveryCodeGeneration() {
  const secret = String(process.env.A2F_SECRET || "").trim();

  if (!secret) {
    throw new Error("A2F_SECRET belum diset di Environment Variables backend.");
  }

  if (secret === "rahasia-test") {
    throw new Error("A2F_SECRET masih memakai nilai testing. Ganti dengan secret production yang panjang dan acak.");
  }

  if (secret.length < 32) {
    throw new Error("A2F_SECRET terlalu pendek. Gunakan minimal 32 karakter acak.");
  }

  return secret;
}

async function hashOneTimeRecoveryCodeArgon2id(code) {
  const normalized = normalizeOneTimeRecoveryCode(code);
  return argon2.hash(normalized, ARGON2ID_OPTIONS);
}

function oneTimeRecoveryCodeHasRequiredCategories(code) {
  const value = String(code || "");
  return (
    [...ONE_TIME_RECOVERY_DIGITS].some((char) => value.includes(char)) &&
    [...ONE_TIME_RECOVERY_LETTERS].some((char) => value.includes(char)) &&
    [...ONE_TIME_RECOVERY_SYMBOLS].some((char) => value.includes(char))
  );
}

function generateOneTimeRecoveryCode(length = ONE_TIME_RECOVERY_CODE_LENGTH) {
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

async function generateOneTimeRecoveryCodes(reqBody) {
  getA2fSecretForRecoveryCodeGeneration();
  const decoded = await verifyAdminIdToken(reqBody && reqBody.idToken);
  verifyRecentAdminAuth(decoded);
  verifySensitiveTotpCode(reqBody && reqBody.sensitiveTotpCode);
  const count = ONE_TIME_RECOVERY_CODE_COUNT;
  const db = getFirebaseDb();
  const batch = db.batch();
  const codes = [];
  const now = Date.now();

  await revokeExistingOneTimeRecoveryCodes(db, decoded, now);

  while (codes.length < count) {
    const code = generateOneTimeRecoveryCode();
    const argon2Hash = await hashOneTimeRecoveryCodeArgon2id(code);
    const ref = db.collection("a2fRecoveryCodes").doc(crypto.randomBytes(24).toString("base64url"));

    codes.push(code);
    batch.set(ref, {
      uid: decoded.uid,
      email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      argon2Hash,
      hashType: "argon2id",
      hashParams: {
        memoryCost: ARGON2ID_OPTIONS.memoryCost,
        timeCost: ARGON2ID_OPTIONS.timeCost,
        parallelism: ARGON2ID_OPTIONS.parallelism,
        hashLength: ARGON2ID_OPTIONS.hashLength
      },
      active: true,
      used: false,
      revoked: false,
      label: `Recovery code ${codes.length}`,
      codeLength: ONE_TIME_RECOVERY_CODE_LENGTH,
      codeFormat: ONE_TIME_RECOVERY_CODE_FORMAT,
      alphabetVersion: "numbers-uppercase-symbols-v1",
      randomMethod: "crypto.randomInt",
      lookupType: "argon2id-active-candidate-scan",
      purpose: "face_recovery_step_5",
      createdByUid: decoded.uid,
      createdByEmail: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      createdAtMs: now,
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

  return codes;
}

async function sendEmailOtp(code) {
  const apiKey = process.env.BREVO_API_KEY;
  const adminEmail = process.env.A2F_ADMIN_EMAIL;
  const senderEmail = process.env.A2F_SENDER_EMAIL;

  if (!apiKey) throw new Error("BREVO_API_KEY belum diset");
  if (!adminEmail) throw new Error("A2F_ADMIN_EMAIL belum diset");
  if (!senderEmail) throw new Error("A2F_SENDER_EMAIL belum diset");

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: "Dirac Admin",
        email: senderEmail
      },
      to: [
        {
          email: adminEmail,
          name: "Admin"
        }
      ],
      subject: "Kode A2F Tahap 3 Dirac Admin",
      htmlContent: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Kode A2F Tahap 3</h2>
          <p>Kode verifikasi kamu:</p>
          <div style="font-size:28px;font-weight:700;letter-spacing:4px">
            ${code}
          </div>
          <p>Kode berlaku 5 menit.</p>
          <p>Jika kamu tidak login, abaikan email ini.</p>
        </div>
      `,
      textContent: `Kode A2F tahap 3 kamu adalah: ${code}. Kode berlaku 5 menit.`
    })
  });

  const result = await response.text();

  if (!response.ok) {
    throw new Error(result || "Gagal kirim email OTP");
  }

  return result;
}

async function sendRecoveryEmailOtp(code, stepNumber) {
  const apiKey = process.env.BREVO_API_KEY;
  const adminEmail = process.env.A2F_RECOVERY_EMAIL || process.env.A2F_ADMIN_EMAIL;
  const senderEmail = process.env.A2F_SENDER_EMAIL;
  const recoveryStep = stepNumber - 5;

  if (!apiKey) throw new Error("BREVO_API_KEY belum diset");
  if (!adminEmail) throw new Error("A2F_RECOVERY_EMAIL atau A2F_ADMIN_EMAIL belum diset");
  if (!senderEmail) throw new Error("A2F_SENDER_EMAIL belum diset");

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: "Dirac Admin",
        email: senderEmail
      },
      to: [
        {
          email: adminEmail,
          name: "Admin"
        }
      ],
      subject: `Kode Recovery Face ID Tahap ${recoveryStep} Dirac Admin`,
      htmlContent: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Kode Recovery Face ID Tahap ${recoveryStep}</h2>
          <p>Kode recovery kamu:</p>
          <div style="font-size:28px;font-weight:700;letter-spacing:4px">
            ${code}
          </div>
          <p>Kode berlaku 5 menit.</p>
          <p>Jika kamu tidak sedang recovery Face ID, abaikan email ini dan cek keamanan akun.</p>
        </div>
      `,
      textContent: `Kode Recovery Face ID tahap ${recoveryStep} kamu adalah: ${code}. Kode berlaku 5 menit.`
    })
  });

  const result = await response.text();

  if (!response.ok) {
    throw new Error(result || "Gagal kirim email recovery OTP");
  }

  return result;
}

function getRecoveryTotpSecret() {
  const envName = "A2F_RECOVERY_TOTP_SECRET_2";
  const secret = String(process.env[envName] || "").replace(/\s+/g, "").trim();

  if (!secret) {
    throw new Error("Kode verifikasi belum siap");
  }

  if (secret.length < 16) {
    throw new Error("Kode verifikasi belum siap");
  }

  return { envName };
}

function getRecoveryLocalCode(stepNumber) {
  const config = {
    8: {
      envName: "A2F_RECOVERY_STEP3_CODE",
      label: "Recovery Face ID tahap 3"
    },
    9: {
      envName: "A2F_RECOVERY_STEP4_CODE",
      label: "Recovery Face ID tahap 4"
    }
  };

  const item = config[stepNumber];
  if (!item) {
    throw new Error("Step recovery lokal tidak valid");
  }

  const code = String(process.env[item.envName] || "").trim();

  if (!code) {
    throw new Error("Kode verifikasi belum siap");
  }

  if (code.length < 12 || code.length > 96) {
    throw new Error("Kode verifikasi belum siap");
  }

  return { code, label: item.label, envName: item.envName };
}


const PUBLIC_MFA_SETUP_TTL_MS = Number(process.env.PUBLIC_MFA_SETUP_TTL_MS || 5 * 60 * 1000);
const PUBLIC_MFA_EMAIL_CODE_TTL_MS = Number(process.env.PUBLIC_MFA_EMAIL_CODE_TTL_MS || PUBLIC_MFA_SETUP_TTL_MS);
const PUBLIC_MFA_CHALLENGE_PURPOSE = "public-a2f-setup-v1";

function normalizePublicMfaMethod(method) {
  const value = String(method || "").trim().toLowerCase();
  if (["email", "otp", "email-otp", "mail"].includes(value)) return "email";
  if (["authenticator", "totp", "app", "google-authenticator"].includes(value)) return "authenticator";
  if (["passkey", "webauthn", "security-key", "security_key"].includes(value)) return "passkey";
  return "";
}

function isPublicMfaStartRequest(body) {
  const method = normalizePublicMfaMethod(body && body.method);
  const action = String((body && body.action) || "setup").trim().toLowerCase();
  return Boolean(method && ["setup", "start", "resend", "begin", "register", "create"].includes(action));
}

function getPublicMfaSecret() {
  const secret = String(process.env.A2F_SECRET || process.env.PUBLIC_MFA_SECRET || "").trim();
  if (!secret || secret === "rahasia-test" || secret.length < 32) {
    const err = new Error("A2F_SECRET/PUBLIC_MFA_SECRET belum aman. Gunakan secret production minimal 32 karakter.");
    err.statusCode = 500;
    throw err;
  }
  return secret;
}

function publicMfaRandomId(bytes = 18) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function publicMfaBase64Url(input) {
  return Buffer.from(input).toString("base64url");
}

function normalizePublicMfaIdentifier(value) {
  const text = String(value || process.env.A2F_ADMIN_EMAIL || "").trim().toLowerCase();
  return text.length > 220 ? text.slice(0, 220) : text;
}

function hashPublicMfaIdentifier(identifier, secret) {
  return crypto.createHmac("sha256", secret).update(`public-mfa-identifier:${normalizePublicMfaIdentifier(identifier)}`).digest("hex");
}

function generatePublicMfaRecoveryCodes(count = 6) {
  const codes = [];
  while (codes.length < count) {
    const left = crypto.randomBytes(5).toString("base64url").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8).padEnd(8, "X");
    const right = crypto.randomBytes(5).toString("base64url").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8).padEnd(8, "Y");
    codes.push(`DIRAC-${left}-${right}`);
  }
  return codes;
}

function randomBase32Secret(length = 32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  while (out.length < length) out += alphabet[crypto.randomInt(0, alphabet.length)];
  return out;
}

function otpauthUrl({ issuer, account, secret }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account || "Dirac User")}`;
  const qs = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: "6", period: "30" });
  return `otpauth://totp/${label}?${qs.toString()}`;
}

function getStrictPublicOrigin() {
  const allowed = getAllowedOrigins().map((item) => String(item || "").trim().replace(/\/+$/, "")).filter(Boolean);
  const configured = String(process.env.WEBAUTHN_ORIGIN || process.env.PUBLIC_MFA_EXPECTED_ORIGIN || process.env.A2F_PUBLIC_BASE_URL || allowed[0] || "https://diracgroup.store").trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(configured);
    if (parsed.protocol !== "https:") throw new Error("origin_must_be_https");
    return `${parsed.protocol}//${parsed.host}`.replace(/\/$/, "");
  } catch (_error) {
    const err = new Error("WEBAUTHN_ORIGIN/PUBLIC_MFA_EXPECTED_ORIGIN tidak valid. Gunakan origin HTTPS production.");
    err.statusCode = 500;
    throw err;
  }
}

function getRequestOrigin(_req) {
  return getStrictPublicOrigin();
}

function getPublicMfaRpId(_req) {
  const envRpId = String(process.env.WEBAUTHN_RP_ID || process.env.PUBLIC_MFA_RP_ID || "").trim();
  if (envRpId) return envRpId;
  try {
    const hostname = new URL(getStrictPublicOrigin()).hostname;
    return hostname.replace(/^www\./i, "");
  } catch (_error) {
    return "diracgroup.store";
  }
}

function getPublicMfaRpName() {
  return String(process.env.WEBAUTHN_RP_NAME || process.env.PUBLIC_MFA_RP_NAME || "Dirac Group").trim() || "Dirac Group";
}

function getSmtpConfigForPublicMfa() {
  const host = String(process.env.SMTP_HOST || process.env.GMAIL_SMTP_HOST || "smtp.gmail.com").trim();
  const port = Number(process.env.SMTP_PORT || process.env.GMAIL_SMTP_PORT || 465);
  const user = String(process.env.SMTP_USER || process.env.GMAIL_USER || process.env.GMAIL_EMAIL || "").trim();
  const pass = String(process.env.SMTP_PASS || process.env.GMAIL_APP_PASSWORD || process.env.GMAIL_PASS || "").trim();
  const fromName = String(process.env.SMTP_FROM_NAME || "Dirac Security").trim();
  const fromEmail = String(process.env.SMTP_FROM_EMAIL || user || process.env.A2F_SENDER_EMAIL || "").trim();
  return { host, port, user, pass, fromName, fromEmail };
}

async function sendPublicMfaEmailOtp({ code, to, expiresAtMs }) {
  const target = String(to || process.env.PUBLIC_MFA_EMAIL_TO || process.env.A2F_ADMIN_EMAIL || "").trim();
  if (!target) throw new Error("Email tujuan OTP belum tersedia.");

  const smtp = getSmtpConfigForPublicMfa();
  if (smtp.user && smtp.pass && smtp.fromEmail) {
    const nodemailer = require("nodemailer");
    const transporter = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.port === 465,
      auth: { user: smtp.user, pass: smtp.pass }
    });
    await transporter.sendMail({
      from: `"${smtp.fromName}" <${smtp.fromEmail}>`,
      to: target,
      subject: "Kode OTP A2F Dirac Group",
      text: `Kode OTP A2F Dirac Group kamu adalah ${code}. Kode berlaku sampai ${new Date(expiresAtMs).toISOString()}. Jangan berikan kode ini ke siapa pun.`,
      html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#111"><h2>Kode OTP A2F Dirac Group</h2><p>Kode verifikasi kamu:</p><div style="font-size:30px;font-weight:800;letter-spacing:5px">${code}</div><p>Kode berlaku sampai <b>${new Date(expiresAtMs).toISOString()}</b>.</p><p>Jika kamu tidak meminta kode ini, abaikan email ini.</p></div>`
    });
    return { provider: "smtp" };
  }

  if (process.env.BREVO_API_KEY && process.env.A2F_SENDER_EMAIL) {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        sender: { name: "Dirac Security", email: process.env.A2F_SENDER_EMAIL },
        to: [{ email: target, name: "Dirac User" }],
        subject: "Kode OTP A2F Dirac Group",
        htmlContent: `<div style="font-family:Arial,sans-serif;line-height:1.6"><h2>Kode OTP A2F</h2><p>Kode verifikasi kamu:</p><div style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</div><p>Kode berlaku singkat. Jangan berikan kode ini ke siapa pun.</p></div>`,
        textContent: `Kode OTP A2F Dirac Group kamu adalah: ${code}`
      })
    });
    const result = await response.text();
    if (!response.ok) throw new Error(result || "Gagal kirim email OTP");
    return { provider: "brevo" };
  }

  throw new Error("SMTP/Gmail belum diset. Isi SMTP_USER dan SMTP_PASS/GMAIL_APP_PASSWORD di Environment Variables.");
}

/* DIRAC CUSTOMER SECURITY HARDENING PATCH 2026-06
   - DB-backed MFA setup token (opaque token, no readable TOTP/recovery data)
   - Argon2id hashes for OTP/reset/recovery secrets
   - strict forgot-password start flow
   - strict CORS allowlist
*/
function publicSafeError(error, fallback) {
  const status = Number(error && error.statusCode || 500);
  if (status >= 500) return fallback || "Server keamanan belum siap.";
  return (error && error.message) || fallback || "Permintaan tidak valid.";
}

function getAllowedOrigins() {
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || process.env.PUBLIC_ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim().replace(/\/$/, ""))
    .filter(Boolean);
  if (fromEnv.length) return fromEnv;
  return ["https://diracgroup.store", "https://www.diracgroup.store"];
}

function setCors(reqOrRes, maybeRes) {
  const req = maybeRes ? reqOrRes : null;
  const res = maybeRes || reqOrRes;
  const origin = req && req.headers ? String(req.headers.origin || "").replace(/\/$/, "") : "";
  const allowed = getAllowedOrigins();
  if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
}

function securityTableName() {
  return String(process.env.PUBLIC_SECURITY_CHALLENGES_TABLE || process.env.PUBLIC_MFA_CHALLENGES_TABLE || "public_security_challenges").trim();
}
function rateLimitTableName() {
  return String(process.env.PUBLIC_SECURITY_RATE_LIMITS_TABLE || "public_security_rate_limits").trim();
}

function hasSupabaseEnv() {
  return Boolean(String(process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "").trim() && String(process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim());
}

function getClientIp(req) {
  const h = (req && req.headers) || {};
  const provider = String(process.env.TRUSTED_IP_HEADER || "").trim().toLowerCase();
  const candidates = [];
  if (provider && h[provider]) candidates.push(h[provider]);
  candidates.push(h["cf-connecting-ip"], h["x-vercel-forwarded-for"], h["x-real-ip"], h["x-forwarded-for"]);
  for (const candidate of candidates) {
    const value = String(candidate || "").split(",")[0].trim();
    if (value && /^[A-Fa-f0-9:.]{3,96}$/.test(value)) return value.slice(0, 96);
  }
  return "unknown";
}
function getUserAgent(req) {
  return String((req && req.headers && req.headers["user-agent"]) || "").slice(0, 500);
}
function hmacSecurity(value) {
  return crypto.createHmac("sha256", getPublicMfaSecret()).update(String(value || "")).digest("hex");
}
function normalizeEmailStrict(value) {
  const email = String(value || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    const err = new Error("Masukkan email yang valid.");
    err.statusCode = 400;
    throw err;
  }
  return email;
}


const DEFAULT_BLOCKED_PASSWORD_RESET_DOMAINS = Object.freeze([
  "10minutemail.com", "20minutemail.com", "33mail.com", "anonaddy.com", "burnermail.io", "dispostable.com", "fakeinbox.com",
  "guerrillamail.com", "guerrillamail.net", "mailinator.com", "mailinator.net", "maildrop.cc", "mohmal.com", "sharklasers.com",
  "tempmail.com", "temp-mail.org", "throwawaymail.com", "trashmail.com", "yopmail.com", "yopmail.fr"
]);

function splitEmailParts(email) {
  const normalized = normalizeEmailStrict(email);
  const at = normalized.lastIndexOf("@");
  return { email: normalized, local: normalized.slice(0, at), domain: normalized.slice(at + 1) };
}

function envList(name) {
  return String(process.env[name] || "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
}

function isDomainListed(domain, list) {
  const value = String(domain || "").toLowerCase();
  return list.some((item) => value === item || value.endsWith(`.${item}`));
}

async function assertPasswordResetEmailSafe(email, user) {
  const parts = splitEmailParts(email);
  if (!parts.local || !parts.domain || parts.local.length > 64 || parts.domain.length > 253) {
    throw Object.assign(new Error("Email reset password tidak valid."), { statusCode: 400 });
  }
  if (/\.\.|^\.|\.$/.test(parts.domain) || /(^-|-$)/.test(parts.domain) || /(^\.|\.$)/.test(parts.local)) {
    throw Object.assign(new Error("Format email reset password tidak aman."), { statusCode: 400 });
  }
  if (/localhost|\.local$|\.test$|\.invalid$|\.example$/.test(parts.domain) || /^\d+\.\d+\.\d+\.\d+$/.test(parts.domain)) {
    throw Object.assign(new Error("Domain email reset password tidak diizinkan."), { statusCode: 400 });
  }
  const allowDomains = envList("PASSWORD_RESET_ALLOWED_EMAIL_DOMAINS");
  if (allowDomains.length && !isDomainListed(parts.domain, allowDomains)) {
    throw Object.assign(new Error("Domain email belum diizinkan untuk reset password."), { statusCode: 403 });
  }
  const blockedDomains = [...DEFAULT_BLOCKED_PASSWORD_RESET_DOMAINS, ...envList("PASSWORD_RESET_BLOCKED_EMAIL_DOMAINS")];
  if (isDomainListed(parts.domain, blockedDomains)) {
    throw Object.assign(new Error("Email sementara/berisiko tidak boleh dipakai untuk reset password."), { statusCode: 403 });
  }
  const mustBeConfirmed = String(process.env.PASSWORD_RESET_REQUIRE_CONFIRMED_EMAIL || "true").toLowerCase() !== "false";
  if (mustBeConfirmed) {
    const confirmed = Boolean(user && (user.email_confirmed_at || user.confirmed_at || (user.user_metadata && user.user_metadata.email_verified === true)));
    if (!confirmed) throw Object.assign(new Error("Email akun belum terverifikasi. Verifikasi email dulu atau hubungi admin."), { statusCode: 403 });
  }
  const requireMx = String(process.env.PASSWORD_RESET_REQUIRE_MX_CHECK || "true").toLowerCase() !== "false";
  if (requireMx) {
    try {
      const mx = await dns.resolveMx(parts.domain);
      if (!Array.isArray(mx) || mx.length === 0) throw new Error("no_mx");
    } catch (_error) {
      throw Object.assign(new Error("Domain email tidak memiliki MX record valid."), { statusCode: 400 });
    }
  }
  return parts.email;
}

async function findSupabaseUserByEmailForReset(email) {
  const supabase = getSupabaseAdmin();
  const target = normalizeEmailStrict(email);
  let page = 1;
  const perPage = Math.min(1000, Math.max(1, Number(process.env.PASSWORD_RESET_USER_LOOKUP_PER_PAGE || 1000)));
  const maxPages = Math.max(1, Number(process.env.PASSWORD_RESET_USER_LOOKUP_MAX_PAGES || 20));
  while (page <= maxPages) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const users = (data && data.users) || [];
    const found = users.find((user) => String(user.email || "").trim().toLowerCase() === target);
    if (found) return found;
    if (users.length < perPage) break;
    page += 1;
  }
  return null;
}
function nowIso() { return new Date().toISOString(); }
async function argon2idStrongHash(value) {
  return argon2.hash(String(value || ""), {
    type: argon2.argon2id,
    memoryCost: Number(process.env.ARGON2_MEMORY_COST || 65536),
    timeCost: Number(process.env.ARGON2_TIME_COST || 3),
    parallelism: Number(process.env.ARGON2_PARALLELISM || 1),
    hashLength: Number(process.env.ARGON2_HASH_LENGTH || 32)
  });
}

function deriveAesKey() {
  return crypto.createHash("sha256").update(`dirac-public-security-v1:${getPublicMfaSecret()}`).digest();
}
function encryptSecurityPayload(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveAesKey(), iv);
  const plain = Buffer.from(JSON.stringify(payload || {}), "utf8");
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}
function randomOpaqueToken(challengeId, bytes = 32) {
  return `${challengeId}.${crypto.randomBytes(bytes).toString("base64url")}`;
}
function splitOpaqueToken(token, label = "token") {
  const parts = String(token || "").split(".");
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]{12,128}$/.test(parts[0]) || parts[1].length < 32) {
    const err = new Error(`${label} tidak valid atau sudah rusak.`);
    err.statusCode = 400;
    throw err;
  }
  return { challengeId: parts[0], tokenSecret: parts[1] };
}
function publicMfaRandomId(bytes = 18) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function mapSecurityChallengeRow(row) {
  row = row && typeof row === "object" ? row : {};
  return {
    challenge_id: String(row.challenge_id || row.challengeId || ""),
    purpose: String(row.purpose || ""),
    method: String(row.method || ""),
    identifier_hash: String(row.identifier_hash || row.identifierHash || ""),
    token_hash: String(row.token_hash || row.tokenHash || ""),
    token_hash_type: String(row.token_hash_type || row.tokenHashType || "argon2id"),
    code_hash: String(row.code_hash || row.codeHash || ""),
    code_hash_type: String(row.code_hash_type || row.codeHashType || "argon2id"),
    encrypted_payload: String(row.encrypted_payload || row.encryptedPayload || ""),
    expires_at_ms: Number(row.expires_at_ms ?? row.expiresAtMs ?? 0),
    attempts: Number(row.attempts || 0),
    max_attempts: Number(row.max_attempts ?? row.maxAttempts ?? 5),
    used_at_ms: Number(row.used_at_ms ?? row.usedAtMs ?? 0),
    locked_at_ms: Number(row.locked_at_ms ?? row.lockedAtMs ?? 0)
  };
}
async function insertSecurityChallenge(row) {
  const payload = {
    challenge_id: row.challenge_id,
    purpose: row.purpose,
    method: row.method,
    identifier_hash: row.identifier_hash,
    token_hash: row.token_hash,
    token_hash_type: row.token_hash_type || "argon2id",
    code_hash: row.code_hash || null,
    code_hash_type: row.code_hash ? "argon2id" : null,
    encrypted_payload: row.encrypted_payload || null,
    expires_at_ms: Number(row.expires_at_ms || 0),
    attempts: Number(row.attempts || 0),
    max_attempts: Number(row.max_attempts || 5),
    used_at_ms: null,
    locked_at_ms: null,
    request_ip_hash: row.request_ip_hash || null,
    user_agent_hash: row.user_agent_hash || null,
    created_at_ms: Date.now(),
    created_at: nowIso(),
    updated_at: nowIso()
  };
  if (hasSupabaseEnv()) {
    try {
      const { data, error } = await getSupabaseAdmin().from(securityTableName()).insert(payload).select("*").single();
      if (error) throw error;
      return mapSecurityChallengeRow(data || payload);
    } catch (error) {
      if (String(process.env.PUBLIC_SECURITY_STORE || "").toLowerCase() === "supabase") throw error;
    }
  }
  const db = getFirebaseDb();
  await db.collection(securityTableName()).doc(payload.challenge_id).set(payload, { merge: false });
  return mapSecurityChallengeRow(payload);
}
async function upsertSecurityRateLimit(req, purpose, identifierHash, maxCount = 5, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const bucket = Math.floor(now / windowMs);
  const key = hmacSecurity(`${purpose}:${identifierHash}:${getClientIp(req)}:${bucket}`);
  const base = { key, purpose, identifier_hash: identifierHash, ip_hash: hmacSecurity(getClientIp(req)), count: 1, expires_at_ms: (bucket + 1) * windowMs, updated_at: nowIso() };
  if (hasSupabaseEnv()) {
    try {
      const { data, error } = await getSupabaseAdmin().rpc("public_increment_security_rate_limit", {
        p_key: key,
        p_purpose: purpose,
        p_identifier_hash: identifierHash,
        p_ip_hash: base.ip_hash,
        p_expires_at_ms: base.expires_at_ms
      });
      if (error) throw error;
      const count = Number(Array.isArray(data) ? data[0] : data || 0);
      if (count > maxCount) {
        const err = new Error("Terlalu banyak permintaan. Tunggu beberapa menit lalu coba lagi.");
        err.statusCode = 429;
        throw err;
      }
      return;
    } catch (error) {
      if (error.statusCode === 429 || String(process.env.PUBLIC_SECURITY_STORE || "").toLowerCase() === "supabase") throw error;
    }
  }
  const db = getFirebaseDb();
  const ref = db.collection(rateLimitTableName()).doc(key);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const current = snap.exists ? Number((snap.data() || {}).count || 0) : 0;
    const count = current + 1;
    if (count > maxCount) {
      const err = new Error("Terlalu banyak permintaan. Tunggu beberapa menit lalu coba lagi.");
      err.statusCode = 429;
      throw err;
    }
    tx.set(ref, { ...base, count }, { merge: true });
  });
}

function buildPublicMfaPasskeyOptions(req, identifier) {
  throw new Error("buildPublicMfaPasskeyOptions diganti oleh startPublicMfaSetup async.");
}

async function startPublicMfaSetup(req, res) {
  const body = req.body || {};
  const method = normalizePublicMfaMethod(body.method);
  const identifier = normalizeEmailStrict(body.identifier || body.email || body.username || "");
  const secret = getPublicMfaSecret();
  const identifierHash = hashPublicMfaIdentifier(identifier, secret);
  await upsertSecurityRateLimit(req, `public-mfa-start:${method || "unknown"}`, identifierHash, Number(process.env.PUBLIC_MFA_START_MAX_PER_WINDOW || 5), Number(process.env.PUBLIC_MFA_START_WINDOW_MS || 10 * 60 * 1000));

  if (!method) return res.status(400).json({ success: false, ok: false, error: "Metode A2F tidak valid." });

  const now = Date.now();
  const ttlMs = method === "email" ? PUBLIC_MFA_EMAIL_CODE_TTL_MS : PUBLIC_MFA_SETUP_TTL_MS;
  const challengeId = publicMfaRandomId(24);
  const setupToken = randomOpaqueToken(challengeId, 36);
  const { tokenSecret } = splitOpaqueToken(setupToken, "setupToken");
  const base = {
    challenge_id: challengeId,
    purpose: PUBLIC_MFA_CHALLENGE_PURPOSE,
    method,
    identifier_hash: identifierHash,
    token_hash: await argon2idStrongHash(`setup-token:${challengeId}:${tokenSecret}`),
    token_hash_type: "argon2id",
    expires_at_ms: now + ttlMs,
    attempts: 0,
    max_attempts: Number(process.env.PUBLIC_MFA_MAX_VERIFY_ATTEMPTS || 5),
    request_ip_hash: hmacSecurity(getClientIp(req)),
    user_agent_hash: hmacSecurity(getUserAgent(req))
  };

  if (method === "email") {
    const code = String(crypto.randomInt(100000, 1000000)).padStart(6, "0");
    await insertSecurityChallenge({
      ...base,
      code_hash: await argon2idStrongHash(`public-email:${identifier}:${code}`),
      encrypted_payload: encryptSecurityPayload({ issuer: getPublicMfaRpName() })
    });
    const mail = await sendPublicMfaEmailOtp({ code, to: identifier, expiresAtMs: now + ttlMs });
    return res.status(200).json({ success: true, ok: true, method, setupToken, mfaSetupToken: setupToken, token: setupToken, ttlSeconds: Math.max(1, Math.floor(ttlMs / 1000)), provider: mail.provider, message: "Kode OTP email berhasil dikirim." });
  }

  if (method === "authenticator") {
    const manualKey = randomBase32Secret(32);
    await insertSecurityChallenge({
      ...base,
      encrypted_payload: encryptSecurityPayload({ totpSecret: manualKey, issuer: getPublicMfaRpName(), account: identifier })
    });
    return res.status(200).json({ success: true, ok: true, method, setupToken, mfaSetupToken: setupToken, token: setupToken, manualKey, secret: manualKey, otpauthUrl: otpauthUrl({ issuer: getPublicMfaRpName(), account: identifier, secret: manualKey }), ttlSeconds: Math.max(1, Math.floor(ttlMs / 1000)), message: "Setup key Authenticator berhasil disiapkan." });
  }

  if (method === "passkey") {
    const challenge = publicMfaBase64Url(crypto.randomBytes(32));
    const userId = publicMfaBase64Url(crypto.randomBytes(32));
    const rpId = getPublicMfaRpId(req);
    const origin = getRequestOrigin(req);
    await insertSecurityChallenge({
      ...base,
      encrypted_payload: encryptSecurityPayload({ challenge, userId, rpId, origin, account: identifier, issuer: getPublicMfaRpName() })
    });
    return res.status(200).json({
      success: true,
      ok: true,
      method,
      setupToken,
      mfaSetupToken: setupToken,
      token: setupToken,
      ttlSeconds: Math.max(1, Math.floor(ttlMs / 1000)),
      publicKey: {
        challenge,
        rp: { name: getPublicMfaRpName(), id: rpId },
        user: { id: userId, name: identifier, displayName: identifier || "Dirac Group User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        timeout: Number(process.env.PUBLIC_MFA_PASSKEY_TIMEOUT_MS || 60000),
        attestation: "none",
        authenticatorSelection: { residentKey: "preferred", requireResidentKey: false, userVerification: "required" },
        extensions: { credProps: true }
      },
      message: "Challenge passkey berhasil dibuat."
    });
  }

  return res.status(400).json({ success: false, ok: false, error: "Metode A2F tidak dikenal." });
}

function normalizePasswordResetAction(body) {
  return String((body && body.action) || "").trim().toLowerCase();
}
function isPasswordResetStartRequest(body) {
  return ["forgot-password", "request-password-reset", "password-reset-start", "start-password-reset", "lupa-password"].includes(normalizePasswordResetAction(body));
}
async function sendPasswordResetOtp({ code, to, expiresAtMs }) {
  const smtp = getSmtpConfigForPublicMfa();
  const subject = "Kode Reset Password Dirac Group";
  const text = `Kode reset password Dirac Group kamu adalah ${code}. Kode berlaku sampai ${new Date(expiresAtMs).toISOString()}. Jika kamu tidak meminta reset password, abaikan email ini.`;
  const html = `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#111"><h2>Kode Reset Password Dirac Group</h2><p>Kode verifikasi kamu:</p><div style="font-size:30px;font-weight:800;letter-spacing:5px">${code}</div><p>Kode berlaku sampai <b>${new Date(expiresAtMs).toISOString()}</b>.</p><p>Jika kamu tidak meminta reset password, abaikan email ini.</p></div>`;
  if (smtp.user && smtp.pass && smtp.fromEmail) {
    const nodemailer = require("nodemailer");
    const transporter = nodemailer.createTransport({ host: smtp.host, port: smtp.port, secure: smtp.port === 465, auth: { user: smtp.user, pass: smtp.pass } });
    await transporter.sendMail({ from: `"${smtp.fromName}" <${smtp.fromEmail}>`, to, subject, text, html });
    return { provider: "smtp" };
  }
  if (process.env.BREVO_API_KEY && process.env.A2F_SENDER_EMAIL) {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ sender: { name: "Dirac Security", email: process.env.A2F_SENDER_EMAIL }, to: [{ email: to, name: "Dirac User" }], subject, htmlContent: html, textContent: text })
    });
    if (!response.ok) throw new Error("Email reset password gagal dikirim.");
    return { provider: "brevo" };
  }
  throw new Error("SMTP/Gmail belum diset. Isi SMTP_USER dan SMTP_PASS/GMAIL_APP_PASSWORD di Environment Variables.");
}
async function startStrictPasswordReset(req, res) {
  const email = normalizeEmailStrict((req.body || {}).email || (req.body || {}).identifier || "");
  const secret = getPublicMfaSecret();
  const identifierHash = hashPublicMfaIdentifier(email, secret);
  await upsertSecurityRateLimit(req, "password-reset-start", identifierHash, Number(process.env.PASSWORD_RESET_START_MAX_PER_WINDOW || 3), Number(process.env.PASSWORD_RESET_START_WINDOW_MS || 15 * 60 * 1000));

  const user = await findSupabaseUserByEmailForReset(email);
  if (!user || !user.id) {
    const err = new Error("Email belum terdaftar. Kode reset tidak dikirim.");
    err.statusCode = 404;
    throw err;
  }
  await assertPasswordResetEmailSafe(email, user);

  const now = Date.now();
  const ttlMs = Number(process.env.PASSWORD_RESET_TTL_MS || 5 * 60 * 1000);
  const challengeId = publicMfaRandomId(24);
  const resetToken = randomOpaqueToken(challengeId, 40);
  const { tokenSecret } = splitOpaqueToken(resetToken, "resetToken");
  const code = String(crypto.randomInt(10000000, 100000000)).padStart(8, "0");
  await insertSecurityChallenge({
    challenge_id: challengeId,
    purpose: "password-reset-v1",
    method: "email",
    identifier_hash: identifierHash,
    token_hash: await argon2idStrongHash(`password-reset-token:${challengeId}:${tokenSecret}`),
    token_hash_type: "argon2id",
    code_hash: await argon2idStrongHash(`password-reset-code:${email}:${code}`),
    code_hash_type: "argon2id",
    encrypted_payload: encryptSecurityPayload({ email, registeredUserId: String(user.id || ""), requestedAtMs: now }),
    expires_at_ms: now + ttlMs,
    attempts: 0,
    max_attempts: Number(process.env.PASSWORD_RESET_MAX_ATTEMPTS || 5),
    request_ip_hash: hmacSecurity(getClientIp(req)),
    user_agent_hash: hmacSecurity(getUserAgent(req))
  });
  await sendPasswordResetOtp({ code, to: email, expiresAtMs: now + ttlMs });
  return res.status(200).json({ success: true, ok: true, resetToken, ttlSeconds: Math.max(1, Math.floor(ttlMs / 1000)), message: "Kode reset 8 digit sudah dikirim ke email akun terdaftar dan terverifikasi." });
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const { step, action } = req.body || {};

  if (isPasswordResetStartRequest(req.body || {})) {
    try {
      return startStrictPasswordReset(req, res);
    } catch (error) {
      return res.status(error.statusCode || 500).json({
        success: false,
        ok: false,
        error: publicSafeError(error, "Permintaan reset password belum bisa diproses.")
      });
    }
  }

  if (isPublicMfaStartRequest(req.body || {})) {
    try {
      return startPublicMfaSetup(req, res);
    } catch (error) {
      return res.status(error.statusCode || 500).json({
        success: false,
        ok: false,
        error: error.message || "Gagal menyiapkan A2F"
      });
    }
  }

  if (action === "checkA2fBanStatus") {
    try {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const data = await ensureA2fLockRow();
      return res.status(200).json(formatLockStatus(data));
    } catch (error) {
      return res.status(error.statusCode || 500).json(error.lockStatus || {
        success: false,
        locked: true,
        error: error.message || "Gagal cek status ban A2F"
      });
    }
  }

  if (action === "recordA2fTimeoutBlock") {
    try {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const status = await recordA2fTimeoutBlock(String((req.body && req.body.reason) || "a2f_timeout"));
      return res.status(200).json(status);
    } catch (error) {
      return res.status(error.statusCode || 500).json(error.lockStatus || {
        success: false,
        locked: true,
        error: error.message || "Gagal mencatat timeout A2F"
      });
    }
  }

  if (action === "recordA2fFailure") {
    try {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const current = await ensureA2fLockRow();
      const currentStatus = formatLockStatus(current);
      if (currentStatus.locked) return res.status(200).json(currentStatus);
      const status = await recordA2fFailure(String((req.body && req.body.reason) || "client_recorded_failure"));
      return res.status(200).json(status);
    } catch (error) {
      return res.status(error.statusCode || 500).json(error.lockStatus || {
        success: false,
        locked: true,
        error: error.message || "Gagal mencatat gagal A2F"
      });
    }
  }

  if (action === "recordA2fTimeoutMarker") {
    try {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const data = await ensureA2fLockRow();
      return res.status(200).json(formatLockStatus(data));
    } catch (error) {
      return res.status(error.statusCode || 500).json(error.lockStatus || {
        success: false,
        locked: true,
        error: error.message || "Gagal mencatat marker timeout A2F"
      });
    }
  }

  if (action === "resetA2fFailure") {
    try {
      await verifyAdminIdToken(req.body && req.body.idToken);
      const status = await resetA2fFailure();
      return res.status(200).json(status);
    } catch (error) {
      return res.status(error.statusCode || 500).json({
        success: false,
        error: error.message || "Gagal reset A2F"
      });
    }
  }

  if (action === "generate-recovery-codes") {
    try {
      const codes = await generateOneTimeRecoveryCodes(req.body || {});

      return res.status(200).json({
        success: true,
        action,
        codes,
        count: codes.length,
        message: "Recovery code sekali pakai berhasil dibuat. Simpan sekarang karena kode asli tidak disimpan di server."
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal membuat recovery code sekali pakai"
      });
    }
  }

  const stepNumber = Number(step);
  const allowedSteps = [2, 3, 6, 7, 8, 9, 10];

  if (!allowedSteps.includes(stepNumber)) {
    return res.status(400).json({
      success: false,
      error: "Step harus 2, 3, 6, 7, 8, 9, atau 10"
    });
  }

  try {
    await verifyAdminIdToken(req.body && req.body.idToken);
    await checkA2fLock();
  } catch (error) {
    return res.status(error.statusCode || 423).json(error.lockStatus || {
      success: false,
      locked: true,
      error: error.message || "A2F terkunci dari backend"
    });
  }

  const secret = getPublicMfaSecret();
  const code = crypto.randomInt(100000, 999999).toString();

  const payload = {
    step: stepNumber,
    flow: stepNumber >= 6 ? "face-recovery" : "normal",
    codeHash: hashCode(`${stepNumber}:${code}`, secret),
    expiresAt: Date.now() + 5 * 60 * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  };

  if (stepNumber === 3) {
    const sessionId = makeSession(payload, secret);

    try {
      await sendEmailOtp(code);

      return res.status(200).json({
        success: true,
        sessionId,
        step: 3,
        message: "Kode verifikasi berhasil disiapkan"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal menyiapkan kode verifikasi"
      });
    }
  }

  if (stepNumber === 6) {
    const sessionId = makeSession(payload, secret);

    try {
      await sendRecoveryEmailOtp(code, stepNumber);

      return res.status(200).json({
        success: true,
        sessionId,
        step: stepNumber,
        recoveryStep: 1,
        message: "Kode verifikasi berhasil disiapkan"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal menyiapkan kode verifikasi"
      });
    }
  }

  if (stepNumber === 7) {
    try {
      getRecoveryTotpSecret();

      const totpPayload = {
        ...payload,
        codeHash: hashCode(`${stepNumber}:recovery-totp`, secret)
      };
      const sessionId = makeSession(totpPayload, secret);

      return res.status(200).json({
        success: true,
        sessionId,
        step: stepNumber,
        recoveryStep: 2,
        message: "Kode verifikasi berhasil disiapkan"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal menyiapkan kode verifikasi"
      });
    }
  }

  if (stepNumber === 8 || stepNumber === 9) {
    try {
      const localRecovery = getRecoveryLocalCode(stepNumber);
      payload.codeHash = hashCode(`${stepNumber}:${localRecovery.code}`, secret);

      const sessionId = makeSession(payload, secret);

      return res.status(200).json({
        success: true,
        sessionId,
        step: stepNumber,
        recoveryStep: stepNumber - 5,
        message: "Kode verifikasi berhasil disiapkan"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal menyiapkan kode verifikasi"
      });
    }
  }

  if (stepNumber === 10) {
    payload.codeHash = hashCode(`${stepNumber}:prepared`, secret);

    const sessionId = makeSession(payload, secret);

    return res.status(200).json({
      success: true,
      sessionId,
      step: stepNumber,
      recoveryStep: 5,
      message: "Kode verifikasi berhasil disiapkan"
    });
  }

  const sessionId = makeSession(payload, secret);

  return res.status(200).json({
    success: true,
    sessionId,
    step: 2,
    message: "Kode verifikasi berhasil disiapkan"
  });
};
