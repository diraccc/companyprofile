const crypto = require("crypto");
const admin = require("firebase-admin");
const argon2 = require("argon2");
const nodemailer = require("nodemailer");
const { createClient } = require("@supabase/supabase-js");
const { generateRegistrationOptions, generateAuthenticationOptions } = require("@simplewebauthn/server");

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

const A2F_LOCKOUTS_TABLE = process.env.SUPABASE_A2F_LOCKOUTS_TABLE || "a2f_lockouts";
const A2F_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
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
    auth: { persistSession: false, autoRefreshToken: false }
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
  const decoded = await admin.auth().verifyIdToken(token);
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

function getStep3EmailTarget() {
  const email = String(
    process.env.A2F_STEP3_EMAIL ||
    process.env.A2F_APPROVAL_EMAIL ||
    process.env.A2F_ADMIN_EMAIL ||
    ""
  ).trim();

  if (!email) {
    throw new Error("A2F_STEP3_EMAIL/A2F_APPROVAL_EMAIL/A2F_ADMIN_EMAIL belum diset");
  }

  return email;
}

function maskEmailForResponse(email) {
  const text = String(email || "").trim();
  const at = text.indexOf("@");
  if (at <= 1) return text ? "***" : "";
  return `${text.slice(0, 2)}***${text.slice(at)}`;
}

function getStep3EmailContent(code) {
  const safeCode = String(code || "").replace(/[^0-9]/g, "");
  return {
    subject: "Kode A2F Tahap 3 Dirac Admin",
    htmlContent: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
        <h2>Kode A2F Tahap 3</h2>
        <p>Kode verifikasi kamu:</p>
        <div style="font-size:32px;font-weight:800;letter-spacing:5px;color:#111827">
          ${safeCode}
        </div>
        <p>Kode berlaku 5 menit.</p>
        <p>Jika kamu tidak login, abaikan email ini.</p>
      </div>
    `,
    textContent: `Kode A2F tahap 3 kamu adalah: ${safeCode}. Kode berlaku 5 menit.`
  };
}

function hasSmtpStep3Config() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

async function sendEmailOtpViaSmtp(code, targetEmail) {
  const host = String(process.env.SMTP_HOST || "").trim();
  const port = Number(process.env.SMTP_PORT || 465);
  const user = String(process.env.SMTP_USER || "").trim();
  const pass = String(process.env.SMTP_PASS || "");
  const fromName = String(process.env.SMTP_FROM_NAME || "Dirac Security").trim();

  if (!host || !user || !pass) {
    throw new Error("ENV SMTP belum lengkap untuk A2F tahap 3");
  }

  const content = getStep3EmailContent(code);
  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });

  const result = await transporter.sendMail({
    from: `"${fromName}" <${user}>`,
    to: targetEmail,
    subject: content.subject,
    text: content.textContent,
    html: content.htmlContent
  });

  return {
    provider: "smtp",
    messageId: result && result.messageId ? String(result.messageId) : ""
  };
}

async function sendEmailOtpViaBrevo(code, targetEmail) {
  const apiKey = String(process.env.BREVO_API_KEY || "").trim();
  const senderEmail = String(process.env.A2F_SENDER_EMAIL || process.env.DIRAC_SENDER_EMAIL || "").trim();
  const senderName = String(process.env.DIRAC_SENDER_NAME || "Dirac Admin").trim();

  if (!apiKey) throw new Error("BREVO_API_KEY belum diset");
  if (!senderEmail) throw new Error("A2F_SENDER_EMAIL atau DIRAC_SENDER_EMAIL belum diset");

  const content = getStep3EmailContent(code);
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: senderName,
        email: senderEmail
      },
      to: [
        {
          email: targetEmail,
          name: "Admin"
        }
      ],
      subject: content.subject,
      htmlContent: content.htmlContent,
      textContent: content.textContent
    })
  });

  const resultText = await response.text();

  if (!response.ok) {
    throw new Error(resultText || "Gagal kirim email OTP via Brevo");
  }

  return {
    provider: "brevo",
    response: resultText
  };
}

async function sendEmailOtp(code) {
  const targetEmail = getStep3EmailTarget();
  const preferredProvider = String(process.env.A2F_STEP3_EMAIL_PROVIDER || "smtp-first").trim().toLowerCase();
  const errors = [];

  async function trySmtp() {
    if (!hasSmtpStep3Config()) {
      throw new Error("SMTP belum dikonfigurasi");
    }
    return sendEmailOtpViaSmtp(code, targetEmail);
  }

  async function tryBrevo() {
    return sendEmailOtpViaBrevo(code, targetEmail);
  }

  const providers = preferredProvider === "brevo"
    ? [tryBrevo, trySmtp]
    : [trySmtp, tryBrevo];

  for (const provider of providers) {
    try {
      const result = await provider();
      return {
        ...result,
        sentTo: maskEmailForResponse(targetEmail)
      };
    } catch (error) {
      errors.push(error && error.message ? error.message : String(error));
    }
  }

  throw new Error(`Gagal kirim email A2F tahap 3. Detail: ${errors.join(" | ")}`);
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


/* =========================================================
   Dirac customer login MFA API bridge for masuk.html
   Additive only: does not alter legacy admin A2F step/hash/login flow.
   Supported frontend payloads:
   - POST /api/2fa/start-step { action:"setup"|"resend", method:"passkey"|"email"|"authenticator", identifier/email }
   - POST /api/2fa/start-step { action:"resend-email-verification", email } // Supabase Auth resend signup confirmation
   ========================================================= */
const DIRAC_CUSTOMER_MFA_TOKEN_TYPE = "dirac-customer-login-mfa-v1";
const DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS = Number(process.env.DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS || 5 * 60 * 1000);
const DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS = Number(process.env.DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS || 3 * 60 * 1000);
const DIRAC_CUSTOMER_MFA_OTP_DIGITS = 6;
const DIRAC_CUSTOMER_MFA_TOTP_BYTES = 20;
const DIRAC_CUSTOMER_MFA_RP_NAME = process.env.WEBAUTHN_RP_NAME || "Dirac Group";
const DIRAC_CUSTOMER_MFA_RP_ID = process.env.WEBAUTHN_RP_ID || "diracgroup.store";
const DIRAC_CUSTOMER_MFA_PROFILE_COLLECTION = process.env.DIRAC_CUSTOMER_MFA_RECOVERY_COLLECTION || "diracCustomerMfaProfiles";
const DIRAC_CUSTOMER_MFA_EMAIL_SUBJECT = process.env.DIRAC_CUSTOMER_MFA_EMAIL_SUBJECT || "Kode A2F Login Dirac Group";
const DIRAC_EMAIL_VERIFY_SUBJECT = process.env.DIRAC_EMAIL_VERIFY_SUBJECT || "Verifikasi email akun Dirac Group";
const DIRAC_PASSWORD_RESET_TOKEN_TYPE = "dirac-password-reset-v1";
const DIRAC_PASSWORD_RESET_CODE_DIGITS = 8;
const DIRAC_PASSWORD_RESET_TTL_MS = Number(process.env.DIRAC_PASSWORD_RESET_TTL_MS || 10 * 60 * 1000);
const DIRAC_PASSWORD_RESET_EMAIL_SUBJECT = process.env.DIRAC_PASSWORD_RESET_EMAIL_SUBJECT || "Kode reset password Dirac Group";

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

function diracBufferToBase64Url(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function diracRandomId(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function diracRandomDigitCode(length = DIRAC_CUSTOMER_MFA_OTP_DIGITS) {
  let out = "";
  while (out.length < length) out += String(crypto.randomInt(0, 10));
  return out;
}

function diracBase32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = Buffer.from(buffer);
  let bits = "";
  let out = "";

  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    out += alphabet[parseInt(chunk, 2)];
  }

  return out;
}

function diracBuildCustomerMfaToken(payload) {
  return makeSession({
    tokenType: DIRAC_CUSTOMER_MFA_TOKEN_TYPE,
    version: 1,
    createdAtMs: Date.now(),
    ...payload
  }, diracGetCustomerMfaSecret());
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

function diracMaskEmail(email) {
  email = diracNormalizeEmail(email);
  const [name, domain] = email.split("@");
  if (!name || !domain) return "email akun";
  return `${name.slice(0, 2)}***@${domain}`;
}

function diracBuildOtpAuthUrl({ email, secret }) {
  const issuer = process.env.WEBAUTHN_RP_NAME || "Dirac Group";
  const label = `${issuer}:${email}`;
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function diracBuildPasskeyPublicKeyOptions({ email, challenge }) {
  const userId = crypto
    .createHash("sha256")
    .update(`dirac-customer-passkey-user-v1:${email}`)
    .digest();

  return {
    challenge,
    rp: {
      name: DIRAC_CUSTOMER_MFA_RP_NAME,
      id: DIRAC_CUSTOMER_MFA_RP_ID
    },
    user: {
      id: diracBufferToBase64Url(userId),
      name: email,
      displayName: email
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 }
    ],
    timeout: DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "preferred"
    }
  };
}

async function diracSendBrevoMail({ to, subject, htmlContent, textContent }) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.A2F_SENDER_EMAIL || process.env.DIRAC_SENDER_EMAIL;
  const senderName = process.env.DIRAC_SENDER_NAME || "Dirac Group";

  if (!apiKey) throw new Error("BREVO_API_KEY belum diset");
  if (!senderEmail) throw new Error("A2F_SENDER_EMAIL atau DIRAC_SENDER_EMAIL belum diset");

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      sender: { name: senderName, email: senderEmail },
      to: [{ email: to, name: to.split("@")[0] || "Pelanggan" }],
      subject,
      htmlContent,
      textContent
    })
  });

  const result = await response.text();
  if (!response.ok) throw new Error(result || "Gagal mengirim email");
  return result;
}

async function diracSendCustomerMfaEmailOtp(email, code) {
  const safeEmail = diracAssertEmail(email);
  const safeCode = String(code || "").replace(/\D+/g, "");

  await diracSendBrevoMail({
    to: safeEmail,
    subject: DIRAC_CUSTOMER_MFA_EMAIL_SUBJECT,
    htmlContent: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
        <h2>Kode A2F Login Dirac Group</h2>
        <p>Masukkan kode berikut di halaman masuk:</p>
        <div style="font-size:30px;font-weight:800;letter-spacing:6px;padding:14px 16px;background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;display:inline-block">${safeCode}</div>
        <p>Kode berlaku 5 menit dan hanya untuk proses login yang baru saja dimulai.</p>
        <p>Jika kamu tidak sedang masuk, abaikan email ini dan segera amankan akun.</p>
      </div>
    `,
    textContent: `Kode A2F Login Dirac Group kamu adalah ${safeCode}. Kode berlaku 5 menit.`
  });
}

function diracSupabaseUserEmail(user) {
  const row = user && typeof user === "object" ? user : {};
  return diracNormalizeEmail(row.email || (row.user && row.user.email) || "");
}

function diracIsSupabaseEmailConfirmed(user) {
  const row = user && typeof user === "object" ? user : {};
  return Boolean(row.email_confirmed_at || row.confirmed_at || row.emailConfirmedAt || row.emailVerified === true);
}

async function diracFindSupabaseUserByEmail(email) {
  const supabase = getDomainSupabaseAdmin();
  const targetEmail = diracAssertEmail(email);
  const perPage = Math.max(1, Math.min(1000, Number(process.env.DIRAC_SUPABASE_USER_SCAN_PER_PAGE || 1000)));
  const maxPages = Math.max(1, Math.min(50, Number(process.env.DIRAC_SUPABASE_USER_SCAN_MAX_PAGES || 10)));

  for (let page = 1; page <= maxPages; page += 1) {
    const { data, error } = await supabase.auth.admin.listUsers({ page, perPage });

    if (error) {
      error.statusCode = error.status || 500;
      throw error;
    }

    const users = Array.isArray(data && data.users)
      ? data.users
      : (Array.isArray(data) ? data : []);

    const matched = users.find((user) => diracSupabaseUserEmail(user) === targetEmail);
    if (matched) return matched;

    if (users.length < perPage) break;
  }

  return null;
}

async function diracResendEmailVerification(req, res) {
  try {
    const email = diracAssertEmail((req.body && (req.body.email || req.body.identifier)) || "");
    const supabase = getDomainSupabaseAdmin();
    const user = await diracFindSupabaseUserByEmail(email);

    if (!user) {
      return res.status(404).json({
        ok: false,
        success: false,
        sent: false,
        provider: "supabase",
        error: "Email belum terdaftar di Supabase Auth. Verifikasi tidak dikirim."
      });
    }

    if (diracIsSupabaseEmailConfirmed(user)) {
      return res.status(409).json({
        ok: false,
        success: false,
        sent: false,
        provider: "supabase",
        error: "Email akun ini sudah terverifikasi di Supabase. Silakan masuk seperti biasa."
      });
    }

    const continueUrl = process.env.A2F_EMAIL_VERIFY_CONTINUE_URL || process.env.SUPABASE_AUTH_CONTINUE_URL || "https://diracgroup.store/masuk.html";
    const { error } = await supabase.auth.resend({
      type: "signup",
      email,
      options: {
        emailRedirectTo: continueUrl
      }
    });

    if (error) {
      error.statusCode = error.status || 500;
      throw error;
    }

    return res.status(200).json({
      ok: true,
      success: true,
      sent: true,
      provider: "supabase",
      email: diracMaskEmail(email),
      message: "Email verifikasi Supabase sudah dikirim ulang. Silakan cek inbox/spam dan gunakan email terbaru."
    });
  } catch (error) {
    const rawMessage = String((error && (error.message || error.error_description || error.msg)) || "");
    const notFound = /not found|not exist|not registered|user.*not|no user/i.test(rawMessage);
    const code = notFound ? 404 : (error.statusCode || error.status || 500);

    return res.status(code).json({
      ok: false,
      success: false,
      sent: false,
      provider: "supabase",
      error: code === 404 ? "Email belum terdaftar di Supabase Auth. Verifikasi tidak dikirim." : (rawMessage || "Gagal mengirim verifikasi email Supabase.")
    });
  }
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

function diracBuildPasswordResetToken(payload) {
  return makeSession({
    tokenType: DIRAC_PASSWORD_RESET_TOKEN_TYPE,
    version: 1,
    purpose: "password-reset",
    createdAtMs: Date.now(),
    ...payload
  }, diracGetCustomerMfaSecret());
}

async function diracSendPasswordResetEmail(email, code) {
  const safeEmail = diracAssertEmail(email);
  const safeCode = String(code || "").replace(/\D+/g, "");

  if (!/^\d{8}$/.test(safeCode)) {
    const err = new Error("Kode reset internal tidak valid.");
    err.statusCode = 500;
    throw err;
  }

  await diracSendBrevoMail({
    to: safeEmail,
    subject: DIRAC_PASSWORD_RESET_EMAIL_SUBJECT,
    htmlContent: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
        <h2>Kode Reset Password Dirac Group</h2>
        <p>Masukkan kode 8 digit berikut di halaman lupa password:</p>
        <div style="font-size:30px;font-weight:800;letter-spacing:6px;padding:14px 16px;background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;display:inline-block">${safeCode}</div>
        <p>Kode berlaku singkat dan hanya untuk permintaan reset password terbaru.</p>
        <p>Jika kamu tidak meminta reset password, abaikan email ini dan segera amankan akun.</p>
      </div>
    `,
    textContent: `Kode reset password Dirac Group kamu adalah ${safeCode}. Kode berlaku singkat dan hanya untuk permintaan terbaru.`
  });
}

async function diracHandlePasswordResetRequest(req, res) {
  try {
    const email = diracAssertEmail((req.body && (req.body.email || req.body.identifier)) || "");
    const user = await diracFindSupabaseUserByEmail(email);

    if (!user || !user.id) {
      return res.status(404).json({
        ok: false,
        success: false,
        sent: false,
        provider: "supabase",
        error: "Email belum terdaftar di Supabase Auth. Kode reset tidak dikirim."
      });
    }

    const now = Date.now();
    const nonce = diracRandomId(24);
    const code = diracRandomDigitCode(DIRAC_PASSWORD_RESET_CODE_DIGITS);
    const expiresAtMs = now + DIRAC_PASSWORD_RESET_TTL_MS;
    const resetToken = diracBuildPasswordResetToken({
      email,
      userId: String(user.id),
      nonce,
      codeHash: diracHashPasswordResetCode({ email, userId: user.id, code, nonce }),
      expiresAtMs
    });

    await diracSendPasswordResetEmail(email, code);

    return res.status(200).json({
      ok: true,
      success: true,
      sent: true,
      provider: "supabase",
      email: diracMaskEmail(email),
      resetToken,
      token: resetToken,
      expiresAtMs,
      ttlSeconds: Math.floor(DIRAC_PASSWORD_RESET_TTL_MS / 1000),
      message: "Kode reset 8 digit sudah dikirim. Cek email lalu masukkan password baru."
    });
  } catch (error) {
    const rawMessage = String((error && (error.message || error.error_description || error.msg)) || "");
    const notFound = /not found|not exist|not registered|user.*not|no user/i.test(rawMessage);
    const code = notFound ? 404 : (error.statusCode || error.status || 500);

    return res.status(code).json({
      ok: false,
      success: false,
      sent: false,
      provider: "supabase",
      error: code === 404 ? "Email belum terdaftar di Supabase Auth. Kode reset tidak dikirim." : (rawMessage || "Gagal mengirim kode reset password.")
    });
  }
}


function diracMfaProfileId(email) {
  return hashCode(`dirac-customer-mfa-profile-v1:${diracNormalizeEmail(email)}`, diracGetCustomerMfaSecret());
}

async function diracReadCustomerMfaProfile(email) {
  const db = getFirebaseDb();
  const snap = await db.collection(DIRAC_CUSTOMER_MFA_PROFILE_COLLECTION).doc(diracMfaProfileId(email)).get();
  if (!snap.exists) return null;
  return { id: snap.id, ...(snap.data() || {}) };
}

function diracAllowedOriginsForCustomerMfa() {
  return String(process.env.A2F_ALLOWED_ORIGINS || "https://diracgroup.store,https://www.diracgroup.store,https://companyprofilee-expk.vercel.app")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function diracPasskeyCredentialFromProfile(profile) {
  const row = profile && typeof profile === "object" ? profile : {};
  const id = String(row.passkeyCredentialId || "").trim();
  const publicKey = String(row.passkeyPublicKey || "").trim();
  if (!id || !publicKey || row.enabled !== true) return null;
  return {
    id,
    type: "public-key",
    transports: Array.isArray(row.passkeyTransports) ? row.passkeyTransports : []
  };
}

async function diracBuildCustomerPasskeyStart({ email, now, nonce }) {
  const profile = await diracReadCustomerMfaProfile(email).catch((error) => {
    error.statusCode = error.statusCode || error.status || 500;
    throw error;
  });
  const existingCredential = diracPasskeyCredentialFromProfile(profile);

  if (existingCredential) {
    const options = await generateAuthenticationOptions({
      rpID: DIRAC_CUSTOMER_MFA_RP_ID,
      userVerification: "preferred",
      allowCredentials: [existingCredential]
    });
    const setupToken = diracBuildCustomerMfaToken({
      method: "passkey",
      email,
      nonce,
      challenge: options.challenge,
      rpId: DIRAC_CUSTOMER_MFA_RP_ID,
      credentialId: existingCredential.id,
      allowedOrigins: diracAllowedOriginsForCustomerMfa(),
      expiresAtMs: now + DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS,
      purpose: "passkey-authentication-login-mfa"
    });

    return {
      ok: true,
      success: true,
      method: "passkey",
      passkeyMode: "authentication",
      needsRegistration: false,
      setupToken,
      mfaSetupToken: setupToken,
      token: setupToken,
      publicKey: options,
      expiresAtMs: now + DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS,
      ttlSeconds: Math.floor(DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS / 1000),
      message: "Passkey tersimpan ditemukan. Lanjutkan verifikasi perangkat."
    };
  }

  const options = await generateRegistrationOptions({
    rpName: DIRAC_CUSTOMER_MFA_RP_NAME,
    rpID: DIRAC_CUSTOMER_MFA_RP_ID,
    userName: email,
    userID: crypto.createHash("sha256").update(`dirac-customer-passkey-user-v1:${email}`).digest(),
    userDisplayName: email,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "preferred"
    },
    timeout: DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS
  });
  const setupToken = diracBuildCustomerMfaToken({
    method: "passkey",
    email,
    nonce,
    challenge: options.challenge,
    rpId: DIRAC_CUSTOMER_MFA_RP_ID,
    allowedOrigins: diracAllowedOriginsForCustomerMfa(),
    expiresAtMs: now + DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS,
    purpose: "passkey-registration-login-mfa"
  });

  return {
    ok: true,
    success: true,
    method: "passkey",
    passkeyMode: "registration",
    needsRegistration: true,
    setupToken,
    mfaSetupToken: setupToken,
    token: setupToken,
    publicKey: options,
    expiresAtMs: now + DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS,
    ttlSeconds: Math.floor(DIRAC_CUSTOMER_MFA_PASSKEY_TTL_MS / 1000),
    message: "Belum ada passkey tersimpan. Daftarkan passkey perangkat ini sekali saja."
  };
}

async function diracHandleCustomerMfaStart(req, res) {
  try {
    const action = String((req.body && req.body.action) || "").trim().toLowerCase();
    const method = diracNormalizeMfaMethod(req.body && req.body.method);
    const email = diracAssertEmail((req.body && (req.body.identifier || req.body.email)) || "");
    const now = Date.now();
    const nonce = diracRandomId(24);

    if (method === "email") {
      const code = diracRandomDigitCode();
      const setupToken = diracBuildCustomerMfaToken({
        method,
        email,
        nonce,
        codeHash: diracHashCustomerMfaCode({ method, email, code, nonce }),
        expiresAtMs: now + DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS,
        purpose: "email-otp-login-mfa"
      });

      await diracSendCustomerMfaEmailOtp(email, code);

      return res.status(200).json({
        ok: true,
        success: true,
        sent: true,
        method,
        setupToken,
        mfaSetupToken: setupToken,
        token: setupToken,
        expiresAtMs: now + DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS,
        ttlSeconds: Math.floor(DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS / 1000),
        message: action === "resend" ? "Kode email baru sudah dikirim." : "Kode email sudah dikirim."
      });
    }

    if (method === "authenticator") {
      const totpSecret = diracBase32Encode(crypto.randomBytes(DIRAC_CUSTOMER_MFA_TOTP_BYTES));
      const setupToken = diracBuildCustomerMfaToken({
        method,
        email,
        nonce,
        totpSecret,
        expiresAtMs: now + DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS,
        purpose: "authenticator-setup-login-mfa"
      });

      return res.status(200).json({
        ok: true,
        success: true,
        method,
        setupToken,
        mfaSetupToken: setupToken,
        token: setupToken,
        manualKey: totpSecret,
        secret: totpSecret,
        otpAuthUrl: diracBuildOtpAuthUrl({ email, secret: totpSecret }),
        expiresAtMs: now + DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS,
        ttlSeconds: Math.floor(DIRAC_CUSTOMER_MFA_TOKEN_TTL_MS / 1000),
        message: action === "resend" ? "Setup key Authenticator baru sudah disiapkan." : "Setup key Authenticator berhasil disiapkan."
      });
    }

    const passkeyStart = await diracBuildCustomerPasskeyStart({ email, now, nonce });
    return res.status(200).json(passkeyStart);
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      ok: false,
      success: false,
      error: error.message || "Gagal menyiapkan A2F login."
    });
  }
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

  const { step, action } = req.body || {};

  const normalizedAction = String(action || "").trim().toLowerCase();

  if (normalizedAction === "setup" || normalizedAction === "resend") {
    return diracHandleCustomerMfaStart(req, res);
  }

  if (normalizedAction === "request-password-reset") {
    return diracHandlePasswordResetRequest(req, res);
  }

  if (normalizedAction === "resend-email-verification") {
    return diracResendEmailVerification(req, res);
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

  const secret = getA2fSecretForRecoveryCodeGeneration();
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
      const emailResult = await sendEmailOtp(code);

      return res.status(200).json({
        success: true,
        sessionId,
        step: 3,
        emailProvider: emailResult && emailResult.provider ? emailResult.provider : "unknown",
        sentTo: emailResult && emailResult.sentTo ? emailResult.sentTo : "",
        message: "Kode verifikasi berhasil dikirim"
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
