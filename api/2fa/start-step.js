const crypto = require("crypto");
const admin = require("firebase-admin");
const argon2 = require("argon2");
const { createClient } = require("@supabase/supabase-js");

const ONE_TIME_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ONE_TIME_RECOVERY_RANDOM_LENGTH = 50;
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
  res.setHeader("Access-Control-Allow-Origin", "*");
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

function getOneTimeRecoveryLookupHash(code, secret) {
  const normalized = normalizeOneTimeRecoveryCode(code);
  return crypto.createHmac("sha256", secret).update(`one-time-recovery-lookup:${normalized}`).digest("hex");
}

async function hashOneTimeRecoveryCodeArgon2id(code) {
  const normalized = normalizeOneTimeRecoveryCode(code);
  return argon2.hash(normalized, ARGON2ID_OPTIONS);
}

function generateRandomRecoveryBody(length = ONE_TIME_RECOVERY_RANDOM_LENGTH) {
  const bytes = crypto.randomBytes(length);
  let body = "";

  for (const byte of bytes) {
    body += ONE_TIME_RECOVERY_ALPHABET[byte & 31];
  }

  return body;
}

function formatOneTimeRecoveryCode(body) {
  const groups = String(body).match(/.{1,5}/g) || [];
  return `DG-RCV-${groups.join("-")}`;
}

function generateOneTimeRecoveryCode() {
  return formatOneTimeRecoveryCode(generateRandomRecoveryBody());
}

async function generateOneTimeRecoveryCodes(reqBody) {
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const decoded = await verifyAdminIdToken(reqBody && reqBody.idToken);
  verifyRecentAdminAuth(decoded);
  verifySensitiveTotpCode(reqBody && reqBody.sensitiveTotpCode);
  const countRaw = Number(reqBody && reqBody.count);
  const count = Number.isFinite(countRaw) ? Math.min(20, Math.max(1, Math.floor(countRaw))) : 10;
  const db = getFirebaseDb();
  const batch = db.batch();
  const codes = [];
  const now = Date.now();

  while (codes.length < count) {
    const code = generateOneTimeRecoveryCode();
    const lookupHash = getOneTimeRecoveryLookupHash(code, secret);
    const argon2Hash = await hashOneTimeRecoveryCodeArgon2id(code);
    const ref = db.collection("a2fRecoveryCodes").doc(lookupHash);

    codes.push(code);
    batch.set(ref, {
      lookupHash,
      argon2Hash,
      hashType: "argon2id",
      hashParams: {
        memoryCost: ARGON2ID_OPTIONS.memoryCost,
        timeCost: ARGON2ID_OPTIONS.timeCost,
        parallelism: ARGON2ID_OPTIONS.parallelism,
        hashLength: ARGON2ID_OPTIONS.hashLength
      },
      codeFormat: "DG-RCV-10x5",
      randomLength: ONE_TIME_RECOVERY_RANDOM_LENGTH,
      used: false,
      revoked: false,
      label: `Recovery code ${codes.length}`,
      codePreview: code.slice(-5),
      createdByUid: decoded.uid,
      createdByEmail: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      createdAtMs: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      usedAtMs: null,
      usedAt: null,
      usedByUid: null,
      usedByEmail: null
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

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const { step, action } = req.body || {};

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

  const secret = process.env.A2F_SECRET || "rahasia-test";
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
