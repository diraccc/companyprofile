const crypto = require("crypto");
const admin = require("firebase-admin");
const argon2 = require("argon2");
const nodemailer = require("nodemailer");

const ONE_TIME_RECOVERY_RANDOM_LENGTH = 50;
const ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32
});

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

function hashCode(code, secret) {
  return crypto.createHmac("sha256", secret).update(String(code)).digest("hex");
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

function randomDigitCode(length = 60) {
  let out = "";
  while (out.length < length) {
    out += String(crypto.randomInt(0, 10));
  }
  return out;
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

function getOneTimeRecoveryLookupHash(code, secret) {
  const normalized = normalizeOneTimeRecoveryCode(code);
  return crypto.createHmac("sha256", secret).update(`one-time-recovery-lookup:${normalized}`).digest("hex");
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

async function consumeOneTimeRecoveryCode(code, secret, idToken) {
  const normalized = normalizeOneTimeRecoveryCode(code);

  if (!new RegExp(`^DGRCV[A-Z2-9]{${ONE_TIME_RECOVERY_RANDOM_LENGTH}}$`).test(normalized)) {
    return { ok: false, reason: "format" };
  }

  const decoded = await verifyAdminIdToken(idToken);
  const db = getFirebaseDb();
  const lookupHash = getOneTimeRecoveryLookupHash(normalized, secret);
  const ref = db.collection("a2fRecoveryCodes").doc(lookupHash);
  const now = Date.now();
  const snap = await ref.get();

  if (!snap.exists) {
    return { ok: false, reason: "not-found" };
  }

  const firstRead = snap.data() || {};

  if (firstRead.revoked === true) {
    return { ok: false, reason: "revoked" };
  }

  if (firstRead.used === true) {
    return { ok: false, reason: "used" };
  }

  if (firstRead.hashType !== "argon2id" || !(await verifyOneTimeRecoveryArgon2id(normalized, firstRead.argon2Hash))) {
    return { ok: false, reason: "not-found" };
  }

  let result = { ok: false, reason: "not-found" };

  await db.runTransaction(async (tx) => {
    const txSnap = await tx.get(ref);

    if (!txSnap.exists) {
      result = { ok: false, reason: "not-found" };
      return;
    }

    const data = txSnap.data() || {};

    if (data.revoked === true) {
      result = { ok: false, reason: "revoked" };
      return;
    }

    if (data.used === true) {
      result = { ok: false, reason: "used" };
      return;
    }

    if (data.hashType !== "argon2id" || data.argon2Hash !== firstRead.argon2Hash) {
      result = { ok: false, reason: "not-found" };
      return;
    }

    tx.set(ref, {
      used: true,
      usedAtMs: now,
      usedAt: admin.firestore.FieldValue.serverTimestamp(),
      usedByUid: decoded.uid,
      usedByEmail: decoded.email || process.env.A2F_ADMIN_EMAIL || ""
    }, { merge: true });

    result = { ok: true };
  });

  return result;
}

function getLockMessage(lockUntilMs) {
  const remainingMs = Math.max(0, Number(lockUntilMs || 0) - Date.now());
  const remainingSeconds = Math.ceil(remainingMs / 1000);
  const minutes = Math.floor(remainingSeconds / 60);
  const seconds = remainingSeconds % 60;

  if (minutes > 0) {
    return `A2F terkunci. Coba lagi dalam ${minutes} menit ${seconds} detik.`;
  }

  return `A2F terkunci. Coba lagi dalam ${seconds} detik.`;
}

async function checkA2fLock() {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const ref = db.collection("a2fLockouts").doc(uid);
  const snap = await ref.get();

  if (!snap.exists) {
    await ref.set({
      uid,
      email: process.env.A2F_ADMIN_EMAIL || "",
      failedCount: 0,
      lockUntilMs: 0,
      permanentBan: false,
      lastFailedAtMs: 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return;
  }

  const data = snap.data() || {};

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
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const ref = db.collection("a2fLockouts").doc(uid);

  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? snap.data() || {} : {};
    const failedCount = Number(data.failedCount || 0) + 1;
    const now = Date.now();

    const nextData = {
      uid,
      email: process.env.A2F_ADMIN_EMAIL || data.email || "",
      failedCount,
      lastFailedAtMs: now,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (failedCount >= 3) {
      nextData.permanentBan = true;
      nextData.lockUntilMs = 0;
    } else if (failedCount === 2) {
      nextData.permanentBan = false;
      nextData.lockUntilMs = now + 30 * 60 * 1000;
    } else {
      nextData.permanentBan = false;
      nextData.lockUntilMs = now + 60 * 1000;
    }

    tx.set(ref, nextData, { merge: true });

    return nextData;
  });
}

async function resetA2fFailure() {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const ref = db.collection("a2fLockouts").doc(uid);

  await ref.set({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 0,
    lockUntilMs: 0,
    permanentBan: false,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
}


async function recordPermanentBan(reason) {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const now = Date.now();

  await db.collection("a2fLockouts").doc(uid).set({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 999,
    lockUntilMs: 0,
    permanentBan: true,
    permanentBanReason: reason,
    bannedAtMs: now,
    bannedAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
}

async function sendWrongCodeResponse(res) {
  const lockData = await recordA2fFailure();

  if (lockData.permanentBan === true) {
    return res.status(403).json({
      success: false,
      error: "Kode salah. A2F diblokir permanen karena salah kode 3x.",
      failedCount: lockData.failedCount,
      permanentBan: true
    });
  }

  return res.status(401).json({
    success: false,
    error: getLockMessage(lockData.lockUntilMs),
    failedCount: lockData.failedCount,
    lockUntilMs: lockData.lockUntilMs
  });
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

async function sendStep6Email({ requestId, approveToken, denyToken, emailCode, email }) {
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
    `&token=${encodeURIComponent(approveToken)}`;

  const denyUrl =
    `${baseUrl}/api/2fa/verify-step?action=denyStep6` +
    `&requestId=${encodeURIComponent(requestId)}` +
    `&token=${encodeURIComponent(denyToken)}`;

  const groupedCode = String(emailCode || "").replace(/(\d{6})(?=\d)/g, "$1 ");
  const subject = "SETUJUI Login Admin Dirac + Kode 60 Digit";

  const text =
`Ada percobaan login ke Admin Dirac.

LANGKAH 1:
Klik SETUJUI dulu:
${approveUrl}

LANGKAH 2:
Kembali ke dashboard admin, lalu masukkan kode 60 digit ini:

${groupedCode}

Salah 1x akan membuat A2F diblokir permanen.

Jika ini bukan kamu, klik TOLAK & BAN PERMANEN:
${denyUrl}`;

  const html =
`<div style="font-family:Arial,sans-serif;line-height:1.5;color:#111">
  <h2>Persetujuan Login Admin Dirac</h2>
  <p>Ada percobaan login ke Admin Dirac.</p>
  <ol>
    <li>Klik <b>SETUJUI LOGIN</b> dulu.</li>
    <li>Kembali ke dashboard admin.</li>
    <li>Masukkan kode 60 digit di bawah ini ke dashboard admin.</li>
  </ol>
  <p>
    <a href="${approveUrl}" style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;padding:13px 20px;border-radius:999px;font-weight:700">SETUJUI LOGIN</a>
  </p>
  <p>Kode <b>60 digit</b> untuk dimasukkan ke dashboard admin:</p>
  <div style="font-size:22px;font-weight:800;letter-spacing:2px;line-height:1.7;padding:14px 18px;background:#eef6ff;border-radius:12px;word-break:break-all">${groupedCode}</div>
  <p style="padding:12px;border-radius:12px;background:#fff7ed;color:#9a3412"><b>Penting:</b> salah 1x akan membuat A2F diblokir permanen.</p>
  <p>
    <a href="${denyUrl}" style="display:inline-block;background:#dc2626;color:#fff;text-decoration:none;padding:12px 18px;border-radius:999px;font-weight:700">TOLAK & BAN PERMANEN</a>
  </p>
  <p style="color:#666;font-size:13px">Jika ini bukan kamu, klik TOLAK. Jika email ini sudah lama, abaikan.</p>
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

  const { idToken } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const requestId = randomId(18);
  const approveToken = randomId(32);
  const denyToken = randomId(32);
  const screenCode = randomDigitCode(60);
  const screenCodeArgon2Hash = await argon2.hash(screenCode, ARGON2ID_OPTIONS);
  const now = Date.now();
  const expiresAtMs = now + 20 * 1000;

  const ref = db.collection("a2fEmailApprovals").doc(requestId);

  await ref.set({
    uid: decoded.uid,
    email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
    status: "pending_email_approval",
    screenCodeHashType: "argon2id",
    screenCodeArgon2Hash,
    approveTokenHash: hashCode(`step6-approve:${requestId}:${approveToken}`, secret),
    denyTokenHash: hashCode(`step6-deny:${requestId}:${denyToken}`, secret),
    failedCodeCount: 0,
    createdAtMs: now,
    expiresAtMs,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: false });

  await sendStep6Email({
    requestId,
    approveToken,
    denyToken,
    emailCode: screenCode,
    email: decoded.email || ""
  });

  return res.status(200).json({
    success: true,
    requestId,
    status: "pending_email_approval",
    expiresAtMs,
    message: "Kode 60 digit sudah dikirim ke email. Hash disimpan sebagai Argon2id."
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

  if (Date.now() > Number(data.expiresAtMs || 0) && data.status !== "approved") {
    await snap.ref.set({
      status: "expired",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return res.status(408).json({
      success: false,
      status: "expired",
      error: "Waktu approval habis. Login ulang."
    });
  }

  if (String(data.status || "") === "denied_permanent_ban" || String(data.status || "").startsWith("permanent_ban")) {
    return res.status(403).json({
      success: false,
      status: data.status,
      permanentBan: true,
      error: "Step 6 ditolak. A2F diblokir permanen."
    });
  }

  return res.status(200).json({
    success: true,
    status: data.status || "unknown",
    expiresAtMs: data.expiresAtMs || 0
  });
}

async function submitStep6ScreenCode(req, res) {
  await checkA2fLock();

  const { idToken, requestId, code } = req.body || {};
  await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const ref = db.collection("a2fEmailApprovals").doc(String(requestId || ""));
  const snap = await ref.get();

  if (!snap.exists) {
    return res.status(404).json({
      success: false,
      error: "Request approval tidak ditemukan"
    });
  }

  const data = snap.data() || {};

  if (Date.now() > Number(data.expiresAtMs || 0)) {
    await ref.set({
      status: "expired",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return res.status(408).json({
      success: false,
      status: "expired",
      error: "Waktu approval habis. Login ulang."
    });
  }

  if (String(data.status || "") === "approved") {
    return res.status(200).json({
      success: true,
      status: "approved",
      message: "Step 6 sudah disetujui."
    });
  }

  if (String(data.status || "") === "denied_permanent_ban" || String(data.status || "").startsWith("permanent_ban")) {
    return res.status(403).json({
      success: false,
      status: data.status,
      permanentBan: true,
      error: "Step 6 ditolak. A2F diblokir permanen."
    });
  }

  if (String(data.status || "") !== "approved_waiting_code") {
    return res.status(409).json({
      success: false,
      status: data.status || "unknown",
      error: "Klik SETUJUI di email dulu, baru masukkan kode 60 digit."
    });
  }

  const inputCode = String(code || "").replace(/\D+/g, "");

  if (!inputCode) {
    return res.status(400).json({
      success: false,
      error: "Kode 60 digit wajib diisi."
    });
  }

  const step6CodeOk = inputCode.length === 60 && await verifyStep6Argon2idCode(inputCode, data.screenCodeArgon2Hash);

  if (!step6CodeOk) {
    await ref.set({
      status: "permanent_ban_wrong_code",
      failedCodeCount: Number(data.failedCodeCount || 0) + 1,
      wrongCodeAtMs: Date.now(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await recordPermanentBan("step6_wrong_60_digit_email_code_argon2id");

    return res.status(403).json({
      success: false,
      status: "permanent_ban_wrong_code",
      permanentBan: true,
      error: "Kode step 6 salah. A2F diblokir permanen."
    });
  }

  await ref.set({
    status: "approved",
    approvedFinalAtMs: Date.now(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  await resetA2fFailure();

  return res.status(200).json({
    success: true,
    status: "approved",
    message: "Kode 60 digit benar. Dashboard boleh dibuka.",
    nextStep: 7
  });
}

async function approveStep6FromEmail(req, res) {
  try {
    await checkA2fLock();

    const requestId = String((req.query && req.query.requestId) || "");
    const token = String((req.query && req.query.token) || "");
    const secret = process.env.A2F_SECRET || "rahasia-test";

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await ref.set({
        status: "expired",
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return res.status(408).send(htmlPage("Approval expired", "<p>Waktu approval sudah habis. Silakan login ulang.</p>"));
    }

    const tokenHash = hashCode(`step6-approve:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.approveTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link approval tidak valid.</p>"));
    }

    if (data.status === "pending_email_approval") {
      await ref.set({
        status: "approved_waiting_code",
        emailApprovedAtMs: Date.now(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }

    return res.status(200).send(htmlPage(
      "Login disetujui",
      "<p>Email sudah disetujui. Sekarang kembali ke dashboard admin dan masukkan kode 60 digit yang ada di email.</p><div class=\"warn\">Jangan salah: salah 1x akan ban permanen.</div>"
    ));
  } catch (error) {
    return res.status(error.statusCode || 500).send(htmlPage(
      "Approval gagal",
      `<p>${escapeHtml(error.publicMessage || error.message || "Gagal menyetujui login.")}</p>`
    ));
  }
}

async function confirmApproveStep6FromEmail(req, res) {
  try {
    await checkA2fLock();

    const requestId = String((req.query && req.query.requestId) || "");
    const token = String((req.query && req.query.token) || "");
    const inputCode = String((req.query && req.query.code) || "").replace(/\D+/g, "");
    const secret = process.env.A2F_SECRET || "rahasia-test";

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await ref.set({
        status: "expired",
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return res.status(408).send(htmlPage("Approval expired", "<p>Waktu approval sudah habis. Silakan login ulang.</p>"));
    }

    const tokenHash = hashCode(`step6-approve:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.approveTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link approval tidak valid.</p>"));
    }

    if (data.status !== "approved_waiting_code" && data.status !== "pending_email_approval") {
      return res.status(409).send(htmlPage("Status tidak valid", `<p>Status login saat ini: ${escapeHtml(data.status || "unknown")}</p>`));
    }

    const step6CodeOk = inputCode.length === 60 && await verifyStep6Argon2idCode(inputCode, data.screenCodeArgon2Hash);

    if (!step6CodeOk) {
      await ref.set({
        status: "permanent_ban_wrong_code",
        failedCodeCount: Number(data.failedCodeCount || 0) + 1,
        wrongCodeAtMs: Date.now(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      await recordPermanentBan("step6_wrong_60_digit_code_argon2id");

      return res.status(403).send(htmlPage(
        "Kode salah",
        "<p>Kode salah. A2F diblokir permanen. Reset hanya bisa lewat secret admin.</p>"
      ));
    }

    await ref.set({
      status: "approved",
      approvedFinalAtMs: Date.now(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await resetA2fFailure();

    return res.status(200).send(htmlPage(
      "Login disetujui",
      "<p>Kode cocok. Kembali ke halaman admin. Dashboard akan terbuka otomatis.</p>"
    ));
  } catch (error) {
    return res.status(error.statusCode || 500).send(htmlPage(
      "Approval gagal",
      `<p>${escapeHtml(error.publicMessage || error.message || "Gagal menyetujui login.")}</p>`
    ));
  }
}

async function denyStep6FromEmail(req, res) {
  try {
    const requestId = String((req.query && req.query.requestId) || "");
    const token = String((req.query && req.query.token) || "");
    const secret = process.env.A2F_SECRET || "rahasia-test";

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};
    const tokenHash = hashCode(`step6-deny:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.denyTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link penolakan tidak valid.</p>"));
    }

    await ref.set({
      status: "denied_permanent_ban",
      deniedAtMs: Date.now(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await recordPermanentBan("step6_email_denied");

    return res.status(200).send(htmlPage(
      "Login ditolak",
      "<p>Login sudah ditolak dan A2F diblokir permanen. Reset hanya bisa lewat secret admin.</p>"
    ));
  } catch (error) {
    return res.status(error.statusCode || 500).send(htmlPage(
      "Penolakan gagal",
      `<p>${escapeHtml(error.publicMessage || error.message || "Gagal menolak login.")}</p>`
    ));
  }
}


async function checkA2fBanStatus(req, res) {
  const { idToken } = req.body || {};
  await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const uid = getAdminUid();
  const snap = await db.collection("a2fLockouts").doc(uid).get();
  const data = snap.exists ? snap.data() || {} : {};
  const lockUntilMs = Number(data.lockUntilMs || 0);
  const permanentBan = data.permanentBan === true;
  const locked = permanentBan || lockUntilMs > Date.now();

  return res.status(200).json({
    success: true,
    locked,
    permanentBan,
    failedCount: Number(data.failedCount || 0),
    lockUntilMs,
    permanentBanReason: data.permanentBanReason || data.reason || "",
    error: permanentBan
      ? "A2F diblokir permanen dari backend."
      : (lockUntilMs > Date.now() ? getLockMessage(lockUntilMs) : "")
  });
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method === "GET") {
    const action = String((req.query && req.query.action) || "");

    if (action === "approveStep6") return approveStep6FromEmail(req, res);
    if (action === "confirmApproveStep6") return confirmApproveStep6FromEmail(req, res);
    if (action === "denyStep6") return denyStep6FromEmail(req, res);

    return res.status(405).send(htmlPage("Method tidak diizinkan", "<p>Endpoint ini hanya menerima link approval A2F.</p>"));
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  try {
    const action = String((req.body && req.body.action) || "").trim();

    if (action === "checkA2fBanStatus") return checkA2fBanStatus(req, res);

    if (action === "startStep6EmailApproval") return startStep6EmailApproval(req, res);
    if (action === "checkStep6EmailApproval") return checkStep6EmailApproval(req, res);
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

    const secret = process.env.A2F_SECRET || "rahasia-test";
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
