const crypto = require("crypto");
const admin = require("firebase-admin");
const argon2 = require("argon2");

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
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
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
    err.publicMessage = "A2F diblokir permanen karena salah kode 3x.";
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

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  try {
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
