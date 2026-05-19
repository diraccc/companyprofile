const crypto = require("crypto");
const admin = require("firebase-admin");

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

    const { sessionId, code, step } = req.body || {};
    const stepNumber = Number(step);

    if (!sessionId || !code || ![2, 3].includes(stepNumber)) {
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

    const inputHash = hashCode(`${stepNumber}:${code}`, secret);

    if (!safeEqual(inputHash, payload.codeHash)) {
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

    await resetA2fFailure();

    return res.status(200).json({
      success: true,
      message: `Kode A2F tahap ${stepNumber} benar`,
      nextStep: stepNumber + 1
    });
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      success: false,
      error: error.publicMessage || error.message || "Server A2F error"
    });
  }
};
