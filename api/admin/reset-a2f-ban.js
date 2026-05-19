const crypto = require("crypto");
const admin = require("firebase-admin");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-reset-secret");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));

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

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  try {
    const resetSecret = String(process.env.RESET_A2F_SECRET || "");
    const inputSecret = String(req.headers["x-reset-secret"] || "");

    if (!resetSecret || !safeEqual(inputSecret, resetSecret)) {
      return res.status(403).json({
        success: false,
        error: "Secret reset A2F salah atau belum diset"
      });
    }

    const uid = String(process.env.A2F_ADMIN_UID || "").trim();

    if (!uid) {
      return res.status(500).json({
        success: false,
        error: "A2F_ADMIN_UID belum diset"
      });
    }

    const db = getFirebaseDb();

    await db.collection("a2fLockouts").doc(uid).set({
      uid,
      email: process.env.A2F_ADMIN_EMAIL || "",
      failedCount: 0,
      lockUntilMs: 0,
      permanentBan: false,
      lastFailedAtMs: 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return res.status(200).json({
      success: true,
      message: "Ban A2F berhasil direset",
      uid
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message || "Gagal reset ban A2F"
    });
  }
};
