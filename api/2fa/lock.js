const crypto = require("crypto");
const admin = require("firebase-admin");

const LOCK_1_MS = 60 * 1000;
const LOCK_2_MS = 30 * 60 * 1000;

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
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

function getAdminUid() {
  const uid = String(process.env.A2F_ADMIN_UID || "").trim();

  if (!uid) {
    throw new Error("A2F_ADMIN_UID belum diset");
  }

  return uid;
}

function getPublicLockState(data) {
  const now = Date.now();
  const failedCount = Number(data.failedCount || 0);
  const lockUntilMs = Number(data.lockUntilMs || 0);
  const permanentBan = data.permanentBan === true;

  if (permanentBan) {
    return {
      success: false,
      locked: true,
      permanentBan: true,
      failedCount,
      lockUntilMs: 0,
      remainingMs: 0,
      error: data.reason || "A2F diblokir permanen"
    };
  }

  if (lockUntilMs > now) {
    return {
      success: false,
      locked: true,
      permanentBan: false,
      failedCount,
      lockUntilMs,
      remainingMs: lockUntilMs - now,
      error: "A2F masih terkunci sementara"
    };
  }

  return {
    success: true,
    locked: false,
    permanentBan: false,
    failedCount,
    lockUntilMs: 0,
    remainingMs: 0
  };
}

async function ensureLockDoc(db, uid) {
  const ref = db.collection("a2fLockouts").doc(uid);
  const snap = await ref.get();

  if (snap.exists) {
    return {
      ref,
      data: snap.data() || {}
    };
  }

  const freshData = {
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 0,
    lockUntilMs: 0,
    permanentBan: false,
    timeoutBlocked: false,
    reason: "",
    lastFailedAtMs: 0,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };

  await ref.set(freshData, { merge: true });

  return {
    ref,
    data: freshData
  };
}

async function checkLock() {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const { data } = await ensureLockDoc(db, uid);

  return getPublicLockState(data);
}

async function recordFailure() {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const ref = db.collection("a2fLockouts").doc(uid);

  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const current = snap.exists ? snap.data() || {} : {};
    const currentState = getPublicLockState(current);

    if (currentState.permanentBan === true) {
      return currentState;
    }

    if (currentState.locked === true && Number(currentState.lockUntilMs || 0) > Date.now()) {
      return currentState;
    }

    const now = Date.now();
    const failedCount = Number(current.failedCount || 0) + 1;

    const nextData = {
      uid,
      email: process.env.A2F_ADMIN_EMAIL || current.email || "",
      failedCount,
      timeoutBlocked: false,
      lastFailedAtMs: now,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (failedCount >= 3) {
      nextData.permanentBan = true;
      nextData.lockUntilMs = 0;
      nextData.reason = "A2F diblokir permanen karena salah 3x";
    } else if (failedCount === 2) {
      nextData.permanentBan = false;
      nextData.lockUntilMs = now + LOCK_2_MS;
      nextData.reason = "A2F salah 2x, terkunci sementara";
    } else {
      nextData.permanentBan = false;
      nextData.lockUntilMs = now + LOCK_1_MS;
      nextData.reason = "A2F salah 1x, terkunci sementara";
    }

    tx.set(ref, nextData, { merge: true });

    return getPublicLockState(nextData);
  });
}

async function recordTimeoutBlock(payload = {}) {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const now = Date.now();
  const reason = "A2F lebih dari 25 detik";

  const lockData = {
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 3,
    lockUntilMs: 0,
    permanentBan: true,
    timeoutBlocked: true,
    reason,
    step: Number(payload.step || 0),
    maxSeconds: Number(payload.maxSeconds || 25),
    deadlineMs: Number(payload.deadlineMs || 0),
    timedOutAtMs: Number(payload.timedOutAtMs || now),
    lastFailedAtMs: now,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };

  await db.collection("a2fLockouts").doc(uid).set(lockData, { merge: true });

  await db.collection("a2fTimeoutBlocks").doc(uid).set({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    reason,
    step: lockData.step,
    maxSeconds: lockData.maxSeconds,
    deadlineMs: lockData.deadlineMs,
    timedOutAtMs: lockData.timedOutAtMs,
    blockedAtMs: now,
    blockedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  await db.collection("blocked_users").doc(uid).set({
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    reason,
    source: "a2f_timeout",
    step: lockData.step,
    blockedAtMs: now,
    blockedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  await admin.auth().updateUser(uid, {
    disabled: true
  });

  await admin.auth().revokeRefreshTokens(uid);

  return getPublicLockState(lockData);
}

async function resetLock() {
  const db = getFirebaseDb();
  const uid = getAdminUid();
  const ref = db.collection("a2fLockouts").doc(uid);

  const resetData = {
    uid,
    email: process.env.A2F_ADMIN_EMAIL || "",
    failedCount: 0,
    lockUntilMs: 0,
    permanentBan: false,
    timeoutBlocked: false,
    reason: "",
    lastFailedAtMs: 0,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };

  await ref.set(resetData, { merge: true });

  await db.collection("a2fTimeoutBlocks").doc(uid).delete().catch(() => {});
  await db.collection("blocked_users").doc(uid).delete().catch(() => {});

  await admin.auth().updateUser(uid, {
    disabled: false
  });

  await admin.auth().revokeRefreshTokens(uid);

  return {
    success: true,
    locked: false,
    permanentBan: false,
    failedCount: 0,
    lockUntilMs: 0,
    remainingMs: 0,
    message: "A2F berhasil direset dan akun Firebase sudah aktif lagi"
  };
}


function getClientIp(req) {
  const cfIp = req.headers["cf-connecting-ip"];
  const realIp = req.headers["x-real-ip"];
  const forwarded = req.headers["x-forwarded-for"];

  const raw = Array.isArray(forwarded)
    ? forwarded[0]
    : forwarded || realIp || cfIp || req.socket?.remoteAddress || "";

  return String(raw)
    .split(",")[0]
    .trim()
    .replace(/^::ffff:/, "");
}

function ipDocId(ip) {
  return crypto.createHash("sha256").update(String(ip)).digest("hex");
}

async function verifyEmailPassword(email, password) {
  const apiKey = process.env.FIREBASE_WEB_API_KEY;

  if (!apiKey) {
    throw new Error("FIREBASE_WEB_API_KEY belum diset");
  }

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        password,
        returnSecureToken: true
      })
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    const err = new Error(result?.error?.message || "LOGIN_FAILED");
    err.firebaseError = result?.error?.message || "LOGIN_FAILED";
    err.statusCode = response.status || 401;
    throw err;
  }

  return result;
}

async function writeAdminIpBan(db, req, ip, reason, payload = {}) {
  const now = Date.now();
  const hash = ipDocId(ip);

  await db.collection("adminIpBans").doc(hash).set(
    {
      ip,
      ipHash: hash,
      permanent: true,
      reason,
      source: "admin-login",
      attemptedEmail: String(payload.attemptedEmail || "").trim().toLowerCase(),
      firebaseError: String(payload.firebaseError || ""),
      uid: String(payload.uid || ""),
      userAgent: String(req.headers["user-agent"] || ""),
      bannedAtMs: now,
      bannedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    },
    { merge: true }
  );
}

async function handleAdminLogin(req, res, data = {}) {
  const db = getFirebaseDb();
  const ip = getClientIp(req);

  if (!ip) {
    return res.status(400).json({
      success: false,
      error: "IP tidak terbaca"
    });
  }

  const ipHash = ipDocId(ip);
  const banRef = db.collection("adminIpBans").doc(ipHash);
  const banSnap = await banRef.get();

  if (banSnap.exists && banSnap.data()?.permanent === true) {
    return res.status(403).json({
      success: false,
      error: "IP_BLOCKED_PERMANENTLY",
      message: "IP ini sudah diblokir permanen."
    });
  }

  const email = String(data.email || "").trim().toLowerCase();
  const password = String(data.password || "");

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: "Email dan password wajib diisi"
    });
  }

  let loginData;

  try {
    loginData = await verifyEmailPassword(email, password);
  } catch (error) {
    await writeAdminIpBan(db, req, ip, "wrong_email_or_password", {
      attemptedEmail: email,
      firebaseError: error.firebaseError || error.message || "LOGIN_FAILED"
    });

    return res.status(401).json({
      success: false,
      error: "LOGIN_FAILED_IP_BANNED",
      message: "Email/password salah. IP ini sudah diblokir permanen."
    });
  }

  const expectedUid = getAdminUid();
  const loginUid = String(loginData.localId || "");

  if (loginUid !== expectedUid) {
    await writeAdminIpBan(db, req, ip, "valid_account_but_not_admin", {
      attemptedEmail: email,
      uid: loginUid
    });

    return res.status(403).json({
      success: false,
      error: "NOT_ADMIN_IP_BANNED",
      message: "Akun ini bukan admin. IP ini sudah diblokir permanen."
    });
  }

  const customToken = await admin.auth().createCustomToken(expectedUid);

  await db.collection("adminLoginLogs").add({
    uid: expectedUid,
    email,
    ip,
    ipHash,
    success: true,
    source: "admin-login",
    userAgent: String(req.headers["user-agent"] || ""),
    createdAtMs: Date.now(),
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  return res.status(200).json({
    success: true,
    customToken
  });
}

function getRequestData(req) {
  const query = req.query || {};
  const body = req.body || {};

  if (req.method === "GET") {
    return query;
  }

  return body;
}

function getResetSecretInput(req, data) {
  return String(
    req.headers["x-reset-secret"] ||
    data.secret ||
    req.query?.secret ||
    ""
  );
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST" && req.method !== "GET") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  try {
    const data = getRequestData(req);
    const { action } = data || {};
    const normalizedAction = String(action || "check").trim().toLowerCase();

    if (normalizedAction === "admin-login" || normalizedAction === "admin_login") {
      return handleAdminLogin(req, res, data || {});
    }

    if (normalizedAction === "check") {
      const state = await checkLock();

      if (state.permanentBan) {
        return res.status(403).json(state);
      }

      if (state.locked) {
        return res.status(423).json(state);
      }

      return res.status(200).json(state);
    }

    if (normalizedAction === "fail") {
      const state = await recordFailure();

      if (state.permanentBan) {
        return res.status(403).json(state);
      }

      if (state.locked) {
        return res.status(423).json(state);
      }

      return res.status(401).json(state);
    }

    if (
      normalizedAction === "timeout" ||
      normalizedAction === "timeout-lock" ||
      normalizedAction === "timeout_lock"
    ) {
      const state = await recordTimeoutBlock(data || {});

      return res.status(403).json(state);
    }

    if (normalizedAction === "reset") {
      const resetSecret = String(process.env.RESET_A2F_SECRET || "");
      const inputSecret = getResetSecretInput(req, data);

      if (!resetSecret || !safeEqual(inputSecret, resetSecret)) {
        return res.status(403).json({
          success: false,
          error: "Secret reset A2F salah atau belum diset"
        });
      }

      const state = await resetLock();

      return res.status(200).json(state);
    }

    return res.status(400).json({
      success: false,
      error: "Action tidak valid. Pakai admin-login, check, fail, timeout, timeout-lock, atau reset."
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message || "Server lock A2F error"
    });
  }
};
