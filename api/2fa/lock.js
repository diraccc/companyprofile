const crypto = require("crypto");
const admin = require("firebase-admin");

const LOCK_1_MS = 60 * 1000;
const LOCK_2_MS = 30 * 60 * 1000;
const LOGIN_IP_MAX_FAILURES = Math.max(1, Number(process.env.LOGIN_IP_MAX_FAILURES || 1));
const LOGIN_IP_LOCK_COLLECTION = "ipLockouts";
const BLOCKED_IPS_COLLECTION = "blocked_ips";

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-reset-secret");
  res.setHeader("Cache-Control", "no-store");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));

  if (A.length !== B.length) return false;

  return crypto.timingSafeEqual(A, B);
}

function truncate(value, max = 240) {
  const text = String(value || "");
  return text.length > max ? text.slice(0, max) : text;
}

function normalizeHeaderValue(value) {
  if (Array.isArray(value)) return value[0] || "";
  return String(value || "");
}

function normalizeIp(value) {
  let ip = normalizeHeaderValue(value).split(",")[0].trim();
  if (!ip) return "unknown";
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (ip === "::1") return "127.0.0.1";
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(ip)) {
    ip = ip.replace(/:\d+$/, "");
  }
  return ip || "unknown";
}

function getClientIp(req) {
  const headers = req.headers || {};
  return normalizeIp(
    headers["cf-connecting-ip"] ||
      headers["true-client-ip"] ||
      headers["x-real-ip"] ||
      headers["x-forwarded-for"] ||
      req.ip ||
      req.socket?.remoteAddress ||
      req.connection?.remoteAddress ||
      ""
  );
}

function maskIp(ip) {
  const text = normalizeIp(ip);
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) {
    const parts = text.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
  }
  if (text.includes(":")) {
    return text.split(":").slice(0, 4).join(":") + ":xxxx";
  }
  return text === "unknown" ? "unknown" : "masked";
}

function getIpHashSecret() {
  return String(
    process.env.IP_LOCK_HASH_SECRET ||
      process.env.RESET_A2F_SECRET ||
      process.env.A2F_ADMIN_UID ||
      "dirac-ip-lock-v1"
  );
}

function hashIp(ip) {
  return crypto
    .createHmac("sha256", getIpHashSecret())
    .update(normalizeIp(ip))
    .digest("hex");
}

function resolveIpIdentity(req, payload = {}) {
  const inputHash = String(payload.ipHash || payload.hash || "").trim().toLowerCase();
  const rawIp = normalizeIp(payload.ip || payload.clientIp || getClientIp(req));
  const ipHash = /^[a-f0-9]{64}$/.test(inputHash) ? inputHash : hashIp(rawIp);

  return {
    ip: rawIp,
    ipHash,
    ipMasked: maskIp(rawIp)
  };
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

function getPublicLoginIpState(data = {}, identity = {}) {
  const failedCount = Number(data.failedCount || 0);
  const permanentIpBan = data.permanentBan === true;
  const ipHash = String(data.ipHash || identity.ipHash || "");
  const ipMasked = String(data.ipMasked || identity.ipMasked || "");

  if (permanentIpBan) {
    return {
      success: false,
      loginIpLocked: true,
      permanentIpBan: true,
      failedCount,
      ipHash,
      ipMasked,
      error: data.reason || "IP diblokir permanen karena login Firebase salah"
    };
  }

  return {
    success: true,
    loginIpLocked: false,
    permanentIpBan: false,
    failedCount,
    ipHash,
    ipMasked
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

async function checkLoginIpLock(req, payload = {}) {
  const db = getFirebaseDb();
  const identity = resolveIpIdentity(req, payload);
  const snap = await db.collection(LOGIN_IP_LOCK_COLLECTION).doc(identity.ipHash).get();

  if (!snap.exists) {
    return getPublicLoginIpState({}, identity);
  }

  return getPublicLoginIpState(snap.data() || {}, identity);
}

async function recordLoginIpFailure(req, payload = {}) {
  const db = getFirebaseDb();
  const identity = resolveIpIdentity(req, payload);
  const ref = db.collection(LOGIN_IP_LOCK_COLLECTION).doc(identity.ipHash);
  const now = Date.now();
  const emailAttempt = String(payload.email || payload.loginEmail || "").trim().toLowerCase();
  const firebaseCode = truncate(payload.firebaseCode || payload.code || "", 80);
  const firebaseMessage = truncate(payload.firebaseMessage || payload.message || "", 260);
  const userAgent = truncate(req.headers?.["user-agent"] || "", 260);

  const state = await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const current = snap.exists ? snap.data() || {} : {};
    const currentPublicState = getPublicLoginIpState(current, identity);

    if (currentPublicState.permanentIpBan === true) {
      return currentPublicState;
    }

    const failedCount = Number(current.failedCount || 0) + 1;
    const permanentBan = failedCount >= LOGIN_IP_MAX_FAILURES;
    const reason = permanentBan
      ? "IP diblokir permanen karena login Firebase salah"
      : "Login Firebase salah";

    const nextData = {
      ipHash: identity.ipHash,
      ipMasked: identity.ipMasked,
      failedCount,
      permanentBan,
      reason,
      emailAttempt,
      firebaseCode,
      firebaseMessage,
      userAgent,
      firstFailedAtMs: Number(current.firstFailedAtMs || now),
      lastFailedAtMs: now,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (permanentBan) {
      nextData.blockedAtMs = now;
      nextData.blockedAt = admin.firestore.FieldValue.serverTimestamp();
    }

    tx.set(ref, nextData, { merge: true });

    if (permanentBan) {
      tx.set(db.collection(BLOCKED_IPS_COLLECTION).doc(identity.ipHash), {
        ipHash: identity.ipHash,
        ipMasked: identity.ipMasked,
        emailAttempt,
        firebaseCode,
        reason,
        source: "firebase_login_failed",
        blockedAtMs: now,
        blockedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }

    return getPublicLoginIpState(nextData, identity);
  });

  return state;
}

async function recordLoginIpSuccess(req, payload = {}) {
  const db = getFirebaseDb();
  const identity = resolveIpIdentity(req, payload);
  const ref = db.collection(LOGIN_IP_LOCK_COLLECTION).doc(identity.ipHash);
  const snap = await ref.get();

  if (!snap.exists) {
    return getPublicLoginIpState({}, identity);
  }

  const current = snap.data() || {};
  if (current.permanentBan === true) {
    return getPublicLoginIpState(current, identity);
  }

  await ref.set({
    failedCount: 0,
    lastSuccessAtMs: Date.now(),
    lastSuccessEmail: String(payload.email || payload.loginEmail || "").trim().toLowerCase(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  return getPublicLoginIpState({ ...current, failedCount: 0, permanentBan: false }, identity);
}

async function resetLoginIpLock(req, payload = {}) {
  const db = getFirebaseDb();
  const identity = resolveIpIdentity(req, payload);
  const resetData = {
    ipHash: identity.ipHash,
    ipMasked: identity.ipMasked,
    failedCount: 0,
    permanentBan: false,
    reason: "",
    resetAtMs: Date.now(),
    resetAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };

  await db.collection(LOGIN_IP_LOCK_COLLECTION).doc(identity.ipHash).set(resetData, { merge: true });
  await db.collection(BLOCKED_IPS_COLLECTION).doc(identity.ipHash).delete().catch(() => {});

  return {
    success: true,
    loginIpLocked: false,
    permanentIpBan: false,
    failedCount: 0,
    ipHash: identity.ipHash,
    ipMasked: identity.ipMasked,
    message: "Ban IP login Firebase berhasil direset"
  };
}

async function resetAllLoginIpLocks() {
  const db = getFirebaseDb();
  const lockSnap = await db.collection(LOGIN_IP_LOCK_COLLECTION).where("permanentBan", "==", true).limit(450).get();
  const blockedSnap = await db.collection(BLOCKED_IPS_COLLECTION).limit(450).get();
  let count = 0;

  const batch = db.batch();
  lockSnap.forEach((docSnap) => {
    count += 1;
    batch.set(docSnap.ref, {
      failedCount: 0,
      permanentBan: false,
      reason: "",
      resetAtMs: Date.now(),
      resetAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  });
  blockedSnap.forEach((docSnap) => {
    batch.delete(docSnap.ref);
  });

  await batch.commit();

  return {
    success: true,
    loginIpLocked: false,
    permanentIpBan: false,
    resetCount: count,
    message: "Semua ban IP login Firebase berhasil direset"
  };
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

function assertResetSecret(req, data) {
  const resetSecret = String(process.env.RESET_A2F_SECRET || "");
  const inputSecret = getResetSecretInput(req, data);

  if (!resetSecret || !safeEqual(inputSecret, resetSecret)) {
    const error = new Error("Secret reset salah atau belum diset");
    error.statusCode = 403;
    throw error;
  }
}

function isLoginCheckAction(action) {
  return ["login-check", "check-login", "ip-check", "check-ip", "login_ip_check"].includes(action);
}

function isLoginFailAction(action) {
  return ["login-fail", "fail-login", "firebase-login-fail", "firebase_login_fail"].includes(action);
}

function isLoginSuccessAction(action) {
  return ["login-success", "success-login", "firebase-login-success", "firebase_login_success"].includes(action);
}

function isLoginResetAction(action) {
  return ["login-reset", "reset-login", "reset-login-ip", "reset-ip", "login_ip_reset"].includes(action);
}

function isLoginResetAllAction(action) {
  return ["login-reset-all", "reset-login-all", "reset-login-ip-all", "reset-all-ip", "login_ip_reset_all"].includes(action);
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

    if (isLoginCheckAction(normalizedAction)) {
      const state = await checkLoginIpLock(req, data || {});
      return res.status(state.permanentIpBan ? 403 : 200).json(state);
    }

    if (isLoginFailAction(normalizedAction)) {
      const state = await recordLoginIpFailure(req, data || {});
      return res.status(state.permanentIpBan ? 403 : 401).json(state);
    }

    if (isLoginSuccessAction(normalizedAction)) {
      const state = await recordLoginIpSuccess(req, data || {});
      return res.status(state.permanentIpBan ? 403 : 200).json(state);
    }

    if (isLoginResetAction(normalizedAction)) {
      assertResetSecret(req, data);
      const state = await resetLoginIpLock(req, data || {});
      return res.status(200).json(state);
    }

    if (isLoginResetAllAction(normalizedAction)) {
      assertResetSecret(req, data);
      const state = await resetAllLoginIpLocks();
      return res.status(200).json(state);
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
      assertResetSecret(req, data);
      const state = await resetLock();

      return res.status(200).json(state);
    }

    return res.status(400).json({
      success: false,
      error: "Action tidak valid. Pakai check, fail, timeout, timeout-lock, reset, login-check, login-fail, reset-login-ip, atau reset-login-ip-all."
    });
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      success: false,
      error: error.message || "Server lock A2F error"
    });
  }
};
