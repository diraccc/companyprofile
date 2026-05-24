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
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
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
  await db.collection("a2fKnownDevices").doc(`${approvalData.uid}_${ctx.device.idHash}`).set({
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
    firstSeenAtMs: approvalData.createdAtMs || now,
    lastSeenAtMs: now,
    lastIp: ctx.network && ctx.network.ip ? ctx.network.ip : "Tidak tersedia",
    lastCountry: ctx.network && ctx.network.country ? ctx.network.country : "Tidak tersedia",
    lastCity: ctx.network && ctx.network.city ? ctx.network.city : "Tidak tersedia",
    lastUserAgent: ctx.device.userAgent || "",
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
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

async function sendStep6Email({ requestId, approveToken, denyToken, emailCode, email, loginContext }) {
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

  const ctx = loginContext || {};
  const account = ctx.account || {};
  const network = ctx.network || {};
  const device = ctx.device || {};
  const browser = ctx.browser || {};
  const security = ctx.security || {};
  const groupedCode = String(emailCode || "").replace(/(\d{6})(?=\d)/g, "$1 ");
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

LANGKAH 2 - kembali ke dashboard admin dan masukkan kode 60 digit ini:
${groupedCode}

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
      <b>Langkah 1:</b> klik SETUJUI dulu. Setelah itu kembali ke dashboard admin dan masukkan kode 60 digit dari email ini.
    </div>
    <p>
      <a href="${approveUrl}" style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;padding:13px 20px;border-radius:999px;font-weight:700">SETUJUI LOGIN</a>
    </p>
    <p style="margin:16px 0 8px"><b>Kode 60 digit</b> untuk dimasukkan ke dashboard admin:</p>
    <div style="font-size:22px;font-weight:800;letter-spacing:2px;line-height:1.7;padding:14px 18px;background:#eef6ff;border-radius:12px;word-break:break-all;color:#0f172a">${escapeHtml(groupedCode)}</div>
    <p style="padding:12px;border-radius:12px;background:#fff7ed;color:#9a3412"><b>Penting:</b> salah 1x akan membuat A2F diblokir permanen.</p>
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
async function startStep6EmailApproval(req, res) {
  await checkA2fLock();

  const { idToken, clientContext } = req.body || {};
  const decoded = await verifyAdminIdToken(idToken);

  const db = getFirebaseDb();
  const secret = getA2fSecret();
  const requestId = randomId(18);
  const approveToken = randomId(32);
  const denyToken = randomId(32);
  const screenCode = randomDigitCode(60);
  const screenCodeArgon2Hash = await argon2.hash(screenCode, ARGON2ID_OPTIONS);
  const now = Date.now();
  const expiresAtMs = now + 60 * 1000;

  const ref = db.collection("a2fEmailApprovals").doc(requestId);
  const loginContext = await buildStep6LoginContext({ req, db, decoded, clientContext, secret });
  loginContext.account.requestId = requestId;

  await ref.set({
    uid: decoded.uid,
    email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
    status: "pending_email_approval",
    screenCodeHashType: "argon2id",
    screenCodeArgon2Hash,
    approveTokenHash: hashCode(`step6-approve:${requestId}:${approveToken}`, secret),
    denyTokenHash: hashCode(`step6-deny:${requestId}:${denyToken}`, secret),
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
    emailCode: screenCode,
    email: decoded.email || "",
    loginContext
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
  const secret = getA2fSecret();
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

  await rememberStep6KnownDevice(db, data);
  const a2fSession = await createA2fVerifiedSession(db, Object.assign({}, data, { requestId: String(requestId || "") }));
  await resetA2fFailure();

  return res.status(200).json({
    success: true,
    status: "approved",
    message: "Kode 60 digit benar. Dashboard boleh dibuka.",
    nextStep: 7,
    a2fSessionId: a2fSession.sessionId,
    a2fSessionExpiresAtMs: a2fSession.expiresAtMs,
    role: "admin"
  });
}

async function expireStep6Approval(ref) {
  await ref.set({
    status: "expired",
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
}

function getA2fSessionTtlMs() {
  const hours = Number(process.env.A2F_SESSION_TTL_HOURS || 8);
  const safeHours = Number.isFinite(hours) && hours > 0 && hours <= 24 ? hours : 8;
  return Math.round(safeHours * 60 * 60 * 1000);
}

function getA2fSessionHash(uid, sessionId, secret) {
  return hashCode(`a2f-session:${uid}:${sessionId}`, secret);
}

async function createA2fVerifiedSession(db, approvalData) {
  const secret = getA2fSecret();
  const uid = String((approvalData && approvalData.uid) || getAdminUid());
  const sessionId = randomId(36);
  const now = Date.now();
  const expiresAtMs = now + getA2fSessionTtlMs();
  const loginContext = (approvalData && approvalData.loginContext) || {};
  const device = loginContext.device || {};

  await db.collection("a2fSessions").doc(uid).set({
    uid,
    email: (approvalData && approvalData.email) || process.env.A2F_ADMIN_EMAIL || "",
    role: "admin",
    verified: true,
    sessionHash: getA2fSessionHash(uid, sessionId, secret),
    requestId: (approvalData && approvalData.requestId) || "",
    deviceIdHash: device.idHash || "",
    deviceName: device.name || "",
    createdAtMs: now,
    expiresAtMs,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  return { sessionId, expiresAtMs };
}

async function verifyA2fSessionForAdmin(idToken, a2fSessionId) {
  await checkA2fLock();
  const decoded = await verifyAdminIdToken(idToken);
  const sessionId = String(a2fSessionId || "").trim();

  if (!sessionId) {
    const err = new Error("Session A2F admin wajib dikirim.");
    err.statusCode = 401;
    throw err;
  }

  const db = getFirebaseDb();
  const snap = await db.collection("a2fSessions").doc(decoded.uid).get();

  if (!snap.exists) {
    const err = new Error("Session A2F admin tidak ditemukan. Login ulang.");
    err.statusCode = 401;
    throw err;
  }

  const data = snap.data() || {};
  const expiresAtMs = Number(data.expiresAtMs || 0);

  if (data.verified !== true || expiresAtMs <= Date.now()) {
    const err = new Error("Session A2F admin sudah expired. Login ulang.");
    err.statusCode = 401;
    throw err;
  }

  const expectedHash = getA2fSessionHash(decoded.uid, sessionId, getA2fSecret());

  if (!safeEqual(expectedHash, data.sessionHash || "")) {
    const err = new Error("Session A2F admin tidak valid.");
    err.statusCode = 401;
    throw err;
  }

  return {
    uid: decoded.uid,
    email: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
    role: data.role || "admin",
    expiresAtMs,
    deviceName: data.deviceName || "",
    deviceIdHash: data.deviceIdHash || ""
  };
}

async function verifyA2fSessionAction(req, res) {
  const body = getParsedBody(req);
  const session = await verifyA2fSessionForAdmin(body.idToken, body.a2fSessionId || req.headers["x-a2f-session"] || "");
  return res.status(200).json({ success: true, session });
}

function approvalHiddenInputs(action, requestId, token) {
  return `
    <input type="hidden" name="action" value="${escapeHtml(action)}">
    <input type="hidden" name="requestId" value="${escapeHtml(requestId)}">
    <input type="hidden" name="token" value="${escapeHtml(token)}">
  `;
}

function getParsedBody(req) {
  const body = req && req.body;

  if (!body) return {};
  if (typeof body === "object") return body;

  const raw = String(body || "");

  if (!raw) return {};

  try {
    return JSON.parse(raw);
  } catch (_error) {
    const out = {};
    const params = new URLSearchParams(raw);
    for (const [key, value] of params.entries()) out[key] = value;
    return out;
  }
}

function getRequestParam(req, name) {
  const body = getParsedBody(req);
  if (Object.prototype.hasOwnProperty.call(body, name)) return body[name];
  if (req && req.query && Object.prototype.hasOwnProperty.call(req.query, name)) return req.query[name];
  return "";
}

function approvalFormHtml({ action, requestId, token, buttonText, danger }) {
  const actionUrl = `/api/2fa/verify-step?action=${encodeURIComponent(action)}&requestId=${encodeURIComponent(requestId)}&token=${encodeURIComponent(token)}`;
  return `
    <form method="POST" action="${actionUrl}">
      ${approvalHiddenInputs(action, requestId, token)}
      <button class="${danger ? "danger" : ""}" type="submit">${escapeHtml(buttonText)}</button>
    </form>
  `;
}

async function approveStep6FromEmail(req, res) {
  try {
    await checkA2fLock();

    const requestId = String(getRequestParam(req, "requestId") || "");
    const token = String(getRequestParam(req, "token") || "");
    const secret = getA2fSecret();

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};
    const status = String(data.status || "");

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await expireStep6Approval(ref);
      return res.status(408).send(htmlPage("Approval expired", "<p>Waktu approval sudah habis. Silakan login ulang.</p>"));
    }

    const tokenHash = hashCode(`step6-approve:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.approveTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link approval tidak valid.</p>"));
    }

    if (status === "approved") {
      return res.status(200).send(htmlPage("Login sudah selesai", "<p>Step 6 sudah pernah disetujui. Dashboard boleh terbuka jika sesi masih aktif.</p>"));
    }

    if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) {
      return res.status(403).send(htmlPage("Login sudah ditolak", "<p>Request ini sudah ditolak dan A2F sudah diblokir permanen.</p>"));
    }

    if (status !== "pending_email_approval" && status !== "approved_waiting_code") {
      return res.status(409).send(htmlPage("Status tidak valid", `<p>Status login saat ini: ${escapeHtml(status || "unknown")}</p>`));
    }

    return res.status(200).send(htmlPage(
      "Konfirmasi Setujui Login",
      `<p>Tekan tombol di bawah untuk menyetujui login ini. Tahap ini sengaja butuh konfirmasi agar scanner email tidak otomatis menyetujui login.</p>
       <div class="warn">Setelah disetujui, kembali ke dashboard admin dan masukkan kode 60 digit dari email.</div>
       ${approvalFormHtml({ action: "confirmApproveStep6", requestId, token, buttonText: "SETUJUI LOGIN", danger: false })}`
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

    const requestId = String(getRequestParam(req, "requestId") || "");
    const token = String(getRequestParam(req, "token") || "");
    const secret = getA2fSecret();

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};
    const status = String(data.status || "");

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await expireStep6Approval(ref);
      return res.status(408).send(htmlPage("Approval expired", "<p>Waktu approval sudah habis. Silakan login ulang.</p>"));
    }

    const tokenHash = hashCode(`step6-approve:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.approveTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link approval tidak valid.</p>"));
    }

    if (status === "approved") {
      return res.status(200).send(htmlPage("Login sudah selesai", "<p>Step 6 sudah pernah selesai. Kembali ke halaman admin.</p>"));
    }

    if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) {
      return res.status(403).send(htmlPage("Login sudah ditolak", "<p>Request ini sudah ditolak dan A2F sudah diblokir permanen.</p>"));
    }

    if (status !== "pending_email_approval" && status !== "approved_waiting_code") {
      return res.status(409).send(htmlPage("Status tidak valid", `<p>Status login saat ini: ${escapeHtml(status || "unknown")}</p>`));
    }

    await ref.set({
      status: "approved_waiting_code",
      emailApprovedAtMs: Date.now(),
      approveTokenUsedAtMs: data.approveTokenUsedAtMs || Date.now(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

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

async function denyStep6FromEmail(req, res) {
  try {
    const requestId = String(getRequestParam(req, "requestId") || "");
    const token = String(getRequestParam(req, "token") || "");
    const secret = getA2fSecret();

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};
    const status = String(data.status || "");
    const tokenHash = hashCode(`step6-deny:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.denyTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link penolakan tidak valid.</p>"));
    }

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await expireStep6Approval(ref);
      return res.status(408).send(htmlPage("Approval expired", "<p>Waktu approval sudah habis. Link tolak tidak berlaku lagi.</p>"));
    }

    if (status === "approved") {
      return res.status(409).send(htmlPage("Login sudah selesai", "<p>Step 6 sudah selesai disetujui. Link tolak lama tidak bisa dipakai untuk ban.</p>"));
    }

    if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) {
      return res.status(200).send(htmlPage("Sudah diblokir", "<p>Request ini sudah ditolak dan A2F sudah diblokir permanen.</p>"));
    }

    return res.status(200).send(htmlPage(
      "Konfirmasi Tolak Login",
      `<p>Tekan tombol merah di bawah hanya jika percobaan login ini bukan kamu.</p>
       <div class="warn">Konfirmasi ini akan membuat A2F diblokir permanen. Halaman konfirmasi ini mencegah scanner email mem-ban akun otomatis.</div>
       ${approvalFormHtml({ action: "confirmDenyStep6", requestId, token, buttonText: "KONFIRMASI TOLAK & BAN PERMANEN", danger: true })}`
    ));
  } catch (error) {
    return res.status(error.statusCode || 500).send(htmlPage(
      "Penolakan gagal",
      `<p>${escapeHtml(error.publicMessage || error.message || "Gagal menolak login.")}</p>`
    ));
  }
}

async function confirmDenyStep6FromEmail(req, res) {
  try {
    const requestId = String(getRequestParam(req, "requestId") || "");
    const token = String(getRequestParam(req, "token") || "");
    const secret = getA2fSecret();

    const db = getFirebaseDb();
    const ref = db.collection("a2fEmailApprovals").doc(requestId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(404).send(htmlPage("Approval tidak ditemukan", "<p>Request approval login tidak ditemukan.</p>"));
    }

    const data = snap.data() || {};
    const status = String(data.status || "");
    const tokenHash = hashCode(`step6-deny:${requestId}:${token}`, secret);

    if (!safeEqual(tokenHash, data.denyTokenHash)) {
      return res.status(403).send(htmlPage("Token salah", "<p>Link penolakan tidak valid.</p>"));
    }

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await expireStep6Approval(ref);
      return res.status(408).send(htmlPage("Approval expired", "<p>Waktu approval sudah habis. Link tolak tidak berlaku lagi.</p>"));
    }

    if (status === "approved") {
      return res.status(409).send(htmlPage("Login sudah selesai", "<p>Step 6 sudah selesai disetujui. Link tolak lama tidak bisa dipakai untuk ban.</p>"));
    }

    if (status === "denied_permanent_ban" || status.startsWith("permanent_ban")) {
      return res.status(200).send(htmlPage("Sudah diblokir", "<p>Request ini sudah ditolak dan A2F sudah diblokir permanen.</p>"));
    }

    await ref.set({
      status: "denied_permanent_ban",
      deniedAtMs: Date.now(),
      denyTokenUsedAtMs: data.denyTokenUsedAtMs || Date.now(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    await recordPermanentBan("step6_email_denied_confirmed");

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
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method === "GET") {
    const action = String((req.query && req.query.action) || "");

    if (action === "approveStep6") return approveStep6FromEmail(req, res);
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
    const body = getParsedBody(req);
    req.body = body;
    const action = String(getRequestParam(req, "action") || "").trim();

    if (action === "confirmApproveStep6") return confirmApproveStep6FromEmail(req, res);
    if (action === "confirmDenyStep6") return confirmDenyStep6FromEmail(req, res);
    if (action === "verifyA2fSession") return verifyA2fSessionAction(req, res);
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
