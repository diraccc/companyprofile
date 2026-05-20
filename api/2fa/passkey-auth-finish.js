const crypto = require("crypto");
const admin = require("firebase-admin");
const { verifyAuthenticationResponse } = require("@simplewebauthn/server");

const DEFAULT_ALLOWED_COLLECTIONS = [
  "products",
  "orders",
  "customers",
  "settings",
  "securityLogs",
  "categories",
  "brands",
  "variants"
];
const ALLOWED_COLLECTIONS = new Set(
  String(process.env.ADMIN_ALLOWED_COLLECTIONS || DEFAULT_ALLOWED_COLLECTIONS.join(","))
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
);
const A2F_SESSION_COLLECTION = process.env.A2F_SESSION_COLLECTION || "adminA2FSessions";
const A2F_SESSION_TTL_MS = Number(process.env.A2F_SESSION_TTL_MS || 30 * 60 * 1000);
const MAX_UPLOAD_BYTES = Number(process.env.ADMIN_MAX_UPLOAD_BYTES || 7 * 1024 * 1024);
const ALLOWED_UPLOAD_PREFIXES = String(process.env.ADMIN_ALLOWED_UPLOAD_PREFIXES || "product-images/,payment-proofs/")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

function setCors(req, res) {
  const origin = String(req.headers.origin || "");
  const allowed = String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  if (!allowed.length || allowed.includes("*") || allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
  }

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Cache-Control", "no-store");
}

function send(res, status, data) {
  return res.status(status).json(data);
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function base64urlToBuffer(value) {
  return Buffer.from(String(value || ""), "base64url");
}

function parseSession(session) {
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const [payloadBase64, signature] = String(session || "").split(".");

  if (!payloadBase64 || !signature) {
    throw Object.assign(new Error("Session passkey tidak valid"), { status: 400 });
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payloadBase64)
    .digest("base64url");

  if (!safeEqual(signature, expected)) {
    throw Object.assign(new Error("Session passkey palsu"), { status: 401 });
  }

  const data = JSON.parse(base64urlToBuffer(payloadBase64).toString("utf8"));
  if (Number(data.expiresAt || 0) && Date.now() > Number(data.expiresAt)) {
    throw Object.assign(new Error("Session passkey sudah expired"), { status: 401 });
  }
  return data;
}

function initFirebaseAdmin() {
  if (admin.apps.length) return admin.app();

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
  const storageBucket = process.env.FIREBASE_STORAGE_BUCKET || (projectId ? `${projectId}.firebasestorage.app` : undefined);

  if (!projectId || !clientEmail || !privateKey) {
    throw Object.assign(new Error("ENV Firebase Admin belum lengkap"), { status: 500 });
  }

  return admin.initializeApp({
    credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
    storageBucket
  });
}

function getDb() {
  initFirebaseAdmin();
  return admin.firestore();
}

function getBearerToken(req) {
  const header = String(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

async function verifyIdToken(req, body) {
  initFirebaseAdmin();
  const token = getBearerToken(req) || String(body && body.idToken || "").trim();
  if (!token) throw Object.assign(new Error("Missing Authorization Bearer token"), { status: 401 });
  return admin.auth().verifyIdToken(token, true);
}

function normalizeRole(value) {
  const role = String(value || "").trim().toLowerCase();
  if (role === "admin" || role === "owner") return "owner";
  if (role === "editor" || role === "staff") return "editor";
  if (role === "viewer" || role === "read" || role === "readonly") return "viewer";
  return "";
}

async function getAdminRole(db, decoded) {
  const claimRole = normalizeRole(decoded.role || (decoded.admin === true ? "admin" : ""));
  const snap = await db.collection("users").doc(decoded.uid).get();
  const data = snap.exists ? snap.data() || {} : {};
  const docRole = normalizeRole(data.role || "");

  if (data.active === false || data.disabled === true) {
    throw Object.assign(new Error("Role admin akun ini sedang nonaktif"), { status: 403 });
  }

  return docRole || claimRole;
}

function assertExpectedAdmin(decoded) {
  const expectedUid = String(process.env.A2F_ADMIN_UID || "").trim();
  if (expectedUid && decoded.uid !== expectedUid) {
    throw Object.assign(new Error("Akun ini tidak diizinkan memakai panel admin"), { status: 403 });
  }
}

function canWrite(role) {
  return role === "owner" || role === "editor";
}

function canDelete(role) {
  return role === "owner";
}

function toMs(value) {
  if (!value) return 0;
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  if (typeof value.toMillis === "function") return value.toMillis();
  if (typeof value.seconds === "number") return value.seconds * 1000;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

async function createA2FSession(db, decoded) {
  const now = Date.now();
  const expiresAtMs = now + A2F_SESSION_TTL_MS;
  await db.collection(A2F_SESSION_COLLECTION).doc(decoded.uid).set({
    uid: decoded.uid,
    email: decoded.email || "",
    verified: true,
    status: "verified",
    method: "passkey",
    createdAtMs: now,
    lastUsedAtMs: now,
    expiresAtMs,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    lastUsedAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromMillis(expiresAtMs)
  }, { merge: true });
  return expiresAtMs;
}

async function assertA2FSession(db, decoded) {
  const snap = await db.collection(A2F_SESSION_COLLECTION).doc(decoded.uid).get();
  if (!snap.exists) {
    throw Object.assign(new Error("A2F session not found. Selesaikan A2F lagi."), { status: 403 });
  }

  const data = snap.data() || {};
  const verified = data.verified === true || data.completed === true || data.status === "verified";
  const expiresAtMs = toMs(data.expiresAt) || Number(data.expiresAtMs || 0);
  const createdAtMs = toMs(data.createdAt) || Number(data.createdAtMs || 0);
  const notExpired = expiresAtMs ? expiresAtMs > Date.now() : (createdAtMs && Date.now() - createdAtMs <= A2F_SESSION_TTL_MS);

  if (!verified || !notExpired) {
    throw Object.assign(new Error("A2F session expired or invalid. Selesaikan A2F lagi."), { status: 403 });
  }

  await db.collection(A2F_SESSION_COLLECTION).doc(decoded.uid).set({
    lastUsedAtMs: Date.now(),
    lastUsedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true }).catch(() => {});
}

function cleanDocId(id) {
  const value = String(id || "").trim();
  if (!value || value.includes("/") || value.includes("\\") || value === ".." || value.length > 180) {
    throw Object.assign(new Error("ID dokumen tidak valid"), { status: 400 });
  }
  return value;
}

function cleanCollectionName(name) {
  const value = String(name || "").trim();
  if (!ALLOWED_COLLECTIONS.has(value)) {
    throw Object.assign(new Error("Collection tidak diizinkan: " + value), { status: 403 });
  }
  return value;
}

function cleanDocPath(path) {
  const value = String(path || "").replace(/^\/+|\/+$/g, "");
  const parts = value.split("/").filter(Boolean);
  if (parts.length !== 2) {
    throw Object.assign(new Error("Path dokumen admin harus collection/docId"), { status: 400 });
  }
  return `${cleanCollectionName(parts[0])}/${cleanDocId(parts[1])}`;
}

function decodeValue(value) {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map(decodeValue);
  if (typeof value !== "object") return value;

  if (value.__diracFirestoreOp === "serverTimestamp") {
    return admin.firestore.FieldValue.serverTimestamp();
  }
  if (value.__diracFirestoreOp === "increment") {
    return admin.firestore.FieldValue.increment(Number(value.value || 0));
  }

  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (val !== undefined) out[key] = decodeValue(val);
  }
  return out;
}

function cleanUploadPath(path) {
  const value = String(path || "").replace(/^\/+|\/+$/g, "");
  if (!value || value.includes("..") || value.includes("\\") || value.length > 420) {
    throw Object.assign(new Error("Path upload tidak valid"), { status: 400 });
  }
  if (!ALLOWED_UPLOAD_PREFIXES.some((prefix) => value.startsWith(prefix))) {
    throw Object.assign(new Error("Prefix upload tidak diizinkan"), { status: 403 });
  }
  return value;
}

async function handleCreateUploadUrl(body) {
  const path = cleanUploadPath(body.path);
  const contentType = String(body.contentType || "application/octet-stream").toLowerCase();
  const size = Number(body.size || body.sizeBytes || 0);

  if (size <= 0 || size > MAX_UPLOAD_BYTES) {
    throw Object.assign(new Error("Ukuran upload tidak diizinkan"), { status: 400 });
  }
  if (!/^image\//.test(contentType) && contentType !== "application/pdf") {
    throw Object.assign(new Error("Upload hanya boleh gambar atau PDF"), { status: 400 });
  }

  initFirebaseAdmin();
  const bucket = admin.storage().bucket();
  const file = bucket.file(path);
  const token = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const uploadHeaders = {
    "Content-Type": contentType,
    "x-goog-meta-firebasestoragedownloadtokens": token
  };
  const [uploadUrl] = await file.getSignedUrl({
    version: "v4",
    action: "write",
    expires: Date.now() + 10 * 60 * 1000,
    contentType,
    extensionHeaders: {
      "x-goog-meta-firebasestoragedownloadtokens": token
    }
  });
  const downloadURL = `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/${encodeURIComponent(path)}?alt=media&token=${token}`;
  return { success: true, action: "createUploadUrl", uploadUrl, uploadHeaders, downloadURL, url: downloadURL };
}

async function handleFirestoreAction(db, role, body) {
  const action = String(body.action || "").trim();
  if (action === "setDoc") {
    const collection = cleanCollectionName(body.collection);
    const docId = cleanDocId(body.docId);
    await db.collection(collection).doc(docId).set(decodeValue(body.data || {}), { merge: body.merge !== false });
    return { success: true, action, path: `${collection}/${docId}` };
  }

  if (action === "updateDoc") {
    const collection = cleanCollectionName(body.collection);
    const docId = cleanDocId(body.docId);
    await db.collection(collection).doc(docId).update(decodeValue(body.data || {}));
    return { success: true, action, path: `${collection}/${docId}` };
  }

  if (action === "deleteDoc") {
    if (!canDelete(role)) throw Object.assign(new Error("Hanya owner/admin yang boleh hapus data"), { status: 403 });
    const collection = cleanCollectionName(body.collection);
    const docId = cleanDocId(body.docId);
    await db.collection(collection).doc(docId).delete();
    return { success: true, action, path: `${collection}/${docId}` };
  }

  if (action === "batch") {
    const ops = Array.isArray(body.operations) ? body.operations : [];
    if (!ops.length) return { success: true, action, count: 0 };
    if (ops.length > 450) {
      throw Object.assign(new Error("Terlalu banyak operasi batch. Maksimal 450."), { status: 400 });
    }

    const batch = db.batch();
    for (const op of ops) {
      const type = String(op.type || "set").toLowerCase();
      const ref = db.doc(cleanDocPath(op.path));
      if (type === "delete") {
        if (!canDelete(role)) throw Object.assign(new Error("Hanya owner/admin yang boleh delete batch"), { status: 403 });
        batch.delete(ref);
      } else if (type === "update") {
        batch.update(ref, decodeValue(op.data || {}));
      } else {
        batch.set(ref, decodeValue(op.data || {}), { merge: op.merge !== false });
      }
    }

    await batch.commit();
    return { success: true, action, count: ops.length };
  }

  if (action === "createUploadUrl") {
    return handleCreateUploadUrl(body);
  }

  throw Object.assign(new Error("Action admin tidak didukung: " + action), { status: 400 });
}

async function handleAdminAction(req, res, body) {
  const db = getDb();
  const decoded = await verifyIdToken(req, body);
  assertExpectedAdmin(decoded);
  const role = await getAdminRole(db, decoded);
  if (!canWrite(role)) {
    throw Object.assign(new Error("Role admin/editor wajib untuk aksi admin"), { status: 403 });
  }
  await assertA2FSession(db, decoded);

  const result = await handleFirestoreAction(db, role, body);
  await db.collection("adminLogs").add({
    uid: decoded.uid,
    email: decoded.email || "",
    role,
    action: body.action || "",
    ok: true,
    createdAtMs: Date.now(),
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  }).catch(() => {});
  return send(res, 200, result);
}

async function handlePasskeyFinish(req, res, body) {
  const { response, session } = body || {};
  const data = parseSession(session);
  const decoded = await verifyIdToken(req, body);
  assertExpectedAdmin(decoded);

  const rpID = process.env.PASSKEY_RP_ID || "diracgroup.store";
  const origin = process.env.PASSKEY_ORIGIN || "https://diracgroup.store";
  const credentialJson = process.env.PASSKEY_CREDENTIAL_JSON;

  if (!credentialJson) {
    return send(res, 500, {
      success: false,
      error: "PASSKEY_CREDENTIAL_JSON belum diset di Vercel"
    });
  }

  const saved = JSON.parse(credentialJson);
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: data.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential: {
      id: saved.id,
      publicKey: base64urlToBuffer(saved.publicKey),
      counter: Number(saved.counter || 0),
      transports: saved.transports || []
    }
  });

  if (!verification.verified) {
    return send(res, 401, {
      success: false,
      error: "Passkey salah atau ditolak"
    });
  }

  const db = getDb();
  const role = await getAdminRole(db, decoded);
  if (!canWrite(role)) {
    return send(res, 403, {
      success: false,
      error: "Role admin/editor wajib untuk membuka dashboard"
    });
  }

  const expiresAtMs = await createA2FSession(db, decoded);
  await db.collection("adminLogs").add({
    uid: decoded.uid,
    email: decoded.email || "",
    role,
    action: "a2f.passkey_finish",
    ok: true,
    createdAtMs: Date.now(),
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  }).catch(() => {});

  return send(res, 200, {
    success: true,
    message: "Passkey benar",
    a2fSession: "verified",
    expiresAtMs
  });
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method !== "POST") {
    return send(res, 405, {
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const action = String(body.action || "").trim();

    if (action) {
      return await handleAdminAction(req, res, body);
    }

    return await handlePasskeyFinish(req, res, body);
  } catch (error) {
    const message = error.message || "Gagal verifikasi passkey";
    const status = error.status || error.statusCode || (/Missing Authorization/i.test(message) ? 401 : /A2F|Role|Akun|tidak diizinkan|Hanya owner|wajib/i.test(message) ? 403 : 500);
    return send(res, status, {
      success: false,
      error: message
    });
  }
};
