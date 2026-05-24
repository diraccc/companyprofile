const crypto = require("crypto");
const admin = require("firebase-admin");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-reset-secret"
  );
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

function getIdToken(req) {
  const authHeader = String(req.headers.authorization || "");
  if (authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }

  return String((req.body && req.body.idToken) || "").trim();
}

function normalizeRole(value) {
  const role = String(value || "").trim().toLowerCase();

  if (role === "admin" || role === "owner") return "owner";
  if (role === "editor" || role === "staff") return "editor";
  if (role === "viewer" || role === "read" || role === "readonly") return "viewer";

  return "";
}

async function requireAdminRead(req, db) {
  const idToken = getIdToken(req);

  if (!idToken) {
    const err = new Error("Token admin tidak ada. Login ulang dulu.");
    err.statusCode = 401;
    throw err;
  }

  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  let firestoreRole = "";
  let firestoreActive = false;

  try {
    const userSnap = await db.collection("users").doc(uid).get();

    if (userSnap.exists) {
      const data = userSnap.data() || {};
      firestoreRole = normalizeRole(data.role);
      firestoreActive = data.active !== false && data.disabled !== true;
    }
  } catch (_error) {
    firestoreRole = "";
    firestoreActive = false;
  }

  const claimRole = normalizeRole(decoded.role);
  const uidIsMainAdmin = String(process.env.A2F_ADMIN_UID || "").trim() === uid;

  const allowed =
    uidIsMainAdmin ||
    decoded.admin === true ||
    decoded.owner === true ||
    decoded.editor === true ||
    decoded.viewer === true ||
    Boolean(firestoreActive && firestoreRole) ||
    Boolean(claimRole);

  if (!allowed) {
    const err = new Error("Akun ini bukan admin.");
    err.statusCode = 403;
    throw err;
  }

  return {
    uid,
    email: decoded.email || "",
    role: firestoreRole || claimRole || (uidIsMainAdmin ? "owner" : "viewer")
  };
}

function toPlain(value) {
  if (value === null || value === undefined) return value;

  if (typeof value.toMillis === "function") {
    const millis = value.toMillis();
    return {
      seconds: Math.floor(millis / 1000),
      millis
    };
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    return value.map(toPlain);
  }

  if (typeof value === "object") {
    const out = {};

    Object.keys(value).forEach((key) => {
      if (value[key] !== undefined) {
        out[key] = toPlain(value[key]);
      }
    });

    return out;
  }

  return value;
}

async function readCollection(db, collectionName, limit) {
  const snap = await db.collection(collectionName).limit(limit).get();

  return snap.docs.map((doc) => ({
    docId: doc.id,
    ...toPlain(doc.data() || {})
  }));
}

async function readSettings(db) {
  const names = ["store", "payment", "courier", "whatsapp"];
  const out = {};

  for (const name of names) {
    const snap = await db.collection("settings").doc(name).get();
    out[name] = snap.exists ? toPlain(snap.data() || {}) : null;
  }

  return out;
}

async function handleReadAdminData(req, res) {
  const db = getFirebaseDb();
  const adminUser = await requireAdminRead(req, db);

  const body = req.body || {};
  const requested = Array.isArray(body.collections) && body.collections.length
    ? body.collections.map(String)
    : [
        "products",
        "orders",
        "customers",
        "settings",
        "securityLogs",
        "categories",
        "brands",
        "variants"
      ];

  const want = new Set(requested);

  const limits = {
    products: Math.min(Number(body.productsLimit || 5000), 10000),
    orders: Math.min(Number(body.ordersLimit || 5000), 10000),
    customers: Math.min(Number(body.customersLimit || 25000), 30000),
    securityLogs: Math.min(Number(body.securityLogsLimit || 120), 500),
    categories: Math.min(Number(body.categoriesLimit || 5000), 10000),
    brands: Math.min(Number(body.brandsLimit || 5000), 10000),
    variants: Math.min(Number(body.variantsLimit || 5000), 10000)
  };

  const result = {
    success: true,
    readFrom: "backend-admin-sdk",
    admin: adminUser,
    loadedAtMs: Date.now()
  };

  if (want.has("products")) {
    result.products = await readCollection(db, "products", limits.products);
  }

  if (want.has("orders")) {
    result.orders = await readCollection(db, "orders", limits.orders);
  }

  if (want.has("customers")) {
    result.customers = await readCollection(db, "customers", limits.customers);
  }

  if (want.has("settings")) {
    result.settings = await readSettings(db);
  }

  if (want.has("securityLogs")) {
    result.securityLogs = await readCollection(db, "securityLogs", limits.securityLogs);
  }

  if (want.has("categories")) {
    result.categories = await readCollection(db, "categories", limits.categories);
  }

  if (want.has("brands")) {
    result.brands = await readCollection(db, "brands", limits.brands);
  }

  if (want.has("variants")) {
    result.variants = await readCollection(db, "variants", limits.variants);
  }

  return res.status(200).json(result);
}

async function handleResetA2fBan(req, res) {
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
    const action = String((req.body && req.body.action) || "").trim();

    if (action === "readAdminData") {
      return await handleReadAdminData(req, res);
    }

    return await handleResetA2fBan(req, res);
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      success: false,
      error: error.message || "Gagal memproses request admin"
    });
  }
};
