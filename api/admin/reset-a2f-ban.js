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

function clampLimit(value, fallback, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.max(Math.trunc(parsed), 1), max);
}

function normalizeDirection(value, fallback = "asc") {
  const text = String(value || "").trim().toLowerCase();
  return text === "desc" || text === "descending" ? "desc" : fallback;
}

function normalizeOrderBy(collectionName, value) {
  const field = String(value || "").trim();

  const allowed = {
    products: new Set(["id", "title", "category", "brand", "price", "stock", "createdAtMs", "updatedAtMs"]),
    orders: new Set(["createdAtMs", "updatedAtMs", "orderId", "customerName", "paymentStatus", "orderStatus", "trackingNumber"]),
    customers: new Set(["name", "createdAtMs", "updatedAtMs", "totalSpent", "segment"]),
    securityLogs: new Set(["createdAtMs", "updatedAtMs", "action", "email"]),
    categories: new Set(["name", "createdAtMs", "updatedAtMs"]),
    brands: new Set(["name", "createdAtMs", "updatedAtMs"]),
    variants: new Set(["name", "createdAtMs", "updatedAtMs"])
  };

  if (collectionName === "orders" && field === "createdAt") return "createdAtMs";
  if (allowed[collectionName] && allowed[collectionName].has(field)) return field;

  if (collectionName === "products") return "id";
  if (collectionName === "orders") return "createdAtMs";
  if (collectionName === "customers") return "name";
  if (["categories", "brands", "variants"].includes(collectionName)) return "name";
  if (collectionName === "securityLogs") return "createdAtMs";

  return "";
}

function rowFromDoc(doc) {
  return {
    docId: doc.id,
    ...toPlain(doc.data() || {})
  };
}

function textIncludes(value, keyword) {
  return String(value || "").toLowerCase().includes(keyword);
}

function orderMatchesFilters(row, options = {}) {
  const keyword = String(options.search || "").trim().toLowerCase();
  const paymentStatus = String(options.paymentStatus || "").trim();
  const orderStatus = String(options.orderStatus || "").trim();

  if (paymentStatus && String(row.paymentStatus || "") !== paymentStatus) return false;
  if (orderStatus && String(row.orderStatus || "") !== orderStatus) return false;

  if (!keyword) return true;

  const haystack = [
    row.docId,
    row.orderId,
    row.customerName,
    row.productName,
    Array.isArray(row.items) ? row.items.map((item) => [item.productName, item.title, item.qty].join(" ")).join(" ") : "",
    row.paymentMethod,
    row.paymentStatus,
    row.orderStatus,
    row.courier,
    row.trackingNumber,
    row.address,
    row.note,
    row.searchText,
    row.total
  ].join(" ").toLowerCase();

  return haystack.includes(keyword);
}

function sortOrdersDesc(a, b) {
  const aMs = Number(a.createdAtMs || (a.createdAt && a.createdAt.millis) || 0);
  const bMs = Number(b.createdAtMs || (b.createdAt && b.createdAt.millis) || 0);
  return bMs - aMs || String(b.orderId || b.docId || "").localeCompare(String(a.orderId || a.docId || ""));
}

async function readCollectionPage(db, collectionName, limit, options = {}) {
  const orderByField = normalizeOrderBy(collectionName, options.orderBy);
  const orderDirection = normalizeDirection(options.orderDirection, collectionName === "orders" || collectionName === "securityLogs" ? "desc" : "asc");
  let ref = db.collection(collectionName);

  if (orderByField) {
    ref = ref.orderBy(orderByField, orderDirection);
  }

  const cursor = String(options.cursor || "").trim();
  if (cursor) {
    const cursorSnap = await db.collection(collectionName).doc(cursor).get();
    if (cursorSnap.exists) {
      ref = ref.startAfter(cursorSnap);
    }
  }

  const snap = await ref.limit(limit + 1).get();
  const docs = snap.docs.slice(0, limit);
  const lastDoc = docs[docs.length - 1] || null;

  return {
    rows: docs.map(rowFromDoc),
    pageInfo: {
      limit,
      returned: docs.length,
      hasMore: snap.docs.length > limit,
      cursor: lastDoc ? lastDoc.id : null,
      orderBy: orderByField,
      orderDirection,
      mode: options.search ? "search" : "page"
    }
  };
}

async function readCollection(db, collectionName, limit, options = {}) {
  const page = await readCollectionPage(db, collectionName, limit, options);
  return page.rows;
}

async function addOrderQueryResults(map, queryRef, maxPerQuery, options) {
  try {
    const snap = await queryRef.limit(maxPerQuery).get();
    snap.docs.forEach((doc) => {
      const row = rowFromDoc(doc);
      if (orderMatchesFilters(row, options)) map.set(doc.id, row);
    });
  } catch (_error) {
    // Sebagian project belum punya index tertentu. Query lain tetap dipakai agar pencarian tidak gagal total.
  }
}

async function readOrdersSearch(db, limit, options = {}) {
  const keywordRaw = String(options.search || "").trim();
  const keywordLower = keywordRaw.toLowerCase();
  const rowsById = new Map();
  const ordersCol = db.collection("orders");
  const maxPerQuery = Math.min(Math.max(limit, 30), 120);

  if (!keywordRaw) {
    const page = await readCollectionPage(db, "orders", limit, options);
    page.rows = page.rows.filter((row) => orderMatchesFilters(row, options));
    page.pageInfo.returned = page.rows.length;
    return page;
  }

  if (!keywordRaw.includes("/")) {
    const exactDoc = await ordersCol.doc(keywordRaw).get();
    if (exactDoc.exists) {
      const row = rowFromDoc(exactDoc);
      if (orderMatchesFilters(row, options)) rowsById.set(exactDoc.id, row);
    }
  }

  const keywordVariants = Array.from(new Set([keywordRaw, keywordRaw.toUpperCase(), keywordRaw.toLowerCase()].filter(Boolean)));

  const exactFields = ["orderId", "trackingNumber"];
  for (const field of exactFields) {
    for (const value of keywordVariants) {
      await addOrderQueryResults(rowsById, ordersCol.where(field, "==", value), maxPerQuery, options);
    }
  }

  const prefixFields = ["searchText", "orderId", "customerName", "productName", "trackingNumber"];
  for (const field of prefixFields) {
    const values = field === "searchText" ? [keywordLower] : keywordVariants;
    for (const prefixValue of values) {
      await addOrderQueryResults(
        rowsById,
        ordersCol.orderBy(field).startAt(prefixValue).endAt(prefixValue + "\uf8ff"),
        maxPerQuery,
        options
      );
    }
  }

  const rows = Array.from(rowsById.values())
    .filter((row) => orderMatchesFilters(row, Object.assign({}, options, { search: keywordLower })))
    .sort(sortOrdersDesc)
    .slice(0, limit);

  return {
    rows,
    pageInfo: {
      limit,
      returned: rows.length,
      hasMore: false,
      cursor: null,
      orderBy: "search",
      orderDirection: "desc",
      mode: "search",
      search: keywordRaw
    }
  };
}

async function readOrdersPage(db, limit, options = {}) {
  if (String(options.search || "").trim()) {
    return await readOrdersSearch(db, limit, options);
  }

  const page = await readCollectionPage(db, "orders", limit, Object.assign({ orderBy: "createdAtMs", orderDirection: "desc" }, options));

  if (options.paymentStatus || options.orderStatus) {
    page.rows = page.rows.filter((row) => orderMatchesFilters(row, options));
    page.pageInfo.returned = page.rows.length;
  }

  return page;
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
    // Produk memang diminta tetap dibaca penuh oleh dashboard.
    products: clampLimit(body.productsLimit, 30000, 30000),
    // Pesanan dibatasi 100 per request agar dashboard tidak membaca 22k dokumen sekaligus.
    orders: clampLimit(body.ordersLimit, 100, 500),
    customers: clampLimit(body.customersLimit, 25000, 30000),
    securityLogs: clampLimit(body.securityLogsLimit, 120, 500),
    categories: clampLimit(body.categoriesLimit, 5000, 10000),
    brands: clampLimit(body.brandsLimit, 5000, 10000),
    variants: clampLimit(body.variantsLimit, 5000, 10000)
  };

  const result = {
    success: true,
    readFrom: "backend-admin-sdk",
    admin: adminUser,
    loadedAtMs: Date.now()
  };

  if (want.has("products")) {
    result.products = await readCollection(db, "products", limits.products, {
      orderBy: body.productsOrderBy || "id",
      orderDirection: body.productsOrderDirection || "asc"
    });
  }

  if (want.has("orders")) {
    const ordersPage = await readOrdersPage(db, limits.orders, {
      cursor: body.ordersCursor,
      search: body.ordersSearch,
      paymentStatus: body.ordersPaymentStatus,
      orderStatus: body.ordersOrderStatus,
      orderBy: body.ordersOrderBy || "createdAtMs",
      orderDirection: body.ordersOrderDirection || "desc"
    });
    result.orders = ordersPage.rows;
    result.ordersPage = ordersPage.pageInfo;
  }

  if (want.has("customers")) {
    result.customers = await readCollection(db, "customers", limits.customers, {
      orderBy: body.customersOrderBy || "name",
      orderDirection: body.customersOrderDirection || "asc"
    });
  }

  if (want.has("settings")) {
    result.settings = await readSettings(db);
  }

  if (want.has("securityLogs")) {
    result.securityLogs = await readCollection(db, "securityLogs", limits.securityLogs, {
      orderBy: body.securityLogsOrderBy || "createdAtMs",
      orderDirection: body.securityLogsOrderDirection || "desc"
    });
  }

  if (want.has("categories")) {
    result.categories = await readCollection(db, "categories", limits.categories, {
      orderBy: body.categoriesOrderBy || "name",
      orderDirection: body.categoriesOrderDirection || "asc"
    });
  }

  if (want.has("brands")) {
    result.brands = await readCollection(db, "brands", limits.brands, {
      orderBy: body.brandsOrderBy || "name",
      orderDirection: body.brandsOrderDirection || "asc"
    });
  }

  if (want.has("variants")) {
    result.variants = await readCollection(db, "variants", limits.variants, {
      orderBy: body.variantsOrderBy || "name",
      orderDirection: body.variantsOrderDirection || "asc"
    });
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
