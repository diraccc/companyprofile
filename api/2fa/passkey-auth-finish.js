const crypto = require("crypto");
const admin = require("firebase-admin");
const { createClient } = require("@supabase/supabase-js");
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
const A2F_SESSION_COLLECTION = process.env.A2F_SESSION_COLLECTION || "adminA2FSessions"; // legacy Firebase fallback name
const A2F_SESSION_TABLE = process.env.A2F_SESSION_TABLE || "admin_a2f_sessions";
const ADMIN_LOG_TABLE = process.env.ADMIN_LOG_TABLE || "admin_logs";
const ADMIN_DOCUMENTS_TABLE = process.env.ADMIN_DOCUMENTS_TABLE || "admin_documents";
const A2F_SESSION_TTL_MS = Number(process.env.A2F_SESSION_TTL_MS || 30 * 60 * 1000);
const MAX_UPLOAD_BYTES = Number(process.env.ADMIN_MAX_UPLOAD_BYTES || 7 * 1024 * 1024);
const ALLOWED_UPLOAD_PREFIXES = String(process.env.ADMIN_ALLOWED_UPLOAD_PREFIXES || "product-images/,payment-proofs/")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

function getAllowedOrigins() {
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return fromEnv.length ? fromEnv : [
    "https://diracgroup.store",
    "https://www.diracgroup.store",
    "https://companyprofilee-expk.vercel.app",
    "https://companyprofilee-ochre.vercel.app"
  ];
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return getAllowedOrigins().includes(origin);
}

function setCors(req, res) {
  const origin = String((req && req.headers && req.headers.origin) || "");
  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "https://diracgroup.store");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
  return isAllowedOrigin(origin);
}

function getA2fSecret() {
  const secret = String(process.env.A2F_SECRET || "").trim();
  if (!secret || secret === "rahasia-test" || secret.length < 32) {
    throw Object.assign(new Error("A2F_SECRET production wajib diset minimal 32 karakter acak."), { status: 500 });
  }
  return secret;
}

function send(res, status, data) {
  return res.status(status).json(data);
}

function isDisabledLegacyPublicStorefrontAction(action) {
  return action === "publicReadProducts" || action === "publicCreateOrder";
}

function sendDisabledLegacyPublicStorefrontAction(res, action) {
  return send(res, 410, {
    success: false,
    ok: false,
    disabled: true,
    action,
    error: "Endpoint publik legacy sudah dinonaktifkan. Gunakan endpoint checkout/produk publik resmi yang divalidasi backend."
  });
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function isResourceExhausted(error) {
  const code = error && (error.code || error.status || error.statusCode);
  const message = [
    error && error.message,
    error && error.details,
    error && error.stack
  ].filter(Boolean).join("\n");

  return (
    code === 8 ||
    String(code || "").toLowerCase() === "resource-exhausted" ||
    /RESOURCE_EXHAUSTED|quota exceeded|quota/i.test(message)
  );
}

function resourceExhaustedWarning(context, error) {
  const rawMessage = String((error && error.message) || "Quota exceeded").replace(/\s+/g, " ").trim();
  return `${context}: ${rawMessage}`;
}

function base64urlToBuffer(value) {
  return Buffer.from(String(value || ""), "base64url");
}

function parseSession(session) {
  const secret = getA2fSecret();
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

function getSupabaseAdmin() {
  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !serviceRoleKey) {
    throw Object.assign(new Error("ENV Supabase belum lengkap. Isi SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di Vercel."), { status: 500 });
  }

  return createClient(url, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });
}

async function writeAdminLog({ uid, email, role, action, ok = true, message = "" }) {
  const supabase = getSupabaseAdmin();
  const { error } = await supabase.from(ADMIN_LOG_TABLE).insert({
    uid: uid || "",
    email: email || "",
    role: role || "",
    action: action || "",
    ok: Boolean(ok),
    message: message || ""
  });

  if (error) {
    console.warn("Gagal menulis admin log Supabase:", error.message || error);
  }
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
  let data = {};

  try {
    const snap = await db.collection("users").doc(decoded.uid).get();
    data = snap.exists ? snap.data() || {} : {};
  } catch (error) {
    if (isResourceExhausted(error) && claimRole) {
      return claimRole;
    }
    throw error;
  }

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

function getPasskeyOpenRole(decoded) {
  const envRole = normalizeRole(process.env.A2F_ADMIN_ROLE || process.env.ADMIN_ROLE || "");
  const claimRole = normalizeRole(decoded && (decoded.role || (decoded.admin === true ? "admin" : "")));
  return envRole || claimRole || "owner";
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

async function createA2FSession(decoded, role) {
  const supabase = getSupabaseAdmin();
  const now = Date.now();
  const expiresAtMs = now + A2F_SESSION_TTL_MS;

  const { error } = await supabase.from(A2F_SESSION_TABLE).upsert({
    uid: decoded.uid,
    email: decoded.email || "",
    role: role || "",
    verified: true,
    status: "verified",
    method: "passkey",
    created_at: new Date(now).toISOString(),
    last_used_at: new Date(now).toISOString(),
    expires_at: new Date(expiresAtMs).toISOString()
  }, { onConflict: "uid" });

  if (error) {
    throw Object.assign(new Error("Gagal menyimpan session A2F ke Supabase: " + error.message), { status: 500 });
  }

  return {
    expiresAtMs,
    stored: true,
    quotaFallback: false
  };
}

async function assertA2FSession(decoded) {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from(A2F_SESSION_TABLE)
    .select("uid, role, verified, status, expires_at")
    .eq("uid", decoded.uid)
    .maybeSingle();

  if (error) {
    throw Object.assign(new Error("Gagal cek session A2F Supabase: " + error.message), { status: 500 });
  }

  if (!data) {
    throw Object.assign(new Error("A2F session not found. Selesaikan A2F lagi."), { status: 403 });
  }

  const verified = data.verified === true || data.status === "verified";
  const expiresAtMs = Date.parse(data.expires_at || "");
  const notExpired = Number.isFinite(expiresAtMs) && expiresAtMs > Date.now();

  if (!verified || !notExpired) {
    throw Object.assign(new Error("A2F session expired or invalid. Selesaikan A2F lagi."), { status: 403 });
  }

  await supabase
    .from(A2F_SESSION_TABLE)
    .update({ last_used_at: new Date().toISOString() })
    .eq("uid", decoded.uid);

  return data;
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

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function decodeValue(value) {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map(decodeValue);
  if (typeof value !== "object") return value;

  if (value.__diracFirestoreOp === "serverTimestamp") {
    return new Date().toISOString();
  }

  if (value.__diracFirestoreOp === "increment") {
    return { __diracSupabaseOp: "increment", value: Number(value.value || 0) };
  }

  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (val !== undefined) out[key] = decodeValue(val);
  }
  return out;
}

function applyDecodedPatch(current, patch, merge) {
  const base = merge && isPlainObject(current) ? { ...current } : {};
  const input = isPlainObject(patch) ? patch : {};

  for (const [key, value] of Object.entries(input)) {
    if (isPlainObject(value) && value.__diracSupabaseOp === "increment") {
      base[key] = Number(base[key] || 0) + Number(value.value || 0);
      continue;
    }

    if (merge && isPlainObject(base[key]) && isPlainObject(value)) {
      base[key] = applyDecodedPatch(base[key], value, true);
      continue;
    }

    base[key] = value;
  }

  return base;
}

function getOrderValue(row, key) {
  const data = row && row.data && typeof row.data === "object" ? row.data : {};
  if (key === "docId" || key === "id") return data[key] || row.doc_id || "";
  return data[key] !== undefined ? data[key] : "";
}

function normalizeComparable(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return value;
  if (typeof value === "boolean") return value ? 1 : 0;
  const text = String(value);
  const numeric = Number(text);
  if (text.trim() !== "" && Number.isFinite(numeric)) return numeric;
  const parsed = Date.parse(text);
  if (Number.isFinite(parsed) && /\d{4}-\d{2}-\d{2}|T\d{2}:\d{2}/.test(text)) return parsed;
  return text.toLowerCase();
}

function sortRows(rows, orderByKey, direction) {
  const key = String(orderByKey || "").trim();
  const dir = String(direction || "asc").toLowerCase() === "desc" ? -1 : 1;
  if (!key) return rows;

  return rows.sort((a, b) => {
    const av = normalizeComparable(getOrderValue(a, key));
    const bv = normalizeComparable(getOrderValue(b, key));
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    return String(a.doc_id || "").localeCompare(String(b.doc_id || ""));
  });
}

function filterRows(rows, collection, body) {
  const prefix = `${collection}`;
  const search = String(body[`${prefix}Search`] || "").trim().toLowerCase();
  const paymentStatus = String(body[`${prefix}PaymentStatus`] || "").trim().toLowerCase();
  const orderStatus = String(body[`${prefix}OrderStatus`] || "").trim().toLowerCase();

  return rows.filter((row) => {
    const data = row && row.data && typeof row.data === "object" ? row.data : {};
    if (search && !JSON.stringify(data).toLowerCase().includes(search) && !String(row.doc_id || "").toLowerCase().includes(search)) return false;
    if (paymentStatus && String(data.paymentStatus || "").trim().toLowerCase() !== paymentStatus) return false;
    if (orderStatus && String(data.status || data.orderStatus || "").trim().toLowerCase() !== orderStatus) return false;
    return true;
  });
}

function truthyFlag(value) {
  return value === true || String(value || "").trim().toLowerCase() === "true" || String(value || "").trim() === "1";
}

function normalizeProductStatus(data) {
  const input = data && typeof data === "object" ? data : {};
  const raw = String(input.status || "").trim().toLowerCase();
  const flagSold = truthyFlag(input.isSold) || truthyFlag(input.soldOut) || truthyFlag(input.outOfStock);
  if (flagSold || raw === "sold" || raw === "habis" || raw === "soldout" || raw === "sold_out") return "sold";
  return "ready";
}

function canonicalizeProductData(data) {
  const input = data && typeof data === "object" && !Array.isArray(data) ? data : {};
  const out = Object.assign({}, input);
  const status = normalizeProductStatus(out);
  out.status = status;
  out.isSold = status === "sold";
  out.soldOut = status === "sold";
  out.outOfStock = status === "sold";
  return out;
}

function applyExplicitProductStatusIntent(nextData, decodedPatch) {
  const patch = decodedPatch && typeof decodedPatch === "object" && !Array.isArray(decodedPatch) ? decodedPatch : {};
  if (!Object.prototype.hasOwnProperty.call(patch, "status")) return nextData;
  const raw = String(patch.status || "").trim().toLowerCase();
  if (raw !== "sold" && raw !== "ready") return nextData;
  const forced = Object.assign({}, nextData);
  forced.status = raw;
  forced.isSold = raw === "sold";
  forced.soldOut = raw === "sold";
  forced.outOfStock = raw === "sold";
  if (raw === "ready" && Number(forced.stock || 0) <= 0) {
    forced.stock = 1;
  }
  return forced;
}

function rowToClient(row) {
  const raw = row && row.data && typeof row.data === "object" && !Array.isArray(row.data) ? row.data : {};
  const data = row && row.collection === "products" ? canonicalizeProductData(raw) : raw;
  return {
    docId: row.doc_id,
    id: data.id || row.doc_id,
    data: Object.assign({}, data, { docId: row.doc_id })
  };
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

async function getSupabaseDocument(collection, docId) {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from(ADMIN_DOCUMENTS_TABLE)
    .select("collection, doc_id, data, created_at, updated_at")
    .eq("collection", collection)
    .eq("doc_id", docId)
    .maybeSingle();

  if (error) {
    throw Object.assign(new Error("Gagal membaca dokumen Supabase: " + error.message), { status: 500 });
  }

  return data || null;
}

async function upsertSupabaseDocument(collection, docId, patch, merge) {
  const supabase = getSupabaseAdmin();
  const existing = merge ? await getSupabaseDocument(collection, docId) : null;
  const nowIso = new Date().toISOString();
  const decodedPatch = decodeValue(patch || {});
  let nextData = applyDecodedPatch(existing && existing.data ? existing.data : {}, decodedPatch, merge);
  if (collection === "products") {
    nextData = canonicalizeProductData(applyExplicitProductStatusIntent(nextData, decodedPatch));
  }

  const { error } = await supabase
    .from(ADMIN_DOCUMENTS_TABLE)
    .upsert({
      collection,
      doc_id: docId,
      data: nextData,
      updated_at: nowIso,
      created_at: existing && existing.created_at ? existing.created_at : nowIso
    }, { onConflict: "collection,doc_id" });

  if (error) {
    throw Object.assign(new Error("Gagal menyimpan dokumen Supabase: " + error.message), { status: 500 });
  }
}

async function updateSupabaseDocument(collection, docId, patch) {
  const existing = await getSupabaseDocument(collection, docId);
  if (!existing) {
    throw Object.assign(new Error("Dokumen tidak ditemukan: " + collection + "/" + docId), { status: 404 });
  }

  return upsertSupabaseDocument(collection, docId, patch, true);
}

async function deleteSupabaseDocument(collection, docId) {
  const supabase = getSupabaseAdmin();
  const { error } = await supabase
    .from(ADMIN_DOCUMENTS_TABLE)
    .delete()
    .eq("collection", collection)
    .eq("doc_id", docId);

  if (error) {
    throw Object.assign(new Error("Gagal menghapus dokumen Supabase: " + error.message), { status: 500 });
  }
}

async function readSupabaseCollection(collection, body) {
  const supabase = getSupabaseAdmin();
  const limitRaw = Number(body[`${collection}Limit`] || body.limit || 30000);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(Math.trunc(limitRaw), 1), 30000) : 30000;
  const cursor = String(body[`${collection}Cursor`] || "").trim();
  const orderByKey = String(body[`${collection}OrderBy`] || "").trim();
  const orderDirection = String(body[`${collection}OrderDirection`] || "asc").trim();

  let query = supabase
    .from(ADMIN_DOCUMENTS_TABLE)
    .select("collection, doc_id, data, created_at, updated_at")
    .eq("collection", collection)
    .limit(30000);

  const { data, error } = await query;
  if (error) {
    throw Object.assign(new Error("Gagal membaca collection Supabase: " + error.message), { status: 500 });
  }

  let rows = Array.isArray(data) ? data.slice() : [];

  if (!rows.length && shouldAutoMigrateFirebase(body)) {
    const migrated = await migrateFirebaseCollectionToSupabase(collection).catch((error) => {
      if (isResourceExhausted(error)) {
        throw Object.assign(new Error("Firebase quota masih habis, data lama belum bisa disalin ke Supabase. Tunggu quota pulih atau impor data manual."), { status: 429 });
      }
      throw error;
    });

    if (migrated.count > 0) {
      const reread = await supabase
        .from(ADMIN_DOCUMENTS_TABLE)
        .select("collection, doc_id, data, created_at, updated_at")
        .eq("collection", collection)
        .limit(30000);

      if (reread.error) {
        throw Object.assign(new Error("Gagal membaca ulang collection Supabase setelah migrasi: " + reread.error.message), { status: 500 });
      }

      rows = Array.isArray(reread.data) ? reread.data.slice() : [];
    }
  }

  rows = filterRows(rows, collection, body);
  rows = sortRows(rows, orderByKey || "docId", orderDirection);

  let startIndex = 0;
  if (cursor) {
    const found = rows.findIndex((row) => String(row.doc_id) === cursor);
    if (found >= 0) startIndex = found + 1;
  }

  const pageRows = rows.slice(startIndex, startIndex + limit);
  const next = rows[startIndex + limit] ? String(pageRows[pageRows.length - 1].doc_id || "") : "";

  return {
    rows: pageRows.map(rowToClient),
    page: {
      limit,
      total: rows.length,
      returned: pageRows.length,
      cursor: cursor || "",
      nextCursor: next,
      hasMore: Boolean(next)
    }
  };
}


function normalizeFirestoreJson(value) {
  if (value === undefined) return null;
  if (value === null) return null;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(normalizeFirestoreJson);

  if (typeof value === "object") {
    if (typeof value.toDate === "function") {
      try {
        return value.toDate().toISOString();
      } catch (_error) {
        return null;
      }
    }

    if (typeof value.latitude === "number" && typeof value.longitude === "number") {
      return {
        latitude: value.latitude,
        longitude: value.longitude
      };
    }

    if (typeof value.path === "string" && value.firestore) {
      return value.path;
    }

    const out = {};
    for (const [key, val] of Object.entries(value)) {
      if (val !== undefined) out[key] = normalizeFirestoreJson(val);
    }
    return out;
  }

  return value;
}

function shouldAutoMigrateFirebase(body) {
  const explicit = String(body.autoMigrateFirebase || "").trim().toLowerCase();
  if (explicit === "false" || explicit === "0" || explicit === "no") return false;

  const env = String(process.env.ADMIN_AUTO_MIGRATE_FIREBASE_ON_EMPTY || "true").trim().toLowerCase();
  return !(env === "false" || env === "0" || env === "no");
}

async function migrateFirebaseCollectionToSupabase(collection) {
  const db = getDb();
  const supabase = getSupabaseAdmin();
  const snap = await db.collection(collection).get();
  const nowIso = new Date().toISOString();
  const rows = [];

  snap.forEach((doc) => {
    rows.push({
      collection,
      doc_id: doc.id,
      data: normalizeFirestoreJson(Object.assign({}, doc.data() || {}, { docId: doc.id, id: (doc.data() || {}).id || doc.id })),
      created_at: nowIso,
      updated_at: nowIso
    });
  });

  for (let i = 0; i < rows.length; i += 400) {
    const chunk = rows.slice(i, i + 400);
    if (!chunk.length) continue;

    const { error } = await supabase
      .from(ADMIN_DOCUMENTS_TABLE)
      .upsert(chunk, { onConflict: "collection,doc_id" });

    if (error) {
      throw Object.assign(new Error("Gagal migrasi " + collection + " ke Supabase: " + error.message), { status: 500 });
    }
  }

  return {
    collection,
    count: rows.length
  };
}

async function migrateFirebaseCollectionsToSupabase(collections) {
  const selected = Array.isArray(collections) && collections.length
    ? collections.map(cleanCollectionName)
    : ["products", "orders", "customers", "settings", "securityLogs", "categories", "brands", "variants"];

  const result = {};
  for (const collection of selected) {
    result[collection] = await migrateFirebaseCollectionToSupabase(collection);
  }
  return result;
}

async function handleReadAdminData(body) {
  const requested = Array.isArray(body.collections) ? body.collections : [];
  const collections = requested.length ? requested.map(cleanCollectionName) : ["products", "orders", "customers", "settings", "securityLogs", "categories", "brands", "variants"];
  const response = { success: true, action: "readAdminData", provider: "supabase", autoMigrateFirebaseOnEmpty: shouldAutoMigrateFirebase(body) };

  for (const collection of collections) {
    const result = await readSupabaseCollection(collection, body);
    response[collection] = result.rows;
    response[`${collection}Page`] = result.page;
  }

  return response;
}


function plainDataFromRow(row) {
  const raw = row && row.data && typeof row.data === "object" && !Array.isArray(row.data) ? row.data : {};
  const data = row && row.collection === "products" ? canonicalizeProductData(raw) : raw;
  return Object.assign({}, data, {
    docId: row.doc_id,
    id: data.id || row.doc_id,
    _collection: row.collection,
    _createdAt: row.created_at || null,
    _updatedAt: row.updated_at || null
  });
}

/* Legacy public storefront handlers removed/disabled.
   Public order/product actions must not live in admin passkey endpoint. */

async function fetchAllAdminDocumentsForExport() {
  const supabase = getSupabaseAdmin();
  const pageSize = 1000;
  let from = 0;
  const rows = [];

  while (true) {
    const { data, error } = await supabase
      .from(ADMIN_DOCUMENTS_TABLE)
      .select("collection, doc_id, data, created_at, updated_at")
      .order("collection", { ascending: true })
      .order("doc_id", { ascending: true })
      .range(from, from + pageSize - 1);

    if (error) {
      throw Object.assign(new Error("Gagal membaca backup Supabase: " + error.message), { status: 500 });
    }

    const batch = Array.isArray(data) ? data : [];
    rows.push(...batch);

    if (batch.length < pageSize) break;
    from += pageSize;
  }

  return rows;
}

function groupAdminDocumentRows(rows) {
  const grouped = {
    products: [],
    orders: [],
    customers: [],
    settings: [],
    securityLogs: [],
    categories: [],
    brands: [],
    variants: [],
    order_items: []
  };

  for (const row of rows) {
    const collection = String(row.collection || "").trim();
    if (!grouped[collection]) grouped[collection] = [];
    grouped[collection].push(plainDataFromRow(row));
  }

  return grouped;
}

async function exportAdminDataFromSupabase() {
  const rows = await fetchAllAdminDocumentsForExport();
  const grouped = groupAdminDocumentRows(rows);

  return {
    success: true,
    action: "exportAdminData",
    provider: "supabase",
    table: ADMIN_DOCUMENTS_TABLE,
    exportedAt: new Date().toISOString(),
    counts: {
      total: rows.length,
      products: grouped.products.length,
      orders: grouped.orders.length,
      customers: grouped.customers.length,
      settings: grouped.settings.length,
      securityLogs: grouped.securityLogs.length,
      categories: grouped.categories.length,
      brands: grouped.brands.length,
      variants: grouped.variants.length,
      order_items: grouped.order_items.length
    },
    products: grouped.products,
    orders: grouped.orders,
    customers: grouped.customers,
    settings: grouped.settings,
    securityLogs: grouped.securityLogs,
    categories: grouped.categories,
    brands: grouped.brands,
    variants: grouped.variants,
    order_items: grouped.order_items,
    rawRows: rows
  };
}

function numberForReport(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

async function reportAdminDataFromSupabase() {
  const rows = await fetchAllAdminDocumentsForExport();
  const grouped = groupAdminDocumentRows(rows);
  const revenue = grouped.orders.reduce((sum, order) => sum + numberForReport(order.total), 0);

  return {
    success: true,
    action: "reportAdminData",
    provider: "supabase",
    counts: {
      products: grouped.products.length,
      orders: grouped.orders.length,
      customers: grouped.customers.length,
      settings: grouped.settings.length,
      securityLogs: grouped.securityLogs.length
    },
    totals: {
      revenue
    },
    products: grouped.products,
    orders: grouped.orders,
    customers: grouped.customers
  };
}

async function handleAdminDataAction(role, body) {
  const action = String(body.action || "").trim();

  if (action === "migrateFirebaseToSupabase") {
    if (!canWrite(role)) throw Object.assign(new Error("Role admin/editor wajib untuk migrasi data"), { status: 403 });
    const migrated = await migrateFirebaseCollectionsToSupabase(body.collections);
    return { success: true, action, provider: "supabase", migrated };
  }

  if (action === "readAdminData") {
    return handleReadAdminData(body);
  }

  if (action === "setDoc") {
    if (!canWrite(role)) throw Object.assign(new Error("Role admin/editor wajib untuk simpan data"), { status: 403 });
    const collection = cleanCollectionName(body.collection);
    const docId = cleanDocId(body.docId);
    await upsertSupabaseDocument(collection, docId, body.data || {}, body.merge !== false);
    return { success: true, action, provider: "supabase", path: `${collection}/${docId}` };
  }

  if (action === "updateDoc") {
    if (!canWrite(role)) throw Object.assign(new Error("Role admin/editor wajib untuk update data"), { status: 403 });
    const collection = cleanCollectionName(body.collection);
    const docId = cleanDocId(body.docId);
    await updateSupabaseDocument(collection, docId, body.data || {});
    return { success: true, action, provider: "supabase", path: `${collection}/${docId}` };
  }

  if (action === "deleteDoc") {
    if (!canDelete(role)) throw Object.assign(new Error("Hanya owner/admin yang boleh hapus data"), { status: 403 });
    const collection = cleanCollectionName(body.collection);
    const docId = cleanDocId(body.docId);
    await deleteSupabaseDocument(collection, docId);
    return { success: true, action, provider: "supabase", path: `${collection}/${docId}` };
  }

  if (action === "batch") {
    if (!canWrite(role)) throw Object.assign(new Error("Role admin/editor wajib untuk batch data"), { status: 403 });
    const ops = Array.isArray(body.operations) ? body.operations : [];
    if (!ops.length) return { success: true, action, provider: "supabase", count: 0 };
    if (ops.length > 450) {
      throw Object.assign(new Error("Terlalu banyak operasi batch. Maksimal 450."), { status: 400 });
    }

    for (const op of ops) {
      const type = String(op.type || "set").toLowerCase();
      const [collectionRaw, docIdRaw] = cleanDocPath(op.path).split("/");
      const collection = cleanCollectionName(collectionRaw);
      const docId = cleanDocId(docIdRaw);

      if (type === "delete") {
        if (!canDelete(role)) throw Object.assign(new Error("Hanya owner/admin yang boleh delete batch"), { status: 403 });
        await deleteSupabaseDocument(collection, docId);
      } else if (type === "update") {
        await updateSupabaseDocument(collection, docId, op.data || {});
      } else {
        await upsertSupabaseDocument(collection, docId, op.data || {}, op.merge !== false);
      }
    }

    return { success: true, action, provider: "supabase", count: ops.length };
  }

  if (action === "createUploadUrl") {
    return handleCreateUploadUrl(body);
  }

  if (action === "exportAdminData") {
    return exportAdminDataFromSupabase();
  }

  if (action === "reportAdminData") {
    return reportAdminDataFromSupabase(body);
  }

  throw Object.assign(new Error("Action admin tidak didukung: " + action), { status: 400 });
}

async function handleAdminAction(req, res, body) {
  const decoded = await verifyIdToken(req, body);
  assertExpectedAdmin(decoded);

  const session = await assertA2FSession(decoded);
  const role = normalizeRole(session && session.role) || getPasskeyOpenRole(decoded);

  const action = String(body.action || "").trim();
  if (action !== "readAdminData" && !canWrite(role)) {
    throw Object.assign(new Error("Role admin/editor wajib untuk aksi admin"), { status: 403 });
  }

  const result = await handleAdminDataAction(role, body);
  await writeAdminLog({
    uid: decoded.uid,
    email: decoded.email || "",
    role,
    action: body.action || "",
    ok: true
  });
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

  // Tahap 5 hanya membuka A2F session setelah passkey valid.
  // Jangan baca Firestore di sini agar tidak mentok RESOURCE_EXHAUSTED.
  // Akses admin tetap dikunci oleh verifyIdToken + A2F_ADMIN_UID + passkey.
  const role = getPasskeyOpenRole(decoded);
  if (!canWrite(role)) {
    return send(res, 403, {
      success: false,
      error: "Role admin/editor wajib untuk membuka dashboard"
    });
  }

  const a2fSessionResult = await createA2FSession(decoded, role);
  const expiresAtMs = a2fSessionResult.expiresAtMs;
  await writeAdminLog({
    uid: decoded.uid,
    email: decoded.email || "",
    role,
    action: "a2f.passkey_finish",
    ok: true
  });

  return send(res, 200, {
    success: true,
    message: "Passkey benar",
    a2fSession: "verified",
    expiresAtMs,
    sessionStored: a2fSessionResult.stored,
    quotaFallback: a2fSessionResult.quotaFallback,
    warning: a2fSessionResult.warning
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

    if (isDisabledLegacyPublicStorefrontAction(action)) {
      return sendDisabledLegacyPublicStorefrontAction(res, action);
    }

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
