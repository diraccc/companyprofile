const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const PUBLIC_TOTP_TABLE = process.env.SUPABASE_PUBLIC_TOTP_TABLE || "user_totp_mfa";
const TOTP_ISSUER = process.env.TOTP_ISSUER || "Dirac Group";
const SETUP_TOKEN_TTL_MS = Number(process.env.PUBLIC_TOTP_SETUP_TOKEN_TTL_MS || 10 * 60 * 1000);
const PUBLIC_LOCK_MS = Number(process.env.PUBLIC_TOTP_LOCK_MS || 10 * 60 * 1000);
const PUBLIC_MAX_FAILED = Number(process.env.PUBLIC_TOTP_MAX_FAILED || 5);
const CORS_ALLOWED_ORIGIN = process.env.A2F_ALLOWED_ORIGIN || "https://diracgroup.store";

let supabaseAdminClient = null;

function setCors(req, res) {
  const origin = String((req && req.headers && req.headers.origin) || "");
  if (!origin || origin === CORS_ALLOWED_ORIGIN || origin === "https://www.diracgroup.store" || /\.vercel\.app$/i.test(new URL(origin || "https://x.vercel.app").hostname)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
}

function json(res, status, data) {
  return res.status(status).json(data);
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function getEncryptionSecret() {
  const secret = String(process.env.A2F_SECRET || process.env.TOTP_ENCRYPTION_SECRET || "").trim();
  if (!secret || secret.length < 32) {
    const err = new Error("A2F_SECRET wajib minimal 32 karakter acak di Vercel Environment Variables.");
    err.statusCode = 500;
    throw err;
  }
  return secret;
}

function getSupabaseAdmin() {
  if (supabaseAdminClient) return supabaseAdminClient;

  const supabaseUrl = String(process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "").trim();
  const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();

  if (!supabaseUrl || !serviceRoleKey) {
    const err = new Error("ENV Supabase belum lengkap. Isi SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di Vercel.");
    err.statusCode = 500;
    throw err;
  }

  supabaseAdminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false }
  });

  return supabaseAdminClient;
}

function publicError(error) {
  return {
    message: String((error && error.message) || ""),
    details: String((error && error.details) || ""),
    hint: String((error && error.hint) || ""),
    code: String((error && error.code) || ""),
    status: Number((error && (error.status || error.statusCode)) || 0)
  };
}

function normalizeIdentifier(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "")
    .slice(0, 180);
}

function randomBase32(length = 32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  while (out.length < length) out += alphabet[crypto.randomInt(0, alphabet.length)];
  return out;
}

function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const bytes = [];
  base32 = String(base32 || "").replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  for (const char of base32) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw Object.assign(new Error("Secret Authenticator tidak valid."), { statusCode: 400 });
    bits += val.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
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

function verifyTotpCode(secret, code) {
  const input = String(code || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(input)) return false;
  const validCodes = [generateTotp(secret, -1), generateTotp(secret, 0), generateTotp(secret, 1)];
  return validCodes.some((validCode) => safeEqual(input, validCode));
}

function deriveEncryptionKey() {
  return crypto.createHash("sha256").update(`dirac-public-totp-v2:${getEncryptionSecret()}`).digest();
}

function encryptSecret(base32Secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(base32Secret), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 2,
    alg: "aes-256-gcm",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    data: encrypted.toString("base64url")
  };
}

function decryptSecret(payload) {
  if (typeof payload === "string" && /^[A-Z2-7]+=*$/i.test(payload.replace(/\s+/g, ""))) {
    return payload.replace(/\s+/g, "").toUpperCase();
  }
  const row = payload && typeof payload === "object" ? payload : {};
  if (!row.iv || !row.tag || !row.data) {
    throw Object.assign(new Error("Secret Authenticator belum disiapkan."), { statusCode: 400 });
  }
  const decipher = crypto.createDecipheriv("aes-256-gcm", deriveEncryptionKey(), Buffer.from(String(row.iv), "base64url"));
  decipher.setAuthTag(Buffer.from(String(row.tag), "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(String(row.data), "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function sign(data) {
  return crypto.createHmac("sha256", getEncryptionSecret()).update(data).digest("base64url");
}

function makeSetupToken({ identifier, secret }) {
  const payload = {
    v: 1,
    type: "dirac_public_totp_setup",
    identifier,
    secret,
    iat: Date.now(),
    exp: Date.now() + SETUP_TOKEN_TTL_MS
  };
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(body)}`;
}

function parseSetupToken(token, expectedIdentifier) {
  const [body, signature] = String(token || "").split(".");
  if (!body || !signature || !safeEqual(signature, sign(body))) {
    throw Object.assign(new Error("Setup Authenticator sudah tidak valid. Tekan Kirim ulang/Resend."), { statusCode: 400 });
  }
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  if (payload.type !== "dirac_public_totp_setup" || payload.v !== 1) {
    throw Object.assign(new Error("Setup Authenticator tidak valid."), { statusCode: 400 });
  }
  if (Number(payload.exp || 0) < Date.now()) {
    throw Object.assign(new Error("Setup Authenticator sudah expired. Tekan Kirim ulang/Resend."), { statusCode: 400 });
  }
  if (normalizeIdentifier(payload.identifier) !== normalizeIdentifier(expectedIdentifier)) {
    throw Object.assign(new Error("Setup Authenticator tidak cocok dengan akun ini."), { statusCode: 400 });
  }
  return payload;
}

function otpauthUrl(identifier, secret) {
  const label = `${TOTP_ISSUER}:${identifier}`;
  const params = new URLSearchParams({
    secret,
    issuer: TOTP_ISSUER,
    algorithm: "SHA1",
    digits: "6",
    period: "30"
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

async function makeQrCodeDataUrl(uri) {
  try {
    const QRCode = require("qrcode");
    return await QRCode.toDataURL(uri, { margin: 1, width: 220 });
  } catch (_error) {
    return "";
  }
}

function makeRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    codes.push(`DRC-${crypto.randomBytes(4).toString("hex").toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`);
  }
  return codes;
}

function hashRecoveryCodes(codes) {
  return codes.map((code) => crypto.createHmac("sha256", getEncryptionSecret()).update(String(code)).digest("hex"));
}

async function readPublicMfa(identifier) {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from(PUBLIC_TOTP_TABLE)
    .select("identifier, secret_enc, enabled, failed_count, lock_until_ms, recovery_hashes, created_at, updated_at, verified_at, last_failed_at")
    .eq("identifier", identifier)
    .maybeSingle();
  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }
  return data || null;
}

function cleanDbRow(row) {
  const out = {};
  Object.keys(row || {}).forEach((key) => {
    if (row[key] !== undefined) out[key] = row[key];
  });
  return out;
}

async function updatePublicMfa(identifier, patch) {
  const supabase = getSupabaseAdmin();
  const row = cleanDbRow(Object.assign({}, patch, {
    identifier,
    updated_at: new Date().toISOString()
  }));

  const { error } = await supabase
    .from(PUBLIC_TOTP_TABLE)
    .update(row)
    .eq("identifier", identifier);

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }
  return row;
}

async function insertPublicMfa(identifier, patch) {
  const supabase = getSupabaseAdmin();
  const now = new Date().toISOString();
  const row = cleanDbRow(Object.assign({}, patch, {
    identifier,
    created_at: patch.created_at || now,
    updated_at: now
  }));

  const { error } = await supabase
    .from(PUBLIC_TOTP_TABLE)
    .insert(row);

  if (error) {
    error.statusCode = error.status || 500;
    throw error;
  }
  return row;
}

async function savePublicMfa(identifier, patch) {
  const id = normalizeIdentifier(identifier);
  if (!id) throw Object.assign(new Error("Identifier pengguna kosong."), { statusCode: 400 });

  const existing = await readPublicMfa(id).catch((error) => {
    console.error("Gagal membaca user_totp_mfa:", publicError(error));
    throw error;
  });

  try {
    if (existing) return await updatePublicMfa(id, patch);
    return await insertPublicMfa(id, patch);
  } catch (error) {
    const info = publicError(error);
    console.error("Gagal menyimpan user_totp_mfa:", info);

    // Duplicate primary key / race condition: retry as update.
    if (String(info.code) === "23505") {
      return await updatePublicMfa(id, patch);
    }

    throw error;
  }
}

function lockMessage(lockUntilMs) {
  const minutes = Math.ceil(Math.max(0, Number(lockUntilMs || 0) - Date.now()) / 60000);
  return minutes > 0 ? `Terlalu banyak percobaan. Coba lagi dalam ${minutes} menit.` : "Terlalu banyak percobaan. Coba lagi nanti.";
}

async function setupAuthenticator(identifier) {
  const id = normalizeIdentifier(identifier);
  if (!id) {
    return { status: 400, body: { success: false, ok: false, error: "Email/nomor pengguna wajib ada sebelum mengaktifkan A2F." } };
  }

  let existing = null;
  try {
    existing = await readPublicMfa(id);
  } catch (error) {
    // Setup tetap bisa jalan memakai setupToken, supaya UI tidak mati hanya karena cache/permission Supabase.
    console.error("Read Supabase saat setup gagal, lanjut dengan token sementara:", publicError(error));
  }

  let secret = "";
  try {
    secret = existing && existing.secret_enc ? decryptSecret(existing.secret_enc) : "";
  } catch (_error) {
    secret = "";
  }
  if (!secret) secret = randomBase32(32);

  const uri = otpauthUrl(id, secret);
  const setupToken = makeSetupToken({ identifier: id, secret });
  const qrCodeDataUrl = await makeQrCodeDataUrl(uri);

  let persisted = false;
  let persistError = "";
  try {
    await savePublicMfa(id, {
      secret_enc: encryptSecret(secret),
      enabled: existing && existing.enabled === true,
      failed_count: 0,
      lock_until_ms: 0
    });
    persisted = true;
  } catch (error) {
    persistError = error.message || "Supabase gagal menyimpan setup.";
    // Tidak throw: setupToken tetap membuat kode bisa diverifikasi dengan aman pada sesi ini.
  }

  return {
    status: 200,
    body: {
      success: true,
      ok: true,
      method: "authenticator",
      qrCodeDataUrl,
      manualKey: secret,
      otpauthUrl: uri,
      setupToken,
      persisted,
      persistError: persisted ? "" : persistError,
      message: "Scan QR atau masukkan setup key di aplikasi Authenticator, lalu masukkan kode 6 digit."
    }
  };
}

async function verifyAuthenticator(identifier, code, setupToken) {
  const id = normalizeIdentifier(identifier);
  if (!id) {
    return { status: 400, body: { success: false, ok: false, error: "Email/nomor pengguna wajib ada untuk verifikasi A2F." } };
  }

  let row = null;
  let secret = "";
  let source = "database";

  try {
    row = await readPublicMfa(id);
    if (row && row.lock_until_ms && Number(row.lock_until_ms) > Date.now()) {
      return { status: 423, body: { success: false, ok: false, locked: true, lockUntilMs: Number(row.lock_until_ms), error: lockMessage(row.lock_until_ms) } };
    }
    if (row && row.secret_enc) secret = decryptSecret(row.secret_enc);
  } catch (error) {
    console.error("Read Supabase saat verify gagal:", publicError(error));
  }

  if (!secret && setupToken) {
    const payload = parseSetupToken(setupToken, id);
    secret = payload.secret;
    source = "setupToken";
  }

  if (!secret) {
    return { status: 400, body: { success: false, ok: false, error: "Authenticator belum disiapkan. Tekan Lanjutkan/Kirim ulang untuk membuat QR baru." } };
  }

  if (!verifyTotpCode(secret, code)) {
    const failedCount = Number((row && row.failed_count) || 0) + 1;
    const lockUntilMs = failedCount >= PUBLIC_MAX_FAILED ? Date.now() + PUBLIC_LOCK_MS : 0;
    if (row) {
      try {
        await savePublicMfa(id, {
          secret_enc: row.secret_enc || encryptSecret(secret),
          enabled: row.enabled === true,
          failed_count: failedCount,
          lock_until_ms: lockUntilMs,
          last_failed_at: new Date().toISOString()
        });
      } catch (error) {
        console.error("Gagal simpan failed_count MFA:", publicError(error));
      }
    }
    return {
      status: lockUntilMs ? 423 : 401,
      body: {
        success: false,
        ok: false,
        locked: Boolean(lockUntilMs),
        failedCount,
        lockUntilMs,
        error: lockUntilMs ? lockMessage(lockUntilMs) : "Kode verifikasi salah. Masukkan kode 6 digit terbaru dari aplikasi Authenticator."
      }
    };
  }

  const recoveryCodes = makeRecoveryCodes(8);
  let persisted = false;
  let persistError = "";
  try {
    await savePublicMfa(id, {
      secret_enc: row && row.secret_enc ? row.secret_enc : encryptSecret(secret),
      enabled: true,
      failed_count: 0,
      lock_until_ms: 0,
      verified_at: new Date().toISOString(),
      recovery_hashes: hashRecoveryCodes(recoveryCodes)
    });
    persisted = true;
  } catch (error) {
    persistError = error.message || "Supabase gagal menyimpan status verified.";
    console.error("Verifikasi berhasil tetapi persist Supabase gagal:", publicError(error));
  }

  return {
    status: 200,
    body: {
      success: true,
      ok: true,
      verified: true,
      method: "authenticator",
      source,
      persisted,
      persistError: persisted ? "" : persistError,
      recoveryCodes,
      message: persisted ? "Kode verifikasi benar" : "Kode benar. Supabase belum menerima penyimpanan, tetapi sesi ini sudah terverifikasi."
    }
  };
}

async function legacyAdminVerify(code, action) {
  if (action === "setup" || action === "resend") {
    return { status: 200, body: { success: true, ok: true, method: "authenticator", message: "Authenticator siap. Masukkan kode 6 digit." } };
  }

  const secret = process.env.TOTP_SECRET;
  if (!secret) {
    return { status: 500, body: { success: false, ok: false, error: "TOTP_SECRET belum diset untuk mode admin lama." } };
  }

  if (!verifyTotpCode(secret, code)) {
    return { status: 401, body: { success: false, ok: false, error: "Kode verifikasi salah." } };
  }

  return { status: 200, body: { success: true, ok: true, verified: true, method: "authenticator", message: "Kode verifikasi benar" } };
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return json(res, 405, { success: false, ok: false, error: "Method tidak diizinkan" });
  }

  try {
    const body = req.body || {};
    const method = String(body.method || "authenticator").trim().toLowerCase();
    const action = String(body.action || (body.code ? "verify" : "setup")).trim().toLowerCase();
    const identifier = normalizeIdentifier(body.identifier || body.email || body.username || body.userId || "");

    if (method !== "authenticator") {
      return json(res, 400, { success: false, ok: false, error: "Endpoint ini khusus Authenticator. Pilih metode Authenticator." });
    }

    // Pastikan secret backend valid sebelum membuat QR atau token.
    getEncryptionSecret();

    if (!identifier) {
      const legacy = await legacyAdminVerify(body.code, action);
      return json(res, legacy.status, legacy.body);
    }

    if (action === "setup" || action === "resend") {
      const result = await setupAuthenticator(identifier);
      return json(res, result.status, result.body);
    }

    if (!/^\d{6}$/.test(String(body.code || "").replace(/\s+/g, ""))) {
      return json(res, 400, { success: false, ok: false, error: "Kode wajib 6 digit." });
    }

    const result = await verifyAuthenticator(identifier, body.code, body.setupToken || body.mfaSetupToken || "");
    return json(res, result.status, result.body);
  } catch (error) {
    const status = Number(error.statusCode || error.status || 500);
    const safe = publicError(error);
    console.error("verify-totp fatal:", safe);
    return json(res, status, {
      success: false,
      ok: false,
      error: error.message || "Gagal memproses A2F Authenticator",
      code: safe.code || undefined,
      hint: safe.hint || undefined,
      details: process.env.A2F_DEBUG === "true" ? safe.details : undefined
    });
  }
};
