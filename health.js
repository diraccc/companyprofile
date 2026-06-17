'use strict';

const crypto = require('crypto');
const DIRAC_MIDTRANS_DEBUG_PATCH = 'midtrans-dashboard-key-accept-v11';
const DIRAC_IPAYMU_PATCH = 'ipaymu-redirect-v12';
const DIRAC_COOKIE_SESSION_PATCH = 'cookie-signed-session-v16';

const DEFAULT_ALLOWED_ORIGINS = [
  'https://diracgroup.store',
  'https://www.diracgroup.store',
  'https://companyprofilee-ochre.vercel.app',
  'https://companyprofilee-expk.vercel.app'
];

const DOMAIN_ACTIONS = new Set([
  'domain_health',
  'hostinger_check',
  'domain_login',
  'domain_register',
  'domain_me',
  'domain_dashboard_me',
  'domain_logout',
  'domain_check',
  'domain_checkout',
  'domain_orders',
  'domain_mfa_status'
]);

const DOMAIN_ACTION_ALIASES = Object.freeze({
  'domain-health': 'domain_health',
  'domain_health': 'domain_health',
  'hostinger-check': 'hostinger_check',
  'hostinger_check': 'hostinger_check',
  'hostinger-domain-check': 'hostinger_check',
  'domain_hostinger_check': 'hostinger_check',
  'check-domain': 'domain_check',
  'domain_check': 'domain_check',
  'create-order': 'domain_checkout',
  'domain_create_order': 'domain_checkout',
  'get-orders': 'domain_orders',
  'domain_get_orders': 'domain_orders',
  'domain-login': 'domain_login',
  'domain_login': 'domain_login',
  'login-domain': 'domain_login',
  'domain-register': 'domain_register',
  'domain_register': 'domain_register',
  'register-domain': 'domain_register',
  'domain-me': 'domain_me',
  'domain-dashboard-me': 'domain_dashboard_me',
  'domain_dashboard_me': 'domain_dashboard_me',
  'dashboard-me': 'domain_dashboard_me',
  'dashboard_me': 'domain_dashboard_me',
  'domain_logout': 'domain_logout',
  'domain-logout': 'domain_logout',
  'domain-mfa-status': 'domain_mfa_status',
  'domain_mfa_status': 'domain_mfa_status',
  'dashboard-mfa-status': 'domain_mfa_status'
});

module.exports = async function handler(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = normalizeDomainAction(rawAction);
  const isDomainAction = DOMAIN_ACTIONS.has(action);
  const isLegacyAuthPost = !rawAction && (req.method === 'POST' || req.method === 'OPTIONS');

  const cors = setCors(req, res, { isDomainAction: isDomainAction || isLegacyAuthPost });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  if (isDomainAction) {
    return handleDomainAction(action, req, res);
  }

  if (isLegacyAuthPost) {
    let legacyBody;
    try {
      legacyBody = await readLimitedJsonBody(req, LOGIN_SECURITY_BODY_LIMIT_BYTES);
    } catch (error) {
      return res.status(error.statusCode || 400).json({
        ok: false,
        code: error.code || 'LOGIN_REQUEST_INVALID',
        message: error.publicMessage || 'Request login tidak valid.'
      });
    }
    const legacyMode = String(legacyBody.mode || legacyBody.action || '').trim().toLowerCase();
    if (legacyMode === 'login' || legacyMode === 'domain_login') return domainLogin(req, res, legacyBody);
    if (legacyMode === 'register' || legacyMode === 'signup' || legacyMode === 'domain_register') return domainRegister(req, res, legacyBody);
    return res.status(400).json({ ok: false, message: 'Mode autentikasi tidak valid.' });
  }

  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Method tidak diizinkan.' });

  const payload = {
    ok: true,
    service: 'dirac-ai',
    chatEndpoint: '/api/chat',
    time: diracNowIso()
  };

  if (isAdminRequest(req) || allowPublicHealthDetails(req)) {
    payload.providers = {
      gemini: Boolean(process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEYS || process.env.GEMINI_API_KEY_1),
      groq: Boolean(process.env.GROQ_API_KEY || process.env.GROQ_API_KEYS || process.env.GROQ_API_KEY_1),
      openai: Boolean(process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEYS || process.env.OPENAI_API_KEY_1)
    };
    payload.siteUrl = process.env.SITE_URL || 'https://diracgroup.store';
  }

  return res.status(200).json(payload);
};

function setCors(req, res, options = {}) {
  const allowed = new Set(getAllowedOrigins());
  const origin = req.headers && req.headers.origin;
  const noOrigin = !origin;
  const allowedOrigin = origin && allowed.has(origin) ? origin : '';
  if (allowedOrigin) res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', options.isDomainAction ? 'GET, POST, OPTIONS' : 'GET, OPTIONS');

  const domainAllowedHeaders = [
    'Content-Type',
    'Accept',
    'Idempotency-Key',
    'X-Idempotency-Key',
    'content-type',
    'accept',
    'idempotency-key',
    'x-idempotency-key'
  ];

  // PATCH 3A: backend-only customer auth.
  // Frontend/customer HTML tidak lagi dipercaya membawa Authorization, refresh token,
  // atau MFA proof lewat header. Browser hanya mengirim HttpOnly Secure cookie otomatis.
  if (options.isDomainAction && shouldAcceptFrontendAuthHeaders()) {
    domainAllowedHeaders.push(
      'Authorization',
      'X-Supabase-Access-Token',
      'X-Domain-Access-Token',
      'X-Dirac-Access-Token',
      'X-Firebase-ID-Token',
      'X-Admin-Auth-Provider',
      'X-Dirac-Admin',
      'X-Domain-Refresh',
      'X-Refresh-Token',
      'X-Dirac-MFA-Proof',
      'X-Dashboard-MFA-Proof',
      'X-Dirac-Dashboard-MFA',
      'authorization',
      'x-domain-refresh',
      'x-refresh-token',
      'x-dirac-mfa-proof',
      'x-dashboard-mfa-proof',
      'x-dirac-dashboard-mfa'
    );
  }

  res.setHeader(
    'Access-Control-Allow-Headers',
    options.isDomainAction
      ? domainAllowedHeaders.join(', ')
      : 'Content-Type, X-Dirac-Admin, content-type, x-dirac-admin'
  );
  if (options.isDomainAction) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    const exposedHeaders = ['X-Domain-Token-Refreshed', 'Retry-After'];
    if (!shouldHideDomainAuthTokens()) {
      exposedHeaders.unshift('X-Domain-Access-Token', 'X-Domain-Refresh-Token');
    }
    res.setHeader('Access-Control-Expose-Headers', exposedHeaders.join(', '));
  }
  res.setHeader('Access-Control-Max-Age', '600');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return { allowed: noOrigin || !!allowedOrigin };
}

function getAllowedOrigins() {
  const fromEnv = String(process.env.AI_ALLOWED_ORIGINS || '').split(',').map((item) => item.trim()).filter(Boolean);
  const domainSite = String(process.env.DOMAIN_SITE_URL || '').trim();
  const dev = process.env.NODE_ENV !== 'production' ? ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'] : [];
  return Array.from(new Set([...DEFAULT_ALLOWED_ORIGINS, domainSite, ...fromEnv, ...dev].filter(Boolean)));
}

function isAdminRequest(req) {
  const secret = process.env.AI_ADMIN_SECRET;
  return !!secret && String(req.headers && req.headers['x-dirac-admin'] || '') === secret;
}

function normalizeDomainAction(action) {
  const cleanAction = String(action || '').trim();
  return DOMAIN_ACTION_ALIASES[cleanAction] || cleanAction;
}

/* ============================================================
   DOMAIN ROUTER TAMBAHAN
   Endpoint tetap memakai file lama:
   /api/health?action=domain_health
   /api/health?action=domain-health
   /api/health?action=hostinger-check&domain=contoh.com
   /api/health?action=domain_login
   /api/health?action=domain_register
   /api/health?action=domain_me
   /api/health?action=domain_dashboard_me
   /api/health?action=domain_logout
   /api/health?action=domain_check&domain=contoh.com
   /api/health?action=check-domain&domain=contoh.com
   /api/health?action=domain_checkout
   /api/health?action=create-order
   /api/health?action=domain_orders
   /api/health?action=get-orders
   ============================================================ */

const ACCESS_COOKIE = process.env.DOMAIN_SESSION_COOKIE || 'dirac_domain_session';
const REFRESH_COOKIE = process.env.DOMAIN_REFRESH_COOKIE || 'dirac_domain_refresh';
const CUSTOMER_MFA_COOKIE = process.env.DIRAC_CUSTOMER_MFA_COOKIE || 'dirac_customer_mfa_session';
const DOMAIN_SIGNED_SESSION_COOKIE = process.env.DOMAIN_SIGNED_SESSION_COOKIE || 'dirac_domain_signed_session';
const CUSTOMER_MFA_SESSION_TYPE = 'dirac-customer-mfa-session-v1';
const DOMAIN_SIGNED_SESSION_TYPE = 'dirac-domain-signed-session-v1';

// SAFE V2: database-backed protected-page lock, fail-safe.
// Login/hash/A2F/payment/webhook tidak diubah. Jika database session belum siap/schema berbeda,
// dashboard tidak diblokir. Blokir hanya saat row database jelas revoked/expired/idle.
const DOMAIN_PROTECTED_IDLE_TIMEOUT_MS_RAW = Number(process.env.DOMAIN_PROTECTED_IDLE_TIMEOUT_MS || 5 * 60 * 1000);
const DOMAIN_PROTECTED_IDLE_TIMEOUT_MS = Number.isFinite(DOMAIN_PROTECTED_IDLE_TIMEOUT_MS_RAW)
  ? Math.max(15 * 1000, DOMAIN_PROTECTED_IDLE_TIMEOUT_MS_RAW)
  : 5 * 60 * 1000;
const DOMAIN_PROTECTED_SESSION_REVOKE_REASON = 'protected_idle_timeout_5m';


const HOSTINGER_API_BASE = 'https://developers.hostinger.com';
const HOSTINGER_CHECK_CACHE = new Map();

// Pool token Hostinger disimpan di memori instance Vercel.
// Tetap kompatibel dengan env lama HOSTINGER_API_TOKEN:
// - 1 token: HOSTINGER_API_TOKEN=token_utama
// - 11 token: HOSTINGER_API_TOKEN=token1,token2,...,token11
// Opsional juga mendukung HOSTINGER_API_TOKEN_1 s.d. HOSTINGER_API_TOKEN_11.
const HOSTINGER_TOKEN_COOLDOWNS = globalThis.__DIRAC_HOSTINGER_TOKEN_COOLDOWNS__ || new Map();
globalThis.__DIRAC_HOSTINGER_TOKEN_COOLDOWNS__ = HOSTINGER_TOKEN_COOLDOWNS;
globalThis.__DIRAC_HOSTINGER_TOKEN_POINTER__ = globalThis.__DIRAC_HOSTINGER_TOKEN_POINTER__ || 0;


// Provider domain tambahan untuk mengurangi ketergantungan ke Hostinger.
// Endpoint publik tetap sama: /api/health?action=hostinger-check&domain=contoh.com
// Urutan default: Name.com -> NameSilo -> WhoisJSON -> Hostinger.
const DOMAIN_PROVIDER_COOLDOWNS = globalThis.__DIRAC_DOMAIN_PROVIDER_COOLDOWNS__ || new Map();
globalThis.__DIRAC_DOMAIN_PROVIDER_COOLDOWNS__ = DOMAIN_PROVIDER_COOLDOWNS;

// Public domain-check abuse guard. In-memory by default so normal website flow is not disturbed.
// This protects the public hostinger-check/domain availability endpoint from Termux/API spam.
const PUBLIC_DOMAIN_CHECK_RATE_STORE = globalThis.__DIRAC_PUBLIC_DOMAIN_CHECK_RATE_STORE__ || new Map();
globalThis.__DIRAC_PUBLIC_DOMAIN_CHECK_RATE_STORE__ = PUBLIC_DOMAIN_CHECK_RATE_STORE;
const PUBLIC_DOMAIN_CHECK_WINDOW_MS_RAW = Number(process.env.PUBLIC_DOMAIN_CHECK_RATE_WINDOW_MS || 60 * 1000);
const PUBLIC_DOMAIN_CHECK_WINDOW_MS = Number.isFinite(PUBLIC_DOMAIN_CHECK_WINDOW_MS_RAW)
  ? Math.max(10 * 1000, PUBLIC_DOMAIN_CHECK_WINDOW_MS_RAW)
  : 60 * 1000;
const PUBLIC_DOMAIN_CHECK_MAX_RAW = Number(process.env.PUBLIC_DOMAIN_CHECK_RATE_MAX || 45);
const PUBLIC_DOMAIN_CHECK_MAX = Number.isFinite(PUBLIC_DOMAIN_CHECK_MAX_RAW)
  ? Math.max(5, PUBLIC_DOMAIN_CHECK_MAX_RAW)
  : 45;


// Backend-only login SQL injection guard.
// Isolated in-memory store: does not write password, OTP, token, cookie, or raw payload.
const LOGIN_SECURITY_GUARD_STORE = globalThis.__DIRAC_LOGIN_SECURITY_GUARD_STORE__ || new Map();
globalThis.__DIRAC_LOGIN_SECURITY_GUARD_STORE__ = LOGIN_SECURITY_GUARD_STORE;
const LOGIN_SECURITY_RETRY_AFTER_SECONDS = 30;
const LOGIN_SECURITY_TEN_YEARS_MS = 10 * 365 * 24 * 60 * 60 * 1000;
const LOGIN_SECURITY_BODY_LIMIT_BYTES_RAW = Number(process.env.LOGIN_SECURITY_BODY_LIMIT_BYTES || 16 * 1024);
const LOGIN_SECURITY_BODY_LIMIT_BYTES = Number.isFinite(LOGIN_SECURITY_BODY_LIMIT_BYTES_RAW)
  ? Math.max(1024, LOGIN_SECURITY_BODY_LIMIT_BYTES_RAW)
  : 16 * 1024;
// Optional durable security storage. Default empty = safe in-memory fallback, no new DB writes.
// To activate later, create a dedicated security table and set LOGIN_SECURITY_PERSIST_TABLE.
const LOGIN_SECURITY_PERSIST_TABLE = String(process.env.LOGIN_SECURITY_PERSIST_TABLE || '').trim();
const LOGIN_SECURITY_PERSIST_TTL_SECONDS = 10 * 365 * 24 * 60 * 60;

async function handleDomainAction(action, req, res) {
  try {
    if (action === 'domain_health') return domainHealth(req, res);
    if (action === 'hostinger_check') return hostingerCheckDomain(req, res);
    if (action === 'domain_login') return domainLogin(req, res);
    if (action === 'domain_register') return domainRegister(req, res);
    if (action === 'domain_me') return domainMe(req, res);
    if (action === 'domain_dashboard_me') return domainDashboardMe(req, res);
    if (action === 'domain_mfa_status') return domainMfaStatus(req, res);
    if (action === 'domain_logout') return domainLogout(req, res);
    if (action === 'domain_check') return domainCheck(req, res);
    if (action === 'domain_checkout') return domainCheckout(req, res);
    if (action === 'domain_orders') return domainOrders(req, res);

    return res.status(404).json({ ok: false, message: 'Action domain tidak ditemukan.' });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: 'Terjadi kesalahan pada domain router.',
      error: String(error && error.message ? error.message : error)
    });
  }
}


function isPublicDomainCheckThreat(value) {
  const raw = String(value || '');
  if (!raw) return false;
  if (raw.length > 253) return true;
  if (isClearDomainLoginSqlInjection(raw)) return true;
  return /[<>{}\[\]"'`;]|(?:--|\/\*|\*\/)/.test(raw);
}

async function checkPublicDomainRateLimit(req, parts) {
  if (isEnvTrue('PUBLIC_DOMAIN_CHECK_RATE_DISABLED')) return { ok: true, retryAfterSeconds: 0 };

  const now = Date.now();
  cleanupPublicDomainRateStore(now);

  const headers = (req && req.headers) || {};
  const ip = getLoginSecurityIp(req);
  const userAgent = String(headers['user-agent'] || '').slice(0, 120);
  const action = 'hostinger_check';
  const key = loginSecurityHash([ip, userAgent, action].join('|'));
  let current = PUBLIC_DOMAIN_CHECK_RATE_STORE.get(key) || null;

  // PATCH 3G: when LOGIN_SECURITY_PERSIST_TABLE is active, keep public-domain
  // rate counters in the same isolated backend security table instead of relying
  // only on serverless memory. No raw domain, cookie, token, or payload is stored.
  if (!current && LOGIN_SECURITY_PERSIST_TABLE) {
    const persisted = await readPersistentSecurityJson(`public-domain-check:${key}`);
    if (persisted && typeof persisted === 'object') {
      current = {
        count: Number(persisted.count || 0),
        windowStartMs: Number(persisted.windowStartMs || persisted.window_start_ms || now),
        resetAtMs: Number(persisted.resetAtMs || persisted.reset_at_ms || 0),
        sampleDomain: String(persisted.sampleDomain || persisted.sample_domain || '').slice(0, 120)
      };
    }
  }

  current = current || {
    count: 0,
    windowStartMs: now,
    resetAtMs: now + PUBLIC_DOMAIN_CHECK_WINDOW_MS,
    sampleDomain: parts && parts.fullDomain ? String(parts.fullDomain).slice(0, 120) : ''
  };

  if (now > Number(current.resetAtMs || 0)) {
    current.count = 0;
    current.windowStartMs = now;
    current.resetAtMs = now + PUBLIC_DOMAIN_CHECK_WINDOW_MS;
    current.sampleDomain = parts && parts.fullDomain ? String(parts.fullDomain).slice(0, 120) : '';
  }

  current.count = Number(current.count || 0) + 1;
  PUBLIC_DOMAIN_CHECK_RATE_STORE.set(key, current);
  if (LOGIN_SECURITY_PERSIST_TABLE) {
    await writePersistentSecurityJson(`public-domain-check:${key}`, {
      count: Number(current.count || 0),
      windowStartMs: Number(current.windowStartMs || now),
      resetAtMs: Number(current.resetAtMs || 0),
      sampleDomainHash: parts && parts.fullDomain ? loginSecurityHash(String(parts.fullDomain).slice(0, 120)) : ''
    }, 0, Math.ceil(PUBLIC_DOMAIN_CHECK_WINDOW_MS / 1000) + 60);
  }

  if (current.count > PUBLIC_DOMAIN_CHECK_MAX) {
    return {
      ok: false,
      retryAfterSeconds: Math.max(1, Math.ceil((Number(current.resetAtMs || now) - now) / 1000))
    };
  }

  return { ok: true, retryAfterSeconds: 0 };
}

function cleanupPublicDomainRateStore(now = Date.now()) {
  if (PUBLIC_DOMAIN_CHECK_RATE_STORE.size < 5000) return;
  for (const [key, value] of PUBLIC_DOMAIN_CHECK_RATE_STORE.entries()) {
    if (Number(value && value.resetAtMs || 0) <= now) {
      PUBLIC_DOMAIN_CHECK_RATE_STORE.delete(key);
    }
  }
}

async function domainHealth(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  return res.status(200).json({
    ok: true,
    service: 'dirac-domain',
    debugPatch: DIRAC_COOKIE_SESSION_PATCH,
    signedSessionCookie: DOMAIN_SIGNED_SESSION_COOKIE,
    message: 'Domain API aktif.',
    endpoints: {
      check: '/api/health?action=domain_check&domain=contoh.com',
      hostingerCheck: '/api/health?action=hostinger-check&domain=contoh.com',
      checkout: '/api/health?action=domain_checkout',
      orders: '/api/health?action=domain_orders'
    },
    aliases: {
      health: '/api/health?action=domain-health',
      hostingerCheck: '/api/health?action=hostinger-check&domain=contoh.com',
      check: '/api/health?action=check-domain&domain=contoh.com',
      createOrder: '/api/health?action=create-order',
      getOrders: '/api/health?action=get-orders'
    },
    time: diracNowIso()
  });
}

async function hostingerCheckDomain(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const rawDomainInput = String(req.query && req.query.domain || '');
  if (isPublicDomainCheckThreat(rawDomainInput)) {
    return res.status(400).json({
      ok: false,
      code: 'DOMAIN_INPUT_REJECTED',
      message: 'Domain tidak valid. Gunakan format seperti namabrand.com'
    });
  }

  const domain = normalizeDomain(rawDomainInput);
  const parts = splitDomainForHostinger(domain);

  if (!parts) {
    return res.status(400).json({ ok: false, message: 'Domain tidak valid. Contoh: namabrand.com' });
  }

  const cacheKey = `domain-provider:${parts.fullDomain}`;
  const cacheSeconds = Math.max(0, Number(process.env.DOMAIN_API_CACHE_SECONDS || process.env.HOSTINGER_DOMAIN_CACHE_SECONDS || 60));
  const cached = HOSTINGER_CHECK_CACHE.get(cacheKey);

  if (cached && cached.expiresAt > Date.now()) {
    return res.status(200).json({ ...cached.payload, cached: true });
  }

  const publicLimit = await checkPublicDomainRateLimit(req, parts);
  if (!publicLimit.ok) {
    res.setHeader('Retry-After', String(publicLimit.retryAfterSeconds));
    return res.status(429).json({
      ok: false,
      code: 'DOMAIN_CHECK_RATE_LIMITED',
      retry_after_seconds: publicLimit.retryAfterSeconds,
      message: 'Terlalu banyak permintaan cek domain. Silakan coba lagi sebentar lagi.'
    });
  }

  const check = await checkDomainWithProviders(parts);

  if (!check.ok) {
    return res.status(check.status || 502).json({
      ok: false,
      message: check.message || 'Gagal cek ketersediaan domain.',
      provider: check.provider || null
    });
  }

  if (check.available === false) {
    const payload = {
      ok: true,
      domain: parts.fullDomain,
      available: false,
      provider: check.provider || null,
      message: 'Domain tidak tersedia.'
    };
    if (cacheSeconds > 0) HOSTINGER_CHECK_CACHE.set(cacheKey, { expiresAt: Date.now() + cacheSeconds * 1000, payload });
    return res.status(200).json(payload);
  }

  const priceInfo = check.priceInfo || await resolveDomainPrice(parts, check);

  if (!priceInfo) {
    return res.status(502).json({
      ok: false,
      domain: parts.fullDomain,
      available: check.available !== false,
      provider: check.provider || null,
      message: `Domain tersedia, tetapi harga .${parts.tld} belum ditemukan.`
    });
  }

  const priced = buildDomainPrice(parts, priceInfo);
  const payload = {
    ok: true,
    domain: parts.fullDomain,
    available: check.available !== false,
    provider: check.provider || priceInfo.source || null,
    price: priced.price,
    price_label: formatCurrency(priced.price, priced.currency),
    currency: priced.currency,
    message: check.available === null ? 'Domain berhasil dicek.' : 'Domain tersedia.'
  };

  if (cacheSeconds > 0) HOSTINGER_CHECK_CACHE.set(cacheKey, { expiresAt: Date.now() + cacheSeconds * 1000, payload });

  return res.status(200).json(payload);
}

async function domainLogin(req, res, preloadedBody) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  let body;
  try {
    body = preloadedBody || await readLimitedJsonBody(req, LOGIN_SECURITY_BODY_LIMIT_BYTES);
  } catch (error) {
    return res.status(error.statusCode || 400).json({
      ok: false,
      code: error.code || 'LOGIN_REQUEST_INVALID',
      message: error.publicMessage || 'Request login tidak valid.'
    });
  }
  const rawEmail = String(body.email || body.identifier || body.customer_email || '');
  const email = normalizeAuthEmail(rawEmail);
  const password = String(body.password || '');

  const loginGuard = await guardDomainLoginInput(req, res, {
    rawEmail,
    email,
    password,
    action: 'domain_login',
    form: 'Login',
    endpoint: '/api/health?action=domain_login'
  });
  if (!loginGuard.ok) {
    return res.status(loginGuard.status).json(loginGuard.body);
  }

  const result = await supabaseFetch('/auth/v1/token?grant_type=password', {
    method: 'POST',
    auth: 'anon',
    body: { email: loginGuard.email, password }
  });

  if (!result.ok) {
    return res.status(result.status).json({
      ok: false,
      message: 'Email atau password belum sesuai.'
    });
  }

  if (!hasValidDomainSessionTokens(result.data)) {
    clearSessionCookies(res);
    return res.status(502).json({
      ok: false,
      code: 'LOGIN_SESSION_TOKEN_MISSING',
      message: 'Login berhasil di server autentikasi, tetapi token sesi tidak diterima backend. Silakan coba login ulang.'
    });
  }

  setSessionCookies(res, result.data);

  return res.status(200).json({
    ok: true,
    message: 'Login berhasil. Silakan lanjutkan verifikasi keamanan.',
    twoFactorRequired: true,
    mfaRequired: true,
    next: 'mfa_required',
    user: sanitizeUser(result.data.user),
    session: buildDomainAuthSessionPayload(result.data)
  });
}

async function guardDomainLoginInput(req, res, input) {
  const rawEmail = String(input && input.rawEmail || '');
  const email = String(input && input.email || '');
  const password = String(input && input.password || '');
  const action = String(input && input.action || 'domain_login');
  const form = String(input && input.form || (action === 'domain_register' ? 'Register' : 'Login'));
  const endpoint = String(input && input.endpoint || `/api/health?action=${action}`);
  const now = Date.now();
  const identity = getLoginSecurityIdentity(req, action);
  const record = await getLoginSecurityRecord(identity, now);

  if (Number(record.blockedUntilMs || 0) > now) {
    const incident = buildLoginSecurityIncident(req, identity, record, now, { form, endpoint });
    return {
      ok: false,
      status: 403,
      body: buildLoginSecurityTenYearBody(incident)
    };
  }

  if (Number(record.cooldownUntilMs || 0) > now) {
    res.setHeader('Retry-After', String(LOGIN_SECURITY_RETRY_AFTER_SECONDS));
    return {
      ok: false,
      status: 429,
      body: buildLoginSecurityCooldownBody(LOGIN_SECURITY_RETRY_AFTER_SECONDS)
    };
  }

  if (!email || !password) {
    return {
      ok: false,
      status: 400,
      body: { ok: false, message: action === 'domain_register' ? 'Email dan password wajib diisi.' : 'Email atau password belum sesuai.' }
    };
  }

  const threat = detectDomainAuthThreat({ rawEmail, password });
  if (threat.detected) {
    const nextCount = Number(record.count || 0) + 1;
    record.count = nextCount;
    record.lastSeenMs = now;
    record.emailFingerprint = loginSecurityHash(rawEmail);
    record.threatField = threat.field;
    record.threatKind = threat.kind;
    record.cooldownUntilMs = nextCount >= 4 ? 0 : now + LOGIN_SECURITY_RETRY_AFTER_SECONDS * 1000;
    if (!record.incidentCode) record.incidentCode = createLoginSecurityIncidentCode(identity.key, now);

    if (nextCount >= 4) {
      record.blockedUntilMs = now + LOGIN_SECURITY_TEN_YEARS_MS;
      await saveLoginSecurityRecord(identity, record);
      const incident = buildLoginSecurityIncident(req, identity, record, now, { form, endpoint });
      await notifyLoginSecurityIncidentSafe(incident);
      return {
        ok: false,
        status: 403,
        body: buildLoginSecurityTenYearBody(incident)
      };
    }

    await saveLoginSecurityRecord(identity, record);
    res.setHeader('Retry-After', String(LOGIN_SECURITY_RETRY_AFTER_SECONDS));
    return {
      ok: false,
      status: 429,
      body: buildLoginSecurityCooldownBody(LOGIN_SECURITY_RETRY_AFTER_SECONDS)
    };
  }

  if (!isStrictDomainLoginEmail(email)) {
    return {
      ok: false,
      status: 400,
      body: {
        ok: false,
        code: 'INVALID_EMAIL_FORMAT',
        message: 'Email belum sesuai.\nGunakan huruf kecil, angka, tanda @, dan titik.\nContoh:\nnama@gmail.com'
      }
    };
  }

  return { ok: true, email };
}

function detectDomainAuthThreat(input) {
  const rawEmail = String(input && input.rawEmail || '');
  const password = String(input && input.password || '');

  if (isClearDomainLoginSqlInjection(rawEmail)) {
    return { detected: true, field: 'email', kind: 'sql_injection' };
  }

  // Password tetap boleh memakai simbol biasa. Deteksi ini hanya untuk pola SQL injection yang sangat jelas.
  // Nilai password tidak pernah dicatat, tidak pernah dikirim ke webhook, dan tidak pernah ditampilkan ulang.
  if (isClearDomainLoginSqlInjection(password)) {
    return { detected: true, field: 'password', kind: 'sql_injection' };
  }

  return { detected: false, field: '', kind: '' };
}

function isStrictDomainLoginEmail(email) {
  const value = String(email || '').trim();
  if (!/^[a-z0-9@.]+$/.test(value)) return false;
  if ((value.match(/@/g) || []).length !== 1) return false;
  if (value.startsWith('.') || value.endsWith('.') || value.includes('..')) return false;
  return /^[a-z0-9]+(?:\.[a-z0-9]+)*@[a-z0-9]+(?:\.[a-z0-9]+)+$/.test(value);
}

function isClearDomainLoginSqlInjection(value) {
  const samples = buildLoginSecurityInspectionSamples(value);
  const highRiskPatterns = [
    /\bor\s+1\s*=\s*1\b/i,
    /\band\s+1\s*=\s*1\b/i,
    /\bunion\s+(?:all\s+)?select\b/i,
    /\bdrop\s+table\b/i,
    /\bpg_sleep\s*\(/i,
    /\bsleep\s*\(/i,
    /\bbenchmark\s*\(/i,
    /admin\s*['"`]\s*--/i,
    /['"`]\s*(?:or|and)\s+['"`]?\w+['"`]?\s*=\s*['"`]?\w+/i,
    /['"`]\s*--/i,
    /\/\*/i,
    /\*\//i,
    /;\s*(?:select|insert|update|delete|drop|alter|truncate|create)\b/i,
    /\b(?:information_schema|pg_catalog|sqlite_master)\b/i
  ];
  return samples.some((sample) => highRiskPatterns.some((pattern) => pattern.test(sample)));
}

function buildLoginSecurityInspectionSamples(value) {
  const raw = String(value || '');
  const plusAsSpace = raw.replace(/\+/g, ' ');
  const samples = new Set([raw, raw.toLowerCase(), plusAsSpace, plusAsSpace.toLowerCase()]);
  let current = raw;
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(current);
      samples.add(decoded);
      samples.add(decoded.toLowerCase());
      samples.add(decoded.replace(/\+/g, ' '));
      samples.add(decoded.replace(/\+/g, ' ').toLowerCase());
      if (decoded === current) break;
      current = decoded;
    } catch (_) {
      break;
    }
  }
  return Array.from(samples).map((sample) => String(sample).slice(0, 2000));
}

function buildLoginSecurityCooldownBody(seconds) {
  return {
    ok: false,
    code: 'LOGIN_INPUT_BLOCKED',
    retry_after_seconds: seconds,
    message: 'Input belum bisa digunakan.\n\nSistem menemukan karakter atau kata yang tidak sesuai pada form masuk.\n\nPastikan email hanya menggunakan huruf kecil, angka, tanda @, dan titik.\n\nContoh:\nnama@gmail.com\n\nSilakan coba lagi dalam 30 detik.'
  };
}

function buildLoginSecurityTenYearBody(incident) {
  return {
    ok: false,
    code: 'LOGIN_ACCESS_RESTRICTED',
    blocked_years: 10,
    incident_code: incident.incidentCode,
    message: 'AKSES MASUK DIBATASI\n\nSistem keamanan DiracGroup mendeteksi percobaan berbahaya berulang pada form masuk.\n\nAkses masuk dari perangkat ini telah dibatasi selama 10 tahun karena terindikasi melakukan manipulasi input dan percobaan menerobos sistem keamanan.\n\nData teknis yang berhasil dikumpulkan:\n\n* Kode Insiden: ' + incident.incidentCode + '\n* Waktu Server: ' + incident.serverTime + '\n* Waktu Perangkat: Sesuai waktu perangkat pengguna\n* Halaman: masuk.html\n* Form: ' + incident.form + '\n* Endpoint Target: ' + incident.endpoint + '\n* Jumlah Percobaan: ' + incident.attemptCount + ' kali\n* Jenis Deteksi: SQL Injection / Manipulasi Input\n* Status Risiko: Tinggi\n* Tindakan Sistem: Akses masuk dibatasi selama 10 tahun\n\nData Jaringan:\n\n* IP Address: ' + incident.maskedIp + '\n* Provider / ISP: Sesuai hasil deteksi sistem\n* ASN Jaringan: Sesuai hasil deteksi sistem\n* Lokasi Jaringan: Sesuai hasil analisis jaringan\n* Deteksi VPN / Proxy: Sesuai hasil pemeriksaan sistem\n\nData Perangkat:\n\n* Browser: ' + incident.userAgentSummary + '\n* Bahasa Browser: ' + incident.language + '\n* Zona Waktu: Sesuai perangkat pengguna\n* Device Key: ' + incident.deviceKey + '\n* Session Key: ' + incident.sessionKey + '\n\nAktivitas ini telah dicatat otomatis oleh sistem keamanan DiracGroup.\n\nJika ditemukan unsur penyalahgunaan, penyerangan, manipulasi sistem, atau upaya akses tanpa hak, DiracGroup dapat memproses aktivitas ini sesuai ketentuan yang berlaku.'
  };
}

function getLoginSecurityIdentity(req, actionName) {
  const ip = getLoginSecurityIp(req);
  const userAgent = String(req && req.headers && req.headers['user-agent'] || '').slice(0, 240);
  const method = String(req && req.method || '').toUpperCase();
  const action = String(actionName || req && req.query && req.query.action || '').trim().slice(0, 80);
  const path = String(req && req.url || '/api/health').split('?')[0].slice(0, 160);

  // Tidak memakai X-Device-Id/X-Dirac-Device-Id sebagai kunci utama karena header frontend bisa dimanipulasi.
  const base = [ip, userAgent, method, path, action].join('|');
  const digest = loginSecurityHash(base);
  return {
    ip,
    userAgent,
    method,
    path,
    action,
    key: digest,
    deviceKey: 'DG-DEV-' + digest.slice(0, 6).toUpperCase(),
    sessionKey: 'DG-SES-' + digest.slice(6, 12).toUpperCase()
  };
}

function getLoginSecurityIp(req) {
  const headers = (req && req.headers) || {};
  const forwarded = String(headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || String(headers['x-real-ip'] || req.socket && req.socket.remoteAddress || '').trim() || 'unknown';
}

function maskLoginSecurityIp(ip) {
  const value = String(ip || 'unknown').trim();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    const parts = value.split('.');
    return parts[0] + '.xxx.xxx.' + parts[3];
  }
  if (value.includes(':')) return value.split(':').slice(0, 2).join(':') + ':xxxx';
  return 'unknown';
}

function buildLoginSecurityIncident(req, identity, record, now, meta = {}) {
  const headers = (req && req.headers) || {};
  return {
    incidentCode: record.incidentCode || createLoginSecurityIncidentCode(identity.key, now),
    attemptCount: Number(record.count || 0),
    serverTime: formatDiracWibTime(now),
    maskedIp: maskLoginSecurityIp(identity.ip),
    userAgentSummary: summarizeLoginSecurityUserAgent(identity.userAgent),
    language: String(headers['accept-language'] || '').split(',')[0].slice(0, 32) || 'unknown',
    deviceKey: identity.deviceKey,
    sessionKey: identity.sessionKey,
    form: String(meta.form || 'Login').replace(/[<>]/g, '').slice(0, 40),
    endpoint: String(meta.endpoint || '/api/health?action=domain_login').replace(/[<>]/g, '').slice(0, 120),
    blockedUntilMs: Number(record.blockedUntilMs || 0)
  };
}

function createLoginSecurityIncidentCode(key, now) {
  return 'DG-SEC-LOGIN-' + loginSecurityHash(String(key || '') + ':' + String(now || Date.now())).slice(0, 6).toUpperCase();
}


async function getLoginSecurityRecord(identity, now = Date.now()) {
  const key = identity && identity.key;
  const memory = key ? LOGIN_SECURITY_GUARD_STORE.get(key) : null;
  if (memory) return normalizeLoginSecurityRecord(memory, now);

  const persisted = await readPersistentLoginSecurityRecord(identity);
  if (persisted) {
    const normalized = normalizeLoginSecurityRecord(persisted, now);
    LOGIN_SECURITY_GUARD_STORE.set(key, normalized);
    return normalized;
  }

  return createEmptyLoginSecurityRecord(now);
}

async function saveLoginSecurityRecord(identity, record) {
  const key = identity && identity.key;
  const normalized = normalizeLoginSecurityRecord(record, Date.now());
  if (key) LOGIN_SECURITY_GUARD_STORE.set(key, normalized);
  await writePersistentLoginSecurityRecord(identity, normalized);
  return normalized;
}

function createEmptyLoginSecurityRecord(now = Date.now()) {
  return {
    count: 0,
    firstSeenMs: now,
    lastSeenMs: 0,
    cooldownUntilMs: 0,
    blockedUntilMs: 0,
    incidentCode: ''
  };
}

function normalizeLoginSecurityRecord(record, now = Date.now()) {
  const row = record && typeof record === 'object' ? record : {};
  return {
    count: Number(row.count || row.attempt_count || 0),
    firstSeenMs: Number(row.firstSeenMs || row.first_seen_ms || now),
    lastSeenMs: Number(row.lastSeenMs || row.last_seen_ms || 0),
    cooldownUntilMs: Number(row.cooldownUntilMs || row.cooldown_until_ms || 0),
    blockedUntilMs: Number(row.blockedUntilMs || row.blocked_until_ms || 0),
    incidentCode: String(row.incidentCode || row.incident_code || ''),
    emailFingerprint: String(row.emailFingerprint || row.email_fingerprint || ''),
    threatField: String(row.threatField || row.threat_field || ''),
    threatKind: String(row.threatKind || row.threat_kind || '')
  };
}


async function readPersistentSecurityJson(securityKey) {
  const key = String(securityKey || '').trim();
  if (!LOGIN_SECURITY_PERSIST_TABLE || !key) return null;

  try {
    const path = `/rest/v1/${encodeURIComponent(LOGIN_SECURITY_PERSIST_TABLE)}?select=security_key,record_json,blocked_until_ms,expires_at&security_key=eq.${encodeURIComponent(key)}&limit=1`;
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok || !Array.isArray(result.data) || !result.data.length) return null;

    const row = result.data[0] || {};
    const expiresAtMs = Date.parse(row.expires_at || '');
    if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) return null;
    return row.record_json && typeof row.record_json === 'object' ? row.record_json : null;
  } catch (_) {
    return null;
  }
}

async function writePersistentSecurityJson(securityKey, record, blockedUntilMs = 0, ttlSeconds = LOGIN_SECURITY_PERSIST_TTL_SECONDS) {
  const key = String(securityKey || '').trim();
  if (!LOGIN_SECURITY_PERSIST_TABLE || !key) return false;

  try {
    const now = Date.now();
    const safeRecord = record && typeof record === 'object' ? record : {};
    const expiresAt = new Date(now + Math.max(60, Number(ttlSeconds || 60)) * 1000).toISOString();
    const payload = [{
      security_key: key,
      record_json: safeRecord,
      blocked_until_ms: Number(blockedUntilMs || 0),
      updated_at: new Date(now).toISOString(),
      expires_at: expiresAt
    }];

    const result = await supabaseFetch(`/rest/v1/${encodeURIComponent(LOGIN_SECURITY_PERSIST_TABLE)}?on_conflict=security_key`, {
      method: 'POST',
      auth: 'service',
      prefer: 'resolution=merge-duplicates',
      body: payload
    });
    return !!result.ok;
  } catch (_) {
    return false;
  }
}

async function readPersistentLoginSecurityRecord(identity) {
  if (!LOGIN_SECURITY_PERSIST_TABLE || !identity || !identity.key) return null;

  try {
    const path = `/rest/v1/${encodeURIComponent(LOGIN_SECURITY_PERSIST_TABLE)}?select=security_key,record_json,blocked_until_ms,expires_at&security_key=eq.${encodeURIComponent(identity.key)}&limit=1`;
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok || !Array.isArray(result.data) || !result.data.length) return null;

    const row = result.data[0] || {};
    const expiresAtMs = Date.parse(row.expires_at || '');
    if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) return null;

    if (row.record_json && typeof row.record_json === 'object') return row.record_json;
    return row;
  } catch (_) {
    return null;
  }
}

async function writePersistentLoginSecurityRecord(identity, record) {
  if (!LOGIN_SECURITY_PERSIST_TABLE || !identity || !identity.key) return false;

  try {
    const now = Date.now();
    const expiresAt = new Date(now + LOGIN_SECURITY_PERSIST_TTL_SECONDS * 1000).toISOString();
    const payload = [{
      security_key: identity.key,
      record_json: normalizeLoginSecurityRecord(record, now),
      blocked_until_ms: Number(record && record.blockedUntilMs || 0),
      updated_at: new Date(now).toISOString(),
      expires_at: expiresAt
    }];

    const result = await supabaseFetch(`/rest/v1/${encodeURIComponent(LOGIN_SECURITY_PERSIST_TABLE)}?on_conflict=security_key`, {
      method: 'POST',
      auth: 'service',
      prefer: 'resolution=merge-duplicates',
      body: payload
    });
    return !!result.ok;
  } catch (_) {
    return false;
  }
}

function loginSecurityHash(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function summarizeLoginSecurityUserAgent(userAgent) {
  const value = String(userAgent || '').slice(0, 120);
  if (!value) return 'unknown';
  if (/Chrome/i.test(value) && /Mobile|Android/i.test(value)) return 'Chrome Mobile';
  if (/Chrome/i.test(value)) return 'Chrome';
  if (/Safari/i.test(value) && /Mobile|iPhone|iPad/i.test(value)) return 'Mobile Safari';
  if (/Firefox/i.test(value)) return 'Firefox';
  if (/Edg/i.test(value)) return 'Microsoft Edge';
  return value.replace(/[<>]/g, '').slice(0, 80);
}

function formatDiracWibTime(ms) {
  try {
    return new Intl.DateTimeFormat('id-ID', {
      timeZone: 'Asia/Jakarta',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      timeZoneName: 'short'
    }).format(new Date(Number(ms || Date.now())));
  } catch (_) {
    return new Date(Number(ms || Date.now())).toISOString();
  }
}

async function notifyLoginSecurityIncidentSafe(incident) {
  // Optional webhook only. No password, OTP, token, cookie, secret, or raw payload is sent.
  const webhookUrl = String(process.env.DIRAC_LOGIN_SECURITY_WEBHOOK_URL || '').trim();
  if (!webhookUrl) return false;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'dirac_login_security_incident',
        incident_code: incident.incidentCode,
        attempt_count: incident.attemptCount,
        server_time: incident.serverTime,
        masked_ip: incident.maskedIp,
        device_key: incident.deviceKey,
        session_key: incident.sessionKey,
        risk: 'high'
      })
    });
    return true;
  } catch (_) {
    return false;
  }
}

async function domainRegister(req, res, preloadedBody) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  let body;
  try {
    body = preloadedBody || await readLimitedJsonBody(req, LOGIN_SECURITY_BODY_LIMIT_BYTES);
  } catch (error) {
    return res.status(error.statusCode || 400).json({
      ok: false,
      code: error.code || 'REGISTER_REQUEST_INVALID',
      message: error.publicMessage || 'Request pendaftaran tidak valid.'
    });
  }
  const rawEmail = String(body.email || body.identifier || body.customer_email || '');
  const email = normalizeAuthEmail(rawEmail);
  const password = String(body.password || '');
  const fullName = String(body.full_name || body.fullName || body.name || '').trim();
  const whatsapp = normalizePhone(body.whatsapp || body.phone || body.customer_whatsapp || '');

  const registerGuard = await guardDomainLoginInput(req, res, {
    rawEmail,
    email,
    password,
    action: 'domain_register',
    form: 'Register',
    endpoint: '/api/health?action=domain_register'
  });
  if (!registerGuard.ok) {
    return res.status(registerGuard.status).json(registerGuard.body);
  }

  if (password.length < 6) {
    return res.status(400).json({ ok: false, message: 'Password minimal 6 karakter.' });
  }

  const userData = {};
  if (fullName) {
    userData.full_name = fullName;
    userData.name = fullName;
  }
  if (whatsapp) userData.whatsapp = whatsapp;

  const signupBody = { email, password };
  if (Object.keys(userData).length) signupBody.data = userData;

  // Register duplicate check v2:
  // cek backend-only memakai service role sebelum signup.
  // Tidak menyentuh domainLogin(), hash, A2F/MFA, cookie, token, dashboard, checkout, atau order.
  const existingAuthUser = await findSupabaseAuthUserByEmail(email);
  if (existingAuthUser && existingAuthUser.exists === true) {
    return res.status(409).json(buildDomainRegisterDuplicateEmailBody());
  }

  const result = await supabaseFetch('/auth/v1/signup', {
    method: 'POST',
    auth: 'anon',
    body: signupBody
  });

  if (!result.ok) {
    if (isSupabaseRegisterDuplicateEmailError(result.data)) {
      return res.status(409).json(buildDomainRegisterDuplicateEmailBody());
    }

    // PATCH REGISTER EMAIL DELIVERY RECOVERY v1:
    // Jika Supabase gagal mengirim confirmation email, jangan langsung menampilkan error mentah
    // "Error sending confirmation email" ke customer. Backend mencoba recovery aman memakai
    // service role: akun baru tetap dibuat/di-confirm tanpa mengirim email, lalu sesi hanya
    // dikunci lewat HttpOnly cookie. domainLogin(), cookie helper, A2F/MFA, checkout, dan order
    // tidak disentuh.
    if (isSupabaseRegisterEmailDeliveryError(result.data)) {
      const recovered = await recoverDomainRegisterFromSupabaseEmailDeliveryFailure({
        email,
        password,
        userData
      });

      if (recovered && recovered.duplicate === true) {
        return res.status(409).json(buildDomainRegisterDuplicateEmailBody());
      }

      if (recovered && recovered.ok === true) {
        const recoveredSession = recovered.session && typeof recovered.session === 'object' ? recovered.session : {};
        if (recoveredSession.access_token && recoveredSession.refresh_token) {
          setSessionCookies(res, recoveredSession);
        }

        return res.status(200).json({
          ok: true,
          code: 'REGISTER_CREATED_EMAIL_DELIVERY_RECOVERED',
          message: recoveredSession.access_token
            ? 'Akun berhasil dibuat dan login otomatis. Silakan lanjutkan setup keamanan akun.'
            : 'Akun berhasil dibuat. Silakan masuk lalu lanjutkan setup keamanan akun.',
          needs_email_confirmation: false,
          email_delivery_recovered: true,
          first_register_setup_required: true,
          next: 'security_setup_required',
          user: sanitizeUser(recovered.user || recoveredSession.user),
          session: buildDomainAuthSessionPayload(recoveredSession)
        });
      }

      return res.status(recovered && recovered.status ? recovered.status : 502).json({
        ok: false,
        code: 'REGISTER_EMAIL_DELIVERY_FAILED',
        message: 'Pendaftaran belum bisa diselesaikan karena layanan email verifikasi sedang bermasalah. Silakan coba lagi sebentar lagi.'
      });
    }

    return res.status(result.status).json({
      ok: false,
      message: result.data.error_description || result.data.msg || result.data.message || 'Pendaftaran gagal.'
    });
  }

  const signupData = result.data && typeof result.data === 'object' ? result.data : {};

  // Supabase Auth dengan email confirmation aktif dapat mengembalikan HTTP 200
  // untuk email yang sudah terdaftar, tetapi user.identities kosong.
  // Kondisi ini tidak boleh ditampilkan sebagai akun baru berhasil dibuat.
  if (isSupabaseRegisterExistingAccountResponse(signupData)) {
    return res.status(409).json(buildDomainRegisterDuplicateEmailBody());
  }

  if (!hasSupabaseRegisterNewAccountEvidence(signupData)) {
    // Supabase kadang menyamarkan signup email lama sebagai respons tidak jelas.
    // Untuk halaman customer, jangan tampilkan pesan ambigu dan jangan klaim akun baru dibuat.
    // Treat as already registered agar user diarahkan masuk / lupa password / email lain.
    return res.status(409).json(buildDomainRegisterDuplicateEmailBody());
  }

  const signupHasSession = hasValidDomainSessionTokens(signupData);
  if (signupHasSession) {
    setSessionCookies(res, signupData);
  } else {
    clearSessionCookies(res);
  }

  return res.status(200).json({
    ok: true,
    message: signupHasSession
      ? 'Akun berhasil dibuat dan login otomatis.'
      : 'Akun berhasil dibuat. Silakan cek email verifikasi jika diperlukan.',
    needs_email_confirmation: !signupHasSession,
    user: sanitizeUser(signupData.user),
    session: buildDomainAuthSessionPayload(signupData)
  });
}

function buildDomainRegisterDuplicateEmailBody() {
  return {
    ok: false,
    code: 'EMAIL_ALREADY_REGISTERED',
    already_registered: true,
    email_already_registered: true,
    needs_email_confirmation: false,
    next: 'login_or_reset_password',
    message: 'Email ini sudah terdaftar. Silakan masuk, atau gunakan lupa password jika tidak ingat kata sandi.'
  };
}


function isSupabaseRegisterEmailDeliveryError(data) {
  const fields = [];
  if (typeof data === 'string') fields.push(data);
  if (data && typeof data === 'object') {
    fields.push(
      data.error,
      data.error_code,
      data.code,
      data.msg,
      data.message,
      data.error_description,
      data.detail
    );
  }

  const text = fields
    .filter((item) => item !== undefined && item !== null)
    .map((item) => String(item).toLowerCase())
    .join(' | ');

  if (!text) return false;

  return /error\s+sending\s+confirmation\s+email/i.test(text)
    || /confirmation\s+email/i.test(text)
    || /email.*(?:send|sending|sent|delivery|deliver|smtp|mailer|mailgun|sendgrid|resend|brevo|ses).*?(?:error|failed|fail|invalid|rejected)/i.test(text)
    || /(?:send|sending|delivery|deliver|smtp|mailer|mailgun|sendgrid|resend|brevo|ses).*?email.*?(?:error|failed|fail|invalid|rejected)/i.test(text);
}

async function recoverDomainRegisterFromSupabaseEmailDeliveryFailure(input) {
  const email = normalizeAuthEmail(input && input.email);
  const password = String(input && input.password || '');
  const userData = input && input.userData && typeof input.userData === 'object' ? input.userData : {};

  if (!email || !isStrictDomainLoginEmail(email) || !password) {
    return { ok: false, status: 400 };
  }

  // 1) Jika Supabase sudah sempat membuat user sebelum email gagal dikirim,
  //    jangan buat user kedua. Recovery hanya boleh untuk user baru yang
  //    created_at sangat dekat dengan request ini dan belum pernah confirmed.
  const existing = await getSupabaseAuthUserByEmail(email);
  if (existing && existing.user) {
    if (!isSupabaseAuthUserSafeRecentUnconfirmed(existing.user)) {
      return { ok: false, duplicate: true, status: 409 };
    }

    const confirmed = await confirmRecentSupabaseAuthUser(existing.user);
    if (!confirmed.ok) {
      return { ok: false, status: confirmed.status || 502 };
    }

    const login = await loginSupabaseAuthUserAfterRegisterRecovery(email, password);
    if (!login.ok) {
      return {
        ok: true,
        user: confirmed.user || existing.user,
        session: null,
        recovered_from: 'recent_unconfirmed_user'
      };
    }

    return {
      ok: true,
      user: login.session && login.session.user ? login.session.user : (confirmed.user || existing.user),
      session: login.session,
      recovered_from: 'recent_unconfirmed_user'
    };
  }

  // 2) Jika tidak ada user yang tercipta, buat akun lewat Admin API tanpa
  //    mengirim confirmation email. Ini backend-only dan tetap tidak membuka token
  //    ke JavaScript karena response session diproses oleh buildDomainAuthSessionPayload().
  const createBody = {
    email,
    password,
    email_confirm: true
  };

  if (Object.keys(userData).length) {
    createBody.user_metadata = userData;
  }

  const created = await supabaseFetch('/auth/v1/admin/users', {
    method: 'POST',
    auth: 'service',
    body: createBody
  });

  if (!created.ok) {
    if (isSupabaseRegisterDuplicateEmailError(created.data)) {
      return { ok: false, duplicate: true, status: 409 };
    }

    return {
      ok: false,
      status: created.status || 502,
      error: created.data || null
    };
  }

  const login = await loginSupabaseAuthUserAfterRegisterRecovery(email, password);
  if (!login.ok) {
    return {
      ok: true,
      user: normalizeSupabaseAdminUser(created.data),
      session: null,
      recovered_from: 'admin_create_confirmed_user'
    };
  }

  return {
    ok: true,
    user: login.session && login.session.user ? login.session.user : normalizeSupabaseAdminUser(created.data),
    session: login.session,
    recovered_from: 'admin_create_confirmed_user'
  };
}

async function getSupabaseAuthUserByEmail(email) {
  const normalizedEmail = normalizeAuthEmail(email);
  if (!normalizedEmail || !isStrictDomainLoginEmail(normalizedEmail)) return { user: null, checked: false };

  try {
    const result = await supabaseFetch(`/auth/v1/admin/users?email=${encodeURIComponent(normalizedEmail)}`, {
      method: 'GET',
      auth: 'service'
    });

    if (!result.ok || !result.data) return { user: null, checked: false };

    const data = result.data;
    const candidates = [];
    if (Array.isArray(data)) candidates.push(...data);
    if (Array.isArray(data.users)) candidates.push(...data.users);
    if (data.user && typeof data.user === 'object') candidates.push(data.user);

    const user = candidates.find((item) => {
      if (!item || typeof item !== 'object') return false;
      const userEmail = normalizeAuthEmail(item.email || item.email_address || '');
      return userEmail === normalizedEmail;
    }) || null;

    return { user, checked: true };
  } catch (_) {
    return { user: null, checked: false };
  }
}

function normalizeSupabaseAdminUser(data) {
  if (!data || typeof data !== 'object') return null;
  if (data.user && typeof data.user === 'object') return data.user;
  return data;
}

function isSupabaseAuthUserSafeRecentUnconfirmed(user) {
  if (!user || typeof user !== 'object') return false;

  const confirmedAt = user.confirmed_at || user.email_confirmed_at || '';
  if (confirmedAt) return false;

  const createdAtMs = Date.parse(user.created_at || user.createdAt || '');
  if (!Number.isFinite(createdAtMs)) return false;

  const ageMs = Math.abs(Date.now() - createdAtMs);
  const maxRecoveryAgeMs = Math.max(60 * 1000, Number(process.env.DOMAIN_REGISTER_EMAIL_RECOVERY_MAX_AGE_MS || 10 * 60 * 1000));
  return ageMs <= maxRecoveryAgeMs;
}

async function confirmRecentSupabaseAuthUser(user) {
  const userId = String(user && user.id || '').trim();
  if (!userId) return { ok: false, status: 400 };

  const result = await supabaseFetch(`/auth/v1/admin/users/${encodeURIComponent(userId)}`, {
    method: 'PUT',
    auth: 'service',
    body: {
      email_confirm: true
    }
  });

  if (!result.ok) {
    return { ok: false, status: result.status || 502, error: result.data || null };
  }

  return { ok: true, user: normalizeSupabaseAdminUser(result.data) || user };
}

async function loginSupabaseAuthUserAfterRegisterRecovery(email, password) {
  const result = await supabaseFetch('/auth/v1/token?grant_type=password', {
    method: 'POST',
    auth: 'anon',
    body: {
      email: normalizeAuthEmail(email),
      password: String(password || '')
    }
  });

  if (!result.ok || !result.data || !result.data.access_token) {
    return { ok: false, status: result.status || 401, error: result.data || null };
  }

  return { ok: true, session: result.data };
}


async function findSupabaseAuthUserByEmail(email) {
  const normalizedEmail = normalizeAuthEmail(email);
  if (!normalizedEmail || !isStrictDomainLoginEmail(normalizedEmail)) return { exists: false, checked: false };

  try {
    const result = await supabaseFetch(`/auth/v1/admin/users?email=${encodeURIComponent(normalizedEmail)}`, {
      method: 'GET',
      auth: 'service'
    });

    if (!result.ok || !result.data) return { exists: false, checked: false };

    const data = result.data;
    const candidates = [];
    if (Array.isArray(data)) candidates.push(...data);
    if (Array.isArray(data.users)) candidates.push(...data.users);
    if (data.user && typeof data.user === 'object') candidates.push(data.user);

    const exists = candidates.some((user) => {
      if (!user || typeof user !== 'object') return false;
      const userEmail = normalizeAuthEmail(user.email || user.email_address || '');
      return userEmail === normalizedEmail;
    });

    return { exists, checked: true };
  } catch (_) {
    // Pre-check hanya penguat deteksi duplikat. Jika admin endpoint tidak tersedia,
    // signup tetap berjalan dan tetap difilter oleh response checks di bawah.
    return { exists: false, checked: false };
  }
}

function isSupabaseRegisterDuplicateEmailError(data) {
  const fields = [];
  if (typeof data === 'string') fields.push(data);
  if (data && typeof data === 'object') {
    fields.push(
      data.error,
      data.error_code,
      data.code,
      data.msg,
      data.message,
      data.error_description,
      data.detail
    );
  }

  const text = fields
    .filter((item) => item !== undefined && item !== null)
    .map((item) => String(item).toLowerCase())
    .join(' | ');

  if (!text) return false;
  return /(?:user|email|account|akun).*?(?:already|exists|registered|terdaftar|dipakai|digunakan)/i.test(text)
    || /(?:already|exists|registered|duplicate|terdaftar).*?(?:user|email|account|akun)/i.test(text)
    || /email_exists|user_already_exists|duplicate_email|email_already_registered/i.test(text);
}

function isSupabaseRegisterExistingAccountResponse(data) {
  const user = data && typeof data === 'object' && data.user && typeof data.user === 'object'
    ? data.user
    : null;
  if (!user) return false;

  // Sinyal resmi yang umum muncul pada signUp email lama saat confirmation aktif.
  if (Array.isArray(user.identities) && user.identities.length === 0) return true;

  return false;
}

function hasSupabaseRegisterNewAccountEvidence(data) {
  if (!data || typeof data !== 'object') return false;
  if (data.access_token && data.refresh_token) return true;

  const user = data.user && typeof data.user === 'object' ? data.user : null;
  if (!user || !user.id) return false;

  if (Array.isArray(user.identities)) return user.identities.length > 0;

  // Kompatibilitas untuk respons Supabase Auth lama yang tidak selalu menyertakan identities.
  return Boolean(user.email || user.created_at || user.aud === 'authenticated');
}

async function domainMe(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  return res.status(200).json({
    ok: true,
    user: sanitizeUser(user)
  });
}

async function requireDomainDashboardAccess(req, res) {
  const user = await requireDomainUser(req, res);
  if (!user) return null;

  const mfa = verifyCustomerDashboardMfaCookie(req, user);
  if (!mfa.ok) {
    res.status(403).json({
      ok: false,
      dashboard: false,
      message: mfa.message || 'Dashboard wajib verifikasi A2F backend sebelum dibuka.'
    });
    return null;
  }

  const protectedLock = await requireDomainProtectedDatabaseSessionLockSafe(req, res, user).catch((error) => {
    console.error('[domain-protected-lock-safe]', customerSecuritySafeLogError(error));
    return { ok: true, skipped: true, reason: 'lock_exception_fail_open' };
  });
  if (!protectedLock) return null;

  return { user, mfa, protectedLock };
}

async function requireDomainProtectedDatabaseSessionLockSafe(req, res, user) {
  const checked = await checkDomainProtectedDatabaseSessionLockSafe(req, user);
  if (checked && checked.ok) return checked;

  if (checked && checked.clearCookies) clearSessionCookies(res);

  return res.status((checked && checked.status) || 401).json({
    ok: false,
    dashboard: false,
    code: (checked && checked.code) || 'PROTECTED_SESSION_LOCKED',
    message: (checked && checked.message) || 'Sesi protected sudah dikunci. Silakan login ulang.',
    idle_timeout_ms: DOMAIN_PROTECTED_IDLE_TIMEOUT_MS,
    source: 'database_protected_lock_safe_v2'
  });
}

async function checkDomainProtectedDatabaseSessionLockSafe(req, user) {
  const authUserId = String(user && user.id || '').trim();
  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId)) {
    return { ok: true, skipped: true, reason: 'invalid_user_fail_open' };
  }

  const linkResult = await customerSecurityFetchAuthLink(authUserId);
  if (!linkResult.ok) {
    return { ok: true, skipped: true, reason: 'auth_link_unavailable_fail_open', status: linkResult.status };
  }

  const link = Array.isArray(linkResult.data) && linkResult.data.length ? linkResult.data[0] : null;
  const customerId = String(link && link.customer_id || '').trim();
  if (!link || link.link_status !== 'active' || !customerSecurityLooksLikeUuid(customerId)) {
    return { ok: true, skipped: true, reason: 'customer_link_not_ready_fail_open' };
  }

  const fingerprint = customerSecurityBuildSessionFingerprint(req, customerId);
  if (!fingerprint || !fingerprint.session_token_hash) {
    return { ok: true, skipped: true, reason: 'missing_fingerprint_fail_open', customerId };
  }

  const select = 'id,status,last_seen_at,expires_at,revoked_at,revoke_reason';
  const readPath = '/rest/v1/security_customer_sessions?select=' +
    encodeURIComponent(select) +
    '&customer_id=eq.' + encodeURIComponent(customerId) +
    '&session_token_hash=eq.' + encodeURIComponent(fingerprint.session_token_hash) +
    '&limit=1';

  const found = await supabaseFetch(readPath, { method: 'GET', auth: 'service' });
  if (!found.ok) {
    return { ok: true, skipped: true, reason: 'session_read_unavailable_fail_open', status: found.status, customerId };
  }

  const rows = Array.isArray(found.data) ? found.data : [];
  const row = rows[0] || null;
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();

  if (!row || !row.id) {
    // Jangan blokir login hanya karena row belum ada. Buat/touch session memakai fungsi existing.
    await customerSecurityTouchCurrentSession(req, customerId).catch(() => null);
    return { ok: true, created_or_touched: true, customerId, skipped: false, reason: 'session_created_if_possible' };
  }

  const status = String(row.status || '').trim().toLowerCase();
  const revoked = Boolean(row.revoked_at) || status === 'revoked';
  const expiresAtMs = Date.parse(row.expires_at || '');
  const expired = Number.isFinite(expiresAtMs) && expiresAtMs <= nowMs;
  const lastSeenMs = Date.parse(row.last_seen_at || '');
  const hasLastSeen = Number.isFinite(lastSeenMs) && lastSeenMs > 0;
  const idleMs = hasLastSeen ? nowMs - lastSeenMs : 0;
  const idleExpired = hasLastSeen && idleMs >= DOMAIN_PROTECTED_IDLE_TIMEOUT_MS;

  if (revoked || expired || idleExpired) {
    const reason = revoked
      ? String(row.revoke_reason || 'session_revoked')
      : (expired ? 'session_expired' : DOMAIN_PROTECTED_SESSION_REVOKE_REASON);

    await supabaseFetch('/rest/v1/security_customer_sessions?id=eq.' + encodeURIComponent(row.id), {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=minimal',
      body: {
        status: 'revoked',
        revoked_at: row.revoked_at || nowIso,
        revoke_reason: reason
      }
    }).catch(() => null);

    await customerSecurityWriteGuardEvent(customerId, {
      event_type: 'session_revoked',
      status: 'warning',
      risk_level: idleExpired ? 'medium' : 'low',
      description: idleExpired
        ? 'Sesi protected dikunci database karena idle lebih dari batas aman.'
        : 'Sesi protected ditolak karena revoked/expired.',
      req,
      metadata: {
        source: 'domain_dashboard_me_safe_v2',
        reason,
        idle_ms: idleExpired ? idleMs : 0,
        idle_timeout_ms: DOMAIN_PROTECTED_IDLE_TIMEOUT_MS
      }
    }).catch(() => null);

    return {
      ok: false,
      status: 401,
      code: idleExpired ? 'PROTECTED_SESSION_IDLE_TIMEOUT' : 'PROTECTED_SESSION_REVOKED',
      clearCookies: true,
      customerId,
      sessionId: row.id,
      message: idleExpired
        ? 'Sesi dikunci database karena tidak aktif lebih dari 5 menit. Silakan login ulang.'
        : 'Sesi sudah dicabut/expired. Silakan login ulang.'
    };
  }

  await customerSecurityTouchCurrentSession(req, customerId).catch(() => null);
  return { ok: true, customerId, sessionId: row.id, idleMs, idle_timeout_ms: DOMAIN_PROTECTED_IDLE_TIMEOUT_MS };
}

async function revokeCurrentDomainProtectedSessionSafe(req, reason) {
  const user = await getDomainUserForProtectedLogoutSafe(req);
  if (!user || !user.id) return { ok: false, reason: 'no_user' };

  const authUserId = String(user.id || '').trim();
  if (!customerSecurityLooksLikeUuid(authUserId)) return { ok: false, reason: 'invalid_user' };

  const linkResult = await customerSecurityFetchAuthLink(authUserId);
  if (!linkResult.ok) return { ok: false, reason: 'auth_link_read_failed', status: linkResult.status };

  const link = Array.isArray(linkResult.data) && linkResult.data.length ? linkResult.data[0] : null;
  const customerId = String(link && link.customer_id || '').trim();
  if (!link || link.link_status !== 'active' || !customerSecurityLooksLikeUuid(customerId)) {
    return { ok: false, reason: 'auth_link_inactive' };
  }

  const fingerprint = customerSecurityBuildSessionFingerprint(req, customerId);
  if (!fingerprint || !fingerprint.session_token_hash) return { ok: false, reason: 'missing_fingerprint' };

  const nowIso = new Date().toISOString();
  const patched = await supabaseFetch('/rest/v1/security_customer_sessions?customer_id=eq.' +
    encodeURIComponent(customerId) +
    '&session_token_hash=eq.' + encodeURIComponent(fingerprint.session_token_hash), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=minimal',
    body: {
      status: 'revoked',
      revoked_at: nowIso,
      revoke_reason: String(reason || 'manual_logout').slice(0, 80)
    }
  });

  if (!patched.ok) return { ok: false, reason: 'session_revoke_failed', status: patched.status };
  return { ok: true };
}

async function getDomainUserForProtectedLogoutSafe(req) {
  const cookies = parseCookies(req);
  const accessTokens = uniqueNonEmptyStrings(readCookieTokenCandidates(cookies, ACCESS_COOKIE));

  for (const accessToken of accessTokens) {
    const userResult = await supabaseFetch('/auth/v1/user', {
      method: 'GET',
      auth: 'anon',
      bearer: accessToken
    });
    if (userResult.ok && userResult.data && userResult.data.id) return userResult.data;
  }

  const signedSessionUser = await readSignedDomainSessionUser(cookies);
  if (signedSessionUser && signedSessionUser.id) return signedSessionUser;

  return null;
}

async function domainDashboardMe(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;

  const { user, mfa } = access;

  return res.status(200).json({
    ok: true,
    dashboard: true,
    user: sanitizeUser(user),
    mfa: {
      active: true,
      method: mfa.method || '',
      activeAtMs: mfa.activeAtMs || 0,
      expiresAtMs: mfa.expiresAtMs || 0,
      source: mfa.source || ''
    }
  });
}

async function domainMfaStatus(req, res) {
  if (!isEnvTrue('DOMAIN_MFA_STATUS_DEBUG')) {
    return res.status(404).json({ ok: false, message: 'Action domain tidak ditemukan.' });
  }

  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  const proof = getCustomerDashboardMfaToken(req);
  const payload = decodeCustomerDashboardMfaToken(proof.token);
  const mfa = verifyCustomerDashboardMfaCookie(req, user);

  return res.status(200).json({
    ok: true,
    login: true,
    dashboard: mfa.ok === true,
    mfa: {
      present: Boolean(proof.token),
      valid: mfa.ok === true,
      source: proof.source || '',
      code: mfa.code || (mfa.ok ? 'mfa_ok' : 'mfa_unknown'),
      method: mfa.method || (payload && payload.method) || '',
      expiresAtMs: mfa.expiresAtMs || (payload && Number(payload.expiresAtMs || 0)) || 0,
      message: mfa.ok ? 'Sesi A2F backend valid.' : (mfa.message || 'Sesi A2F backend belum valid.')
    }
  });
}

async function domainLogout(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  // SAFE V2: logout mencabut row session database jika tersedia, tetapi tidak menggagalkan logout.
  await revokeCurrentDomainProtectedSessionSafe(req, 'manual_logout').catch(() => null);

  clearSessionCookies(res);

  return res.status(200).json({
    ok: true,
    message: 'Logout berhasil.'
  });
}

async function domainCheck(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  const domain = normalizeDomain(req.query && req.query.domain);

  if (!domain) {
    return res.status(400).json({ ok: false, message: 'Domain wajib diisi.' });
  }

  const checkApi = requiredEnv('DOMAIN_CHECK_API');
  const response = await fetch(`${checkApi}?domain=${encodeURIComponent(domain)}`);
  const data = await response.json().catch(() => ({}));

  return res.status(response.status).json(data);
}

async function domainCheckout(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  // Anti-bypass: checkout domain berada sejajar dengan dashboard, jadi tidak cukup hanya login.
  // Backend wajib memastikan sesi user + A2F/MFA dashboard masih valid sebelum membuat order.
  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;
  const { user } = access;

  const body = await readBody(req);

  const customerName = String(body.customer_name || '').trim();
  const customerWhatsapp = String(body.customer_whatsapp || '').trim();
  const customerEmail = String(body.customer_email || user.email || '').trim() || null;
  const ownerEmail = String(body.owner_email || customerEmail || '').trim() || null;
  const authUserId = String(user.id || '').trim();
  const authEmail = normalizeAuthEmail(user.email || '');

  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId) || !authEmail || !isValidAuthEmail(authEmail)) {
    return res.status(401).json({ ok: false, message: 'Sesi login tidak valid untuk membuat pesanan domain.' });
  }

  const dnsMethod = body.dns_method || 'managed_by_dirac';
  const nameserver1 = body.nameserver_1 || null;
  const nameserver2 = body.nameserver_2 || null;
  const targetPlatform = body.target_platform || null;
  const customerNote = body.customer_note || null;

  const items = Array.isArray(body.items) ? body.items : [];

  if (!customerName || !customerWhatsapp) {
    return res.status(400).json({ ok: false, message: 'Nama dan nomor HP wajib diisi.' });
  }

  if (!items.length) {
    return res.status(400).json({ ok: false, message: 'Ringkasan domain masih kosong.' });
  }

  const owner = await sessionOwnershipCheckoutResolveCustomerOwner({
    authUserId,
    email: authEmail,
    fullName: customerName || authEmail,
    phone: customerWhatsapp
  });

  if (!owner || !owner.ok || !owner.customer || !customerSecurityLooksLikeUuid(owner.customer.id)) {
    return res.status(owner && owner.status ? owner.status : 403).json({
      ok: false,
      message: owner && owner.message
        ? owner.message
        : 'Akun login belum terhubung ke customer profile aktif. Checkout domain dihentikan agar tidak salah owner.',
      ownership_locked: true,
      frontend_customer_id_ignored: true
    });
  }

  const ownerCustomer = owner.customer;
  const ownerCustomerId = String(ownerCustomer.id || '').trim();

  if (items.length > 10) {
    return res.status(400).json({ ok: false, message: 'Maksimal 10 domain per checkout.' });
  }

  const pricesResult = await supabaseFetch('/rest/v1/domain_tld_prices?select=extension,register_price,renewal_price,currency,is_active&is_active=eq.true', {
    method: 'GET',
    auth: 'service'
  });

  if (!pricesResult.ok) {
    return res.status(pricesResult.status).json({
      ok: false,
      message: 'Gagal mengambil data harga domain.',
      error: pricesResult.data
    });
  }

  const prices = Array.isArray(pricesResult.data) ? pricesResult.data : [];

  if (!prices.length) {
    return res.status(400).json({ ok: false, message: 'Data harga domain masih kosong.' });
  }

  const extensions = prices.map((item) => item.extension);
  const orderItems = [];

  for (const item of items) {
    const domainName = normalizeDomain(item.domain_name);

    if (!domainName) {
      return res.status(400).json({ ok: false, message: 'Ada nama domain yang tidak valid.' });
    }

    const extension = getExtension(domainName, extensions);

    if (!extension) {
      return res.status(400).json({
        ok: false,
        message: `Harga untuk ekstensi ${domainName} belum tersedia.`
      });
    }

    const priceRow = prices.find((price) => price.extension === extension);

    if (!priceRow) {
      return res.status(400).json({
        ok: false,
        message: `Data harga ${extension} tidak ditemukan.`
      });
    }

    const years = Math.trunc(Number(item.years || 1));

    if (!Number.isFinite(years) || years < 1 || years > 10) {
      return res.status(400).json({ ok: false, message: 'Durasi pembelian domain harus 1 sampai 10 tahun.' });
    }

    const partsForCheckout = splitDomainForHostinger(domainName);
    if (!partsForCheckout) {
      return res.status(400).json({ ok: false, message: `Format domain ${domainName} tidak valid.` });
    }

    const requireAvailabilityCheck = String(process.env.DOMAIN_CHECKOUT_REQUIRE_AVAILABILITY || 'true').toLowerCase() !== 'false';
    if (requireAvailabilityCheck) {
      const availabilityCheck = await checkDomainWithProviders(partsForCheckout);
      if (!availabilityCheck || !availabilityCheck.ok) {
        return res.status(409).json({
          ok: false,
          message: `Backend belum bisa memverifikasi ketersediaan ${domainName}. Checkout dihentikan agar tidak bisa dibypass.`,
          provider: availabilityCheck && availabilityCheck.provider ? availabilityCheck.provider : null
        });
      }
      if (availabilityCheck.available === false) {
        return res.status(409).json({
          ok: false,
          message: `${domainName} tidak tersedia saat diverifikasi backend.`,
          provider: availabilityCheck.provider || null
        });
      }
    }

    const registerPrice = Number(priceRow.register_price);
    const renewalPrice = Number(priceRow.renewal_price);
    const subtotal = registerPrice * years;

    orderItems.push({
      domain_name: domainName,
      extension,
      years,
      register_price: registerPrice,
      renewal_price: renewalPrice,
      subtotal,
      availability_snapshot: item.availability_snapshot ?? true
    });
  }

  const totalAmount = orderItems.reduce((total, item) => total + item.subtotal, 0);

  const primaryDomainName = orderItems.length === 1
    ? orderItems[0].domain_name
    : orderItems.map((item) => item.domain_name).join(', ').slice(0, 240);

  const orderResult = await supabaseFetch('/rest/v1/domain_orders', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      customer_id: ownerCustomerId,
      customer_name: customerName || ownerCustomer.name || authEmail,
      customer_whatsapp: customerWhatsapp,
      customer_email: customerEmail || authEmail,
      owner_email: ownerEmail || authEmail,
      domain_name: primaryDomainName,
      dns_method: dnsMethod,
      nameserver_1: nameserver1,
      nameserver_2: nameserver2,
      target_platform: targetPlatform,
      customer_note: customerNote,
      total_price: totalAmount,
      currency: 'IDR',
      order_status: 'pending',
      status: 'pending',
      payment_status: 'unpaid'
    }]
  });

  if (!orderResult.ok) {
    return res.status(orderResult.status).json({
      ok: false,
      message: 'Gagal membuat pesanan.',
      error: orderResult.data
    });
  }

  const order = Array.isArray(orderResult.data) ? orderResult.data[0] : orderResult.data;

  if (!order || !order.id) {
    return res.status(500).json({
      ok: false,
      message: 'Pesanan dibuat, tetapi ID pesanan tidak ditemukan.'
    });
  }

  const itemResult = await supabaseFetch('/rest/v1/domain_order_items', {
    method: 'POST',
    auth: 'service',
    body: orderItems.map((item) => ({
      ...item,
      order_id: order.id
    }))
  });

  if (!itemResult.ok) {
    return res.status(itemResult.status).json({
      ok: false,
      message: 'Pesanan dibuat, tetapi item domain gagal disimpan.',
      error: itemResult.data
    });
  }

  let payment = { configured: false, payment_url: null };
  try {
    payment = await maybeCreateDomainPaymentInvoice(order, orderItems, {
      customerName,
      customerWhatsapp,
      customerEmail,
      ownerEmail,
      totalAmount
    });
  } catch (paymentError) {
    payment = {
      configured: true,
      payment_url: null,
      provider: 'midtrans',
      error: String(paymentError && paymentError.message ? paymentError.message : paymentError)
    };
  }

  const orderMailNotification = orderMailPendingPaymentSkipSummary('domain_checkout');

  return res.status(200).json({
    ok: true,
    message: payment && payment.payment_url
      ? 'Pesanan domain berhasil dibuat. Lanjutkan pembayaran otomatis.'
      : 'Pesanan domain berhasil dibuat. Payment gateway belum mengembalikan URL pembayaran.',
    order_id: order.id,
    customer_id: ownerCustomerId,
    owner_source: owner.source || 'security_customer_auth_links',
    total_amount: totalAmount,
    total_price: totalAmount,
    currency: 'IDR',
    payment_status: 'unpaid',
    order_status: 'pending_payment',
    payment_url: payment && payment.payment_url ? payment.payment_url : null,
    invoice_id: payment && payment.invoice_id ? payment.invoice_id : null,
    payment_provider: payment && payment.provider ? payment.provider : null,
    payment_gateway_configured: Boolean(payment && payment.configured),
    payment_error: payment && payment.error ? payment.error : null,
    order_mail_notification: orderMailNotification,
    items: orderItems
  });
}


async function maybeCreateDomainPaymentInvoice(order, orderItems, customer) {
  // MIDTRANS ONLY v1:
  // Domain checkout hanya boleh membuat payment melalui Midtrans.
  // iPaymu dan gateway eksternal sengaja tidak dibaca agar provider tidak bercampur.
  if (midtransPaymentIsConfigured()) {
    return await midtransCreateDomainPaymentInvoice(order, orderItems, customer);
  }

  return {
    configured: false,
    provider: 'midtrans',
    payment_url: null,
    invoice_id: null,
    error: 'midtrans_not_configured'
  };
}

async function domainOrders(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;

  const { user } = access;
  const authUserId = String(user.id || '').trim();
  const linkResult = await customerSecurityFetchAuthLink(authUserId);
  const linkRows = linkResult.ok && Array.isArray(linkResult.data) ? linkResult.data : [];
  const activeCustomerIds = linkRows
    .filter((row) => row && row.link_status === 'active' && customerSecurityLooksLikeUuid(row.customer_id))
    .map((row) => String(row.customer_id));

  if (!activeCustomerIds.length) {
    return res.status(403).json({
      ok: false,
      message: 'Akun login belum terhubung ke customer profile aktif. Pesanan domain dikunci aman agar tidak salah owner.',
      ownership_locked: true,
      frontend_customer_id_ignored: true
    });
  }

  const select = [
    'id',
    'customer_id',
    'created_at',
    'customer_name',
    'customer_whatsapp',
    'customer_email',
    'owner_email',
    'dns_method',
    'nameserver_1',
    'nameserver_2',
    'target_platform',
    'customer_note',
    'domain_name',
    'total_price',
    'currency',
    'order_status',
    'payment_status',
    'domain_order_items(id,domain_name,extension,years,register_price,renewal_price,subtotal)'
  ].join(',');

  const ids = activeCustomerIds.map(encodeURIComponent).join(',');
  const path = `/rest/v1/domain_orders?select=${encodeURIComponent(select)}&customer_id=in.(${ids})&order=created_at.desc`;

  const result = await supabaseFetch(path, {
    method: 'GET',
    auth: 'service'
  });

  if (!result.ok) {
    return res.status(result.status).json({
      ok: false,
      message: 'Gagal memuat pesanan.',
      error: result.data
    });
  }

  return res.status(200).json({
    ok: true,
    data: Array.isArray(result.data) ? result.data : []
  });
}

async function requireDomainUser(req, res) {
  const cookies = parseCookies(req);
  const acceptFrontendAuthHeaders = shouldAcceptFrontendAuthHeaders();
  const headerToken = acceptFrontendAuthHeaders ? getBearerToken(req) : '';
  const headerRefreshToken = acceptFrontendAuthHeaders
    ? String((req.headers && (req.headers['x-domain-refresh'] || req.headers['x-refresh-token'])) || '').trim()
    : '';

  const accessTokens = uniqueNonEmptyStrings([
    headerToken,
    ...readCookieTokenCandidates(cookies, ACCESS_COOKIE)
  ]);

  for (const accessToken of accessTokens) {
    const userResult = await supabaseFetch('/auth/v1/user', {
      method: 'GET',
      auth: 'anon',
      bearer: accessToken
    });

    if (userResult.ok && userResult.data && userResult.data.id) {
      return userResult.data;
    }
  }

  const refreshTokens = uniqueNonEmptyStrings([
    headerRefreshToken,
    ...readCookieTokenCandidates(cookies, REFRESH_COOKIE)
  ]);

  for (const refreshToken of refreshTokens) {
    const refreshResult = await supabaseFetch('/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      auth: 'anon',
      body: { refresh_token: refreshToken }
    });

    if (refreshResult.ok && refreshResult.data && refreshResult.data.access_token) {
      const refreshedSession = Object.assign({}, refreshResult.data, {
        refresh_token: refreshResult.data.refresh_token || refreshToken
      });
      if (hasValidDomainSessionTokens(refreshedSession)) {
        setSessionCookies(res, refreshedSession);
        if (!shouldHideDomainAuthTokens()) {
          res.setHeader('X-Domain-Access-Token', refreshedSession.access_token);
          res.setHeader('X-Domain-Refresh-Token', refreshedSession.refresh_token);
        }
        res.setHeader('X-Domain-Token-Refreshed', 'true');
        return refreshedSession.user || refreshResult.data.user;
      }
    }
  }

  const signedSessionUser = await readSignedDomainSessionUser(cookies);
  if (signedSessionUser && signedSessionUser.id) {
    res.setHeader('X-Domain-Signed-Session', 'true');
    return signedSessionUser;
  }

  clearSessionCookies(res);
  res.status(401).json({ ok: false, message: 'Belum login atau sesi sudah habis.' });
  return null;
}


function safeEqual(a, b) {
  const A = Buffer.from(String(a || ''));
  const B = Buffer.from(String(b || ''));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function signDashboardMfa(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function hashDashboardMfa(value, secret) {
  return crypto.createHmac('sha256', secret).update(String(value || '')).digest('hex');
}

function getCustomerMfaSecret() {
  const secret = String(process.env.DIRAC_MFA_SECRET || process.env.A2F_SECRET || '').trim();
  if (!secret || secret === 'rahasia-test' || secret.length < 32) {
    const err = new Error('DIRAC_MFA_SECRET atau A2F_SECRET production wajib minimal 32 karakter acak.');
    err.statusCode = 500;
    throw err;
  }
  return secret;
}

function customerMfaProfileId(email) {
  return hashDashboardMfa(`dirac-customer-mfa-profile-v1:${normalizeAuthEmail(email)}`, getCustomerMfaSecret());
}

function decodeCustomerDashboardMfaToken(token) {
  const [payloadBase64, signature] = String(token || '').split('.');
  if (!payloadBase64 || !signature) return null;

  const expected = signDashboardMfa(payloadBase64, getCustomerMfaSecret());
  if (!safeEqual(signature, expected)) return null;

  try {
    return JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

function normalizeDashboardMfaOrigin(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw).origin;
  } catch (_) {
    return raw.replace(/\/+$/, '');
  }
}

function requestOrigin(req) {
  const headers = (req && req.headers) || {};
  return normalizeDashboardMfaOrigin(headers.origin) || normalizeDashboardMfaOrigin(headers.referer);
}

function requestUserAgent(req) {
  return String((req && req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
}

function customerMfaBindingHash(kind, value) {
  const text = String(value || '').trim();
  if (!text) return '';
  return hashDashboardMfa(`dirac-customer-mfa-binding-v2:${kind}:${text}`, getCustomerMfaSecret());
}

function getCustomerDashboardMfaToken(req) {
  const cookies = parseCookies(req);
  const cookieToken = String(cookies[CUSTOMER_MFA_COOKIE] || '').trim();
  if (cookieToken) return { token: cookieToken, source: 'http_only_cookie' };

  // PATCH 3B: full backend customer auth.
  // MFA proof dari header frontend sengaja ditolak. JavaScript tidak boleh membawa
  // X-Dirac-MFA-Proof / X-Dashboard-MFA-Proof / X-Dirac-Dashboard-MFA.
  // Satu-satunya sumber yang diterima adalah HttpOnly Secure cookie dari backend.
  return { token: '', source: 'missing_http_only_cookie' };
}

function verifyCustomerDashboardMfaCookie(req, user) {
  const proof = getCustomerDashboardMfaToken(req);
  const payload = decodeCustomerDashboardMfaToken(proof.token);
  const email = normalizeAuthEmail(user && user.email);

  if (!payload || payload.type !== CUSTOMER_MFA_SESSION_TYPE) {
    return { ok: false, code: proof && proof.token ? 'mfa_cookie_invalid_or_unsigned' : 'mfa_cookie_missing', message: proof && proof.token ? 'Sesi A2F backend tidak valid. Login dan verifikasi A2F ulang dari domain resmi.' : 'Sesi A2F backend tidak ditemukan. Login dan verifikasi A2F ulang dari domain resmi.' };
  }

  if (!payload.expiresAtMs || Date.now() > Number(payload.expiresAtMs)) {
    return { ok: false, code: 'mfa_cookie_expired', message: 'Sesi A2F backend sudah expired. Login dan verifikasi A2F ulang.' };
  }

  if (!email || !payload.emailHash || !safeEqual(String(payload.emailHash), customerMfaProfileId(email))) {
    return { ok: false, code: 'mfa_cookie_user_mismatch', message: 'Sesi A2F backend tidak cocok dengan akun login.' };
  }

  if (payload.originHash) {
    const expectedOriginHash = customerMfaBindingHash('origin', requestOrigin(req));
    if (!expectedOriginHash || !safeEqual(String(payload.originHash), expectedOriginHash)) {
      return { ok: false, code: 'mfa_cookie_origin_mismatch', message: 'Sesi A2F backend tidak cocok dengan origin website ini. Login ulang dari domain resmi.' };
    }
  }

  if (payload.uaHash) {
    const expectedUaHash = customerMfaBindingHash('ua', requestUserAgent(req));
    if (!expectedUaHash || !safeEqual(String(payload.uaHash), expectedUaHash)) {
      return { ok: false, code: 'mfa_cookie_browser_mismatch', message: 'Sesi A2F backend tidak cocok dengan browser/perangkat ini. Login ulang dari browser yang sama.' };
    }
  }

  return {
    ok: true,
    method: String(payload.method || ''),
    activeAtMs: Number(payload.activeAtMs || 0),
    expiresAtMs: Number(payload.expiresAtMs || 0),
    source: proof.source
  };
}

function getDomainProviderOrder() {
  const aliases = {
    'name.com': 'namecom',
    'name_com': 'namecom',
    namecom: 'namecom',
    namesilo: 'namesilo',
    name_silo: 'namesilo',
    'name-silo': 'namesilo',
    whoisjson: 'whoisjson',
    'whois-json': 'whoisjson',
    whois_json: 'whoisjson',
    hostinger: 'hostinger'
  };

  const raw = String(process.env.DOMAIN_AVAILABILITY_PROVIDERS || process.env.DOMAIN_CHECK_PROVIDERS || 'namecom,namesilo,whoisjson,hostinger')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .map((item) => aliases[item] || item)
    .filter((item) => ['namecom', 'namesilo', 'whoisjson', 'hostinger'].includes(item));

  return Array.from(new Set(raw.length ? raw : ['namecom', 'namesilo', 'whoisjson', 'hostinger']));
}

function hasDomainProviderCredentials(provider) {
  if (provider === 'namecom') return Boolean(process.env.NAMECOM_USERNAME && process.env.NAMECOM_API_TOKEN);
  if (provider === 'namesilo') return Boolean(process.env.NAMESILO_API_KEY);
  if (provider === 'whoisjson') return Boolean(process.env.WHOISJSON_API_KEY);
  if (provider === 'hostinger') return Boolean(process.env.HOSTINGER_API_TOKEN || process.env.HOSTINGER_API_TOKENS || process.env.HOSTINGER_API_KEYS || process.env.HOSTINGER_API_TOKEN_1);
  return false;
}

async function checkDomainWithProviders(parts) {
  const providers = getDomainProviderOrder().filter(hasDomainProviderCredentials);
  let lastError = null;
  let availableCandidate = null;

  if (!providers.length) {
    return {
      ok: false,
      status: 500,
      message: 'Belum ada API domain yang disetel. Isi NAMECOM_API_TOKEN, NAMESILO_API_KEY, WHOISJSON_API_KEY, atau HOSTINGER_API_TOKEN.'
    };
  }

  for (const provider of providers) {
    const cooldownUntil = Number(DOMAIN_PROVIDER_COOLDOWNS.get(provider) || 0);
    if (cooldownUntil > Date.now()) {
      lastError = {
        ok: false,
        status: 429,
        provider,
        message: `${getProviderLabel(provider)} masih cooldown. Coba lagi ${Math.ceil((cooldownUntil - Date.now()) / 1000)} detik.`
      };
      continue;
    }

    try {
      const result = await checkDomainWithProvider(provider, parts);

      if (!result || !result.ok) {
        lastError = result || { ok: false, status: 502, provider, message: `${getProviderLabel(provider)} tidak merespons.` };
        if (lastError.status === 429) setProviderCooldown(provider, lastError.retry_after_seconds || 60);
        continue;
      }

      if (result.available === false) return result;

      if (result.available === true || result.available === null) {
        const priceInfo = await resolveDomainPrice(parts, result);
        if (priceInfo) return { ...result, priceInfo };
        if (result.available === true && !availableCandidate) availableCandidate = result;
      }
    } catch (error) {
      lastError = {
        ok: false,
        status: 502,
        provider,
        message: String(error && error.message ? error.message : error)
      };
    }
  }

  if (availableCandidate) return { ...availableCandidate, priceInfo: null };

  return {
    ok: false,
    status: lastError && lastError.status ? lastError.status : 502,
    provider: lastError && lastError.provider ? lastError.provider : null,
    message: lastError && lastError.message ? lastError.message : 'Semua provider domain gagal mengecek domain.'
  };
}

async function checkDomainWithProvider(provider, parts) {
  if (provider === 'namecom') return checkNamecomDomain(parts);
  if (provider === 'namesilo') return checkNamesiloDomain(parts);
  if (provider === 'whoisjson') return checkWhoisJsonDomain(parts);
  if (provider === 'hostinger') return checkHostingerDomainAvailabilityAndPrice(parts);
  return { ok: false, status: 400, provider, message: `Provider ${provider} tidak dikenal.` };
}

async function checkNamecomDomain(parts) {
  const username = requiredEnv('NAMECOM_USERNAME');
  const token = requiredEnv('NAMECOM_API_TOKEN');
  const baseUrl = String(process.env.NAMECOM_API_BASE || 'https://api.name.com').replace(/\/$/, '');
  const auth = Buffer.from(`${username}:${token}`).toString('base64');

  const response = await fetch(`${baseUrl}/core/v1/domains:checkAvailability`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify({
      domainNames: [parts.fullDomain],
      purchaseType: 'registration'
    })
  });

  const data = await parseFetchResponse(response);
  if (!response.ok) {
    return upstreamFailure('namecom', response, data);
  }

  const results = Array.isArray(data && data.results) ? data.results : [];
  const item = results.find((entry) => String(entry && entry.domainName || '').toLowerCase() === parts.fullDomain) || results[0];

  if (!item || typeof item !== 'object') {
    return { ok: false, status: 502, provider: 'namecom', message: 'Response Name.com tidak berisi hasil domain.' };
  }

  const purchasable = typeof item.purchasable === 'boolean' ? item.purchasable : parseAvailabilityValue(item.available ?? item.status ?? item.reason);
  const rawPrice = Number(item.purchasePrice ?? item.price ?? item.registrationPrice);

  return {
    ok: true,
    status: 200,
    provider: 'namecom',
    available: purchasable === null ? null : Boolean(purchasable),
    priceInfo: Number.isFinite(rawPrice) && rawPrice > 0 ? {
      price: rawPrice,
      currency: String(item.currency || process.env.NAMECOM_DEFAULT_CURRENCY || 'USD').toUpperCase(),
      source: 'namecom',
      final: false
    } : null,
    data
  };
}

async function checkNamesiloDomain(parts) {
  const apiKey = requiredEnv('NAMESILO_API_KEY');
  const baseUrl = String(process.env.NAMESILO_API_BASE || 'https://www.namesilo.com/api').replace(/\/$/, '');
  const url = new URL(`${baseUrl}/checkRegisterAvailability`);
  url.searchParams.set('version', '1');
  url.searchParams.set('type', 'json');
  url.searchParams.set('key', apiKey);
  url.searchParams.set('domains', parts.fullDomain);

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: { Accept: 'application/json' }
  });

  const data = await parseFetchResponse(response);
  if (!response.ok) return upstreamFailure('namesilo', response, data);

  const reply = data && data.reply ? data.reply : data;
  const code = Number(reply && reply.code);
  if (Number.isFinite(code) && code !== 300) {
    return {
      ok: false,
      status: code === 280 ? 429 : 502,
      provider: 'namesilo',
      message: getUpstreamMessage(reply) || `NameSilo mengembalikan kode ${code}.`,
      data
    };
  }

  const availableDomains = extractDomainStrings(reply && reply.available).map((item) => item.toLowerCase());
  const unavailableDomains = extractDomainStrings(reply && reply.unavailable).map((item) => item.toLowerCase());
  let available = null;

  if (availableDomains.includes(parts.fullDomain)) available = true;
  if (unavailableDomains.includes(parts.fullDomain)) available = false;

  if (available === null) available = parseAvailabilityValue(reply && (reply.available || reply.status || reply.detail));

  return {
    ok: true,
    status: 200,
    provider: 'namesilo',
    available,
    data
  };
}

async function checkWhoisJsonDomain(parts) {
  const apiKey = requiredEnv('WHOISJSON_API_KEY');
  const baseUrl = String(process.env.WHOISJSON_API_BASE || 'https://whoisjson.com/api/v1').replace(/\/$/, '');
  const url = new URL(`${baseUrl}/domain-availability`);
  url.searchParams.set('domain', parts.fullDomain);

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      Authorization: `TOKEN=${apiKey}`,
      Accept: 'application/json'
    }
  });

  const data = await parseFetchResponse(response);
  if (!response.ok) return upstreamFailure('whoisjson', response, data);

  return {
    ok: true,
    status: 200,
    provider: 'whoisjson',
    available: parseAvailabilityValue(data && (data.available ?? data.is_available ?? data.status ?? data.result)),
    data
  };
}

async function checkHostingerDomainAvailabilityAndPrice(parts) {
  const availability = await hostingerFetch('/api/domains/v1/availability', {
    method: 'POST',
    body: {
      domain: parts.name,
      tlds: [parts.tld],
      with_alternatives: false
    }
  });

  if (!availability.ok) {
    return {
      ok: false,
      status: availability.status || 502,
      provider: 'hostinger',
      message: getUpstreamMessage(availability.data) || 'Hostinger gagal cek ketersediaan domain.',
      data: availability.data
    };
  }

  const available = parseHostingerAvailability(availability.data, parts.fullDomain);

  if (available === false) {
    return {
      ok: true,
      status: 200,
      provider: 'hostinger',
      available: false,
      data: availability.data
    };
  }

  // Hindari request katalog Hostinger tambahan jika harga final sudah tersedia di Supabase.
  const localPrice = await getLocalDomainPrice(parts);
  const priceInfo = localPrice || await getHostingerDomainPriceInfo(parts);

  return {
    ok: true,
    status: 200,
    provider: 'hostinger',
    available: available === null ? null : Boolean(available),
    priceInfo,
    data: availability.data
  };
}

async function getHostingerDomainPriceInfo(parts) {
  const catalog = await hostingerFetch(`/api/billing/v1/catalog?category=DOMAIN&name=${encodeURIComponent(`.${parts.tld.toUpperCase()}*`)}`, {
    method: 'GET'
  });

  if (!catalog.ok) return null;

  const priceInfo = extractHostingerDomainPrice(catalog.data, parts.tld);
  return priceInfo ? { ...priceInfo, source: 'hostinger', final: false } : null;
}

async function resolveDomainPrice(parts, providerResult = {}) {
  const localPrice = await getLocalDomainPrice(parts);
  if (localPrice) return localPrice;
  if (providerResult.priceInfo) return providerResult.priceInfo;
  return null;
}

async function getLocalDomainPrice(parts) {
  if (!process.env.DOMAIN_SUPABASE_URL || !process.env.DOMAIN_SUPABASE_ANON_KEY || !process.env.DOMAIN_SUPABASE_SERVICE_ROLE_KEY) {
    return null;
  }

  try {
    const result = await supabaseFetch('/rest/v1/domain_tld_prices?select=extension,register_price,renewal_price,currency,is_active&is_active=eq.true', {
      method: 'GET',
      auth: 'service'
    });

    if (!result.ok || !Array.isArray(result.data)) return null;

    const row = result.data.find((item) => {
      const ext = normalizeExtension(item && item.extension);
      return ext && ext === normalizeExtension(parts.tld);
    });

    if (!row) return null;

    const price = Number(row.register_price);
    if (!Number.isFinite(price) || price <= 0) return null;

    return {
      price,
      currency: String(row.currency || process.env.DOMAIN_DEFAULT_CURRENCY || 'IDR').toUpperCase(),
      source: 'supabase',
      final: true
    };
  } catch (_) {
    return null;
  }
}

function buildDomainPrice(parts, priceInfo) {
  const defaultCurrency = String(process.env.DOMAIN_DEFAULT_CURRENCY || 'IDR').toUpperCase();
  let currency = String(priceInfo.currency || defaultCurrency).toUpperCase();
  let price = Number(priceInfo.price || 0);

  if (!Number.isFinite(price) || price <= 0) {
    return { price: 0, currency: defaultCurrency };
  }

  if (priceInfo.final) {
    return { price: Math.round(price), currency };
  }

  if (currency !== defaultCurrency && currency === 'USD' && defaultCurrency === 'IDR') {
    const exchangeRate = Math.max(1, Number(process.env.DOMAIN_USD_TO_IDR || process.env.NAMECOM_USD_TO_IDR || 16000));
    price = price * exchangeRate;
    currency = defaultCurrency;
  }

  const normalMarkup = Math.max(0, Number(process.env.DOMAIN_PRICE_MARKUP || 10000));
  const storeMarkup = Math.max(0, Number(process.env.DOMAIN_STORE_MARKUP || 1200000));
  const markup = parts.tld === 'store' ? storeMarkup : normalMarkup;

  if (currency === 'IDR') {
    return { price: Math.round(price + markup), currency };
  }

  const foreignMarkup = Math.max(0, Number(process.env.DOMAIN_FOREIGN_PRICE_MARKUP || 0));
  return { price: Number((price + foreignMarkup).toFixed(2)), currency };
}

function upstreamFailure(provider, response, data) {
  const retryAfterMs = response.status === 429 ? getRetryAfterMs(response) : 0;
  return {
    ok: false,
    status: response.status,
    provider,
    retry_after_seconds: retryAfterMs ? Math.ceil(retryAfterMs / 1000) : undefined,
    message: getUpstreamMessage(data) || `${getProviderLabel(provider)} error ${response.status}.`,
    data
  };
}

function setProviderCooldown(provider, seconds) {
  DOMAIN_PROVIDER_COOLDOWNS.set(provider, Date.now() + Math.max(1, Number(seconds || 60)) * 1000);
}

function getProviderLabel(provider) {
  if (provider === 'namecom') return 'Name.com';
  if (provider === 'namesilo') return 'NameSilo';
  if (provider === 'whoisjson') return 'WhoisJSON';
  if (provider === 'hostinger') return 'Hostinger';
  return provider || 'Provider';
}

function parseAvailabilityValue(value) {
  if (typeof value === 'boolean') return value;
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) return null;
  if (['true', 'available', 'purchasable', 'free', 'ok', 'success', 'yes'].includes(text)) return true;
  if (['false', 'taken', 'unavailable', 'registered', 'not_available', 'blocked', 'no'].includes(text)) return false;
  return null;
}

function extractDomainStrings(value) {
  const output = [];

  function walk(item) {
    if (item === null || item === undefined) return;
    if (typeof item === 'string') {
      output.push(item.trim());
      return;
    }
    if (Array.isArray(item)) {
      item.forEach(walk);
      return;
    }
    if (typeof item === 'object') {
      Object.values(item).forEach(walk);
    }
  }

  walk(value);
  return output.filter(Boolean);
}

function normalizeExtension(value) {
  return String(value || '').trim().toLowerCase().replace(/^\./, '');
}

async function hostingerFetch(path, options = {}) {
  const tokens = getHostingerApiTokens();
  const baseUrl = String(process.env.HOSTINGER_API_BASE || HOSTINGER_API_BASE).replace(/\/$/, '');
  const fetchOptionsTemplate = buildHostingerFetchOptions(options);
  const startPointer = Number(globalThis.__DIRAC_HOSTINGER_TOKEN_POINTER__ || 0);
  let lastLimited = null;
  let lastAuthError = null;

  for (let attempt = 0; attempt < tokens.length; attempt += 1) {
    const index = (startPointer + attempt) % tokens.length;
    const cooldownUntil = Number(HOSTINGER_TOKEN_COOLDOWNS.get(index) || 0);

    if (cooldownUntil > Date.now()) {
      lastLimited = {
        status: 429,
        api_index: index + 1,
        retry_after_seconds: Math.ceil((cooldownUntil - Date.now()) / 1000),
        message: `API Hostinger ke-${index + 1} masih cooldown.`
      };
      continue;
    }

    const response = await fetch(`${baseUrl}${path}`, {
      ...fetchOptionsTemplate,
      headers: {
        ...fetchOptionsTemplate.headers,
        Authorization: `Bearer ${tokens[index]}`
      }
    });

    const data = await parseFetchResponse(response);

    if (response.status === 429) {
      const cooldownMs = getRetryAfterMs(response);
      HOSTINGER_TOKEN_COOLDOWNS.set(index, Date.now() + cooldownMs);
      lastLimited = {
        status: 429,
        api_index: index + 1,
        retry_after_seconds: Math.ceil(cooldownMs / 1000),
        message: getUpstreamMessage(data) || `API Hostinger ke-${index + 1} terkena limit.`,
        data
      };
      continue;
    }

    if (response.status === 401 || response.status === 403) {
      const cooldownMs = Math.max(60_000, Number(process.env.HOSTINGER_AUTH_ERROR_COOLDOWN_SECONDS || 300) * 1000);
      HOSTINGER_TOKEN_COOLDOWNS.set(index, Date.now() + cooldownMs);
      lastAuthError = {
        status: response.status,
        api_index: index + 1,
        retry_after_seconds: Math.ceil(cooldownMs / 1000),
        message: getUpstreamMessage(data) || `API Hostinger ke-${index + 1} tidak valid atau tidak punya izin.`,
        data
      };
      continue;
    }

    globalThis.__DIRAC_HOSTINGER_TOKEN_POINTER__ = (index + 1) % tokens.length;

    return {
      ok: response.ok,
      status: response.status,
      data,
      api_index: index + 1
    };
  }

  const fallback = lastLimited || lastAuthError || {
    status: 429,
    message: 'Semua API Hostinger sedang terkena limit atau belum dapat dipakai.',
    retry_after_seconds: 60
  };

  return {
    ok: false,
    status: fallback.status || 429,
    data: {
      message: fallback.message || 'Semua API Hostinger sedang terkena limit atau belum dapat dipakai.',
      api_index: fallback.api_index || null,
      retry_after_seconds: fallback.retry_after_seconds || 60
    }
  };
}

function buildHostingerFetchOptions(options = {}) {
  const headers = {
    Accept: 'application/json'
  };

  const fetchOptions = {
    method: options.method || 'GET',
    headers
  };

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    fetchOptions.body = JSON.stringify(options.body);
  }

  return fetchOptions;
}

function getHostingerApiTokens() {
  const fromMainEnv = String(process.env.HOSTINGER_API_TOKEN || '')
    .split(',')
    .map((token) => token.trim())
    .filter(Boolean);

  const fromAliases = String(process.env.HOSTINGER_API_TOKENS || process.env.HOSTINGER_API_KEYS || '')
    .split(',')
    .map((token) => token.trim())
    .filter(Boolean);

  const numbered = Array.from({ length: 11 }, (_, index) => String(process.env[`HOSTINGER_API_TOKEN_${index + 1}`] || '').trim())
    .filter(Boolean);

  const tokens = Array.from(new Set([...fromMainEnv, ...fromAliases, ...numbered]));

  if (!tokens.length) {
    throw new Error('HOSTINGER_API_TOKEN belum diisi di Environment Variables Vercel.');
  }

  return tokens;
}

function getRetryAfterMs(response) {
  const retryAfter = response && response.headers && response.headers.get ? response.headers.get('retry-after') : '';

  if (!retryAfter) {
    return Math.max(1, Number(process.env.HOSTINGER_DEFAULT_COOLDOWN_SECONDS || 60)) * 1000;
  }

  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.max(1, seconds) * 1000;
  }

  const retryDate = new Date(retryAfter).getTime();
  if (Number.isFinite(retryDate)) {
    return Math.max(retryDate - Date.now(), 1000);
  }

  return Math.max(1, Number(process.env.HOSTINGER_DEFAULT_COOLDOWN_SECONDS || 60)) * 1000;
}

async function parseFetchResponse(response) {
  const text = await response.text();

  try {
    return text ? JSON.parse(text) : null;
  } catch (_) {
    return text;
  }
}

function splitDomainForHostinger(value) {
  const domain = normalizeDomain(value);

  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain)) {
    return null;
  }

  const labels = domain.split('.').filter(Boolean);
  if (labels.length < 2) return null;

  return {
    fullDomain: domain,
    name: labels[0],
    tld: labels.slice(1).join('.')
  };
}

function parseHostingerAvailability(data, fullDomain) {
  const items = Array.isArray(data) ? data : Array.isArray(data && data.data) ? data.data : [data];
  const wanted = String(fullDomain || '').toLowerCase();
  const match = items.find((item) => {
    const domain = String((item && (item.domain || item.name || item.fqdn || item.domain_name)) || '').toLowerCase();
    return domain === wanted || domain.endsWith(`.${wanted}`) || wanted.endsWith(`.${domain}`);
  }) || items[0];

  if (!match || typeof match !== 'object') return null;

  const directFields = ['available', 'is_available', 'isAvailable', 'available_for_registration', 'is_free'];
  for (const field of directFields) {
    if (typeof match[field] === 'boolean') return match[field];
  }

  const status = String(match.status || match.availability || match.result || match.state || '').toLowerCase();
  if (['available', 'free', 'success', 'ok'].includes(status)) return true;
  if (['taken', 'unavailable', 'registered', 'not_available', 'blocked'].includes(status)) return false;

  return null;
}

function extractHostingerDomainPrice(data, tld) {
  const items = Array.isArray(data) ? data : Array.isArray(data && data.data) ? data.data : [];
  const targetTld = String(tld || '').toLowerCase().replace(/^\./, '');
  const divisor = Math.max(1, Number(process.env.HOSTINGER_PRICE_DIVISOR || 100));

  const candidates = items.filter((item) => {
    const name = String((item && item.name) || '').toLowerCase();
    const id = String((item && item.id) || '').toLowerCase();
    const metadata = JSON.stringify((item && item.metadata) || {}).toLowerCase();
    return name.includes(targetTld) || id.includes(targetTld) || metadata.includes(targetTld) || !targetTld;
  });

  const pool = candidates.length ? candidates : items;

  for (const item of pool) {
    const prices = Array.isArray(item && item.prices) ? item.prices : [];
    const sortedPrices = [...prices].sort((a, b) => {
      const aYear = String(a.period_unit || '').toLowerCase() === 'year' ? 0 : 1;
      const bYear = String(b.period_unit || '').toLowerCase() === 'year' ? 0 : 1;
      const aPeriod = Number(a.period || 9999);
      const bPeriod = Number(b.period || 9999);
      return aYear - bYear || aPeriod - bPeriod;
    });

    for (const price of sortedPrices) {
      const raw = price.first_period_price ?? price.price;
      const number = Number(raw);
      if (!Number.isFinite(number) || number <= 0) continue;

      return {
        price: Math.round(number / divisor),
        currency: String(price.currency || process.env.DOMAIN_DEFAULT_CURRENCY || 'IDR').toUpperCase(),
        period: Number(price.period || 1),
        period_unit: String(price.period_unit || 'year')
      };
    }
  }

  return null;
}

function formatCurrency(value, currency = 'IDR') {
  const numeric = Number(value || 0);
  try {
    return new Intl.NumberFormat('id-ID', {
      style: 'currency',
      currency: String(currency || 'IDR').toUpperCase(),
      maximumFractionDigits: 0
    }).format(numeric).replace(/\s/g, '');
  } catch (_) {
    return `Rp${Math.round(numeric).toLocaleString('id-ID')}`;
  }
}

function getUpstreamMessage(data) {
  if (!data) return '';
  if (typeof data === 'string') return data.slice(0, 220);
  if (Array.isArray(data)) return data.map((item) => getUpstreamMessage(item)).filter(Boolean).join(' | ').slice(0, 220);
  if (typeof data === 'object') {
    const validation = Array.isArray(data.validation_messages) ? data.validation_messages.join(' | ') : '';
    const messages = Array.isArray(data.messages) ? data.messages.join(' | ') : '';
    const errors = Array.isArray(data.errors) ? data.errors.map((item) => getUpstreamMessage(item)).filter(Boolean).join(' | ') : '';
    return String(
      data.status_message ||
      data.statusMessage ||
      data.message ||
      data.error ||
      data.error_description ||
      data.detail ||
      data.hint ||
      data.title ||
      validation ||
      messages ||
      errors ||
      ''
    ).slice(0, 220);
  }
  return '';
}

async function supabaseFetch(path, options = {}) {
  const supabaseUrl = requiredEnv('DOMAIN_SUPABASE_URL').replace(/\/$/, '');
  const anonKey = requiredEnv('DOMAIN_SUPABASE_ANON_KEY');
  const serviceKey = requiredEnv('DOMAIN_SUPABASE_SERVICE_ROLE_KEY');

  const key = options.auth === 'service' ? serviceKey : anonKey;
  const bearer = options.bearer || key;

  const headers = {
    apikey: key,
    Authorization: `Bearer ${bearer}`,
    'Content-Type': 'application/json'
  };

  if (options.prefer) headers.Prefer = options.prefer;

  const fetchOptions = {
    method: options.method || 'GET',
    headers
  };

  if (options.body !== undefined) {
    fetchOptions.body = JSON.stringify(options.body);
  }

  const response = await fetch(`${supabaseUrl}${path}`, fetchOptions);
  const text = await response.text();

  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {
    data = text;
  }

  return {
    ok: response.ok,
    status: response.status,
    data
  };
}


function hasValidDomainSessionTokens(session) {
  const data = session && typeof session === 'object' ? session : {};
  return Boolean(
    data.access_token &&
    typeof data.access_token === 'string' &&
    data.access_token.length > 20 &&
    data.refresh_token &&
    typeof data.refresh_token === 'string' &&
    data.refresh_token.length > 10
  );
}

function buildDomainAuthSessionPayload(session) {
  const data = session && typeof session === 'object' ? session : {};
  if (!data.access_token) return null;

  if (shouldHideDomainAuthTokens()) {
    return {
      expires_in: data.expires_in || null,
      backend_only: true
    };
  }

  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in
  };
}

function shouldHideDomainAuthTokens() {
  // PATCH 3A: customer auth wajib backend-only.
  // Access/refresh token Supabase tidak boleh dikirim ke JavaScript/frontend.
  return true;
}

function shouldAcceptFrontendAuthHeaders() {
  // PATCH 3A: jangan percaya Authorization, X-Domain-Refresh, atau MFA proof dari frontend.
  // Sumber otoritas customer hanya HttpOnly Secure cookie + validasi backend.
  return false;
}

function allowPublicHealthDetails(req) {
  if (process.env.AI_PUBLIC_HEALTH_DETAILS !== 'true') return false;
  // Di production, detail provider hanya boleh admin. Ini mencegah bocor informasi kecil dari public health.
  if (process.env.NODE_ENV === 'production' && !isAdminRequest(req)) return false;
  return true;
}

function isEnvTrue(name) {
  return String(process.env[name] || '').trim().toLowerCase() === 'true';
}

function normalizeAuthEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidAuthEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

function normalizePhone(value) {
  return String(value || '').trim().replace(/[^+\d]/g, '');
}

async function readLimitedJsonBody(req, limitBytes = LOGIN_SECURITY_BODY_LIMIT_BYTES) {
  const limit = Math.max(1024, Number(limitBytes || LOGIN_SECURITY_BODY_LIMIT_BYTES || 16 * 1024));

  if (req.body && typeof req.body === 'object') {
    const approxBytes = Buffer.byteLength(JSON.stringify(req.body), 'utf8');
    if (approxBytes > limit) {
      const err = new Error('LOGIN_BODY_TOO_LARGE');
      err.statusCode = 413;
      err.code = 'LOGIN_BODY_TOO_LARGE';
      err.publicMessage = 'Request terlalu besar. Silakan ulangi dengan input yang lebih ringkas.';
      throw err;
    }
    return req.body;
  }

  if (typeof req.body === 'string') {
    if (Buffer.byteLength(req.body, 'utf8') > limit) {
      const err = new Error('LOGIN_BODY_TOO_LARGE');
      err.statusCode = 413;
      err.code = 'LOGIN_BODY_TOO_LARGE';
      err.publicMessage = 'Request terlalu besar. Silakan ulangi dengan input yang lebih ringkas.';
      throw err;
    }
    try {
      return JSON.parse(req.body || '{}');
    } catch (_) {
      const err = new Error('LOGIN_BODY_INVALID_JSON');
      err.statusCode = 400;
      err.code = 'LOGIN_BODY_INVALID_JSON';
      err.publicMessage = 'Request login tidak valid.';
      throw err;
    }
  }

  return await new Promise((resolve, reject) => {
    let raw = '';
    let rejected = false;

    req.on('data', (chunk) => {
      if (rejected) return;
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > limit) {
        rejected = true;
        const err = new Error('LOGIN_BODY_TOO_LARGE');
        err.statusCode = 413;
        err.code = 'LOGIN_BODY_TOO_LARGE';
        err.publicMessage = 'Request terlalu besar. Silakan ulangi dengan input yang lebih ringkas.';
        reject(err);
        if (typeof req.destroy === 'function') req.destroy();
      }
    });

    req.on('end', () => {
      if (rejected) return;
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (_) {
        const err = new Error('LOGIN_BODY_INVALID_JSON');
        err.statusCode = 400;
        err.code = 'LOGIN_BODY_INVALID_JSON';
        err.publicMessage = 'Request login tidak valid.';
        reject(err);
      }
    });
    req.on('error', () => {
      if (rejected) return;
      const err = new Error('LOGIN_BODY_READ_FAILED');
      err.statusCode = 400;
      err.code = 'LOGIN_BODY_READ_FAILED';
      err.publicMessage = 'Request login tidak valid.';
      reject(err);
    });
  });
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;

  if (typeof req.body === 'string') {
    try {
      return JSON.parse(req.body);
    } catch (_) {
      return {};
    }
  }

  return await new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (_) {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

function parseCookies(req) {
  const header = req.headers && req.headers.cookie ? req.headers.cookie : '';
  const cookies = {};

  Object.defineProperty(cookies, '__all', {
    value: {},
    enumerable: false,
    configurable: false,
    writable: true
  });

  header.split(';').map((item) => item.trim()).filter(Boolean).forEach((item) => {
    const index = item.indexOf('=');
    if (index === -1) {
      if (!cookies.__all[item]) cookies.__all[item] = [];
      cookies.__all[item].push('');
      cookies[item] = '';
      return;
    }

    const key = item.slice(0, index);
    let value = item.slice(index + 1);
    try {
      value = decodeURIComponent(value);
    } catch (_) {
      value = String(value || '');
    }

    if (!cookies.__all[key]) cookies.__all[key] = [];
    cookies.__all[key].push(value);

    // Tetap simpan bentuk lama untuk kompatibilitas fungsi lain.
    // Kalau browser mengirim cookie dobel dari host/domain berbeda, nilai terakhir tetap legacy,
    // sedangkan requireDomainUser akan mencoba semua kandidat lewat __all.
    cookies[key] = value;
  });

  return cookies;
}

function normalizeCookieSameSite(value) {
  const clean = String(value || 'Lax').trim().toLowerCase();
  if (clean === 'strict') return 'Strict';
  if (clean === 'none') return 'None';
  return 'Lax';
}

function normalizeCookieDomain(value) {
  const clean = String(value || '').trim().toLowerCase().replace(/^\./, '');
  if (!clean || /^(none|false|off|host-only|host_only)$/i.test(clean)) return '';
  if (/^localhost$|^127\.|^0\.0\.0\.0$/.test(clean)) return '';
  return clean;
}

function getDomainCookieDomainCandidates() {
  const candidates = [];
  const add = (value) => {
    const domain = normalizeCookieDomain(value);
    if (domain && !candidates.includes(domain)) candidates.push(domain);
  };

  add(process.env.DOMAIN_COOKIE_DOMAIN);
  add(process.env.DOMAIN_SITE_URL ? (() => { try { return new URL(process.env.DOMAIN_SITE_URL).hostname; } catch (_) { return ''; } })() : '');
  add(process.env.SITE_URL ? (() => { try { return new URL(process.env.SITE_URL).hostname; } catch (_) { return ''; } })() : '');
  add('diracgroup.store');

  return candidates;
}

function appendSetCookie(res, cookies) {
  const nextCookies = (Array.isArray(cookies) ? cookies : [cookies]).filter(Boolean);
  if (!nextCookies.length) return;

  const current = typeof res.getHeader === 'function' ? res.getHeader('Set-Cookie') : null;
  const previousCookies = Array.isArray(current)
    ? current
    : current
      ? [String(current)]
      : [];

  res.setHeader('Set-Cookie', previousCookies.concat(nextCookies));
}

function makeCookie(name, value, options = {}) {
  // Produksi paling aman: token customer hanya lewat backend-only cookie.
  // Default None agar cookie tetap dikirim saat frontend dan API beda origin
  // (misal diracgroup.store -> *.vercel.app). Untuk dev HTTP lokal, set env DOMAIN_COOKIE_SAMESITE=Lax.
  const sameSite = normalizeCookieSameSite(process.env.DOMAIN_COOKIE_SAMESITE || 'None');
  const secureCookie = sameSite === 'None' || process.env.NODE_ENV !== 'development' || isEnvTrue('DOMAIN_COOKIE_FORCE_SECURE');
  const parts = [
    `${name}=${encodeURIComponent(value || '')}`,
    'Path=/',
    'HttpOnly'
  ];

  if (secureCookie) parts.push('Secure');
  const cookieDomain = Object.prototype.hasOwnProperty.call(options, 'domain')
    ? normalizeCookieDomain(options.domain)
    : normalizeCookieDomain(process.env.DOMAIN_COOKIE_DOMAIN || '');
  if (cookieDomain) parts.push(`Domain=${cookieDomain}`);
  parts.push(`SameSite=${sameSite}`);
  parts.push('Priority=High');

  if (options.maxAge !== undefined) {
    const maxAge = Math.floor(Number(options.maxAge));
    parts.push(`Max-Age=${Number.isFinite(maxAge) ? maxAge : 0}`);
    if (Number.isFinite(maxAge) && maxAge <= 0) {
      parts.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    }
  }

  return parts.join('; ');
}

const DOMAIN_COOKIE_CHUNK_SIZE = 3400;
const DOMAIN_COOKIE_MAX_CHUNKS = 12;

function getCompactCookieDomainsForSession() {
  const domains = [];
  const add = (value) => {
    const domain = normalizeCookieDomain(value);
    const key = domain || '__host_only__';
    if (domains.some((item) => (item || '__host_only__') === key)) return;
    domains.push(domain);
  };

  // Host-only harus utama agar diracgroup.store langsung membaca cookie hasil login/register.
  add('');
  add(process.env.DOMAIN_COOKIE_DOMAIN);
  add('diracgroup.store');
  return domains;
}

function makeCompactClearCookie(name) {
  return getCompactCookieDomainsForSession().map((domain) => makeCookie(name, '', { maxAge: 0, domain }));
}

function makeCompactClearTokenCookieChunks(name) {
  const cookies = [];
  getCompactCookieDomainsForSession().forEach((domain) => {
    for (let index = 0; index < DOMAIN_COOKIE_MAX_CHUNKS; index += 1) {
      cookies.push(makeCookie(`${name}__${index}`, '', { maxAge: 0, domain }));
    }
  });
  return cookies;
}

function makeTokenCookieSet(name, value, options = {}) {
  const token = String(value || '');
  const cookies = [];

  if (!token) return cookies;

  // FIX: jangan kirim puluhan Set-Cookie clear saat login.
  // Sebelumnya login mengirim clear cookie untuk host-only + domain + semua chunk,
  // lalu baru mengirim cookie sesi baru. Di mobile Safari / edge proxy / Vercel,
  // header Set-Cookie yang terlalu banyak bisa membuat cookie sesi baru tidak tersimpan.
  // Clear besar tetap dilakukan hanya di logout melalui makeClearTokenCookieSet().
  if (token.length <= DOMAIN_COOKIE_CHUNK_SIZE) {
    cookies.push(makeCookie(name, token, Object.assign({}, options, { domain: '' })));
    return cookies;
  }

  const chunks = [];
  for (let index = 0; index < token.length; index += DOMAIN_COOKIE_CHUNK_SIZE) {
    chunks.push(token.slice(index, index + DOMAIN_COOKIE_CHUNK_SIZE));
  }

  if (chunks.length > DOMAIN_COOKIE_MAX_CHUNKS) {
    return cookies;
  }

  cookies.push(makeCookie(name, `__chunked_${chunks.length}`, Object.assign({}, options, { domain: '' })));
  chunks.forEach((chunk, index) => {
    cookies.push(makeCookie(`${name}__${index}`, chunk, Object.assign({}, options, { domain: '' })));
  });
  return cookies;
}

function makeClearTokenCookieChunks(name) {
  return makeCompactClearTokenCookieChunks(name);
}

function makeClearTokenCookieSet(name) {
  return [
    ...makeCompactClearCookie(name),
    ...makeCompactClearTokenCookieChunks(name)
  ];
}

function uniqueNonEmptyStrings(values) {
  const seen = new Set();
  const output = [];
  (Array.isArray(values) ? values : [values]).forEach((value) => {
    const clean = String(value || '').trim();
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    output.push(clean);
  });
  return output;
}

function getCookieAllValues(cookies, name) {
  const jar = cookies && typeof cookies === 'object' ? cookies : {};
  const all = jar.__all && typeof jar.__all === 'object' && Array.isArray(jar.__all[name])
    ? jar.__all[name]
    : [];
  const values = all.length ? all.slice() : [jar[name]];
  return uniqueNonEmptyStrings(values).reverse();
}

function readCookieTokenFromMarker(cookies, name, markerValue) {
  const jar = cookies && typeof cookies === 'object' ? cookies : {};
  const marker = String(markerValue || '');
  const chunkMatch = marker.match(/^__chunked_(\d+)$/);
  if (chunkMatch) {
    const count = Math.max(0, Math.min(DOMAIN_COOKIE_MAX_CHUNKS, Number(chunkMatch[1]) || 0));
    let token = '';
    for (let index = 0; index < count; index += 1) {
      const chunk = jar[`${name}__${index}`];
      if (!chunk) return '';
      token += String(chunk);
    }
    return token;
  }

  if (marker) return marker;

  // Recovery untuk browser/proxy yang menghilangkan marker utama tapi masih mengirim chunks.
  if (jar[`${name}__0`]) {
    let token = '';
    for (let index = 0; index < DOMAIN_COOKIE_MAX_CHUNKS; index += 1) {
      const chunk = jar[`${name}__${index}`];
      if (!chunk) break;
      token += String(chunk);
    }
    return token;
  }

  return '';
}

function readCookieTokenCandidates(cookies, name) {
  const markers = getCookieAllValues(cookies, name);
  const candidates = markers.map((marker) => readCookieTokenFromMarker(cookies, name, marker));
  candidates.push(readCookieTokenFromMarker(cookies, name, cookies && cookies[name]));
  return uniqueNonEmptyStrings(candidates);
}

function readCookieToken(cookies, name) {
  return readCookieTokenCandidates(cookies, name)[0] || '';
}

function makeCookieVariants(name, value, options = {}) {
  const cookies = [];
  const usedDomains = new Set();
  const addCookie = (domain) => {
    const normalized = normalizeCookieDomain(domain || '');
    const key = normalized || '__host_only__';
    if (usedDomains.has(key)) return;
    usedDomains.add(key);
    cookies.push(makeCookie(name, value, Object.assign({}, options, { domain: normalized })));
  };

  // Canonical utama selalu host-only agar login/register di apex diracgroup.store langsung terbaca
  // walaupun ENV DOMAIN_COOKIE_DOMAIN lama pernah terisi subdomain/wrong domain.
  addCookie('');
  addCookie(process.env.DOMAIN_COOKIE_DOMAIN);

  // Compatibility cookie domain untuk membersihkan/menyamakan sisa cookie lama dari host/domain lain.
  getDomainCookieDomainCandidates().forEach((domain) => addCookie(domain));

  return cookies;
}

function makeClearCookieVariants(name) {
  return makeCookieVariants(name, '', { maxAge: 0 });
}

function setSessionCookies(res, session) {
  if (!hasValidDomainSessionTokens(session)) {
    clearSessionCookies(res);
    return false;
  }

  const maxAge = 60 * 60 * 24 * 7;
  appendSetCookie(res, [
    ...makeTokenCookieSet(ACCESS_COOKIE, session.access_token, { maxAge }),
    ...makeTokenCookieSet(REFRESH_COOKIE, session.refresh_token, { maxAge }),
    ...makeSignedDomainSessionCookieSet(session, { maxAge })
  ]);
  return true;
}

function clearSessionCookies(res) {
  appendSetCookie(res, [
    ...makeClearTokenCookieSet(ACCESS_COOKIE),
    ...makeClearTokenCookieSet(REFRESH_COOKIE),
    ...makeClearTokenCookieSet(CUSTOMER_MFA_COOKIE),
    ...makeClearTokenCookieSet(DOMAIN_SIGNED_SESSION_COOKIE)
  ]);
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function parseBase64UrlJson(value) {
  try {
    return JSON.parse(Buffer.from(String(value || ''), 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

function decodeJwtPayloadUnsafe(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;
  return parseBase64UrlJson(parts[1]);
}

function getDomainSignedSessionSecret() {
  return String(
    process.env.DOMAIN_SESSION_SIGNING_SECRET ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_JWT_SECRET ||
    process.env.AI_ADMIN_SECRET ||
    process.env.NEXTAUTH_SECRET ||
    ''
  ).trim();
}

function extractUserForSignedDomainSession(session) {
  const sessionObj = session && typeof session === 'object' ? session : {};
  const user = sessionObj.user && typeof sessionObj.user === 'object' ? sessionObj.user : {};
  const jwt = decodeJwtPayloadUnsafe(sessionObj.access_token);
  const id = String(user.id || user.sub || (jwt && (jwt.sub || jwt.user_id)) || '').trim();
  const email = normalizeAuthEmail(user.email || (jwt && jwt.email) || '');
  if (!id || !email) return null;
  return { id, email };
}

function signDomainSessionPayload(payload) {
  const secret = getDomainSignedSessionSecret();
  if (!secret) return '';
  const body = base64UrlJson(payload);
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyDomainSessionCookieValue(value) {
  const secret = getDomainSignedSessionSecret();
  if (!secret) return null;
  const raw = String(value || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (!safeEqual(sig, expected)) return null;
  const payload = parseBase64UrlJson(body);
  if (!payload || payload.typ !== DOMAIN_SIGNED_SESSION_TYPE) return null;
  const exp = Number(payload.exp || 0);
  if (!Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) return null;
  const id = String(payload.uid || payload.id || '').trim();
  const email = normalizeAuthEmail(payload.email || '');
  if (!id || !email) return null;
  return { id, email, exp };
}

function makeSignedDomainSessionCookieSet(session, options = {}) {
  const user = extractUserForSignedDomainSession(session);
  const maxAge = Math.max(60, Math.floor(Number(options.maxAge || 60 * 60 * 24 * 7)));
  const cookies = [];
  if (!user) return cookies;

  const now = Math.floor(Date.now() / 1000);
  const value = signDomainSessionPayload({
    typ: DOMAIN_SIGNED_SESSION_TYPE,
    uid: user.id,
    email: user.email,
    iat: now,
    exp: now + maxAge,
    nonce: crypto.randomBytes(12).toString('base64url')
  });
  if (!value) return cookies;

  cookies.push(makeCookie(DOMAIN_SIGNED_SESSION_COOKIE, value, { maxAge, domain: '' }));
  return cookies;
}

async function readSignedDomainSessionUser(cookies) {
  const values = readCookieTokenCandidates(cookies, DOMAIN_SIGNED_SESSION_COOKIE);
  for (const value of values) {
    const payload = verifyDomainSessionCookieValue(value);
    if (!payload) continue;

    const checked = await getSupabaseAuthUserByEmail(payload.email);
    if (checked && checked.user) {
      const user = normalizeSupabaseAdminUser(checked.user);
      if (user && String(user.id || '') === payload.id) {
        return user;
      }
    }
  }
  return null;
}

function normalizeDomain(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '')
    .replace(/\s+/g, '');
}

function getExtension(domain, extensions) {
  const sorted = [...extensions].sort((a, b) => b.length - a.length);

  for (const ext of sorted) {
    if (domain.endsWith(ext)) return ext;
  }

  return null;
}

function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email
  };
}

function getBearerToken(req) {
  const auth = String((req.headers && req.headers.authorization) || '').trim();
  if (!auth) return '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} belum diisi di Environment Variables Vercel.`);
  }
  return value;
}

/* ============================================================
   CUSTOMER SECURITY STATUS TAMBAHAN - ISOLATED APPEND ONLY
   Tidak mengubah router/fungsi lama. Tidak membuat file API baru.
   Endpoint baru tetap memakai file health lama:
   GET /api/health?action=customer_security_status
   GET /api/health?action=customer-security-status
   ============================================================ */

const __diracOriginalHealthHandler = module.exports;

module.exports = async function customerSecurityHealthWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = customerSecurityNormalizeAction(rawAction);

  if (customerSecurityIsStatusAction(action)) {
    const cors = setCors(req, res, { isDomainAction: true });
    if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
    if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });
    return customerSecurityStatus(req, res);
  }

  return __diracOriginalHealthHandler(req, res);
};

function customerSecurityNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  if (clean === 'customer-security-status') return 'customer_security_status';
  if (clean === 'customer_security_status') return 'customer_security_status';
  return clean;
}

function customerSecurityIsStatusAction(action) {
  return action === 'customer_security_status';
}

async function customerSecurityStatus(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
  }

  try {
    const access = await requireDomainDashboardAccess(req, res);
    if (!access) return;
    const user = access.user;

    const authUserId = String(user.id || '').trim();
    if (!authUserId) {
      return res.status(401).json({ ok: false, message: 'Sesi tidak valid.' });
    }

    const linkResult = await customerSecurityFetchAuthLink(authUserId);
    if (!linkResult.ok) {
      if (customerSecurityIsSchemaCacheMissing(linkResult)) {
        return res.status(200).json(customerSecuritySchemaPendingStatus(user, 'customer_security_status'));
      }

      return res.status(linkResult.status || 500).json({
        ok: false,
        message: 'Gagal membaca status keamanan akun.',
        source: 'customer_security_status',
        error: customerSecuritySafeUpstreamError(linkResult.data)
      });
    }

    const link = Array.isArray(linkResult.data) && linkResult.data.length ? linkResult.data[0] : null;
    const linked = Boolean(link && link.link_status === 'active' && link.customer_id);

    return res.status(200).json({
      ok: true,
      service: 'dirac-customer-security',
      mode: 'service_role_backend_only',
      user: sanitizeUser(user),
      linked,
      link_status: link ? String(link.link_status || 'pending') : 'not_linked',
      customer_id_available: Boolean(link && link.customer_id),
      security_data_ready: false,
      policy_ready: false,
      direct_frontend_table_access: false,
      message: linked
        ? 'Akun sudah terhubung. Data keamanan dapat dibaca melalui backend service_role-only.'
        : 'Akun belum terhubung ke customer profile. Data keamanan belum dibuat.',
      next_allowed_phase: 'backend_api_service_role_only',
      time: diracNowIso()
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: 'Terjadi kesalahan pada customer security status.',
      source: 'customer_security_status',
      error: String(error && error.message ? error.message : error)
    });
  }
}

async function customerSecurityFetchAuthLink(authUserId) {
  const select = [
    'id',
    'auth_user_id',
    'customer_id',
    'link_status',
    'match_confidence'
  ].join(',');

  const path = `/rest/v1/security_customer_auth_links?select=${encodeURIComponent(select)}&auth_user_id=eq.${encodeURIComponent(authUserId)}&limit=1`;

  return supabaseFetch(path, {
    method: 'GET',
    auth: 'service'
  });
}

function customerSecuritySafeUpstreamError(data) {
  if (!data) return null;
  if (typeof data === 'string') return data.slice(0, 180);
  return String(data.message || data.error || data.detail || 'upstream_error').slice(0, 180);
}

function customerSecurityIsSchemaCacheMissing(result) {
  if (!result || Number(result.status) !== 404) return false;
  const data = result.data;
  const text = typeof data === 'string'
    ? data
    : String((data && (data.message || data.error || data.detail || data.hint || data.code)) || '');
  return /schema cache|could not find the table|PGRST205|PGRST202/i.test(text);
}

function customerSecuritySchemaPendingStatus(user, endpoint) {
  return {
    ok: true,
    service: 'dirac-customer-security',
    endpoint: endpoint || 'customer_security_status',
    mode: 'service_role_backend_only',
    user: sanitizeUser(user),
    linked: false,
    link_status: 'schema_pending',
    customer_id_available: false,
    security_data_ready: false,
    storage_ready: false,
    policy_ready: false,
    direct_frontend_table_access: false,
    message: 'Backend login valid, tetapi Supabase REST belum mengenali tabel security_customer. Fitur dikunci aman sampai schema REST siap.',
    next_allowed_phase: 'fix_supabase_rest_schema_cache_or_service_role_visibility',
    time: diracNowIso()
  };
}


/* ============================================================
   CUSTOMER SECURITY OVERVIEW TAMBAHAN - ISOLATED APPEND ONLY
   Tidak mengubah router/fungsi lama. Tidak membuat file API baru.
   Endpoint baru tetap memakai file health lama:
   GET /api/health?action=customer_security_overview
   GET /api/health?action=customer-security-overview
   GET /api/health?action=customer_security_dashboard
   ============================================================ */

const __diracCustomerSecurityWrapperV2PreviousHandler = module.exports;

module.exports = async function customerSecurityOverviewWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = customerSecurityOverviewNormalizeAction(rawAction);

  if (customerSecurityOverviewIsAction(action)) {
    const cors = setCors(req, res, { isDomainAction: true });
    if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
    if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });
    return customerSecurityOverview(req, res);
  }

  return __diracCustomerSecurityWrapperV2PreviousHandler(req, res);
};

function customerSecurityOverviewNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  if (clean === 'customer-security-overview') return 'customer_security_overview';
  if (clean === 'customer_security_overview') return 'customer_security_overview';
  if (clean === 'customer-security-dashboard') return 'customer_security_overview';
  if (clean === 'customer_security_dashboard') return 'customer_security_overview';
  if (clean === 'customer-security-summary') return 'customer_security_overview';
  if (clean === 'customer_security_summary') return 'customer_security_overview';
  return clean;
}

function customerSecurityOverviewIsAction(action) {
  return action === 'customer_security_overview';
}

async function customerSecurityOverview(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
  }

  try {
    const access = await requireDomainDashboardAccess(req, res);
    if (!access) return;
    const user = access.user;

    const authUserId = String(user.id || '').trim();
    if (!authUserId) {
      return res.status(401).json({ ok: false, message: 'Sesi tidak valid.' });
    }

    const linkResult = await customerSecurityFetchAuthLink(authUserId);
    if (!linkResult.ok) {
      if (customerSecurityIsSchemaCacheMissing(linkResult)) {
        return res.status(200).json({
          ...customerSecuritySchemaPendingStatus(user, 'customer_security_overview'),
          overview: customerSecurityEmptyOverview()
        });
      }

      return res.status(linkResult.status || 500).json({
        ok: false,
        message: 'Gagal membaca status penghubung akun.',
        source: 'customer_security_overview',
        error: customerSecuritySafeUpstreamError(linkResult.data)
      });
    }

    const link = Array.isArray(linkResult.data) && linkResult.data.length ? linkResult.data[0] : null;
    const linked = Boolean(link && link.link_status === 'active' && link.customer_id);

    if (!linked) {
      return res.status(200).json({
        ok: true,
        service: 'dirac-customer-security',
        endpoint: 'customer_security_overview',
        mode: 'backend_only',
        user: sanitizeUser(user),
        linked: false,
        link_status: link ? String(link.link_status || 'pending') : 'not_linked',
        customer_id_available: false,
        direct_frontend_table_access: false,
        policy_ready: false,
        security_data_ready: false,
        overview: customerSecurityEmptyOverview(),
        message: 'Akun belum terhubung ke customer profile. Data keamanan belum dibuat.',
        time: diracNowIso()
      });
    }

    const customerId = String(link.customer_id || '').trim();

    // Production-safe sync:
    // - MFA status in security_customer_settings is mandatory true for all linked customers.
    // - Current browser/device is registered in security_customer_sessions.
    // These operations are backend service_role-only and do not touch legacy login/hash/A2F.
    await customerSecurityEnsureSettingsRow(customerId);
    await customerSecurityTouchCurrentSession(req, customerId);

    const overviewResult = await customerSecurityFetchOverviewData(customerId);
    if (!overviewResult.ok) {
      return res.status(overviewResult.status || 500).json({
        ok: false,
        message: 'Gagal membaca overview keamanan akun.',
        source: 'customer_security_overview',
        section: overviewResult.section || 'unknown',
        error: customerSecuritySafeUpstreamError(overviewResult.data)
      });
    }

    return res.status(200).json({
      ok: true,
      service: 'dirac-customer-security',
      endpoint: 'customer_security_overview',
      mode: 'backend_only',
      user: sanitizeUser(user),
      linked: true,
      link_status: String(link.link_status || 'active'),
      customer_id_available: true,
      direct_frontend_table_access: false,
      policy_ready: false,
      security_data_ready: true,
      overview: overviewResult.data,
      message: 'Overview keamanan akun berhasil dibaca melalui backend.',
      time: diracNowIso()
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: 'Terjadi kesalahan pada customer security overview.',
      source: 'customer_security_overview',
      error: String(error && error.message ? error.message : error)
    });
  }
}

function customerSecurityEmptyOverview() {
  return {
    settings: null,
    sessions: [],
    login_logs: [],
    events: [],
    account_requests: [],
    counts: {
      sessions: 0,
      login_logs: 0,
      events: 0,
      account_requests: 0
    }
  };
}

async function customerSecurityFetchOverviewData(customerId) {
  const empty = customerSecurityEmptyOverview();
  const warnings = [];

  function rowsOrEmpty(result, section) {
    if (!result || !result.ok) {
      warnings.push({
        section,
        status: result && result.status ? result.status : 500,
        error: customerSecuritySafeUpstreamError(result && result.data)
      });
      return [];
    }
    return Array.isArray(result.data) ? result.data : [];
  }

  const settingsResult = await customerSecurityFetchRows(
    'security_customer_settings',
    [
      'email_active',
      'two_factor_enabled',
      'two_factor_method',
      'notify_new_login',
      'notify_password_change',
      'notify_new_device',
      'password_changed_at',
      'last_security_check_at',
      'account_locked',
      'locked_until',
      'updated_at'
    ],
    customerId,
    'updated_at.desc',
    1
  ).catch((error) => ({ ok: false, status: 500, data: { message: String(error && error.message ? error.message : error) } }));

  const sessionsResult = await customerSecurityFetchRows(
    'security_customer_sessions',
    [
      'id',
      'device_id',
      'device_name',
      'browser_name',
      'operating_system',
      'country',
      'city',
      'status',
      'trusted_device',
      'created_at',
      'last_seen_at',
      'expires_at',
      'revoked_at',
      'revoke_reason'
    ],
    customerId,
    'last_seen_at.desc',
    10
  ).catch((error) => ({ ok: false, status: 500, data: { message: String(error && error.message ? error.message : error) } }));

  const loginLogsResult = await customerSecurityFetchRows(
    'security_customer_login_logs',
    [
      'id',
      'event_type',
      'status',
      'failure_reason',
      'risk_level',
      'device_name',
      'browser_name',
      'operating_system',
      'country',
      'city',
      'created_at'
    ],
    customerId,
    'created_at.desc',
    10
  ).catch((error) => ({ ok: false, status: 500, data: { message: String(error && error.message ? error.message : error) } }));

  const eventsResult = await customerSecurityFetchRows(
    'security_customer_events',
    [
      'id',
      'event_type',
      'status',
      'risk_level',
      'description',
      'created_at'
    ],
    customerId,
    'created_at.desc',
    20
  ).catch((error) => ({ ok: false, status: 500, data: { message: String(error && error.message ? error.message : error) } }));

  const requestsResult = await customerSecurityFetchRows(
    'security_customer_account_requests',
    [
      'id',
      'request_type',
      'status',
      'reason',
      'created_at',
      'updated_at',
      'completed_at',
      'expires_at'
    ],
    customerId,
    'created_at.desc',
    10
  ).catch((error) => ({ ok: false, status: 500, data: { message: String(error && error.message ? error.message : error) } }));

  const settingsRows = rowsOrEmpty(settingsResult, 'settings');
  const sessions = rowsOrEmpty(sessionsResult, 'sessions');
  const loginLogs = rowsOrEmpty(loginLogsResult, 'login_logs');
  const events = rowsOrEmpty(eventsResult, 'events');
  const accountRequests = rowsOrEmpty(requestsResult, 'account_requests');

  return {
    ok: true,
    data: {
      settings: settingsRows.length ? settingsRows[0] : empty.settings,
      sessions,
      login_logs: loginLogs,
      events,
      account_requests: accountRequests,
      counts: {
        sessions: sessions.length,
        login_logs: loginLogs.length,
        events: events.length,
        account_requests: accountRequests.length
      },
      partial: warnings.length > 0,
      warnings
    }
  };
}

async function customerSecurityFetchRows(tableName, columns, customerId, orderBy, limit) {
  const safeTable = String(tableName || '').trim();
  const select = columns.join(',');
  const path = `/rest/v1/${encodeURIComponent(safeTable)}?select=${encodeURIComponent(select)}&customer_id=eq.${encodeURIComponent(customerId)}&order=${encodeURIComponent(orderBy)}&limit=${encodeURIComponent(String(limit))}`;

  return supabaseFetch(path, {
    method: 'GET',
    auth: 'service'
  });
}


/* ============================================================
   CUSTOMER SECURITY REGISTER BOOTSTRAP TAMBAHAN - ISOLATED APPEND ONLY
   SUMBER PATCH: /mnt/data/health.js FILE SATUAN, BUKAN health (7).js DARI ZIP.
   Tujuan:
   - Tidak mengubah domainRegister() lama.
   - Tidak mengubah domainLogin(), hash, A2F/MFA, passkey, lock, admin/staff.
   - Hanya membungkus response register sukses untuk bootstrap customer security.
   - Semua akses database tetap backend service_role-only.
   ============================================================ */

const __diracCustomerSecurityRegisterBootstrapPreviousHandler = module.exports;

module.exports = async function customerSecurityRegisterBootstrapWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = customerSecurityRegisterBootstrapNormalizeAction(rawAction);

  if (!customerSecurityRegisterBootstrapIsRegisterAction(action) || req.method !== 'POST') {
    return __diracCustomerSecurityRegisterBootstrapPreviousHandler(req, res);
  }

  return customerSecurityBootstrapWrapRegisterResponse(req, res, function runPreviousHandler() {
    return __diracCustomerSecurityRegisterBootstrapPreviousHandler(req, res);
  });
};

function customerSecurityRegisterBootstrapNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  if (clean === 'domain-register') return 'domain_register';
  if (clean === 'domain_register') return 'domain_register';
  if (clean === 'register-domain') return 'domain_register';
  return clean;
}

function customerSecurityRegisterBootstrapIsRegisterAction(action) {
  return action === 'domain_register';
}

async function customerSecurityBootstrapWrapRegisterResponse(req, res, runPreviousHandler) {
  const originalStatus = typeof res.status === 'function' ? res.status.bind(res) : null;
  const originalJson = typeof res.json === 'function' ? res.json.bind(res) : null;
  let capturedStatus = Number(res.statusCode || 200);

  if (!originalJson) {
    return runPreviousHandler();
  }

  res.status = function patchedCustomerSecurityStatus(code) {
    capturedStatus = Number(code || capturedStatus || 200);
    if (originalStatus) return originalStatus(code);
    res.statusCode = capturedStatus;
    return res;
  };

  res.json = async function patchedCustomerSecurityRegisterJson(payload) {
    let finalPayload = payload;
    const httpStatus = Number(capturedStatus || res.statusCode || 200);

    if (httpStatus >= 200 && httpStatus < 300 && payload && payload.ok === true && payload.user && payload.user.id) {
      const bootstrap = await customerSecurityBootstrapRegisteredUser(req, payload.user);
      finalPayload = customerSecurityAttachBootstrapSummary(payload, bootstrap);
    }

    return originalJson(finalPayload);
  };

  return runPreviousHandler();
}

function customerSecurityAttachBootstrapSummary(payload, bootstrap) {
  const safe = bootstrap && bootstrap.ok ? bootstrap : null;
  return {
    ...payload,
    customer_security: {
      mode: 'backend_service_role_only',
      direct_frontend_table_access: false,
      profile_ready: Boolean(safe && safe.customer_id),
      link_ready: Boolean(safe && safe.link_status === 'active' && safe.customer_id),
      settings_ready: Boolean(safe && safe.settings_ready),
      pending: !Boolean(safe && safe.customer_id && safe.link_status === 'active' && safe.settings_ready)
    }
  };
}

async function customerSecurityBootstrapRegisteredUser(req, responseUser) {
  try {
    const body = req && req.body && typeof req.body === 'object' ? req.body : {};
    const authUserId = String(responseUser && responseUser.id || '').trim();
    const email = normalizeAuthEmail((responseUser && responseUser.email) || body.email || body.identifier || body.customer_email);
    const fullName = customerSecuritySafeCustomerName(body.full_name || body.fullName || body.name || email);
    const phone = normalizePhone(body.whatsapp || body.phone || body.customer_whatsapp || '');

    if (!authUserId || !customerSecurityLooksLikeUuid(authUserId) || !email || !isValidAuthEmail(email)) {
      return { ok: false, reason: 'invalid_auth_user_or_email' };
    }

    const existingLinkResult = await customerSecurityFetchAuthLink(authUserId);
    if (!existingLinkResult.ok) return { ok: false, reason: 'auth_link_read_failed', status: existingLinkResult.status };

    const existingLink = Array.isArray(existingLinkResult.data) && existingLinkResult.data.length ? existingLinkResult.data[0] : null;
    if (existingLink && existingLink.link_status === 'active' && existingLink.customer_id) {
      const settingsReadyExisting = await customerSecurityEnsureSettingsRow(existingLink.customer_id);
      return {
        ok: Boolean(settingsReadyExisting.ok),
        customer_id: existingLink.customer_id,
        link_status: 'active',
        settings_ready: Boolean(settingsReadyExisting.ok)
      };
    }

    const customerResult = await customerSecurityFindOrCreateCustomer({ email, fullName, phone });
    if (!customerResult.ok || !customerResult.customer_id) return customerResult;

    const linkWriteResult = existingLink
      ? await customerSecurityActivateExistingAuthLink(authUserId, customerResult.customer_id, email)
      : await customerSecurityCreateAuthLink(authUserId, customerResult.customer_id, email);

    if (!linkWriteResult.ok) return { ok: false, reason: 'auth_link_write_failed', status: linkWriteResult.status };

    const settingsResult = await customerSecurityEnsureSettingsRow(customerResult.customer_id);

    return {
      ok: Boolean(settingsResult.ok),
      customer_id: customerResult.customer_id,
      link_status: 'active',
      settings_ready: Boolean(settingsResult.ok)
    };
  } catch (error) {
    console.error('[customer-security-bootstrap]', customerSecuritySafeLogError(error));
    return { ok: false, reason: 'bootstrap_exception' };
  }
}

function customerSecurityLooksLikeUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

function customerSecuritySafeCustomerName(value) {
  const raw = String(value || '').trim();
  const fromEmail = raw.includes('@') ? raw.split('@')[0] : raw;
  const cleaned = fromEmail.replace(/[^a-zA-Z0-9À-ž ._'-]/g, ' ').replace(/\s+/g, ' ').trim();
  return (cleaned || 'Customer DiracGroup').slice(0, 120);
}

async function customerSecurityFindOrCreateCustomer({ email, fullName, phone }) {
  const existing = await customerSecurityFetchCustomerByEmail(email);
  if (!existing.ok) return { ok: false, reason: 'customer_read_failed', status: existing.status };

  const rows = Array.isArray(existing.data) ? existing.data : [];
  if (rows.length && rows[0] && rows[0].id) {
    return { ok: true, customer_id: rows[0].id, created: false };
  }

  const body = {
    name: fullName || 'Customer DiracGroup',
    email
  };
  if (phone) body.phone = phone;

  const created = await supabaseFetch('/rest/v1/customers', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [body]
  });

  if (!created.ok) return { ok: false, reason: 'customer_create_failed', status: created.status };

  const createdRows = Array.isArray(created.data) ? created.data : [];
  const row = createdRows[0] || created.data;
  if (!row || !row.id) return { ok: false, reason: 'customer_create_no_id' };

  return { ok: true, customer_id: row.id, created: true };
}

async function customerSecurityFetchCustomerByEmail(email) {
  const select = ['id', 'email', 'name', 'phone'].join(',');
  const path = '/rest/v1/customers?select=' + encodeURIComponent(select) + '&email=eq.' + encodeURIComponent(email) + '&limit=1';
  return supabaseFetch(path, { method: 'GET', auth: 'service' });
}

async function customerSecurityActivateExistingAuthLink(authUserId, customerId, email) {
  const body = customerSecurityBuildActiveAuthLinkBody(customerId, email);
  const path = '/rest/v1/security_customer_auth_links?auth_user_id=eq.' + encodeURIComponent(authUserId);
  return supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body
  });
}

async function customerSecurityCreateAuthLink(authUserId, customerId, email) {
  const body = {
    auth_user_id: authUserId,
    ...customerSecurityBuildActiveAuthLinkBody(customerId, email)
  };
  return supabaseFetch('/rest/v1/security_customer_auth_links', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [body]
  });
}

function customerSecurityBuildActiveAuthLinkBody(customerId, email) {
  return {
    customer_id: customerId,
    email,
    link_status: 'active',
    link_method: 'system_created',
    match_confidence: 'active'
  };
}

async function customerSecurityEnsureSettingsRow(customerId) {
  const existing = await customerSecurityFetchRows(
    'security_customer_settings',
    ['id', 'customer_id', 'two_factor_enabled', 'two_factor_method'],
    customerId,
    'created_at.desc',
    1
  );

  if (!existing.ok) return { ok: false, reason: 'settings_read_failed', status: existing.status };

  const rows = Array.isArray(existing.data) ? existing.data : [];
  const mandatoryBody = {
    two_factor_enabled: true,
    two_factor_method: 'authenticator',
    last_security_check_at: new Date().toISOString()
  };

  if (rows.length && rows[0] && rows[0].id) {
    const currentMethod = String(rows[0].two_factor_method || '').trim().toLowerCase();
    const alreadyMandatory = rows[0].two_factor_enabled === true && currentMethod && currentMethod !== 'none';

    if (alreadyMandatory) return { ok: true, created: false, enforced: false };

    const patched = await supabaseFetch('/rest/v1/security_customer_settings?id=eq.' + encodeURIComponent(rows[0].id), {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: mandatoryBody
    });

    if (!patched.ok) return { ok: false, reason: 'settings_enforce_failed', status: patched.status };
    return { ok: true, created: false, enforced: true };
  }

  const created = await supabaseFetch('/rest/v1/security_customer_settings', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      customer_id: customerId,
      ...mandatoryBody
    }]
  });

  if (!created.ok) return { ok: false, reason: 'settings_create_failed', status: created.status };
  return { ok: true, created: true, enforced: true };
}

async function customerSecurityTouchCurrentSession(req, customerId) {
  try {
    const fingerprint = customerSecurityBuildSessionFingerprint(req, customerId);
    if (!fingerprint || !fingerprint.session_token_hash) return { ok: false, reason: 'missing_session_fingerprint' };

    const path = '/rest/v1/security_customer_sessions?select=id,status&customer_id=eq.' +
      encodeURIComponent(customerId) +
      '&session_token_hash=eq.' +
      encodeURIComponent(fingerprint.session_token_hash) +
      '&limit=1';

    const existing = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!existing.ok) return { ok: false, reason: 'session_read_failed', status: existing.status };

    const rows = Array.isArray(existing.data) ? existing.data : [];
    const now = new Date().toISOString();

    const updateBody = {
      device_id: fingerprint.device_id,
      device_name: fingerprint.device_name,
      browser_name: fingerprint.browser_name,
      operating_system: fingerprint.operating_system,
      user_agent: fingerprint.user_agent,
      ip_address: fingerprint.ip_address || null,
      status: 'active',
      last_seen_at: now,
      expires_at: fingerprint.expires_at
    };

    if (rows.length && rows[0] && rows[0].id) {
      const patched = await supabaseFetch('/rest/v1/security_customer_sessions?id=eq.' + encodeURIComponent(rows[0].id), {
        method: 'PATCH',
        auth: 'service',
        prefer: 'return=representation',
        body: updateBody
      });

      if (!patched.ok) return { ok: false, reason: 'session_update_failed', status: patched.status };
      return { ok: true, created: false, session_id: rows[0].id };
    }

    const created = await supabaseFetch('/rest/v1/security_customer_sessions', {
      method: 'POST',
      auth: 'service',
      prefer: 'return=representation',
      body: [{
        customer_id: customerId,
        session_token_hash: fingerprint.session_token_hash,
        trusted_device: false,
        metadata: {
          source: 'customer_security_overview',
          auto_detected: true
        },
        ...updateBody
      }]
    });

    if (!created.ok) return { ok: false, reason: 'session_create_failed', status: created.status };

    await customerSecurityWriteSessionTelemetry(customerId, fingerprint);

    const createdRows = Array.isArray(created.data) ? created.data : [];
    return { ok: true, created: true, session_id: createdRows[0] && createdRows[0].id ? createdRows[0].id : null };
  } catch (error) {
    console.error('[customer-security-session]', customerSecuritySafeLogError(error));
    return { ok: false, reason: 'session_exception' };
  }
}

function customerSecurityBuildSessionFingerprint(req, customerId) {
  const cookies = parseCookies(req);
  const headerToken = getBearerToken(req);
  const headerRefreshToken = String((req.headers && (req.headers['x-domain-refresh'] || req.headers['x-refresh-token'])) || '').trim();
  const tokenMaterial = uniqueNonEmptyStrings([
    headerToken,
    ...readCookieTokenCandidates(cookies, ACCESS_COOKIE),
    headerRefreshToken,
    ...readCookieTokenCandidates(cookies, REFRESH_COOKIE),
    ...readCookieTokenCandidates(cookies, DOMAIN_SIGNED_SESSION_COOKIE)
  ])[0] || '';

  const userAgent = String((req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
  const ip = customerSecurityRequestIp(req);
  const fallbackMaterial = [customerId, userAgent, ip].filter(Boolean).join('|');

  const sessionTokenHash = customerSecuritySha256(tokenMaterial || fallbackMaterial);
  const deviceId = customerSecuritySha256(['device', userAgent, ip].filter(Boolean).join('|')).slice(0, 48);

  return {
    session_token_hash: sessionTokenHash,
    device_id: deviceId,
    device_name: customerSecurityDeviceName(userAgent),
    browser_name: customerSecurityBrowserName(userAgent),
    operating_system: customerSecurityOperatingSystem(userAgent),
    user_agent: userAgent,
    ip_address: ip,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
  };
}

function customerSecuritySha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function customerSecurityRequestIp(req) {
  const forwarded = String((req.headers && (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.headers['cf-connecting-ip'])) || '').trim();
  const first = forwarded.split(',')[0].trim();
  if (!first) return null;
  if (/^[0-9a-f:.]+$/i.test(first)) return first.slice(0, 64);
  return null;
}

function customerSecurityDeviceName(userAgent) {
  const ua = String(userAgent || '');
  if (/iPhone/i.test(ua)) return 'iPhone';
  if (/iPad/i.test(ua)) return 'iPad';
  if (/Android/i.test(ua)) return /Mobile/i.test(ua) ? 'Android Phone' : 'Android Tablet';
  if (/Macintosh|Mac OS X/i.test(ua)) return 'Mac';
  if (/Windows/i.test(ua)) return 'Windows PC';
  if (/Linux/i.test(ua)) return 'Linux Device';
  return 'Unknown Device';
}

function customerSecurityBrowserName(userAgent) {
  const ua = String(userAgent || '');
  if (/Edg\//i.test(ua)) return 'Microsoft Edge';
  if (/OPR\//i.test(ua)) return 'Opera';
  if (/CriOS\//i.test(ua)) return 'Chrome iOS';
  if (/Chrome\//i.test(ua)) return 'Chrome';
  if (/FxiOS\//i.test(ua)) return 'Firefox iOS';
  if (/Firefox\//i.test(ua)) return 'Firefox';
  if (/Safari\//i.test(ua)) return 'Safari';
  return 'Unknown Browser';
}

function customerSecurityOperatingSystem(userAgent) {
  const ua = String(userAgent || '');
  if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
  if (/Android/i.test(ua)) return 'Android';
  if (/Windows NT/i.test(ua)) return 'Windows';
  if (/Mac OS X|Macintosh/i.test(ua)) return 'macOS';
  if (/Linux/i.test(ua)) return 'Linux';
  return 'Unknown OS';
}

async function customerSecurityWriteSessionTelemetry(customerId, fingerprint) {
  const base = {
    customer_id: customerId,
    device_name: fingerprint.device_name,
    browser_name: fingerprint.browser_name,
    operating_system: fingerprint.operating_system,
    user_agent: fingerprint.user_agent,
    ip_address: fingerprint.ip_address || null,
    country: null,
    city: null,
    metadata: {
      source: 'customer_security_overview',
      auto_detected: true
    }
  };

  await supabaseFetch('/rest/v1/security_customer_login_logs', {
    method: 'POST',
    auth: 'service',
    body: [{
      ...base,
      event_type: 'login_success',
      status: 'success',
      risk_level: 'low'
    }]
  }).catch(() => null);

  await supabaseFetch('/rest/v1/security_customer_events', {
    method: 'POST',
    auth: 'service',
    body: [{
      ...base,
      event_type: 'login_from_new_device',
      status: 'info',
      risk_level: 'low',
      description: 'Perangkat terdeteksi otomatis saat membuka halaman keamanan.'
    }]
  }).catch(() => null);
}

function customerSecuritySafeLogError(error) {
  return String(error && error.message ? error.message : error).slice(0, 180);
}



/* ============================================================
   CUSTOMER SECURITY GUARDED ACTIONS - APPEND ONLY
   Tujuan:
   - Anti-bypass backend untuk aksi sensitif customer security.
   - Tidak mengubah domainLogin(), domainRegister(), hash, A2F/MFA lama, passkey, lock, admin/staff.
   - Semua validasi memakai backend service_role-only.
   - customer_id SELALU diambil dari security_customer_auth_links, bukan body/query frontend.
   Endpoint:
   POST /api/health?action=customer_security_revoke_session
   POST /api/health?action=customer_security_revoke_other_sessions
   POST /api/health?action=customer_security_account_request
   GET  /api/health?action=customer_security_guard_status
   ============================================================ */

const __diracCustomerSecurityGuardedActionsPreviousHandler = module.exports;

const CUSTOMER_SECURITY_GUARDED_ACTIONS = new Set([
  'customer_security_guard_status',
  'customer_security_revoke_session',
  'customer_security_revoke_other_sessions',
  'customer_security_account_request',
  'customer_security_recovery_codes_generate',
  'customer_security_recovery_codes_status',
  'customer_security_recovery_code_verify'
]);

const CUSTOMER_SECURITY_GUARDED_ALIASES = Object.freeze({
  'customer-security-guard-status': 'customer_security_guard_status',
  'customer_security_guard_status': 'customer_security_guard_status',
  'customer-security-revoke-session': 'customer_security_revoke_session',
  'customer_security_revoke_session': 'customer_security_revoke_session',
  'customer-security-revoke-other-sessions': 'customer_security_revoke_other_sessions',
  'customer_security_revoke_other_sessions': 'customer_security_revoke_other_sessions',
  'customer-security-account-request': 'customer_security_account_request',
  'customer_security_account_request': 'customer_security_account_request',
  'customer-security-recovery-codes-generate': 'customer_security_recovery_codes_generate',
  'customer_security_recovery_codes_generate': 'customer_security_recovery_codes_generate',
  'customer-security-recovery-codes-status': 'customer_security_recovery_codes_status',
  'customer_security_recovery_codes_status': 'customer_security_recovery_codes_status',
  'customer-security-recovery-code-verify': 'customer_security_recovery_code_verify',
  'customer_security_recovery_code_verify': 'customer_security_recovery_code_verify'
});

const CUSTOMER_SECURITY_RATE_LIMIT_STORE = globalThis.__DIRAC_CUSTOMER_SECURITY_RATE_LIMIT_STORE__ || new Map();
globalThis.__DIRAC_CUSTOMER_SECURITY_RATE_LIMIT_STORE__ = CUSTOMER_SECURITY_RATE_LIMIT_STORE;

module.exports = async function customerSecurityGuardedActionsWrapper(req, res) {
  diracApplySecurityResponseHeaders(res);
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = customerSecurityGuardedNormalizeAction(rawAction);

  if (!CUSTOMER_SECURITY_GUARDED_ACTIONS.has(action)) {
    return __diracCustomerSecurityGuardedActionsPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  const block = await customerSecurityCheckAccessBlock(req, action);
  if (block && block.blocked) {
    return res.status(423).json({
      ok: false,
      code: 'SECURITY_ACCESS_BLOCKED',
      message: 'Akses keamanan sementara diblokir. Silakan coba lagi beberapa menit.',
      blocked_until: block.blocked_until,
      retry_after_seconds: block.retry_after_seconds || 300
    });
  }

  return customerSecurityHandleGuardedAction(action, req, res);
};

function customerSecurityGuardedNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  return CUSTOMER_SECURITY_GUARDED_ALIASES[clean] || clean;
}

async function customerSecurityHandleGuardedAction(action, req, res) {
  try {
    if (action === 'customer_security_guard_status') {
      if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
      const access = await customerSecurityRequireAccess(req, res, {
        action,
        requireMfa: true,
        rateLimit: { limit: 60, windowMs: 60_000 }
      });
      if (!access) return;

      return res.status(200).json({
        ok: true,
        service: 'dirac-customer-security',
        endpoint: action,
        user: sanitizeUser(access.user),
        linked: true,
        link_status: 'active',
        customer_id_available: true,
        direct_frontend_table_access: false,
        mfa_required_for_page: true,
        mfa_required_for_write: true,
        mfa_active_now: Boolean(access.mfa && access.mfa.ok),
        guarded_actions_ready: true,
        rate_limit_mode: 'memory_local_basic',
        write_guard: 'mfa_required',
        customer_id_source: 'security_customer_auth_links',
        message: 'Guard customer security aktif. Halaman dan aksi write sama-sama membutuhkan A2F backend.',
        time: diracNowIso()
      });
    }

    if (action === 'customer_security_revoke_session') {
      if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
      return customerSecurityRevokeSession(req, res, action);
    }

    if (action === 'customer_security_revoke_other_sessions') {
      if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
      return customerSecurityRevokeOtherSessions(req, res, action);
    }

    if (action === 'customer_security_account_request') {
      if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
      return customerSecurityCreateAccountRequest(req, res, action);
    }

    if (action === 'customer_security_recovery_codes_status') {
      if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
      return customerSecurityRecoveryCodesStatus(req, res, action);
    }

    if (action === 'customer_security_recovery_codes_generate') {
      if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
      return customerSecurityGenerateRecoveryCodes(req, res, action);
    }

    if (action === 'customer_security_recovery_code_verify') {
      if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
      return customerSecurityVerifyRecoveryCode(req, res, action);
    }

    return res.status(404).json({ ok: false, message: 'Aksi keamanan tidak ditemukan.' });
  } catch (error) {
    console.error('[customer-security-guarded-action]', customerSecuritySafeLogError(error));
    return res.status(500).json({
      ok: false,
      message: diracSafePublicMessage('Aksi keamanan belum dapat diproses.'),
      source: 'customer_security_guarded_action'
    });
  }
}

async function customerSecurityRequireAccess(req, res, options = {}) {
  const user = await requireDomainUser(req, res);
  if (!user) {
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'user_not_active');
    return null;
  }

  const authUserId = String(user.id || '').trim();
  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId)) {
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'invalid_session');
    res.status(401).json({ ok: false, message: 'Sesi tidak valid.' });
    return null;
  }

  const rate = customerSecurityCheckRateLimit(req, options.action || 'customer_security', authUserId, options.rateLimit);
  if (!rate.ok) {
    res.setHeader('Retry-After', String(Math.ceil(rate.retryAfterMs / 1000)));
    res.status(429).json({
      ok: false,
      message: 'Terlalu banyak percobaan. Coba lagi sebentar.',
      retry_after_seconds: Math.ceil(rate.retryAfterMs / 1000)
    });
    return null;
  }

  const linkResult = await customerSecurityFetchAuthLink(authUserId);
  if (!linkResult.ok) {
    if (customerSecurityIsSchemaCacheMissing(linkResult)) {
      res.status(503).json({
        ok: false,
        message: 'Storage keamanan belum siap. Coba lagi setelah sinkronisasi schema selesai.',
        source: 'customer_security_guard'
      });
      return null;
    }

    res.status(500).json({
      ok: false,
      message: 'Gagal memverifikasi akses customer security.',
      source: 'customer_security_guard'
    });
    return null;
  }

  const link = Array.isArray(linkResult.data) && linkResult.data.length ? linkResult.data[0] : null;
  const customerId = String(link && link.customer_id || '').trim();

  if (!link || link.link_status !== 'active' || !customerSecurityLooksLikeUuid(customerId)) {
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'auth_link_not_active');
    res.status(403).json({
      ok: false,
      message: 'Akun belum terhubung ke customer profile aktif.',
      source: 'customer_security_guard'
    });
    return null;
  }

  await customerSecurityEnsureSettingsRow(customerId).catch(() => null);

  let mfa = null;
  if (options.requireMfa) {
    mfa = verifyCustomerDashboardMfaCookie(req, user);
    if (!mfa || !mfa.ok) {
      await customerSecurityWriteGuardEvent(customerId, {
        event_type: 'security_settings_updated',
        status: 'warning',
        risk_level: 'medium',
        description: 'Aksi keamanan ditolak karena MFA/re-auth proof tidak valid.',
        req,
        metadata: { action: options.action || 'customer_security', reason: 'missing_or_invalid_mfa_proof' }
      });
      await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'missing_or_invalid_mfa_proof', customerId);
      res.status(403).json({
        ok: false,
        code: 'MFA_REQUIRED',
        message: 'Aksi ini membutuhkan verifikasi A2F/MFA ulang dari dashboard resmi.'
      });
      return null;
    }
  } else {
    try { mfa = verifyCustomerDashboardMfaCookie(req, user); } catch (_) { mfa = null; }
  }

  return { user, authUserId, customerId, link, mfa };
}

function customerSecurityCheckRateLimit(req, action, userId, config = {}) {
  const limit = Math.max(1, Number(config.limit || 12));
  const windowMs = Math.max(1000, Number(config.windowMs || 60_000));
  const ip = customerSecurityRequestIp(req) || 'no-ip';
  const key = [String(action || 'customer_security'), String(userId || 'anonymous'), ip].join(':');
  const now = Date.now();
  const bucket = CUSTOMER_SECURITY_RATE_LIMIT_STORE.get(key) || [];
  const fresh = bucket.filter(ts => now - ts < windowMs);
  if (fresh.length >= limit) {
    const oldest = fresh[0] || now;
    return { ok: false, retryAfterMs: Math.max(1000, windowMs - (now - oldest)) };
  }
  fresh.push(now);
  CUSTOMER_SECURITY_RATE_LIMIT_STORE.set(key, fresh);

  if (CUSTOMER_SECURITY_RATE_LIMIT_STORE.size > 5000) {
    for (const [k, values] of CUSTOMER_SECURITY_RATE_LIMIT_STORE.entries()) {
      const active = values.filter(ts => now - ts < windowMs);
      if (active.length) CUSTOMER_SECURITY_RATE_LIMIT_STORE.set(k, active);
      else CUSTOMER_SECURITY_RATE_LIMIT_STORE.delete(k);
      if (CUSTOMER_SECURITY_RATE_LIMIT_STORE.size <= 3500) break;
    }
  }

  return { ok: true };
}

async function customerSecurityRevokeSession(req, res, action) {
  const access = await customerSecurityRequireAccess(req, res, {
    action,
    requireMfa: true,
    rateLimit: { limit: 8, windowMs: 60_000 }
  });
  if (!access) return;

  const body = await readBody(req);
  const sessionId = String(body.session_id || body.id || '').trim();

  if (!customerSecurityLooksLikeUuid(sessionId)) {
    return res.status(400).json({ ok: false, message: 'Session ID tidak valid.' });
  }

  const current = customerSecurityBuildSessionFingerprint(req, access.customerId);
  const readPath = '/rest/v1/security_customer_sessions?select=' +
    encodeURIComponent('id,status,session_token_hash') +
    '&customer_id=eq.' + encodeURIComponent(access.customerId) +
    '&id=eq.' + encodeURIComponent(sessionId) +
    '&limit=1';

  const found = await supabaseFetch(readPath, { method: 'GET', auth: 'service' });
  if (!found.ok) {
    return res.status(500).json({ ok: false, message: 'Gagal membaca sesi.' });
  }

  const rows = Array.isArray(found.data) ? found.data : [];
  const row = rows[0] || null;
  if (!row) {
    return res.status(404).json({ ok: false, message: 'Sesi tidak ditemukan.' });
  }

  if (row.session_token_hash && current && row.session_token_hash === current.session_token_hash) {
    return res.status(409).json({
      ok: false,
      message: 'Sesi saat ini tidak dicabut dari daftar perangkat. Gunakan tombol Logout untuk keluar dari perangkat ini.'
    });
  }

  const patched = await supabaseFetch('/rest/v1/security_customer_sessions?id=eq.' + encodeURIComponent(sessionId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      status: 'revoked',
      revoked_at: new Date().toISOString(),
      revoke_reason: 'customer_requested'
    }
  });

  if (!patched.ok) {
    return res.status(500).json({ ok: false, message: 'Gagal mencabut sesi.' });
  }

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'session_revoked',
    status: 'success',
    risk_level: 'low',
    description: 'Customer mencabut salah satu sesi perangkat.',
    req,
    metadata: { action, session_id: sessionId }
  });

  return res.status(200).json({
    ok: true,
    message: 'Sesi perangkat berhasil dicabut.',
    revoked_session_id: sessionId,
    time: diracNowIso()
  });
}

async function customerSecurityRevokeOtherSessions(req, res, action) {
  const access = await customerSecurityRequireAccess(req, res, {
    action,
    requireMfa: true,
    rateLimit: { limit: 4, windowMs: 60_000 }
  });
  if (!access) return;

  const current = customerSecurityBuildSessionFingerprint(req, access.customerId);
  const path = '/rest/v1/security_customer_sessions?customer_id=eq.' +
    encodeURIComponent(access.customerId) +
    '&status=eq.active' +
    '&session_token_hash=neq.' +
    encodeURIComponent(current.session_token_hash || 'none');

  const patched = await supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      status: 'revoked',
      revoked_at: new Date().toISOString(),
      revoke_reason: 'customer_revoked_other_sessions'
    }
  });

  if (!patched.ok) {
    return res.status(500).json({ ok: false, message: 'Gagal mencabut sesi lain.' });
  }

  const rows = Array.isArray(patched.data) ? patched.data : [];

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'all_sessions_revoked',
    status: 'success',
    risk_level: 'medium',
    description: 'Customer mencabut semua sesi perangkat lain.',
    req,
    metadata: { action, revoked_count: rows.length }
  });

  return res.status(200).json({
    ok: true,
    message: rows.length ? 'Semua sesi perangkat lain berhasil dicabut.' : 'Tidak ada sesi perangkat lain yang aktif.',
    revoked_count: rows.length,
    time: diracNowIso()
  });
}

async function customerSecurityCreateAccountRequest(req, res, action) {
  const access = await customerSecurityRequireAccess(req, res, {
    action,
    requireMfa: true,
    rateLimit: { limit: 3, windowMs: 10 * 60_000 }
  });
  if (!access) return;

  const body = await readBody(req);
  const allowed = new Set(['security_review', 'export_data', 'deactivate_account', 'reactivate_account']);
  const requestType = String(body.request_type || 'security_review').trim().toLowerCase();
  const safeType = allowed.has(requestType) ? requestType : 'security_review';
  const reason = customerSecuritySanitizeReason(body.reason || 'Customer meminta review keamanan akun.');
  const idempotencyKey = customerSecuritySanitizeReason(req.headers && (req.headers['idempotency-key'] || req.headers['x-idempotency-key']) || body.idempotency_key || '');

  if (idempotencyKey) {
    const existingPath = '/rest/v1/security_customer_account_requests?select=' +
      encodeURIComponent('id,request_type,status,created_at') +
      '&customer_id=eq.' + encodeURIComponent(access.customerId) +
      '&request_type=eq.' + encodeURIComponent(safeType) +
      '&status=in.(pending,processing)' +
      '&order=created_at.desc&limit=1';

    const existing = await supabaseFetch(existingPath, { method: 'GET', auth: 'service' });
    if (existing.ok && Array.isArray(existing.data) && existing.data.length) {
      return res.status(200).json({
        ok: true,
        message: 'Request keamanan akun sudah ada dan masih diproses.',
        request: existing.data[0],
        idempotent: true,
        time: diracNowIso()
      });
    }
  }

  const created = await supabaseFetch('/rest/v1/security_customer_account_requests', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      customer_id: access.customerId,
      request_type: safeType,
      status: 'pending',
      reason,
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      metadata: {
        source: 'customer_security_guarded_action',
        action,
        idempotency_key_present: Boolean(idempotencyKey)
      }
    }]
  });

  if (!created.ok) {
    return res.status(500).json({ ok: false, message: 'Gagal membuat request keamanan akun.' });
  }

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'security_settings_updated',
    status: 'info',
    risk_level: 'low',
    description: 'Customer membuat request keamanan akun.',
    req,
    metadata: { action, request_type: safeType }
  });

  const rows = Array.isArray(created.data) ? created.data : [];

  return res.status(200).json({
    ok: true,
    message: 'Request keamanan akun berhasil dibuat.',
    request: rows[0] || null,
    time: diracNowIso()
  });
}

function customerSecuritySanitizeReason(value) {
  return String(value || '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500) || 'Customer security request.';
}

async function customerSecurityWriteGuardEvent(customerId, options = {}) {
  try {
    const req = options.req || {};
    const userAgent = String((req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
    const payload = {
      customer_id: customerId,
      event_type: options.event_type || 'security_settings_updated',
      status: options.status || 'info',
      risk_level: options.risk_level || 'low',
      description: customerSecuritySanitizeReason(options.description || 'Security event.'),
      ip_address: customerSecurityRequestIp(req),
      user_agent: userAgent,
      device_name: customerSecurityDeviceName(userAgent),
      browser_name: customerSecurityBrowserName(userAgent),
      operating_system: customerSecurityOperatingSystem(userAgent),
      metadata: {
        source: 'customer_security_guarded_actions',
        ...(options.metadata && typeof options.metadata === 'object' ? options.metadata : {})
      }
    };

    await supabaseFetch('/rest/v1/security_customer_events', {
      method: 'POST',
      auth: 'service',
      body: [payload]
    });
  } catch (error) {
    console.error('[customer-security-guard-event]', customerSecuritySafeLogError(error));
  }
}


/* ============================================================
   GLOBAL RESPONSE SECURITY HEADERS - APPEND SAFE
   Header ini hanya memperkuat response API health.js.
   Tidak mengubah login/hash/A2F/MFA lama.
   ============================================================ */

function diracApplySecurityResponseHeaders(res, options = {}) {
  try {
    if (!res || !res.setHeader) return;

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');

    if (options.allowCors === false) {
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    }
  } catch (_) {}
}

function diracSafePublicMessage(message, fallback = 'Permintaan belum dapat diproses.') {
  const text = String(message || fallback || '').replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  return text.slice(0, 220) || fallback;
}

function diracNowIso() {
  return new Date().toISOString();
}



/* ============================================================
   CUSTOMER SECURITY ACCESS BLOCK + RECOVERY CODES
   ============================================================ */

const CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY = globalThis.__DIRAC_CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY__ || new Map();
globalThis.__DIRAC_CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY__ = CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY;
const CUSTOMER_SECURITY_ACCESS_BLOCK_SECONDS = 300;

function customerSecurityAccessBlockIdentity(req) {
  const ip = customerSecurityRequestIp(req) || 'no-ip';
  const ua = String((req && req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
  const origin = requestOrigin(req);
  const deviceHeader = String((req && req.headers && (req.headers['x-dirac-device-id'] || req.headers['x-device-id'])) || '').trim().slice(0, 160);
  const deviceMaterial = [deviceHeader, ua, origin].filter(Boolean).join('|') || 'unknown-device';
  return {
    ip,
    ua,
    origin,
    ip_hash: customerSecuritySha256('security-block-ip-v1:' + ip),
    device_hash: customerSecuritySha256('security-block-device-v1:' + deviceMaterial)
  };
}

async function customerSecurityCheckAccessBlock(req, action) {
  const identity = customerSecurityAccessBlockIdentity(req);
  const now = Date.now();
  const memKey = identity.ip_hash + ':' + identity.device_hash;
  const memUntil = Number(CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY.get(memKey) || 0);
  if (memUntil && memUntil > now) {
    return { blocked: true, blocked_until: new Date(memUntil).toISOString(), retry_after_seconds: Math.ceil((memUntil - now) / 1000), source: 'memory' };
  }
  if (memUntil && memUntil <= now) CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY.delete(memKey);

  try {
    const path = '/rest/v1/security_customer_access_blocks?select=' +
      encodeURIComponent('id,blocked_until,reason') +
      '&or=(' +
      'ip_hash.eq.' + encodeURIComponent(identity.ip_hash) + ',' +
      'device_hash.eq.' + encodeURIComponent(identity.device_hash) +
      ')' +
      '&blocked_until=gt.' + encodeURIComponent(new Date().toISOString()) +
      '&order=blocked_until.desc&limit=1';
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (result.ok && Array.isArray(result.data) && result.data.length) {
      const until = new Date(result.data[0].blocked_until).getTime();
      return { blocked: true, blocked_until: result.data[0].blocked_until, retry_after_seconds: Math.max(1, Math.ceil((until - now) / 1000)), source: 'database' };
    }
  } catch (_) {}
  return { blocked: false };
}

async function customerSecurityRegisterFailedVerification(req, action, reason, customerId = null) {
  const identity = customerSecurityAccessBlockIdentity(req);
  const untilMs = Date.now() + CUSTOMER_SECURITY_ACCESS_BLOCK_SECONDS * 1000;
  const blockedUntil = new Date(untilMs).toISOString();
  const memKey = identity.ip_hash + ':' + identity.device_hash;
  CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY.set(memKey, untilMs);

  try {
    await supabaseFetch('/rest/v1/security_customer_access_blocks', {
      method: 'POST',
      auth: 'service',
      prefer: 'return=representation',
      body: [{
        customer_id: customerSecurityLooksLikeUuid(customerId) ? customerId : null,
        ip_hash: identity.ip_hash,
        device_hash: identity.device_hash,
        reason: customerSecuritySanitizeReason(reason || 'security_gate_failed'),
        action: String(action || 'customer_security').slice(0, 120),
        fail_count: 1,
        blocked_until: blockedUntil,
        metadata: { source: 'customer_security_gate', origin: identity.origin || null, user_agent_hash: customerSecuritySha256('ua:' + identity.ua) }
      }]
    });
  } catch (_) {}

  try {
    if (customerSecurityLooksLikeUuid(customerId)) {
      await customerSecurityWriteGuardEvent(customerId, {
        event_type: 'security_access_blocked',
        status: 'warning',
        risk_level: 'high',
        description: 'Akses customer security diblokir sementara setelah verifikasi backend gagal.',
        req,
        metadata: { action, reason, blocked_until: blockedUntil }
      });
    }
  } catch (_) {}

  return { blocked_until: blockedUntil, retry_after_seconds: CUSTOMER_SECURITY_ACCESS_BLOCK_SECONDS };
}

function customerSecurityRecoveryCodeSecret() {
  return getCustomerMfaSecret();
}

const CUSTOMER_SECURITY_RECOVERY_CODE_LENGTH = 500;
const CUSTOMER_SECURITY_RECOVERY_CODE_COUNT = 3;
const CUSTOMER_SECURITY_RECOVERY_DIGITS = '0123456789';
const CUSTOMER_SECURITY_RECOVERY_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const CUSTOMER_SECURITY_RECOVERY_SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?/|~';
// Recovery code harus ASCII printable karena frontend memvalidasi dengan /^[!-~]{500}$/.
// Jangan pakai huruf aksen/Unicode di sini; itu membuat generate sukses di backend tetapi ditolak UI.
const CUSTOMER_SECURITY_RECOVERY_SPECIAL_LETTERS = CUSTOMER_SECURITY_RECOVERY_SYMBOLS;
const CUSTOMER_SECURITY_RECOVERY_ALPHABET =
  CUSTOMER_SECURITY_RECOVERY_DIGITS +
  CUSTOMER_SECURITY_RECOVERY_LETTERS +
  CUSTOMER_SECURITY_RECOVERY_SYMBOLS +
  CUSTOMER_SECURITY_RECOVERY_SPECIAL_LETTERS;

function customerSecurityPickRecoveryChar(charset) {
  return charset[crypto.randomInt(0, charset.length)];
}

function customerSecurityShuffleRecoveryChars(chars) {
  const arr = chars.slice();
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

function customerSecurityGeneratePlainRecoveryCode() {
  const chars = [
    customerSecurityPickRecoveryChar(CUSTOMER_SECURITY_RECOVERY_DIGITS),
    customerSecurityPickRecoveryChar(CUSTOMER_SECURITY_RECOVERY_LETTERS),
    customerSecurityPickRecoveryChar(CUSTOMER_SECURITY_RECOVERY_SYMBOLS),
    customerSecurityPickRecoveryChar(CUSTOMER_SECURITY_RECOVERY_SPECIAL_LETTERS)
  ];

  while (chars.length < CUSTOMER_SECURITY_RECOVERY_CODE_LENGTH) {
    chars.push(customerSecurityPickRecoveryChar(CUSTOMER_SECURITY_RECOVERY_ALPHABET));
  }

  return customerSecurityShuffleRecoveryChars(chars).join('');
}

function customerSecurityNormalizeRecoveryCodeInput(code) {
  // Recovery code alphabet intentionally excludes whitespace.
  // This makes verification tolerant when mobile copy/paste inserts spaces/newlines.
  return String(code || '').replace(/\s+/g, '').trim();
}

function customerSecurityRecoveryCodeArgon2Input(code, customerId) {
  const normalizedCode = customerSecurityNormalizeRecoveryCodeInput(code);
  return [
    'dirac-customer-recovery-code-v2-argon2id',
    String(customerId || ''),
    normalizedCode,
    customerSecurityRecoveryCodeSecret()
  ].join(':');
}

function customerSecurityGetArgon2() {
  try {
    return require('argon2');
  } catch (error) {
    const err = new Error('Dependency argon2 belum terpasang. Tambahkan dependency "argon2" di package.json lalu redeploy.');
    err.statusCode = 500;
    err.code = 'ARGON2ID_DEPENDENCY_MISSING';
    throw err;
  }
}

async function customerSecurityHashRecoveryCode(code, customerId) {
  const argon2 = customerSecurityGetArgon2();
  return await argon2.hash(customerSecurityRecoveryCodeArgon2Input(code, customerId), {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 3,
    parallelism: 1,
    hashLength: 32
  });
}


function customerSecurityRecoveryPublicError(reason) {
  const clean = String(reason || 'invalid_recovery_code').toLowerCase();
  if (clean.includes('used')) {
    return {
      ok: false,
      active: false,
      code: 'RECOVERY_CODE_USED',
      message: 'Recovery code sudah dipakai atau expired.'
    };
  }
  if (clean.includes('expired') || clean.includes('revoked')) {
    return {
      ok: false,
      active: false,
      code: 'RECOVERY_CODE_EXPIRED',
      message: 'Recovery code sudah expired. Gunakan kode recovery lain.'
    };
  }
  if (clean.includes('format') || clean.includes('length')) {
    return {
      ok: false,
      active: false,
      code: 'RECOVERY_CODE_FORMAT_INVALID',
      message: 'Format recovery code tidak valid. Tempel 1 kode penuh dari file TXT.'
    };
  }
  if (clean.includes('mfa') || clean.includes('proof') || clean.includes('session')) {
    return {
      ok: false,
      active: false,
      code: 'SESSION_REQUIRED',
      message: 'Sesi login tidak valid. Silakan login ulang.'
    };
  }
  return {
    ok: false,
    active: false,
    code: 'RECOVERY_CODE_INVALID',
    message: 'Recovery code salah, sudah dipakai, atau expired.'
  };
}

function customerSecuritySendRecoveryError(res, status, reason) {
  const payload = customerSecurityRecoveryPublicError(reason);
  return res.status(status || 400).json(payload);
}

async function customerSecurityVerifyRecoveryCodeHash(code, storedHash, customerId) {
  const hash = String(storedHash || '');
  if (!hash.startsWith('$argon2id$')) return false;
  const argon2 = customerSecurityGetArgon2();
  return await argon2.verify(hash, customerSecurityRecoveryCodeArgon2Input(code, customerId));
}

async function customerSecurityRecoveryCodesStatus(req, res, action) {
  const access = await customerSecurityRequireAccess(req, res, { action, requireMfa: true, rateLimit: { limit: 20, windowMs: 60_000 } });
  if (!access) return;

  const path = '/rest/v1/security_customer_recovery_codes?select=' + encodeURIComponent('id,created_at,used_at,revoked_at') + '&customer_id=eq.' + encodeURIComponent(access.customerId);
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) {
    return res.status(200).json({ ok: true, ready: false, total: 0, unused: 0, used: 0, message: 'Recovery codes storage belum siap.', direct_frontend_table_access: false });
  }

  const rows = Array.isArray(result.data) ? result.data : [];
  const activeRows = rows.filter(row => !row.revoked_at);
  const unused = activeRows.filter(row => !row.used_at).length;
  const used = activeRows.filter(row => row.used_at).length;
  return res.status(200).json({ ok: true, ready: true, total: activeRows.length, unused, used, generated: activeRows.length > 0, message: activeRows.length ? 'Recovery codes tersedia.' : 'Recovery codes belum dibuat.', direct_frontend_table_access: false, time: diracNowIso() });
}

async function customerSecurityGenerateRecoveryCodes(req, res, action) {
  const access = await customerSecurityRequireAccess(req, res, { action, requireMfa: true, rateLimit: { limit: 2, windowMs: 10 * 60_000 } });
  if (!access) return;

  const body = await readBody(req);
  const count = CUSTOMER_SECURITY_RECOVERY_CODE_COUNT;
  const now = diracNowIso();
  const batchId = customerSecuritySha256('recovery-batch:' + access.customerId + ':' + now + ':' + crypto.randomBytes(16).toString('hex')).slice(0, 32);

  await supabaseFetch('/rest/v1/security_customer_recovery_codes?customer_id=eq.' + encodeURIComponent(access.customerId) + '&revoked_at=is.null', {
    method: 'PATCH',
    auth: 'service',
    body: { revoked_at: now, revoke_reason: 'rotated' }
  }).catch(() => null);

  const plainCodes = Array.from({ length: count }, () => customerSecurityGeneratePlainRecoveryCode());
  const rows = await Promise.all(plainCodes.map(async (code, index) => ({
    customer_id: access.customerId,
    code_hash: await customerSecurityHashRecoveryCode(code, access.customerId),
    code_hint: code.slice(-4),
    batch_id: batchId,
    status: 'active',
    used_at: null,
    revoked_at: null,
    metadata: {
      source: 'customer_security_generate_recovery_codes',
      order: index + 1,
      hash_algorithm: 'argon2id',
      code_length: CUSTOMER_SECURITY_RECOVERY_CODE_LENGTH
    }
  })));

  const created = await supabaseFetch('/rest/v1/security_customer_recovery_codes', { method: 'POST', auth: 'service', prefer: 'return=representation', body: rows });
  if (!created.ok) {
    return res.status(500).json({ ok: false, message: 'Gagal membuat recovery codes. Pastikan tabel security_customer_recovery_codes sudah tersedia.' });
  }

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'recovery_codes_generated',
    status: 'success',
    risk_level: 'high',
    description: 'Customer membuat recovery codes baru. Kode lama dicabut.',
    req,
    metadata: { action, count, batch_id: batchId }
  });

  return res.status(200).json({ ok: true, message: '3 recovery codes berhasil dibuat. Download file TXT sekarang; kode hanya dikirim sekali.', codes: plainCodes, count: plainCodes.length, code_length: CUSTOMER_SECURITY_RECOVERY_CODE_LENGTH, active_code_limit: CUSTOMER_SECURITY_RECOVERY_CODE_COUNT, show_once: true, delivery: 'download_txt_only', recovery_policy_version: '500x3-v2', batch_id: batchId, time: diracNowIso() });
}



/* ============================================================
   RECOVERY CODE VERIFY + ARGON2ID MFA PROOF
   - Verifikasi recovery code dari masuk.html.
   - Recovery code hash wajib Argon2id.
   - Setelah cocok: used_at diisi, status=used, proof MFA dibuat.
   ============================================================ */

function customerSecurityCreateDashboardMfaToken(req, user, method = 'recovery_code') {
  const email = normalizeAuthEmail(user && user.email);
  const now = Date.now();
  const maxAgeSeconds = 60 * 60 * 12;
  const payload = {
    type: CUSTOMER_MFA_SESSION_TYPE,
    method,
    emailHash: customerMfaProfileId(email),
    activeAtMs: now,
    expiresAtMs: now + maxAgeSeconds * 1000,
    originHash: customerMfaBindingHash('origin', requestOrigin(req)),
    uaHash: customerMfaBindingHash('ua', requestUserAgent(req)),
    recoveryVerified: method === 'recovery_code'
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = signDashboardMfa(payloadBase64, getCustomerMfaSecret());
  return {
    token: payloadBase64 + '.' + signature,
    expiresAtMs: payload.expiresAtMs,
    activeAtMs: payload.activeAtMs,
    maxAgeSeconds
  };
}

function customerSecuritySetDashboardMfaCookie(res, proof) {
  const token = proof && proof.token ? String(proof.token) : '';
  const maxAge = Math.max(1, Math.floor(Number(proof && proof.maxAgeSeconds || 0)));
  if (!token || !maxAge) return;
  appendSetCookie(res, [
    makeCookie(CUSTOMER_MFA_COOKIE, token, { maxAge })
  ]);
}

async function customerSecurityVerifyRecoveryCode(req, res, action) {
  const access = await customerSecurityRequireAccess(req, res, {
    action,
    requireMfa: false,
    rateLimit: { limit: 3, windowMs: 10 * 60_000 }
  });
  if (!access) return;

  const body = await readBody(req);
  const code = customerSecurityNormalizeRecoveryCodeInput(body.code || body.recovery_code || body.recoveryCode || '');

  if (Array.from(code).length !== CUSTOMER_SECURITY_RECOVERY_CODE_LENGTH) {
    await customerSecurityRegisterFailedVerification(req, action, 'invalid_recovery_code_length', access.customerId);
    return res.status(400).json({
      ok: false,
      message: 'Recovery code tidak valid. Masukkan tepat 500 karakter dari file TXT.'
    });
  }

  const path = '/rest/v1/security_customer_recovery_codes?select=' +
    encodeURIComponent('id,code_hash,used_at,revoked_at,status,batch_id,created_at') +
    '&customer_id=eq.' + encodeURIComponent(access.customerId) +
    '&used_at=is.null' +
    '&revoked_at=is.null' +
    '&status=eq.active' +
    '&order=created_at.desc&limit=10';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) {
    return res.status(500).json({
      ok: false,
      message: 'Gagal membaca recovery codes.'
    });
  }

  const rows = Array.isArray(result.data) ? result.data : [];
  let matched = null;

  for (const row of rows) {
    try {
      const ok = await customerSecurityVerifyRecoveryCodeHash(code, row.code_hash, access.customerId);
      if (ok) {
        matched = row;
        break;
      }
    } catch (error) {
      if (error && error.code === 'ARGON2ID_DEPENDENCY_MISSING') {
        return res.status(500).json({
          ok: false,
          code: 'ARGON2ID_DEPENDENCY_MISSING',
          message: 'Dependency argon2 belum terpasang di backend.'
        });
      }
      throw error;
    }
  }

  if (!matched || !matched.id) {
    await customerSecurityRegisterFailedVerification(req, action, 'recovery_code_not_matched', access.customerId);
    return res.status(403).json({
      ok: false,
      message: 'Recovery code salah, sudah dipakai, atau sudah expired.'
    });
  }

  const now = diracNowIso();
  const patched = await supabaseFetch('/rest/v1/security_customer_recovery_codes?id=eq.' + encodeURIComponent(matched.id), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      used_at: now,
      status: 'used',
      metadata: {
        source: 'customer_security_recovery_code_verify',
        used_by_endpoint: action,
        used_at: now
      }
    }
  });

  if (!patched.ok) {
    return res.status(500).json({
      ok: false,
      message: 'Gagal menandai recovery code sebagai used.'
    });
  }

  const proof = customerSecurityCreateDashboardMfaToken(req, access.user, 'recovery_code');
  customerSecuritySetDashboardMfaCookie(res, proof);

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'recovery_code_used',
    status: 'success',
    risk_level: 'high',
    description: 'Customer memakai recovery code untuk verifikasi A2F/MFA.',
    req,
    metadata: { action, recovery_code_id: matched.id, batch_id: matched.batch_id || null }
  });

  return res.status(200).json({
    ok: true,
    active: true,
    method: 'recovery_code',
    message: 'Recovery code valid. Akses dashboard diverifikasi.',
    dashboardSession: {
      verified: true,
      expiresAtMs: proof.expiresAtMs,
      activeAtMs: proof.activeAtMs,
      method: 'recovery_code',
      transport: 'httponly-secure-cookie-only'
    },
    recovery_code_used: true,
    time: now
  });
}



/* ============================================================
   ADMIN SECURITY CENTER SUPABASE-ONLY - APPEND ONLY - 2026-06-06
   Guard:
   - Tidak membutuhkan konfigurasi Firebase tambahan. Jika admin panel lama login Firebase, tokennya diverifikasi backend lalu role tetap dicek di Supabase admin_users.
   - Wajib Supabase access token atau cookie session domain.
   - Backend ambil user dari Supabase Auth /auth/v1/user.
   - Backend cek public.admin_users:
     role in owner/super_admin/security_admin
     active = true
     status = active/enabled/active atau kosong.
   - Tidak menyentuh login/hash/A2F/recovery lama.
   ============================================================ */

const __diracAdminSecuritySupabasePreviousHandler = module.exports;

const ADMIN_SECURITY_ACTIONS_SUPABASE = new Set([
  'admin_security_overview',
  'admin_security_events',
  'admin_security_blocks',
  'admin_security_unblock_user'
]);

const ADMIN_SECURITY_ACTION_ALIASES_SUPABASE = Object.freeze({
  'admin-security-overview': 'admin_security_overview',
  'admin_security_overview': 'admin_security_overview',
  'admin-security-events': 'admin_security_events',
  'admin_security_events': 'admin_security_events',
  'admin-security-blocks': 'admin_security_blocks',
  'admin_security_blocks': 'admin_security_blocks',
  'admin-security-unblock-user': 'admin_security_unblock_user',
  'admin_security_unblock_user': 'admin_security_unblock_user'
});

module.exports = async function adminSecurityCenterSupabaseWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = ADMIN_SECURITY_ACTION_ALIASES_SUPABASE[rawAction] || rawAction;

  if (!ADMIN_SECURITY_ACTIONS_SUPABASE.has(action)) {
    return __diracAdminSecuritySupabasePreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  try {
    return await adminSecurityHandleActionSupabase(action, req, res);
  } catch (error) {
    console.error('[admin-security-supabase]', adminSecuritySafeErrorSupabase(error));
    return res.status(500).json({
      ok: false,
      message: 'Admin Security Center belum dapat diproses.'
    });
  }
};

async function adminSecurityHandleActionSupabase(action, req, res) {
  if (action === 'admin_security_overview') {
    if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
    const admin = await requireAdminSecuritySupabaseOwner(req, res);
    if (!admin) return;
    return adminSecurityOverviewSupabase(req, res, admin);
  }

  if (action === 'admin_security_events') {
    if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
    const admin = await requireAdminSecuritySupabaseOwner(req, res);
    if (!admin) return;
    return adminSecurityEventsSupabase(req, res, admin);
  }

  if (action === 'admin_security_blocks') {
    if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
    const admin = await requireAdminSecuritySupabaseOwner(req, res);
    if (!admin) return;
    return adminSecurityBlocksSupabase(req, res, admin);
  }

  if (action === 'admin_security_unblock_user') {
    if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
    const admin = await requireAdminSecuritySupabaseOwner(req, res, { write: true });
    if (!admin) return;
    return adminSecurityUnblockUserSupabase(req, res, admin);
  }

  return res.status(404).json({ ok: false, message: 'Admin security action tidak ditemukan.' });
}

async function requireAdminSecuritySupabaseOwner(req, res, options = {}) {
  const user = await adminSecurityRequireSupabaseUser(req);
  if (!user) {
    res.status(401).json({
      ok: false,
      message: 'Sesi admin tidak valid. Login ulang admin, tunggu dashboard terbuka, lalu buka Security Center lagi.'
    });
    return null;
  }

  const email = normalizeAuthEmail(user.email || '');
  const userId = String(user.id || user.user_id || '').trim();
  const adminRow = await adminSecurityFindAdminUserSupabase(userId, email);

  if (!adminRow) {
    res.status(403).json({
      ok: false,
      message: 'Akun ini belum terdaftar di public.admin_users.'
    });
    return null;
  }

  const role = String(adminRow.role || '').trim().toLowerCase();
  // Struktur asli public.admin_users:
  // id, email, role, active, created_at.
  // Jadi validasi admin wajib pakai active=true.
  const active = adminRow.active === true || String(adminRow.active || '').toLowerCase() === 'true';

  if (!active) {
    res.status(403).json({
      ok: false,
      message: 'Admin tidak aktif di public.admin_users.'
    });
    return null;
  }

  const canWrite = ['owner', 'super_admin', 'security_admin'].includes(role);
  const canReadOnly = canWrite || (
    String(process.env.ADMIN_SECURITY_ALLOW_ADMIN_READONLY || '').toLowerCase() === 'true' &&
    role === 'admin'
  );

  if (!canReadOnly) {
    res.status(403).json({
      ok: false,
      message: 'Security Center hanya untuk owner/super_admin/security_admin.',
      role: role || 'none'
    });
    return null;
  }

  if (options.write && !canWrite) {
    res.status(403).json({
      ok: false,
      message: 'Aksi tulis Security Center hanya untuk owner/super_admin/security_admin.'
    });
    return null;
  }

  return {
    id: String(adminRow.id || ''),
    user_id: userId,
    uid: userId,
    email: email || String(adminRow.email || ''),
    role,
    active,
    canWrite,
    auth_user: user
  };
}


function adminSecurityDecodeJwtPayloadNoVerify(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return {};
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch (_) {
    return {};
  }
}

function adminSecurityTokenLooksFirebase(token) {
  const payload = adminSecurityDecodeJwtPayloadNoVerify(token);
  const iss = String(payload.iss || '');
  return iss.indexOf('https://securetoken.google.com/') === 0;
}

function adminSecurityTokenLooksSupabase(token) {
  const payload = adminSecurityDecodeJwtPayloadNoVerify(token);
  const iss = String(payload.iss || '').toLowerCase();
  const aud = String(payload.aud || '').toLowerCase();
  return iss.includes('supabase') || aud === 'authenticated' || aud === 'anon';
}


async function adminSecurityRequireSupabaseUser(req) {
  const token = adminSecurityGetSupabaseAccessToken(req);
  const firebaseHeaderToken = adminSecurityGetFirebaseToken(req);

  // Kalau token login admin adalah Firebase, jangan kirim ke Supabase /auth/v1/user.
  // Ini penyebab log 403 sebelumnya.
  const tokenForFirebase = firebaseHeaderToken || (adminSecurityTokenLooksFirebase(token) ? token : '');
  if (tokenForFirebase) {
    const active = await adminSecurityVerifyFirebaseIdTokenNoEnv(tokenForFirebase);
    if (active && active.ok && active.payload) {
      const payload = active.payload;
      return {
        id: String(payload.user_id || payload.sub || ''),
        user_id: String(payload.user_id || payload.sub || ''),
        email: normalizeAuthEmail(payload.email || ''),
        provider: 'firebase',
        raw: payload
      };
    }
  }

  if (token) {
    const result = await supabaseFetch('/auth/v1/user', {
      method: 'GET',
      auth: 'anon',
      bearer: token
    }).catch(() => null);

    if (result && result.ok && result.data && (result.data.id || result.data.email)) {
      return {
        id: result.data.id || result.data.user_id || '',
        user_id: result.data.id || result.data.user_id || '',
        email: result.data.email || '',
        provider: 'supabase',
        raw: result.data
      };
    }
  }

  if (typeof requireDomainUser === 'function') {
    try {
      const fakeRes = {
        status: () => ({ json: () => null, end: () => null }),
        setHeader: () => null,
        getHeader: () => null
      };
      const user = await requireDomainUser(req, fakeRes);
      if (user) return user;
    } catch (_) {}
  }

  return null;
}

function adminSecurityGetSupabaseAccessToken(req) {
  const bearer = getBearerToken(req);
  if (bearer) return bearer;

  const headerToken = String(req.headers && (
    req.headers['x-domain-access-token'] ||
    req.headers['x-supabase-access-token'] ||
    req.headers['x-dirac-access-token']
  ) || '').trim();

  if (headerToken) return headerToken;

  const cookies = parseCookies(req);
  const cookieToken = String(
    cookies[ACCESS_COOKIE] ||
    cookies.dirac_domain_session ||
    cookies.sb_access_token ||
    ''
  ).trim();

  if (cookieToken) return cookieToken;
  return '';
}


function adminSecurityGetFirebaseToken(req) {
  return String(req.headers && (
    req.headers['x-firebase-id-token'] ||
    req.headers['x-admin-firebase-token'] ||
    ''
  ) || '').trim();
}

function adminSecurityFirebaseProjectIdNoEnv() {
  // Project ID mengikuti konfigurasi Firebase lama yang sudah ada di admin88881.html.
  // Ini tidak mengubah sistem login lama.
  return 'dirac-group';
}

async function adminSecurityVerifyFirebaseIdTokenNoEnv(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return { ok: false, reason: 'bad_jwt' };

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    if (header.alg !== 'RS256' || !header.kid) return { ok: false, reason: 'bad_header' };

    const projectId = adminSecurityFirebaseProjectIdNoEnv();
    const now = Math.floor(Date.now() / 1000);

    if (payload.aud !== projectId) return { ok: false, reason: 'bad_audience' };
    if (payload.iss !== 'https://securetoken.google.com/' + projectId) return { ok: false, reason: 'bad_issuer' };
    if (!payload.sub && !payload.user_id) return { ok: false, reason: 'missing_sub' };
    if (Number(payload.exp || 0) <= now) return { ok: false, reason: 'expired' };
    if (Number(payload.iat || 0) > now + 300) return { ok: false, reason: 'bad_iat' };

    const certs = await adminSecurityFirebaseCertsNoEnv();
    const cert = certs && certs[header.kid];
    if (!cert) return { ok: false, reason: 'missing_cert' };

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(parts[0] + '.' + parts[1]);
    verifier.end();

    const ok = verifier.verify(cert, Buffer.from(parts[2], 'base64url'));
    if (!ok) return { ok: false, reason: 'bad_signature' };

    return { ok: true, payload };
  } catch (error) {
    console.error('[admin-security-firebase-token]', adminSecuritySafeErrorSupabase(error));
    return { ok: false, reason: 'exception' };
  }
}

async function adminSecurityFirebaseCertsNoEnv() {
  const cacheKey = '__DIRAC_ADMIN_SECURITY_FIREBASE_CERTS_NO_ENV__';
  const cached = globalThis[cacheKey] || { expiresAt: 0, certs: null };
  globalThis[cacheKey] = cached;

  if (cached.certs && cached.expiresAt > Date.now()) return cached.certs;

  const response = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com', {
    method: 'GET',
    headers: { 'Accept': 'application/json' }
  });

  if (!response.ok) throw new Error('Gagal mengambil public certs login admin.');

  const certs = await response.json();
  const cacheControl = String(response.headers.get('cache-control') || '');
  const match = cacheControl.match(/max-age=(\d+)/i);
  const maxAge = match ? Math.max(60, Number(match[1]) || 3600) : 3600;

  cached.certs = certs;
  cached.expiresAt = Date.now() + maxAge * 1000;
  return certs;
}


async function adminSecurityFindAdminUserSupabase(userId, email) {
  // Struktur asli public.admin_users hanya:
  // id, email, role, active, created_at.
  // Karena tidak ada user_id/uid/status/active, lookup harus email-only.
  const cleanEmail = normalizeAuthEmail(email || '');
  if (!cleanEmail) return null;

  const select = encodeURIComponent('id,email,role,active,created_at');
  const path = '/rest/v1/admin_users?select=' + select + '&email=ilike.' + encodeURIComponent(cleanEmail) + '&limit=1';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  const rows = result && result.ok && Array.isArray(result.data) ? result.data : [];
  return rows[0] || null;
}

async function adminSecurityOverviewSupabase(req, res, admin) {
  const events = await adminSecurityFetchTableSafeSupabase(
    '/rest/v1/security_customer_events?select=' +
      encodeURIComponent('id,customer_id,event_type,status,risk_level,description,created_at') +
      '&order=created_at.desc&limit=50'
  );

  const blocks = await adminSecurityFetchTableSafeSupabase(
    '/rest/v1/security_customer_access_blocks?select=' +
      encodeURIComponent('id,customer_id,reason,action,blocked_until,created_at') +
      '&blocked_until=gt.' + encodeURIComponent(new Date().toISOString()) +
      '&order=created_at.desc&limit=50'
  );

  const recovery = await adminSecurityFetchTableSafeSupabase(
    '/rest/v1/security_customer_recovery_codes?select=' +
      encodeURIComponent('id,customer_id,status,used_at,revoked_at,created_at') +
      '&order=created_at.desc&limit=80'
  );

  const eventRows = Array.isArray(events.data) ? events.data : [];
  const blockRows = Array.isArray(blocks.data) ? blocks.data : [];
  const recoveryRows = Array.isArray(recovery.data) ? recovery.data : [];

  return res.status(200).json({
    ok: true,
    admin: adminSecuritySanitizeAdminSupabase(admin),
    storage_ready: Boolean(events.ok || blocks.ok || recovery.ok),
    overview: {
      recent_events: eventRows.length,
      high_risk_events: eventRows.filter((row) => String(row.risk_level || '').toLowerCase() === 'high').length,
      active_blocks: blockRows.length,
      recovery_events_generated: recoveryRows.length,
      recovery_events_used: recoveryRows.filter((row) => row.used_at).length,
      recovery_rows_sampled: recoveryRows.length,
      recovery_unused_sampled: recoveryRows.filter((row) => !row.used_at && !row.revoked_at && String(row.status || '') === 'active').length
    },
    recent_events: await adminSecurityDecorateEventsSupabase(eventRows.slice(0, 10)),
    active_blocks: await adminSecurityDecorateBlocksSupabase(blockRows.slice(0, 10)),
    time: diracNowIso()
  });
}

async function adminSecurityEventsSupabase(req, res, admin) {
  const limit = adminSecurityLimitSupabase(req, 80);
  const type = String(req.query && req.query.type || '').trim();
  let path = '/rest/v1/security_customer_events?select=' +
    encodeURIComponent('id,customer_id,event_type,status,risk_level,description,device_name,browser_name,operating_system,created_at') +
    '&order=created_at.desc&limit=' + encodeURIComponent(String(limit));
  if (type) path += '&event_type=eq.' + encodeURIComponent(type);

  const result = await adminSecurityFetchTableSafeSupabase(path);
  const rows = Array.isArray(result.data) ? result.data : [];

  return res.status(200).json({
    ok: true,
    admin: adminSecuritySanitizeAdminSupabase(admin),
    storage_ready: result.ok,
    events: await adminSecurityDecorateEventsSupabase(rows),
    time: diracNowIso()
  });
}

async function adminSecurityBlocksSupabase(req, res, admin) {
  const limit = adminSecurityLimitSupabase(req, 80);
  const includeExpired = String(req.query && req.query.include_expired || '').toLowerCase() === 'true';
  let path = '/rest/v1/security_customer_access_blocks?select=' +
    encodeURIComponent('id,customer_id,ip_hash,device_hash,reason,action,fail_count,blocked_until,created_at,updated_at') +
    '&order=created_at.desc&limit=' + encodeURIComponent(String(limit));
  if (!includeExpired) path += '&blocked_until=gt.' + encodeURIComponent(new Date().toISOString());

  const result = await adminSecurityFetchTableSafeSupabase(path);
  const rows = Array.isArray(result.data) ? result.data : [];

  return res.status(200).json({
    ok: true,
    admin: adminSecuritySanitizeAdminSupabase(admin),
    storage_ready: result.ok,
    blocks: await adminSecurityDecorateBlocksSupabase(rows),
    time: diracNowIso()
  });
}

async function adminSecurityUnblockUserSupabase(req, res, admin) {
  const body = await readBody(req);
  const blockId = String(body.block_id || body.blockId || '').trim();
  const customerIdInput = String(body.customer_id || body.customerId || '').trim();
  const email = normalizeAuthEmail(body.email || body.customer_email || '');

  let customerId = customerSecurityLooksLikeUuid(customerIdInput) ? customerIdInput : '';

  if (!customerId && email) {
    const lookup = await adminSecurityFetchTableSafeSupabase('/rest/v1/customers?select=id,email&email=ilike.' + encodeURIComponent(email) + '&limit=1');
    const rows = Array.isArray(lookup.data) ? lookup.data : [];
    if (rows[0] && customerSecurityLooksLikeUuid(rows[0].id)) customerId = rows[0].id;
  }

  let path = '';
  if (customerSecurityLooksLikeUuid(blockId)) {
    path = '/rest/v1/security_customer_access_blocks?id=eq.' + encodeURIComponent(blockId) + '&blocked_until=gt.' + encodeURIComponent(new Date().toISOString());
  } else if (customerSecurityLooksLikeUuid(customerId)) {
    path = '/rest/v1/security_customer_access_blocks?customer_id=eq.' + encodeURIComponent(customerId) + '&blocked_until=gt.' + encodeURIComponent(new Date().toISOString());
  } else {
    return res.status(400).json({
      ok: false,
      message: 'Masukkan block_id, customer_id, atau email customer yang valid.'
    });
  }

  const patched = await supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      blocked_until: new Date().toISOString(),
      reason: 'manual_unblock_from_admin_security_center',
      metadata: {
        source: 'admin_security_center_supabase',
        admin_user_id: admin.user_id,
        admin_email: admin.email,
        admin_role: admin.role,
        unblocked_at: diracNowIso()
      }
    }
  });

  if (!patched.ok) {
    return res.status(500).json({
      ok: false,
      message: 'Gagal membuka blokir customer.'
    });
  }

  const rows = Array.isArray(patched.data) ? patched.data : [];

  if (customerSecurityLooksLikeUuid(customerId)) {
    await customerSecurityWriteGuardEvent(customerId, {
      event_type: 'admin_security_unblock',
      status: 'success',
      risk_level: 'medium',
      description: 'Owner membuka blokir customer dari Admin Security Center.',
      req,
      metadata: {
        admin_user_id: admin.user_id,
        admin_email: admin.email,
        admin_role: admin.role,
        affected_rows: rows.length
      }
    }).catch(() => null);
  }

  return res.status(200).json({
    ok: true,
    message: rows.length ? 'Blokir berhasil dibuka.' : 'Tidak ada blokir aktif untuk target ini.',
    affected_rows: rows.length,
    time: diracNowIso()
  });
}

async function adminSecurityFetchTableSafeSupabase(path) {
  try {
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok) return { ok: false, status: result.status, data: [] };
    return { ok: true, status: result.status, data: Array.isArray(result.data) ? result.data : [] };
  } catch (error) {
    console.error('[admin-security-supabase-fetch]', adminSecuritySafeErrorSupabase(error));
    return { ok: false, status: 500, data: [] };
  }
}

function adminSecurityLimitSupabase(req, fallback) {
  const raw = Number(req.query && req.query.limit || fallback || 50);
  if (!Number.isFinite(raw)) return fallback || 50;
  return Math.max(1, Math.min(Math.trunc(raw), 100));
}

async function adminSecurityDecorateEventsSupabase(rows) {
  const emailMap = await adminSecurityCustomerEmailMapSupabase(rows.map((row) => row.customer_id));
  return rows.map((row) => ({
    id: row.id,
    customer_id: row.customer_id || '',
    customer_email: emailMap[row.customer_id] || '',
    event_type: String(row.event_type || ''),
    status: String(row.status || ''),
    risk_level: String(row.risk_level || ''),
    description: String(row.description || '').slice(0, 220),
    device_name: String(row.device_name || ''),
    browser_name: String(row.browser_name || ''),
    operating_system: String(row.operating_system || ''),
    created_at: row.created_at || ''
  }));
}

async function adminSecurityDecorateBlocksSupabase(rows) {
  const emailMap = await adminSecurityCustomerEmailMapSupabase(rows.map((row) => row.customer_id));
  return rows.map((row) => ({
    id: row.id,
    customer_id: row.customer_id || '',
    customer_email: emailMap[row.customer_id] || '',
    reason: String(row.reason || ''),
    action: String(row.action || ''),
    fail_count: Number(row.fail_count || 0),
    blocked_until: row.blocked_until || '',
    created_at: row.created_at || '',
    updated_at: row.updated_at || '',
    ip_hash_hint: adminSecurityHashHintSupabase(row.ip_hash),
    device_hash_hint: adminSecurityHashHintSupabase(row.device_hash),
    active: row.blocked_until ? new Date(row.blocked_until).getTime() > Date.now() : false
  }));
}

async function adminSecurityCustomerEmailMapSupabase(ids) {
  const unique = Array.from(new Set((ids || []).filter((id) => customerSecurityLooksLikeUuid(id)))).slice(0, 80);
  if (!unique.length) return {};
  const path = '/rest/v1/customers?select=' + encodeURIComponent('id,email') + '&id=in.(' + unique.map(encodeURIComponent).join(',') + ')';
  const result = await adminSecurityFetchTableSafeSupabase(path);
  const map = {};
  (Array.isArray(result.data) ? result.data : []).forEach((row) => {
    if (row && row.id) map[row.id] = String(row.email || '');
  });
  return map;
}

function adminSecurityHashHintSupabase(value) {
  const text = String(value || '');
  if (!text) return '';
  if (text.length <= 16) return text;
  return text.slice(0, 6) + '…' + text.slice(-6);
}

function adminSecuritySanitizeAdminSupabase(admin) {
  return {
    user_id: String(admin && admin.user_id || ''),
    uid: String(admin && admin.uid || ''),
    email: String(admin && admin.email || ''),
    role: String(admin && admin.role || ''),
    active: Boolean(admin && admin.active),
    can_write: Boolean(admin && admin.canWrite)
  };
}

function adminSecuritySafeErrorSupabase(error) {
  return String(error && error.message ? error.message : error).slice(0, 180);
}

/* ============================================================
   SESSION-OWNERSHIP LOCKED CHECKOUT - ISOLATED APPEND ONLY
   Production safety rules:
   - Login/hash/domain auth functions above are NOT modified.
   - No frontend customer_id ownership is trusted.
   - No frontend payment_status/order_status/paid/completed is trusted.
   - No frontend payment_url is trusted.
   - Checkout ownership is resolved server-side from authenticated session.
   - Default checkout only requires a valid backend session; no JS-readable MFA proof required.
   - If CHECKOUT_REQUIRE_DASHBOARD_MFA=true, dashboard MFA is also required.
   - Payment gateway is not active here: every created order is pending + unpaid + payment_url null.
   - Old HP test endpoint is disabled so it cannot create production orders.
   Endpoint:
   POST /api/health?action=checkout_order
   POST /api/health?action=parfum_checkout
   POST /api/health?action=public_checkout
   POST /api/health?action=layanan_digital_checkout
   POST /api/health?action=jasa_website_checkout
   POST /api/health?action=pengembangan_checkout
   ============================================================ */

const __diracSessionOwnershipCheckoutPreviousHandler = module.exports;

module.exports = async function sessionOwnershipCheckoutWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = sessionOwnershipCheckoutNormalizeAction(rawAction);

  if (!sessionOwnershipCheckoutIsAction(action)) {
    return __diracSessionOwnershipCheckoutPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  if (action === 'checkout_order_hp_test') {
    return res.status(404).json({
      ok: false,
      message: 'Endpoint test checkout HP sudah dinonaktifkan untuk keamanan produksi.'
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
  }

  try {
    return await sessionOwnershipCheckoutCreateUnpaidOrder(req, res);
  } catch (error) {
    console.error('[session-ownership-checkout]', sessionOwnershipCheckoutSafeError(error));
    return res.status(500).json({
      ok: false,
      message: 'Checkout belum dapat diproses dengan aman.'
    });
  }
};

function sessionOwnershipCheckoutNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  const aliases = {
    'checkout_order': 'checkout_order',
    'checkout-order': 'checkout_order',
    'public_checkout': 'checkout_order',
    'public-checkout': 'checkout_order',
    'parfum_checkout': 'checkout_order',
    'parfum-checkout': 'checkout_order',
    'digital_checkout': 'checkout_order',
    'digital-checkout': 'checkout_order',
    'layanan_digital_checkout': 'checkout_order',
    'layanan-digital-checkout': 'checkout_order',
    'jasa_website_checkout': 'checkout_order',
    'jasa-website-checkout': 'checkout_order',
    'pengembangan_checkout': 'checkout_order',
    'pengembangan-checkout': 'checkout_order',
    'create_checkout_order': 'checkout_order',
    'create-checkout-order': 'checkout_order',
    'checkout_order_hp_test': 'checkout_order_hp_test',
    'checkout-order-hp-test': 'checkout_order_hp_test',
    'hp_checkout_test': 'checkout_order_hp_test',
    'hp-checkout-test': 'checkout_order_hp_test'
  };
  return aliases[clean] || clean;
}

function sessionOwnershipCheckoutIsAction(action) {
  return action === 'checkout_order' || action === 'checkout_order_hp_test';
}

async function sessionOwnershipCheckoutCreateUnpaidOrder(req, res) {
  // PATCH 3G: checkout/order creation is strict backend-only.
  // A valid login cookie alone is not enough; customer must also have a valid
  // HttpOnly dashboard MFA cookie. This intentionally ignores the old
  // CHECKOUT_REQUIRE_DASHBOARD_MFA=false default.
  const access = await requireDomainDashboardAccess(req, res);
  if (!access || !access.user) return;

  const body = await readBody(req);
  const user = access.user || {};
  const authUserId = String(user.id || '').trim();
  const userEmail = normalizeAuthEmail(user.email || '');
  const submittedEmail = normalizeAuthEmail(body.customer_email || body.email || '');

  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId) || !userEmail || !isValidAuthEmail(userEmail)) {
    return res.status(401).json({ ok: false, message: 'Sesi login tidak valid.' });
  }

  if (submittedEmail && submittedEmail !== userEmail) {
    return res.status(403).json({
      ok: false,
      message: 'Email pesanan harus sama dengan akun yang sedang login. Customer ownership tidak boleh diganti dari frontend.'
    });
  }

  const customerPhone = normalizePhone(body.customer_phone || body.phone || body.whatsapp || body.customer_whatsapp || '');
  const requestedName = sessionOwnershipCheckoutSafeName(body.customer_name || body.name || body.full_name || sessionOwnershipCheckoutUserMetadataName(user) || userEmail);
  const serviceType = sessionOwnershipCheckoutNormalizeServiceType(body.service_type || body.service || 'parfum');
  const quantity = sessionOwnershipCheckoutPositiveInteger(body.quantity || body.qty || 1, 1, 999);
  const requestedProductTitle = sessionOwnershipCheckoutBuildProductTitle(body, serviceType);

  if (!requestedName) return res.status(400).json({ ok: false, message: 'Nama pelanggan wajib diisi.' });
  if (!customerPhone) return res.status(400).json({ ok: false, message: 'Nomor WhatsApp/HP wajib diisi.' });
  if (!requestedProductTitle) return res.status(400).json({ ok: false, message: 'Nama produk/layanan wajib diisi.' });

  const backendQuote = await sessionOwnershipCheckoutBuildBackendQuote({
    body,
    serviceType,
    requestedProductTitle,
    quantity
  });

  if (!backendQuote.ok) {
    return res.status(backendQuote.status || 400).json({
      ok: false,
      message: backendQuote.message || 'Total pesanan belum bisa dikunci oleh backend.'
    });
  }

  const owner = await sessionOwnershipCheckoutResolveCustomerOwner({
    authUserId,
    email: userEmail,
    fullName: requestedName,
    phone: customerPhone
  });

  if (!owner.ok || !owner.customer || !owner.customer.id) {
    return res.status(owner.status || 409).json({
      ok: false,
      message: owner.message || 'Customer ownership belum siap. Login ulang atau hubungi admin.'
    });
  }

  const customer = owner.customer;
  const customerId = String(customer.id || '').trim();
  const orderCode = sessionOwnershipCheckoutGenerateOrderCode();
  const finalCustomerName = sessionOwnershipCheckoutSafeName(customer.name || requestedName || userEmail);
  const finalCustomerEmail = normalizeAuthEmail(customer.email || userEmail);
  const finalCustomerPhone = normalizePhone(customer.phone || customerPhone);

  if (!customerSecurityLooksLikeUuid(customerId)) {
    return res.status(409).json({ ok: false, message: 'Customer ownership tidak valid.' });
  }

  const orderResult = await supabaseFetch('/rest/v1/orders', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      order_id: orderCode,
      customer_id: customerId,
      customer_name: finalCustomerName,
      customer_phone: finalCustomerPhone,
      customer_email: finalCustomerEmail,
      service_type: serviceType,
      subtotal: backendQuote.subtotal,
      total: backendQuote.total,
      payment_method: 'Belum dipilih',
      payment_status: 'unpaid',
      order_status: 'pending'
    }]
  });

  if (!orderResult.ok) {
    return res.status(orderResult.status || 500).json({
      ok: false,
      message: 'Order gagal dibuat.',
      error: sessionOwnershipCheckoutSafeUpstreamError(orderResult.data)
    });
  }

  const order = Array.isArray(orderResult.data) ? orderResult.data[0] : orderResult.data;
  if (!order || !order.id) {
    return res.status(500).json({ ok: false, message: 'Order dibuat, tetapi ID order tidak ditemukan.' });
  }

  const quoteItems = Array.isArray(backendQuote.items) && backendQuote.items.length
    ? backendQuote.items
    : [{
        productDocId: backendQuote.productDocId || '',
        productTitle: backendQuote.productTitle,
        quantity,
        unitPrice: backendQuote.unitPrice,
        costPrice: backendQuote.costPrice,
        subtotal: backendQuote.subtotal
      }];

  const itemBodies = quoteItems.map((item) => {
    const row = {
      order_id: order.id,
      product_title: sessionOwnershipCheckoutCleanText(item.productTitle || backendQuote.productTitle || 'Item pesanan', 180),
      quantity: sessionOwnershipCheckoutPositiveInteger(item.quantity || 1, 1, 999),
      unit_price: sessionOwnershipCheckoutPositiveMoney(item.unitPrice || 0),
      cost_price: sessionOwnershipCheckoutNonNegativeMoney(item.costPrice || 0)
    };
    const productDocId = sessionOwnershipCheckoutCleanText(item.productDocId || '', 80);
    if (productDocId) row.product_doc_id = productDocId;
    return row;
  });

  const itemResult = await supabaseFetch('/rest/v1/order_items', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: itemBodies
  });

  if (!itemResult.ok) {
    return res.status(itemResult.status || 500).json({
      ok: false,
      message: 'Order dibuat, tetapi item order gagal dibuat.',
      error: sessionOwnershipCheckoutSafeUpstreamError(itemResult.data)
    });
  }

  const orderMailNotification = orderMailPendingPaymentSkipSummary('checkout_order');

  return res.status(200).json({
    ok: true,
    message: 'Pesanan berhasil dibuat. Nominal dikunci backend dari database, payment gateway belum aktif.',
    order_id: order.id,
    order_code: order.order_id || orderCode,
    service_type: serviceType,
    total: backendQuote.total,
    subtotal: backendQuote.subtotal,
    currency: 'IDR',
    order_status: 'pending',
    payment_status: 'unpaid',
    payment_url: null,
    dashboard_mfa_required: true,
    payment_gateway_configured: false,
    order_mail_notification: orderMailNotification,
    ownership_locked: true,
    payment_protected: true,
    price_locked_by_backend: backendQuote.priceLocked,
    price_source: backendQuote.priceSource,
    owner_source: owner.source || 'backend_auth_link',
    frontend_ignored_fields: ['customer_id', 'order_id', 'payment_status', 'order_status', 'paid', 'completed', 'payment_url', 'total', 'amount', 'subtotal', 'unit_price', 'cost_price'],
    payment_note: 'Nominal payment gateway wajib memakai total backend ini dan webhook wajib validasi amount == orders.total.',
    item: {
      product_doc_id: backendQuote.productDocId || null,
      product_title: backendQuote.productTitle,
      quantity,
      unit_price: backendQuote.unitPrice,
      cost_price: backendQuote.costPrice,
      subtotal: backendQuote.subtotal
    },
    items: itemBodies.map((item) => ({
      product_doc_id: item.product_doc_id || null,
      product_title: item.product_title,
      quantity: item.quantity,
      unit_price: item.unit_price,
      cost_price: item.cost_price,
      subtotal: item.unit_price * item.quantity
    }))
  });
}

function sessionOwnershipCheckoutExtractParfumItems(body, requestedProductTitle, fallbackQuantity) {
  const items = [];
  const rawItems = Array.isArray(body && body.items) ? body.items : [];

  for (const raw of rawItems) {
    if (!raw || typeof raw !== 'object') continue;
    const title = sessionOwnershipCheckoutCleanText(
      raw.product_title || raw.title || raw.name || raw.product_name || raw.item_name || '',
      180
    );
    const qty = sessionOwnershipCheckoutPositiveInteger(raw.quantity || raw.qty || raw.count || 1, 1, 999);
    if (!title) continue;
    items.push({
      product_doc_id: sessionOwnershipCheckoutCleanText(raw.product_doc_id || raw.doc_id || raw.firebase_id || raw.product_firebase_id || '', 80),
      product_id: sessionOwnershipCheckoutCleanText(raw.product_id || raw.id || '', 80),
      product_title: title,
      title,
      quantity: qty,
      qty
    });
  }

  if (!items.length) {
    const summary = sessionOwnershipCheckoutCleanText(requestedProductTitle || '', 1000);
    if (summary && summary.includes('|')) {
      summary.split('|').map((part) => part.trim()).filter(Boolean).forEach((part) => {
        const cleaned = part.replace(/^\d+[.)]\s*/, '').trim();
        const match = cleaned.match(/^(.*?)\s+x\s*(\d+)\s*$/i);
        const title = sessionOwnershipCheckoutCleanText(match ? match[1] : cleaned, 180);
        const qty = sessionOwnershipCheckoutPositiveInteger(match ? match[2] : 1, 1, 999);
        if (title) items.push({ product_title: title, title, quantity: qty, qty });
      });
    }
  }

  if (!items.length && requestedProductTitle) {
    const title = sessionOwnershipCheckoutCleanText(requestedProductTitle, 180);
    const qty = sessionOwnershipCheckoutPositiveInteger(fallbackQuantity || 1, 1, 999);
    if (title) items.push({ product_title: title, title, quantity: qty, qty });
  }

  return items.slice(0, 50);
}

function sessionOwnershipCheckoutBuildParfumQuoteTitle(items) {
  const lines = (items || []).map((item, index) => {
    const title = sessionOwnershipCheckoutCleanText(item.productTitle || item.product_title || item.title || 'Produk Parfum', 140);
    const qty = sessionOwnershipCheckoutPositiveInteger(item.quantity || item.qty || 1, 1, 999);
    return `${index + 1}. ${title} x${qty}`;
  });
  const summary = lines.join(' | ');
  return summary.length > 480 ? summary.slice(0, 477) + '...' : summary;
}

async function sessionOwnershipCheckoutBuildBackendQuote({ body, serviceType, requestedProductTitle, quantity }) {
  const normalizedServiceType = sessionOwnershipCheckoutNormalizeServiceType(serviceType);

  if (normalizedServiceType === 'parfum') {
    const checkoutItems = sessionOwnershipCheckoutExtractParfumItems(body, requestedProductTitle, quantity);
    const quoteItems = [];
    const requireReady = String(process.env.CHECKOUT_REQUIRE_PRODUCT_READY || 'false').trim().toLowerCase() === 'true';

    if (!checkoutItems.length) {
      return { ok: false, status: 400, message: 'Item parfum wajib diisi.' };
    }

    for (const rawItem of checkoutItems) {
      const itemTitle = sessionOwnershipCheckoutCleanText(rawItem.product_title || rawItem.title || requestedProductTitle, 180);
      const itemQty = sessionOwnershipCheckoutPositiveInteger(rawItem.quantity || rawItem.qty || 1, 1, 999);
      const productResult = await sessionOwnershipCheckoutFindProductForCheckout(rawItem, itemTitle);

      if (!productResult.ok || !productResult.product) {
        return {
          ok: false,
          status: 409,
          message: productResult.message || `Produk parfum "${itemTitle}" tidak ditemukan di database products. Checkout dihentikan supaya nominal tidak bisa dipalsukan.`
        };
      }

      const product = productResult.product;
      const unitPrice = sessionOwnershipCheckoutPositiveMoney(product.price || 0);
      const costPrice = sessionOwnershipCheckoutNonNegativeMoney(product.cost_price || 0);
      const productDocId = sessionOwnershipCheckoutCleanText(product.doc_id || product.firebase_id || '', 80);
      const productTitle = sessionOwnershipCheckoutCleanText(product.title || product.name || itemTitle, 160);

      if (!productDocId) {
        return { ok: false, status: 409, message: `Produk ${productTitle || itemTitle} ditemukan, tetapi doc_id produk kosong. Checkout dihentikan.` };
      }

      if (!unitPrice || unitPrice <= 0) {
        return { ok: false, status: 409, message: `Harga produk ${productTitle || itemTitle} di database masih 0/kosong. Checkout dihentikan supaya nominal tidak bisa dipalsukan.` };
      }

      if (product.is_active === false) {
        return { ok: false, status: 409, message: `Produk ${productTitle || itemTitle} tidak aktif. Checkout dihentikan.` };
      }

      if (requireReady && product.is_ready === false) {
        return { ok: false, status: 409, message: `Produk ${productTitle || itemTitle} belum ready. Checkout dihentikan.` };
      }

      quoteItems.push({
        productDocId,
        productTitle,
        quantity: itemQty,
        unitPrice,
        costPrice,
        subtotal: unitPrice * itemQty,
        product
      });
    }

    const subtotal = quoteItems.reduce((sum, item) => sum + item.subtotal, 0);
    const totalQty = quoteItems.reduce((sum, item) => sum + item.quantity, 0);
    const productTitle = sessionOwnershipCheckoutBuildParfumQuoteTitle(quoteItems);
    const first = quoteItems[0] || {};

    return {
      ok: true,
      priceLocked: true,
      priceSource: 'products.price.multi_item_server_locked',
      productDocId: first.productDocId || '',
      productTitle,
      unitPrice: first.unitPrice || 0,
      costPrice: first.costPrice || 0,
      quantity: totalQty,
      subtotal,
      total: subtotal,
      items: quoteItems,
      product: first.product || null
    };
  }

  // Untuk layanan custom/jasa, nominal boleh dibuat sebagai draft unpaid saja.
  // Payment gateway jangan diaktifkan sebelum totalnya dikunci backend/admin.
  const frontendQuotedTotal = sessionOwnershipCheckoutPositiveMoney(body.total || body.amount || body.subtotal || 0);
  if (!frontendQuotedTotal || frontendQuotedTotal <= 0) {
    return { ok: false, status: 400, message: 'Total layanan custom wajib lebih dari 0.' };
  }

  return {
    ok: true,
    priceLocked: false,
    priceSource: 'manual_unpaid_quote_no_gateway',
    productDocId: '',
    productTitle: requestedProductTitle,
    unitPrice: frontendQuotedTotal,
    costPrice: 0,
    subtotal: frontendQuotedTotal,
    total: frontendQuotedTotal
  };
}

async function sessionOwnershipCheckoutFindProductForCheckout(body, requestedProductTitle) {
  const idCandidates = sessionOwnershipCheckoutProductIdCandidates(body);
  const textCandidates = sessionOwnershipCheckoutProductTextCandidates(body, requestedProductTitle);
  const select = 'doc_id,firebase_id,title,name,price,cost_price,stock,status,is_ready,is_active';

  for (const id of idCandidates) {
    const path = '/rest/v1/products?select=' + encodeURIComponent(select)
      + '&or=' + encodeURIComponent(`(doc_id.eq.${id},firebase_id.eq.${id})`)
      + '&limit=5';
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (result.ok && Array.isArray(result.data) && result.data.length) {
      return { ok: true, product: result.data[0], match: 'id' };
    }
  }

  const listResult = await supabaseFetch('/rest/v1/products?select=' + encodeURIComponent(select) + '&limit=500', {
    method: 'GET',
    auth: 'service'
  });

  if (!listResult.ok) {
    return { ok: false, status: listResult.status || 500, message: 'Gagal membaca products untuk mengunci harga checkout.' };
  }

  const products = Array.isArray(listResult.data) ? listResult.data : [];
  let best = null;

  for (const product of products) {
    const score = sessionOwnershipCheckoutProductScore(product, idCandidates, textCandidates);
    if (!best || score > best.score) best = { product, score };
  }

  if (best && best.score >= 70) {
    return { ok: true, product: best.product, match: 'title', score: best.score };
  }

  return { ok: false, status: 404, message: 'Produk parfum tidak cocok dengan database products.' };
}

function sessionOwnershipCheckoutProductIdCandidates(body) {
  return Array.from(new Set([
    body.product_doc_id,
    body.product_id,
    body.doc_id,
    body.product_firebase_id,
    body.firebase_id,
    body.productDocId,
    body.productId,
    body.firebaseId
  ].map((value) => sessionOwnershipCheckoutCleanText(value, 80)).filter(Boolean)));
}

function sessionOwnershipCheckoutProductTextCandidates(body, requestedProductTitle) {
  const raw = [
    requestedProductTitle,
    body.product_title,
    body.product,
    body.item_name,
    body.product_name,
    body.name,
    body.title
  ];

  const out = [];
  for (const value of raw) {
    const clean = sessionOwnershipCheckoutNormalizeProductText(value);
    if (clean) out.push(clean);

    const beforePipe = sessionOwnershipCheckoutNormalizeProductText(String(value || '').split('|')[0]);
    if (beforePipe) out.push(beforePipe);
  }

  return Array.from(new Set(out.filter(Boolean)));
}

function sessionOwnershipCheckoutNormalizeProductText(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/^[0-9]+[.)\s-]+/, '')
    .replace(/\bx\s*[0-9]+\b/g, '')
    .replace(/[^a-z0-9À-ž]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function sessionOwnershipCheckoutProductScore(product, idCandidates, textCandidates) {
  const docId = String(product && product.doc_id || '').trim();
  const firebaseId = String(product && product.firebase_id || '').trim();
  if (idCandidates.includes(docId) || idCandidates.includes(firebaseId)) return 1000;

  const title = sessionOwnershipCheckoutNormalizeProductText([product && product.title, product && product.name].filter(Boolean).join(' '));
  if (!title) return 0;

  let score = 0;
  for (const candidate of textCandidates) {
    if (!candidate) continue;
    if (candidate === title) score = Math.max(score, 500);
    else if (title.includes(candidate) || candidate.includes(title)) score = Math.max(score, 220);
    else {
      const words = candidate.split(' ').filter((word) => word.length >= 3);
      const hit = words.filter((word) => title.includes(word)).length;
      if (words.length) score = Math.max(score, Math.round((hit / words.length) * 150));
    }
  }

  return score;
}

function sessionOwnershipCheckoutNonNegativeMoney(value) {
  const number = Number(String(value || '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.round(number);
}

async function sessionOwnershipCheckoutResolveCustomerOwner({ authUserId, email, fullName, phone }) {
  const linkResult = await customerSecurityFetchAuthLink(authUserId);

  if (!linkResult.ok) {
    return { ok: false, status: linkResult.status || 500, message: 'Gagal memverifikasi relasi akun dan customer.' };
  }

  const linkRows = Array.isArray(linkResult.data) ? linkResult.data : [];
  const link = linkRows[0] || null;

  if (link && link.link_status === 'active' && link.customer_id && customerSecurityLooksLikeUuid(link.customer_id)) {
    const customer = await sessionOwnershipCheckoutFetchCustomerById(link.customer_id);
    if (customer.ok && customer.customer && customer.customer.id) return { ok: true, customer: customer.customer, source: 'security_customer_auth_links' };
    return { ok: false, status: customer.status || 409, message: 'Auth link aktif ditemukan, tetapi data customer tidak valid.' };
  }

  const customerResult = await sessionOwnershipCheckoutFindOrCreateCustomerForAuth({ email, fullName, phone });
  if (!customerResult.ok || !customerResult.customer || !customerResult.customer.id) {
    return { ok: false, status: customerResult.status || 500, message: customerResult.message || 'Gagal menyiapkan customer untuk akun login.' };
  }

  const linkUpsert = link && link.id
    ? await sessionOwnershipCheckoutActivateAuthLink(authUserId, customerResult.customer.id, email)
    : await sessionOwnershipCheckoutCreateAuthLink(authUserId, customerResult.customer.id, email);

  if (!linkUpsert.ok) {
    return { ok: false, status: linkUpsert.status || 500, message: 'Customer berhasil ditemukan, tetapi auth link gagal dikunci.' };
  }

  return { ok: true, customer: customerResult.customer, source: customerResult.created ? 'backend_created_from_auth_email' : 'backend_matched_auth_email' };
}

async function sessionOwnershipCheckoutFetchCustomerById(customerId) {
  const select = ['id', 'email', 'name', 'phone'].join(',');
  const path = '/rest/v1/customers?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(customerId) + '&limit=1';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status };
  const rows = Array.isArray(result.data) ? result.data : [];
  const row = rows[0] || null;
  if (!row || !row.id) return { ok: false, status: 404 };
  return { ok: true, customer: row };
}

async function sessionOwnershipCheckoutFindOrCreateCustomerForAuth({ email, fullName, phone }) {
  const existing = await customerSecurityFetchCustomerByEmail(email);
  if (!existing.ok) return { ok: false, status: existing.status, message: 'Gagal membaca customer berdasarkan email akun.' };

  const rows = Array.isArray(existing.data) ? existing.data : [];
  if (rows.length && rows[0] && rows[0].id) return { ok: true, customer: rows[0], created: false };

  const body = { name: sessionOwnershipCheckoutSafeName(fullName || email), email };
  if (phone) body.phone = phone;

  const created = await supabaseFetch('/rest/v1/customers', { method: 'POST', auth: 'service', prefer: 'return=representation', body: [body] });
  if (!created.ok) return { ok: false, status: created.status, message: 'Gagal membuat customer dari akun login.' };

  const createdRows = Array.isArray(created.data) ? created.data : [];
  const row = createdRows[0] || created.data;
  if (!row || !row.id) return { ok: false, status: 500, message: 'Customer dibuat, tetapi ID tidak ditemukan.' };
  return { ok: true, customer: row, created: true };
}

async function sessionOwnershipCheckoutActivateAuthLink(authUserId, customerId, email) {
  const path = '/rest/v1/security_customer_auth_links?auth_user_id=eq.' + encodeURIComponent(authUserId);
  return supabaseFetch(path, { method: 'PATCH', auth: 'service', prefer: 'return=representation', body: sessionOwnershipCheckoutActiveAuthLinkBody(customerId, email) });
}

async function sessionOwnershipCheckoutCreateAuthLink(authUserId, customerId, email) {
  return supabaseFetch('/rest/v1/security_customer_auth_links', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{ auth_user_id: authUserId, ...sessionOwnershipCheckoutActiveAuthLinkBody(customerId, email) }]
  });
}

function sessionOwnershipCheckoutActiveAuthLinkBody(customerId, email) {
  return { customer_id: customerId, email, link_status: 'active', link_method: 'system_created', match_confidence: 'verified' };
}

function sessionOwnershipCheckoutBuildProductTitle(body, serviceType) {
  const base = sessionOwnershipCheckoutCleanText(body.product_title || body.product || body.item_name || body.service_name || body.package_name || 'Pesanan DiracGroup', 120);
  const details = [];
  const detailPairs = [
    ['Game', body.game || body.game_name],
    ['User ID', body.user_id || body.player_id],
    ['Zone ID', body.zone_id || body.server_id],
    ['Provider', body.provider || body.operator],
    ['Nomor Tujuan', body.target_number || body.nomor_tujuan || body.phone_target],
    ['Wallet', body.wallet || body.ewallet],
    ['Kartu', body.card_number || body.nomor_kartu],
    ['Negara', body.destination_country || body.negara_tujuan],
    ['Penerima', body.recipient_name || body.nama_penerima],
    ['Website', body.website_url || body.link_website]
  ];
  for (const [label, value] of detailPairs) {
    const clean = sessionOwnershipCheckoutCleanText(value, 70);
    if (clean) details.push(`${label}: ${clean}`);
  }
  const combined = details.length ? `${base} | ${details.join(' | ')}` : base;
  return sessionOwnershipCheckoutCleanText(combined, 160) || sessionOwnershipCheckoutFallbackTitle(serviceType);
}

function sessionOwnershipCheckoutFallbackTitle(serviceType) {
  const labels = {
    parfum: 'Pesanan Parfum', domain: 'Pesanan Domain', jasa_website: 'Jasa Pembuatan Website', pengembangan_website: 'Pengembangan Website',
    topup_game: 'Top Up Game', isi_pulsa: 'Isi Pulsa', paket_data: 'Paket Data', isi_saldo: 'Isi Saldo', isi_saldo_etoll: 'Isi Saldo E-Toll', transfer_luar_negeri: 'Transfer Luar Negeri'
  };
  return labels[serviceType] || 'Pesanan DiracGroup';
}

function sessionOwnershipCheckoutNormalizeServiceType(value) {
  const clean = String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  const aliases = {
    parfum: 'parfum', perfume: 'parfum', domain: 'domain',
    jasa_website: 'jasa_website', jasa_pembuatan_website: 'jasa_website', pembuatan_website: 'jasa_website', website: 'jasa_website',
    pengembangan: 'pengembangan_website', pengembangan_website: 'pengembangan_website', development: 'pengembangan_website',
    topup: 'topup_game', top_up: 'topup_game', topup_game: 'topup_game', top_up_game: 'topup_game', game: 'topup_game',
    isi_pulsa: 'isi_pulsa', pulsa: 'isi_pulsa', paket_data: 'paket_data', data: 'paket_data',
    isi_saldo: 'isi_saldo', saldo: 'isi_saldo', ewallet: 'isi_saldo', e_wallet: 'isi_saldo',
    isi_saldo_etoll: 'isi_saldo_etoll', isi_saldo_e_toll: 'isi_saldo_etoll', etoll: 'isi_saldo_etoll', e_toll: 'isi_saldo_etoll',
    transfer_luar_negeri: 'transfer_luar_negeri', remitansi: 'transfer_luar_negeri', remittance: 'transfer_luar_negeri'
  };
  return aliases[clean] || 'parfum';
}

function sessionOwnershipCheckoutUserMetadataName(user) {
  const meta = user && typeof user === 'object' ? (user.user_metadata || user.raw_user_meta_data || {}) : {};
  return meta.full_name || meta.fullName || meta.name || '';
}

function sessionOwnershipCheckoutSafeName(value) {
  const raw = String(value || '').trim();
  const fromEmail = raw.includes('@') ? raw.split('@')[0] : raw;
  const cleaned = fromEmail.replace(/[^a-zA-Z0-9À-ž ._'-]/g, ' ').replace(/\s+/g, ' ').trim();
  return (cleaned || 'Customer DiracGroup').slice(0, 120);
}

function sessionOwnershipCheckoutCleanText(value, maxLength) {
  return String(value || '').trim().replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').slice(0, Math.max(1, Number(maxLength || 120)));
}

function sessionOwnershipCheckoutPositiveInteger(value, fallback, max) {
  const number = Math.trunc(Number(value));
  if (!Number.isFinite(number) || number < 1) return fallback || 1;
  return Math.min(number, max || 999);
}

function sessionOwnershipCheckoutPositiveMoney(value) {
  const number = Number(String(value || '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(number) || number <= 0) return 0;
  return Math.round(number);
}

function sessionOwnershipCheckoutGenerateOrderCode() {
  const now = new Date();
  const date = now.toISOString().slice(0, 10).replace(/-/g, '');
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `ORD-${date}-${random}`;
}

function sessionOwnershipCheckoutSafeUpstreamError(data) {
  if (!data) return null;
  if (typeof data === 'string') return data.slice(0, 220);
  return String(data.message || data.error || data.detail || data.hint || 'upstream_error').slice(0, 220);
}

function sessionOwnershipCheckoutSafeError(error) {
  return String(error && error.message ? error.message : error).slice(0, 180);
}

/* ============================================================
   CUSTOMER MY ORDERS / PESANAN SAYA - ISOLATED APPEND ONLY
   Tujuan:
   - Tidak mengubah login/hash/A2F/database.
   - Menambah endpoint read-only untuk customer melihat pesanan miliknya sendiri.
   - Backend menentukan owner dari session HttpOnly cookie, bukan dari frontend.
   - Frontend tidak boleh mengirim customer_id.
   Endpoint:
   GET /api/health?action=my_orders
   GET /api/health?action=pesanan_saya
   GET /api/health?action=customer_orders
   ============================================================ */

const __diracMyOrdersPreviousHandler = module.exports;

module.exports = async function myOrdersWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = myOrdersNormalizeAction(rawAction);

  if (!myOrdersIsAction(action)) {
    return __diracMyOrdersPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
  }

  try {
    return await myOrdersReadForCurrentCustomer(req, res);
  } catch (error) {
    console.error('[my-orders]', myOrdersSafeError(error));
    return res.status(500).json({
      ok: false,
      message: 'Pesanan belum dapat dimuat dengan aman.'
    });
  }
};

function myOrdersNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    my_orders: 'my_orders',
    pesanan: 'my_orders',
    pesanan_saya: 'my_orders',
    customer_orders: 'my_orders',
    orders_saya: 'my_orders',
    my_invoices: 'my_orders',
    invoice_saya: 'my_orders'
  };
  return aliases[clean] || clean;
}

function myOrdersIsAction(action) {
  return action === 'my_orders';
}

async function myOrdersReadForCurrentCustomer(req, res) {
  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;
  const user = access.user;

  const authUserId = String(user.id || '').trim();
  const userEmail = normalizeAuthEmail(user.email || '');
  if (!authUserId || !userEmail || !isValidAuthEmail(userEmail)) {
    return res.status(401).json({ ok: false, message: 'Sesi login tidak valid.' });
  }

  const owner = await myOrdersResolveOwner(authUserId, userEmail);
  if (!owner || !Array.isArray(owner.customerIds) || !owner.customerIds.length) {
    return res.status(403).json({
      ok: false,
      service: 'dirac-my-orders',
      ownership_locked: true,
      direct_frontend_table_access: false,
      frontend_customer_id_ignored: true,
      message: 'Akun login belum terhubung ke customer profile aktif. Pesanan dikunci aman agar tidak salah owner.'
    });
  }

  const genericOrders = await myOrdersFetchGenericOrders(owner, userEmail);
  const domainOrders = await myOrdersFetchDomainOrders(owner, userEmail);
  const allOrders = [...genericOrders.orders, ...domainOrders.orders]
    .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
    .slice(0, 120);

  const summary = myOrdersBuildSummary(allOrders);

  return res.status(200).json({
    ok: true,
    service: 'dirac-my-orders',
    dashboard_mfa_required: true,
    dashboard_mfa_source: access.mfa && access.mfa.source || '',
    user: sanitizeUser(user),
    ownership_locked: true,
    direct_frontend_table_access: false,
    frontend_customer_id_ignored: true,
    payment_gateway_configured: false,
    payment_note: 'Payment gateway belum aktif. Order unpaid belum boleh dianggap lunas dan belum boleh diproses sebagai paid.',
    owner: {
      customer_id_available: Boolean(owner.customerIds.length),
      customer_ids_count: owner.customerIds.length,
      source: owner.sources.join(',') || 'auth_email_only'
    },
    summary,
    orders: allOrders,
    diagnostics: {
      generic_orders_ready: genericOrders.ok,
      domain_orders_ready: domainOrders.ok,
      generic_orders_error: genericOrders.error || null,
      domain_orders_error: domainOrders.error || null
    },
    time: diracNowIso()
  });
}

async function myOrdersResolveOwner(authUserId, userEmail) {
  const customerIds = new Set();
  const sources = [];

  try {
    const link = await customerSecurityFetchAuthLink(authUserId);
    if (link && link.ok && Array.isArray(link.data)) {
      link.data.forEach((row) => {
        if (row && row.link_status === 'active' && customerSecurityLooksLikeUuid(row.customer_id)) {
          customerIds.add(String(row.customer_id));
        }
      });
      if (customerIds.size) sources.push('security_customer_auth_links.active');
    }
  } catch (_) {}

  // Strict ownership mode: customers.email is NOT used as an owner fallback.
  // Orders are shown only when the authenticated backend session has an active
  // auth_user_id -> customer_id link. This prevents email-based leakage/misassignment.
  return {
    customerIds: Array.from(customerIds),
    email: userEmail,
    sources: Array.from(new Set(sources))
  };
}

async function myOrdersFetchGenericOrders(owner, userEmail) {
  const orderMap = new Map();
  const errors = [];
  const select = 'id,order_id,customer_id,customer_name,customer_email,customer_phone,service_type,subtotal,total,payment_method,payment_status,order_status,created_at';

  async function addRowsFromPath(path) {
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok) {
      errors.push(myOrdersSafeUpstreamError(result.data) || `HTTP ${result.status}`);
      return;
    }
    const rows = Array.isArray(result.data) ? result.data : [];
    rows.forEach((row) => {
      if (row && row.id) orderMap.set(String(row.id), row);
    });
  }

  // Strict ownership mode: do not query orders by customer_email.
  // Only active backend-resolved customer_id values are used.
  if (owner.customerIds && owner.customerIds.length) {
    const ids = owner.customerIds.filter(customerSecurityLooksLikeUuid).map(encodeURIComponent).join(',');
    if (ids) {
      await addRowsFromPath('/rest/v1/orders?select=' + encodeURIComponent(select) + '&customer_id=in.(' + ids + ')&order=created_at.desc&limit=80');
    }
  }

  const orderRows = Array.from(orderMap.values());
  const itemMap = await myOrdersFetchOrderItems(orderRows.map((row) => row.id));

  return {
    ok: errors.length === 0 || orderRows.length > 0,
    error: errors[0] || '',
    orders: orderRows.map((row) => myOrdersNormalizeGenericOrder(row, itemMap[String(row.id)] || []))
  };
}

async function myOrdersFetchOrderItems(orderIds) {
  const ids = Array.from(new Set((orderIds || []).filter(customerSecurityLooksLikeUuid))).slice(0, 120);
  const map = {};
  if (!ids.length) return map;
  const select = 'id,order_id,product_title,quantity,created_at';
  const path = '/rest/v1/order_items?select=' + encodeURIComponent(select) + '&order_id=in.(' + ids.map(encodeURIComponent).join(',') + ')&order=created_at.asc';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data)) return map;
  result.data.forEach((item) => {
    const orderId = String(item && item.order_id || '');
    if (!orderId) return;
    if (!map[orderId]) map[orderId] = [];
    map[orderId].push({
      id: String(item.id || ''),
      title: myOrdersCleanText(item.product_title || 'Item pesanan', 180),
      quantity: myOrdersPositiveInteger(item.quantity || 1, 1, 999),
      created_at: item.created_at || ''
    });
  });
  return map;
}

function myOrdersNormalizeGenericOrder(row, items) {
  const total = myOrdersMoney(row.total ?? row.subtotal ?? 0);
  const orderCode = myOrdersCleanText(row.order_id || row.id, 80);
  return {
    type: 'standard_order',
    id: String(row.id || ''),
    order_id: orderCode,
    invoice_code: orderCode,
    service_type: myOrdersCleanText(row.service_type || 'order', 80),
    service_label: myOrdersServiceLabel(row.service_type),
    customer_name: myOrdersCleanText(row.customer_name || '', 120),
    customer_email: normalizeAuthEmail(row.customer_email || ''),
    customer_phone: myOrdersCleanText(row.customer_phone || '', 80),
    subtotal: myOrdersMoney(row.subtotal ?? total),
    total,
    currency: 'IDR',
    payment_method: myOrdersCleanText(row.payment_method || 'Belum dipilih', 80),
    payment_status: myOrdersStatus(row.payment_status || 'unpaid'),
    order_status: myOrdersStatus(row.order_status || row.status || 'pending'),
    payment_url: null,
    can_pay: false,
    payment_gateway_configured: false,
    payment_message: 'Payment gateway belum aktif. Invoice ini belum bisa dibayar otomatis.',
    created_at: row.created_at || '',
    items: Array.isArray(items) && items.length ? items : [{ title: 'Item pesanan', quantity: 1 }]
  };
}

async function myOrdersFetchDomainOrders(owner, userEmail) {
  const errors = [];
  const select = 'id,customer_id,customer_name,customer_whatsapp,customer_email,owner_email,dns_method,target_platform,domain_name,total_price,currency,order_status,status,payment_status,created_at';
  const rowsMap = new Map();

  async function add(path) {
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
    if (!result || !result.ok) {
      errors.push(result ? (myOrdersSafeUpstreamError(result.data) || `HTTP ${result.status}`) : 'request_failed');
      return;
    }
    (Array.isArray(result.data) ? result.data : []).forEach((row) => {
      if (row && row.id) rowsMap.set(String(row.id), row);
    });
  }

  // Strict ownership mode: domain_orders are queried only through backend-resolved customer_id links.
  // Never use frontend customer_id, customer_email, or removed legacy user_id as ownership source.
  if (owner && Array.isArray(owner.customerIds) && owner.customerIds.length) {
    const ids = owner.customerIds.filter(customerSecurityLooksLikeUuid).map(encodeURIComponent).join(',');
    if (ids) {
      await add('/rest/v1/domain_orders?select=' + encodeURIComponent(select) + '&customer_id=in.(' + ids + ')&order=created_at.desc&limit=80');
    }
  }

  const rows = Array.from(rowsMap.values());
  const itemMap = await myOrdersFetchDomainOrderItems(rows.map((row) => row.id));
  return {
    ok: errors.length === 0 || rows.length > 0,
    error: errors[0] || '',
    orders: rows.map((row) => myOrdersNormalizeDomainOrder(row, itemMap[String(row.id)] || []))
  };
}

async function myOrdersFetchDomainOrderItems(orderIds) {
  const ids = Array.from(new Set((orderIds || []).filter(customerSecurityLooksLikeUuid))).slice(0, 120);
  const map = {};
  if (!ids.length) return map;
  const select = 'id,order_id,domain_name,extension,years,register_price,renewal_price,subtotal';
  const path = '/rest/v1/domain_order_items?select=' + encodeURIComponent(select) + '&order_id=in.(' + ids.map(encodeURIComponent).join(',') + ')';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data)) return map;
  result.data.forEach((item) => {
    const orderId = String(item && item.order_id || '');
    if (!orderId) return;
    if (!map[orderId]) map[orderId] = [];
    map[orderId].push({
      id: String(item.id || ''),
      title: myOrdersCleanText(item.domain_name || 'Domain', 180),
      quantity: myOrdersPositiveInteger(item.years || 1, 1, 10),
      subtotal: myOrdersMoney(item.subtotal || item.register_price || 0),
      extension: myOrdersCleanText(item.extension || '', 40)
    });
  });
  return map;
}

function myOrdersNormalizeDomainOrder(row, items) {
  const total = myOrdersMoney(row.total_price ?? row.total_amount ?? 0);
  const invoiceCode = 'DOM-' + String(row.id || '').slice(0, 8).toUpperCase();
  const normalizedItems = Array.isArray(items) && items.length
    ? items
    : (row.domain_name ? [{ title: myOrdersCleanText(row.domain_name, 180), quantity: 1, subtotal: total }] : []);
  return {
    type: 'domain_order',
    id: String(row.id || ''),
    order_id: String(row.id || ''),
    invoice_code: invoiceCode,
    service_type: 'domain',
    service_label: 'Domain',
    customer_name: myOrdersCleanText(row.customer_name || '', 120),
    customer_email: normalizeAuthEmail(row.customer_email || row.owner_email || ''),
    customer_phone: myOrdersCleanText(row.customer_whatsapp || '', 80),
    subtotal: total,
    total,
    currency: String(row.currency || 'IDR').toUpperCase(),
    payment_method: 'Belum dipilih',
    payment_status: myOrdersStatus(row.payment_status || 'unpaid'),
    order_status: myOrdersStatus(row.order_status || row.status || 'pending'),
    payment_url: null,
    can_pay: false,
    payment_gateway_configured: false,
    payment_message: 'Payment gateway domain belum aktif di halaman ini.',
    created_at: row.created_at || '',
    items: normalizedItems.length ? normalizedItems : [{ title: 'Domain order', quantity: 1, subtotal: total }]
  };
}

function myOrdersBuildSummary(orders) {
  const rows = Array.isArray(orders) ? orders : [];
  return {
    total_orders: rows.length,
    unpaid: rows.filter((row) => row.payment_status === 'unpaid').length,
    paid: rows.filter((row) => row.payment_status === 'paid').length,
    pending: rows.filter((row) => row.order_status === 'pending' || row.order_status === 'pending_payment').length,
    processing: rows.filter((row) => row.order_status === 'processing').length,
    completed: rows.filter((row) => row.order_status === 'completed').length,
    failed: rows.filter((row) => row.order_status === 'failed' || row.order_status === 'cancelled').length,
    unpaid_total: rows.filter((row) => row.payment_status === 'unpaid').reduce((sum, row) => sum + myOrdersMoney(row.total || 0), 0)
  };
}

function myOrdersServiceLabel(value) {
  const key = String(value || '').trim().toLowerCase();
  const labels = {
    parfum: 'Parfum', domain: 'Domain', jasa_website: 'Jasa Website', pengembangan_website: 'Pengembangan Website',
    topup_game: 'Top Up Game', isi_pulsa: 'Isi Pulsa', paket_data: 'Paket Data', isi_saldo: 'Isi Saldo', isi_saldo_etoll: 'Isi Saldo E-Toll', transfer_luar_negeri: 'Transfer Luar Negeri'
  };
  return labels[key] || myOrdersCleanText(value || 'Pesanan', 80).replace(/_/g, ' ');
}

function myOrdersStatus(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown';
}

function myOrdersCleanText(value, maxLength) {
  return String(value || '').trim().replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').slice(0, Math.max(1, Number(maxLength || 120)));
}

function myOrdersPositiveInteger(value, fallback, max) {
  const number = Math.trunc(Number(value));
  if (!Number.isFinite(number) || number < 1) return fallback || 1;
  return Math.min(number, max || 999);
}

function myOrdersMoney(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.round(number);
}

function myOrdersSafeUpstreamError(data) {
  if (!data) return '';
  if (typeof data === 'string') return data.slice(0, 180);
  return String(data.message || data.error || data.detail || data.hint || 'upstream_error').slice(0, 180);
}

function myOrdersSafeError(error) {
  return String(error && error.message ? error.message : error).slice(0, 180);
}

/* ============================================================
   LOCKED CREATE PAYMENT - APPEND ONLY
   Tujuan:
   - Tidak menyentuh login/hash/A2F.
   - Frontend hanya boleh kirim order_id/order_code.
   - Nominal gateway selalu dari orders.total di database.
   - Payment hanya dibuat untuk order milik customer login.
   - Default hanya mengizinkan parfum; service custom/jasa jangan aktif gateway
     sebelum totalnya dikunci backend/admin.
   Endpoint:
   POST /api/health?action=create_payment
   POST /api/health?action=create-payment
   POST /api/health?action=pay_order
   ============================================================ */

const __diracLockedCreatePaymentPreviousHandler = module.exports;

module.exports = async function lockedCreatePaymentWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = lockedPaymentNormalizeAction(rawAction);

  if (!lockedPaymentIsAction(action)) {
    return __diracLockedCreatePaymentPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
  }

  try {
    return await lockedPaymentCreateForOrder(req, res);
  } catch (error) {
    console.error('[locked-create-payment]', lockedPaymentSafeError(error));
    return res.status(error && error.statusCode ? error.statusCode : 500).json({
      ok: false,
      message: 'Payment belum dapat dibuat dengan aman.',
      error: lockedPaymentPublicError(error)
    });
  }
};

function lockedPaymentNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  const aliases = {
    'create_payment': 'create_payment',
    'create-payment': 'create_payment',
    'pay_order': 'create_payment',
    'pay-order': 'create_payment',
    'order_payment': 'create_payment',
    'order-payment': 'create_payment',
    'create_payment_order': 'create_payment',
    'create-payment-order': 'create_payment'
  };
  return aliases[clean] || clean;
}

function lockedPaymentIsAction(action) {
  return action === 'create_payment';
}

async function lockedPaymentCreateForOrder(req, res) {
  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;
  const user = access.user;

  const body = await readBody(req);
  const query = (req && req.query) || {};
  const requestedOrderId = lockedPaymentCleanText(
    body.order_id || body.orderId || body.id || body.order_code || body.orderCode || body.invoice_code ||
    query.order_id || query.orderId || query.id || query.order_code || query.orderCode || query.invoice_code ||
    '',
    120
  );

  if (!requestedOrderId) {
    return res.status(400).json({ ok: false, message: 'order_id wajib dikirim. Jangan kirim amount/total dari frontend.' });
  }

  if (body.amount !== undefined || body.total !== undefined || body.payment_status !== undefined || body.paid !== undefined || body.completed !== undefined) {
    // Tidak langsung reject agar frontend lama tidak patah, tapi semua field ini tetap diabaikan total.
    console.warn('[locked-create-payment] ignored frontend payment fields', {
      hasAmount: body.amount !== undefined,
      hasTotal: body.total !== undefined,
      hasPaymentStatus: body.payment_status !== undefined,
      hasPaid: body.paid !== undefined,
      hasCompleted: body.completed !== undefined
    });
  }

  const authUserId = String(user.id || '').trim();
  const userEmail = normalizeAuthEmail(user.email || '');
  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId) || !userEmail || !isValidAuthEmail(userEmail)) {
    return res.status(401).json({ ok: false, message: 'Sesi login tidak valid.' });
  }

  const owner = await sessionOwnershipCheckoutResolveCustomerOwner({
    authUserId,
    email: userEmail,
    fullName: userEmail,
    phone: ''
  });

  if (!owner.ok || !owner.customer || !owner.customer.id) {
    return res.status(owner.status || 409).json({
      ok: false,
      message: owner.message || 'Customer ownership belum siap. Login ulang atau hubungi admin.'
    });
  }

  const customer = owner.customer;
  const customerId = String(customer.id || '').trim();
  if (!customerSecurityLooksLikeUuid(customerId)) {
    return res.status(409).json({ ok: false, message: 'Customer ownership tidak valid.' });
  }

  const order = await lockedPaymentFetchOwnedOrder(requestedOrderId, customerId);
  if (!order.ok) {
    return res.status(order.status || 404).json({ ok: false, message: order.message || 'Order tidak ditemukan untuk akun ini.' });
  }

  const row = order.order;
  const orderId = String(row.id || '').trim();
  const orderCode = lockedPaymentCleanText(row.order_id || orderId, 100);
  const serviceType = lockedPaymentNormalizeServiceType(row.service_type || '');
  const amount = lockedPaymentMoney(row.total);
  const paymentStatus = lockedPaymentStatus(row.payment_status || 'unpaid');
  const orderStatus = lockedPaymentStatus(row.order_status || 'pending');

  if (!customerSecurityLooksLikeUuid(orderId)) {
    return res.status(409).json({ ok: false, message: 'Order ID database tidak valid.' });
  }

  if (paymentStatus !== 'unpaid' && paymentStatus !== 'pending') {
    return res.status(409).json({ ok: false, message: `Order tidak bisa dibayar karena status pembayaran ${paymentStatus}.` });
  }

  if (amount <= 0) {
    return res.status(409).json({ ok: false, message: 'Total order 0/kosong. Payment gateway tidak boleh dibuat.' });
  }

  const allowCustom = String(process.env.PAYMENT_ALLOW_CUSTOM_SERVICE_PAYMENT || 'false').trim().toLowerCase() === 'true';
  if (serviceType !== 'parfum' && !allowCustom) {
    return res.status(409).json({
      ok: false,
      message: 'Payment gateway otomatis baru diaktifkan untuk parfum. Layanan custom harus dikunci admin/backend dulu.'
    });
  }

  const itemCheck = await lockedPaymentValidateOrderItems(orderId, amount, serviceType);
  if (!itemCheck.ok) {
    return res.status(itemCheck.status || 409).json({ ok: false, message: itemCheck.message });
  }

  const existing = await lockedPaymentFindReusableTransaction(orderId, customerId, amount);
  if (existing.ok && existing.transaction && existing.transaction.payment_url) {
    return res.status(200).json({
      ok: true,
      reused: true,
      message: 'Payment sudah pernah dibuat untuk order ini. Menggunakan payment URL yang sama.',
      order_id: orderId,
      order_code: orderCode,
      payment_transaction_id: existing.transaction.id,
      gateway_reference: existing.transaction.gateway_reference || null,
      amount,
      currency: String(existing.transaction.currency || 'IDR').toUpperCase(),
      payment_status: existing.transaction.payment_status || 'unpaid',
      payment_url: existing.transaction.payment_url,
      amount_source: 'orders.total.database',
      ownership_locked: true,
      frontend_ignored_fields: ['amount', 'total', 'payment_status', 'paid', 'completed', 'customer_id']
    });
  }

  const endpoint = '';
  if (!midtransPaymentIsConfigured()) {
    return res.status(503).json({
      ok: false,
      payment_gateway_configured: false,
      provider: 'midtrans',
      message: 'Payment gateway Midtrans belum disetel. Isi MIDTRANS_SERVER_KEY atau MIDTRANS_SANDBOX_SERVER_KEY di Environment Variables Vercel.'
    });
  }

  const gatewayName = lockedPaymentGatewayName();
  const gatewayReference = lockedPaymentGenerateReference(orderCode);
  const nowIso = diracNowIso();

  const transactionResult = await lockedPaymentInsertTransaction({
    orderId,
    customerId,
    serviceType,
    gatewayName,
    gatewayReference,
    amount,
    currency: 'IDR',
    metadata: {
      order_code: orderCode,
      order_status: orderStatus,
      amount_source: 'orders.total.database',
      item_total: itemCheck.totalItem,
      create_payment_started_at: nowIso,
      frontend_amount_ignored: body.amount !== undefined || body.total !== undefined,
      owner_source: owner.source || 'backend_auth_link'
    }
  });

  if (!transactionResult.ok) {
    return res.status(transactionResult.status || 500).json({
      ok: false,
      message: 'Gagal menyimpan transaksi payment.',
      error: lockedPaymentSafeUpstreamError(transactionResult.data)
    });
  }

  const transaction = Array.isArray(transactionResult.data) ? transactionResult.data[0] : transactionResult.data;
  if (!transaction || !transaction.id) {
    return res.status(500).json({ ok: false, message: 'Transaksi payment dibuat, tetapi ID tidak ditemukan.' });
  }

  const gateway = await lockedPaymentCreateGatewayInvoice({
    endpoint,
    gatewayName,
    gatewayReference,
    transactionId: transaction.id,
    orderId,
    orderCode,
    amount,
    currency: 'IDR',
    customer: {
      name: customer.name || userEmail,
      email: customer.email || userEmail,
      phone: customer.phone || ''
    },
    items: itemCheck.items,
    serviceType
  });

  if (!gateway.ok || !gateway.paymentUrl) {
    await lockedPaymentMarkTransactionGatewayFailed(transaction.id, gateway.error || 'gateway_create_failed', gateway.raw || null);
    return res.status(gateway.status || 502).json({
      ok: false,
      message: gateway.message || 'Gateway gagal membuat URL pembayaran.',
      payment_transaction_id: transaction.id,
      amount,
      currency: 'IDR'
    });
  }

  const patchResult = await lockedPaymentPatchTransactionUrl(transaction.id, gateway.paymentUrl, gateway.invoiceId, gateway.raw);
  if (!patchResult.ok) {
    return res.status(patchResult.status || 500).json({
      ok: false,
      message: 'Gateway sudah membuat invoice, tetapi payment URL gagal disimpan ke database.',
      payment_transaction_id: transaction.id,
      payment_url: gateway.paymentUrl,
      error: lockedPaymentSafeUpstreamError(patchResult.data)
    });
  }

  return res.status(200).json({
    ok: true,
    message: 'Payment berhasil dibuat. Nominal dikunci dari database.',
    order_id: orderId,
    order_code: orderCode,
    payment_transaction_id: transaction.id,
    gateway_reference: gatewayReference,
    amount,
    currency: 'IDR',
    payment_status: 'unpaid',
    payment_url: gateway.paymentUrl,
    payment_provider: gateway.provider || gatewayName,
    invoice_id: gateway.invoiceId || null,
    amount_source: 'orders.total.database',
    ownership_locked: true,
    amount_locked: true,
    frontend_ignored_fields: ['amount', 'total', 'payment_status', 'paid', 'completed', 'customer_id'],
    webhook_required_checks: ['signature', 'gateway_event_id_unique', 'amount_equals_orders_total', 'currency_IDR', 'paid_or_settled_status']
  });
}

async function lockedPaymentFetchOwnedOrder(inputOrderId, customerId) {
  const select = ['id', 'order_id', 'customer_id', 'service_type', 'total', 'payment_status', 'order_status', 'created_at'].join(',');
  const clean = lockedPaymentCleanText(inputOrderId, 120);
  const filters = [];

  if (customerSecurityLooksLikeUuid(clean)) filters.push(`id.eq.${clean}`);
  filters.push(`order_id.eq.${clean}`);

  const path = '/rest/v1/orders?select=' + encodeURIComponent(select)
    + '&customer_id=eq.' + encodeURIComponent(customerId)
    + '&or=' + encodeURIComponent(`(${filters.join(',')})`)
    + '&limit=1';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status, message: 'Gagal membaca order.' };

  const rows = Array.isArray(result.data) ? result.data : [];
  const row = rows[0] || null;
  if (!row || !row.id) return { ok: false, status: 404, message: 'Order tidak ditemukan atau bukan milik akun ini.' };
  return { ok: true, order: row };
}

async function lockedPaymentValidateOrderItems(orderId, orderTotal, serviceType) {
  const amount = lockedPaymentMoney(orderTotal);
  const fallback = (reason) => lockedPaymentBuildFallbackOrderItem(amount, serviceType, reason);

  const select = 'id,order_id,product_doc_id,product_title,quantity,unit_price,cost_price';
  const path = '/rest/v1/order_items?select=' + encodeURIComponent(select) + '&order_id=eq.' + encodeURIComponent(orderId);
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch((error) => ({
    ok: false,
    status: 500,
    data: { message: String(error && error.message ? error.message : error) }
  }));

  // PATCH payment-items-fallback-v1:
  // Jika schema order_items berbeda/kolom belum lengkap/kosong, jangan hentikan payment.
  // Amount tetap dikunci dari orders.total database; frontend amount tetap diabaikan.
  // Midtrans tetap membutuhkan item_details, maka dipakai 1 item aman berbasis total database.
  if (!result.ok) {
    console.warn('[locked-create-payment] order_items read fallback', {
      status: result.status || 0,
      reason: lockedPaymentSafeUpstreamError(result.data) || 'order_items_read_failed'
    });
    return fallback('order_items_read_failed');
  }

  const rows = Array.isArray(result.data) ? result.data : [];
  if (!rows.length) return fallback('order_items_empty');

  let total = 0;
  const items = [];
  for (const row of rows) {
    const quantity = lockedPaymentPositiveInteger(row && row.quantity, 0, 9999);
    const unitPrice = lockedPaymentMoney(row && row.unit_price);
    const title = lockedPaymentCleanText(row && row.product_title || 'Item pesanan', 180);

    if (quantity <= 0 || unitPrice <= 0 || !title) continue;

    const subtotal = quantity * unitPrice;
    total += subtotal;
    items.push({
      id: String(row && row.id || ''),
      product_doc_id: lockedPaymentCleanText(row && row.product_doc_id || '', 80) || null,
      title,
      quantity,
      unit_price: unitPrice,
      subtotal
    });
  }

  if (!items.length) return fallback('order_items_invalid_or_incomplete');

  if (lockedPaymentMoney(total) !== amount) {
    return fallback('order_items_total_mismatch');
  }

  return { ok: true, totalItem: total, items };
}

function lockedPaymentBuildFallbackOrderItem(amount, serviceType, reason) {
  const safeAmount = lockedPaymentMoney(amount);
  if (safeAmount <= 0) {
    return { ok: false, status: 409, message: 'Total order 0/kosong. Payment gateway tidak boleh dibuat.' };
  }

  const label = typeof myOrdersServiceLabel === 'function'
    ? myOrdersServiceLabel(serviceType)
    : '';
  const title = lockedPaymentCleanText(label || serviceType || 'Total pesanan', 180) || 'Total pesanan';

  return {
    ok: true,
    totalItem: safeAmount,
    fallback_item: true,
    fallback_reason: lockedPaymentCleanText(reason || 'database_total_fallback', 80),
    items: [{
      id: 'order-total',
      product_doc_id: null,
      title,
      quantity: 1,
      unit_price: safeAmount,
      subtotal: safeAmount
    }]
  };
}

async function lockedPaymentFindReusableTransaction(orderId, customerId, amount) {
  const select = 'id,order_id,customer_id,service_type,gateway_name,gateway_reference,payment_status,amount,currency,payment_url,expired_at,created_at';
  const statuses = ['unpaid', 'pending', 'created'].join(',');
  const path = '/rest/v1/payment_transactions?select=' + encodeURIComponent(select)
    + '&order_id=eq.' + encodeURIComponent(orderId)
    + '&customer_id=eq.' + encodeURIComponent(customerId)
    + '&amount=eq.' + encodeURIComponent(String(amount))
    + '&payment_status=in.(' + statuses + ')'
    + '&order=created_at.desc&limit=5';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status };

  const rows = Array.isArray(result.data) ? result.data : [];
  const now = Date.now();
  const reusable = rows.find((row) => {
    if (!row || !row.payment_url) return false;
    if (!row.expired_at) return true;
    const expires = new Date(row.expired_at).getTime();
    return Number.isFinite(expires) && expires > now;
  });

  return { ok: true, transaction: reusable || null };
}

async function lockedPaymentInsertTransaction(data) {
  const body = {
    customer_id: data.customerId,
    service_type: data.serviceType,
    gateway_name: data.gatewayName,
    gateway_reference: data.gatewayReference,
    payment_status: 'unpaid',
    amount: data.amount,
    currency: data.currency || 'IDR',
    metadata: data.metadata || {}
  };

  if (data.orderId) body.order_id = data.orderId;
  if (data.domainOrderId) body.domain_order_id = data.domainOrderId;

  return supabaseFetch('/rest/v1/payment_transactions', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [body]
  });
}

async function lockedPaymentPatchTransactionUrl(transactionId, paymentUrl, invoiceId, raw) {
  const metadata = {
    gateway_invoice_id: invoiceId || null,
    gateway_created_at: diracNowIso(),
    gateway_debug_patch: lockedPaymentResolveGatewayDebugPatch(raw),
    gateway_raw: raw || null
  };

  const body = {
    payment_url: paymentUrl,
    metadata
  };


  return supabaseFetch('/rest/v1/payment_transactions?id=eq.' + encodeURIComponent(transactionId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body
  });
}

async function lockedPaymentMarkTransactionGatewayFailed(transactionId, error, raw) {
  const metadata = {
    gateway_failed_at: diracNowIso(),
    gateway_debug_patch: lockedPaymentResolveGatewayDebugPatch(raw),
    gateway_error: lockedPaymentCleanText(error, 500) || 'gateway_create_failed'
  };

  const upstreamMessage = getUpstreamMessage(raw) || lockedPaymentSafeUpstreamError(raw);
  if (upstreamMessage) metadata.gateway_response = lockedPaymentCleanText(upstreamMessage, 1000);

  if (raw && typeof raw === 'object') {
    const status = raw.http_status || raw.status || raw.status_code || raw.statusCode || raw.status_message || raw.statusMessage || '';
    if (status) metadata.gateway_status = lockedPaymentCleanText(status, 120);
  }

  const safeRaw = lockedPaymentSafeMetadataRaw(raw);
  metadata.gateway_raw_present = safeRaw !== null;
  if (safeRaw !== null) metadata.gateway_raw = safeRaw;

  return supabaseFetch('/rest/v1/payment_transactions?id=eq.' + encodeURIComponent(transactionId), {
    method: 'PATCH',
    auth: 'service',
    body: { metadata }
  }).catch(() => null);
}

function lockedPaymentSafeMetadataRaw(value, depth = 0) {
  if (value === undefined || value === null) return null;
  if (depth > 4) return '[depth_limited]';

  if (typeof value === 'string') return value.slice(0, 2000);
  if (typeof value === 'number' || typeof value === 'boolean') return value;

  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => lockedPaymentSafeMetadataRaw(item, depth + 1));
  }

  if (typeof value === 'object') {
    const out = {};
    let count = 0;
    for (const [key, item] of Object.entries(value)) {
      if (count >= 40) break;
      const safeKey = String(key || '').slice(0, 80);
      if (/authorization|server_key|client_key|secret|token|password|apikey|api_key|bearer/i.test(safeKey)) {
        out[safeKey] = '[redacted]';
      } else {
        out[safeKey] = lockedPaymentSafeMetadataRaw(item, depth + 1);
      }
      count += 1;
    }
    return out;
  }

  return String(value).slice(0, 500);
}

async function lockedPaymentCreateGatewayInvoice(input) {
  // MIDTRANS ONLY v1:
  // Regular/service payment hanya boleh memakai Midtrans Snap.
  // iPaymu dan gateway eksternal tidak dipakai agar provider aktif tunggal.
  if (midtransPaymentIsConfigured()) {
    return await midtransCreateSnapPayment(input);
  }

  return {
    ok: false,
    status: 503,
    provider: 'midtrans',
    message: 'Payment gateway Midtrans belum dikonfigurasi. Isi MIDTRANS_SERVER_KEY atau MIDTRANS_SANDBOX_SERVER_KEY.',
    error: 'midtrans_not_configured'
  };
}

function lockedPaymentExtractPaymentUrl(data) {
  if (!data || typeof data !== 'object') return '';
  const direct = data.payment_url || data.invoice_url || data.redirect_url || data.checkout_url || data.paymentUrl || data.url;
  if (direct) return String(direct).trim();
  const nested = data.data && typeof data.data === 'object'
    ? (data.data.payment_url || data.data.invoice_url || data.data.redirect_url || data.data.checkout_url || data.data.paymentUrl || data.data.url)
    : '';
  return String(nested || '').trim();
}

function lockedPaymentExtractInvoiceId(data) {
  if (!data || typeof data !== 'object') return '';
  const direct = data.invoice_id || data.id || data.external_id || data.reference || data.gateway_reference;
  if (direct) return String(direct).trim();
  const nested = data.data && typeof data.data === 'object'
    ? (data.data.invoice_id || data.data.id || data.data.external_id || data.data.reference || data.data.gateway_reference)
    : '';
  return String(nested || '').trim();
}

function lockedPaymentGatewayEndpoint() {
  // MIDTRANS ONLY v1: endpoint gateway eksternal tidak dibaca agar gateway aktif tunggal.
  return '';
}

function lockedPaymentGatewaySecret() {
  return String(process.env.PAYMENT_CREATE_SECRET || process.env.ORDER_PAYMENT_CREATE_SECRET || process.env.DOMAIN_PAYMENT_CREATE_SECRET || '').trim();
}

function lockedPaymentGatewayName() {
  // MIDTRANS ONLY v1: abaikan env lama PAYMENT_GATEWAY_NAME=ipaymu agar transaksi baru konsisten ke Midtrans.
  return 'midtrans';
}

function lockedPaymentResolveGatewayDebugPatch(raw) {
  const provider = String(raw && (raw.provider || raw.gateway || raw.payment_provider) || '').trim().toLowerCase();
  if (provider === 'ipaymu') return DIRAC_IPAYMU_PATCH;
  if (provider === 'midtrans') return DIRAC_MIDTRANS_DEBUG_PATCH;
  const debugPatch = String(raw && raw.debugPatch || '').trim();
  if (debugPatch) return debugPatch.slice(0, 80);
  return DIRAC_MIDTRANS_DEBUG_PATCH;
}

function lockedPaymentGenerateReference(orderCode) {
  // PATCH midtrans-order-id-short-v3:
  // Midtrans Snap sensitif terhadap panjang transaction_details.order_id.
  // Format lama dapat >50 karakter, sehingga Midtrans mengembalikan HTTP 400.
  const base = lockedPaymentCleanText(orderCode || 'ORDER', 80).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 20) || 'ORDER';
  const ts = Date.now().toString(36).toUpperCase();
  const rnd = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `PAY-${base}-${ts}-${rnd}`.slice(0, 48);
}

function lockedPaymentNormalizeServiceType(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown';
}

function lockedPaymentStatus(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown';
}

function lockedPaymentPositiveInteger(value, fallback, max) {
  const number = Math.trunc(Number(value));
  if (!Number.isFinite(number) || number < 1) return fallback || 0;
  return Math.min(number, max || 9999);
}

function lockedPaymentMoney(value) {
  const number = Number(String(value || '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.round(number);
}

function lockedPaymentCleanText(value, maxLength) {
  return String(value || '').trim().replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').slice(0, Math.max(1, Number(maxLength || 120)));
}

function lockedPaymentSafeUpstreamError(data) {
  if (!data) return null;
  if (typeof data === 'string') return data.slice(0, 220);
  const message = getUpstreamMessage(data);
  if (message) return message.slice(0, 220);
  if (data && typeof data === 'object' && (data.status_code || data.status || data.http_status)) {
    return String(data.status_message || data.status_code || data.status || data.http_status || 'upstream_error').slice(0, 220);
  }
  return 'upstream_error';
}

function lockedPaymentSafeError(error) {
  return String(error && error.message ? error.message : error).slice(0, 180);
}

function lockedPaymentPublicError(error) {
  const text = lockedPaymentSafeError(error);
  if (!text) return null;
  if (/secret|token|key|authorization|bearer/i.test(text)) return 'internal_payment_error';
  return text;
}

/* ============================================================
   MIDTRANS SNAP + WEBHOOK - APPEND ONLY - 2026-06-10
   Guard:
   - Tidak membuat file API baru; tetap memakai /api/health?action=midtrans_webhook.
   - Tidak menyentuh login/hash/A2F/recovery.
   - Create Snap memakai nominal yang sudah dikunci backend/database.
   - Webhook hanya memproses jika signature Midtrans valid, amount cocok,
     customer/order cocok, dan event idempotent.
   ============================================================ */

const __diracMidtransPaymentPreviousHandler = module.exports;

module.exports = async function midtransPaymentWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = midtransNormalizeAction(rawAction);

  if (!midtransIsWebhookAction(action) && action !== 'midtrans_health') {
    return __diracMidtransPaymentPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  if (action === 'midtrans_health') {
    const selectedKey = midtransSelectedServerKeyInfo();
    return res.status(200).json({
      ok: true,
      provider: 'midtrans',
      snapConfigured: selectedKey.configured,
      webhook: '/api/health?action=midtrans_webhook',
      environment: midtransIsProduction() ? 'production' : 'sandbox',
      debugPatch: DIRAC_MIDTRANS_DEBUG_PATCH,
      keyDebug: {
        selectedSource: selectedKey.source,
        prefix: selectedKey.prefix,
        length: selectedKey.length,
        sha256_12: selectedKey.sha256_12,
        sandboxServerKeyPresent: Boolean(String(process.env.MIDTRANS_SANDBOX_SERVER_KEY || '').trim()),
        genericServerKeyPresent: Boolean(String(process.env.MIDTRANS_SERVER_KEY || '').trim()),
        clientKeyPresent: Boolean(String(process.env.MIDTRANS_CLIENT_KEY || process.env.NEXT_PUBLIC_MIDTRANS_CLIENT_KEY || '').trim()),
        expectedPrefix: midtransIsProduction() ? 'Mid-server-' : 'SB-Mid-server-',
        prefixMatchesEnvironment: selectedKey.prefixMatchesEnvironment,
        dashboardKeyAccepted: selectedKey.dashboardKeyAccepted,
        prefixPolicy: 'warning_only_use_key_exactly_from_midtrans_dashboard',
        valueHasOuterWhitespace: selectedKey.valueHasOuterWhitespace
      }
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Gunakan POST untuk webhook Midtrans.' });
  }

  try {
    return await midtransHandleWebhook(req, res);
  } catch (error) {
    console.error('[midtrans-webhook]', lockedPaymentSafeError(error));
    return res.status(error && error.statusCode ? error.statusCode : 500).json({
      ok: false,
      message: 'Webhook Midtrans gagal diproses dengan aman.',
      error: lockedPaymentPublicError(error)
    });
  }
};

function midtransNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase();
  const aliases = {
    'midtrans_webhook': 'midtrans_webhook',
    'midtrans-webhook': 'midtrans_webhook',
    'midtrans_notification': 'midtrans_webhook',
    'midtrans-notification': 'midtrans_webhook',
    'midtrans_callback': 'midtrans_webhook',
    'midtrans-callback': 'midtrans_webhook',
    'payment_webhook': 'midtrans_webhook',
    'payment-webhook': 'midtrans_webhook',
    'payment_callback': 'midtrans_webhook',
    'payment-callback': 'midtrans_webhook',
    'midtrans_health': 'midtrans_health',
    'midtrans-health': 'midtrans_health'
  };
  return aliases[clean] || clean;
}

function midtransIsWebhookAction(action) {
  return action === 'midtrans_webhook';
}

function midtransPaymentIsConfigured() {
  return midtransSelectedServerKeyInfo().configured;
}

// PATCH v11: pilih key sesuai environment lebih dulu, tetapi jangan menolak key hanya
// karena prefix. Pada sebagian dashboard sandbox, Midtrans dapat menampilkan Server Key
// dengan prefix Mid-server-. Sumber kebenaran adalah Access Keys dashboard Midtrans,
// bukan prefix yang kita tebak. Prefix hanya ditampilkan sebagai warning/debug.
function midtransSelectedServerKeyInfo() {
  const production = midtransIsProduction();
  const genericRaw = String(process.env.MIDTRANS_SERVER_KEY || '');
  const sandboxRaw = String(process.env.MIDTRANS_SANDBOX_SERVER_KEY || '');
  const generic = genericRaw.trim();
  const sandbox = sandboxRaw.trim();

  let source = '';
  let raw = '';
  if (production) {
    source = generic ? 'MIDTRANS_SERVER_KEY' : (sandbox ? 'MIDTRANS_SANDBOX_SERVER_KEY_FALLBACK' : '');
    raw = generic || sandbox;
  } else {
    source = sandbox ? 'MIDTRANS_SANDBOX_SERVER_KEY' : (generic ? 'MIDTRANS_SERVER_KEY_FALLBACK' : '');
    raw = sandbox || generic;
  }

  const prefix = raw.startsWith('SB-Mid-server-')
    ? 'SB-Mid-server-'
    : (raw.startsWith('Mid-server-') ? 'Mid-server-' : (raw ? raw.slice(0, Math.min(14, raw.length)) : ''));
  const expectedPrefix = production ? 'Mid-server-' : 'SB-Mid-server-';
  const originalRaw = source === 'MIDTRANS_SANDBOX_SERVER_KEY' || source === 'MIDTRANS_SANDBOX_SERVER_KEY_FALLBACK'
    ? sandboxRaw
    : genericRaw;

  return {
    configured: Boolean(raw),
    key: raw,
    source: source || 'missing',
    prefix,
    length: raw.length,
    sha256_12: raw ? crypto.createHash('sha256').update(raw).digest('hex').slice(0, 12) : '',
    prefixMatchesEnvironment: Boolean(raw && raw.startsWith(expectedPrefix)),
    dashboardKeyAccepted: Boolean(raw && /^(SB-Mid-server-|Mid-server-)/.test(raw)),
    valueHasOuterWhitespace: Boolean(originalRaw && originalRaw !== originalRaw.trim())
  };
}

function midtransServerKey() {
  const selected = midtransSelectedServerKeyInfo();
  const key = selected.key;
  if (!key) {
    const err = new Error('MIDTRANS_SERVER_KEY / MIDTRANS_SANDBOX_SERVER_KEY belum diisi di Environment Variables Vercel.');
    err.statusCode = 503;
    throw err;
  }
  if (!selected.dashboardKeyAccepted) {
    const err = new Error('Midtrans Server Key tidak memakai format Server Key yang dikenal. Copy ulang Server Key dari Midtrans Dashboard > Settings > Access Keys, jangan Client Key.');
    err.statusCode = 503;
    throw err;
  }
  return key;
}

function midtransIsProduction() {
  const raw = String(process.env.MIDTRANS_IS_PRODUCTION || process.env.MIDTRANS_PRODUCTION || 'false').trim().toLowerCase();
  return raw === 'true' || raw === '1' || raw === 'yes' || raw === 'production';
}

function midtransSnapBaseUrl() {
  return midtransIsProduction() ? 'https://app.midtrans.com' : 'https://app.sandbox.midtrans.com';
}

function midtransNotificationUrl() {
  const explicit = String(process.env.MIDTRANS_NOTIFICATION_URL || process.env.PAYMENT_CALLBACK_URL || process.env.DOMAIN_PAYMENT_CALLBACK_URL || '').trim();
  if (explicit) return explicit;
  const site = String(process.env.DOMAIN_SITE_URL || process.env.SITE_URL || 'https://diracgroup.store').trim().replace(/\/$/, '');
  return site ? `${site}/api/health?action=midtrans_webhook` : '';
}

function midtransBasicAuthHeader() {
  return 'Basic ' + Buffer.from(`${midtransServerKey()}:`).toString('base64');
}

function midtransExpectedSignature(orderId, statusCode, grossAmount) {
  return crypto
    .createHash('sha512')
    .update(`${String(orderId || '')}${String(statusCode || '')}${String(grossAmount || '')}${midtransServerKey()}`)
    .digest('hex');
}

function midtransVerifySignature(payload) {
  const orderId = String(payload && payload.order_id || '').trim();
  const statusCode = String(payload && payload.status_code || '').trim();
  const grossAmount = String(payload && payload.gross_amount || '').trim();
  const signature = String(payload && payload.signature_key || '').trim().toLowerCase();
  if (!orderId || !statusCode || !grossAmount || !signature) return false;
  return safeEqual(signature, midtransExpectedSignature(orderId, statusCode, grossAmount));
}

function midtransMoney(value) {
  const normalized = String(value || '').replace(/[^0-9.]/g, '');
  const number = Number(normalized);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.round(number);
}

function midtransSafeText(value, maxLength) {
  return lockedPaymentCleanText(value, maxLength || 160);
}

function midtransSuccessStatus(payload) {
  const status = String(payload && payload.transaction_status || '').trim().toLowerCase();
  const fraud = String(payload && payload.fraud_status || '').trim().toLowerCase();
  if (status === 'settlement') return true;
  if (status === 'capture') return !fraud || fraud === 'accept';
  return false;
}

function midtransMappedPaymentStatus(payload) {
  const status = String(payload && payload.transaction_status || '').trim().toLowerCase();
  const fraud = String(payload && payload.fraud_status || '').trim().toLowerCase();
  if (status === 'settlement') return 'paid';
  if (status === 'capture' && (!fraud || fraud === 'accept')) return 'paid';
  if (status === 'pending') return 'pending';
  if (status === 'expire') return 'expired';
  if (status === 'cancel') return 'cancelled';
  if (status === 'deny' || status === 'failure') return 'failed';
  if (status === 'refund' || status === 'partial_refund') return 'refunded';
  return 'pending';
}

function midtransGatewayEventId(payload) {
  const tx = midtransSafeText(payload && payload.transaction_id || '', 96);
  const order = midtransSafeText(payload && payload.order_id || '', 96);
  const status = midtransSafeText(payload && payload.transaction_status || '', 40);
  const code = midtransSafeText(payload && payload.status_code || '', 20);
  const base = tx || order;
  return `midtrans:${base}:${status || 'unknown'}:${code || '0'}`.slice(0, 220);
}

function midtransBuildItemDetails(items) {
  const safeItems = Array.isArray(items) ? items : [];
  return safeItems.slice(0, 50).map((item, index) => {
    const quantity = Math.max(1, Math.trunc(Number(item.quantity || item.years || 1)) || 1);
    const price = midtransMoney(item.unit_price ?? item.price ?? item.register_price ?? item.subtotal);
    const subtotal = midtransMoney(item.subtotal || (price * quantity));
    const unitPrice = quantity > 0 ? Math.max(1, Math.round(subtotal / quantity)) : Math.max(1, price);
    return {
      id: midtransSafeText(item.product_doc_id || item.domain_name || item.id || `item-${index + 1}`, 50) || `item-${index + 1}`,
      price: unitPrice,
      quantity,
      name: midtransSafeText(item.title || item.name || item.domain_name || 'Item pesanan', 50) || 'Item pesanan'
    };
  });
}

function midtransAdjustItemDetailsToAmount(items, amount) {
  const target = midtransMoney(amount);
  const details = midtransBuildItemDetails(items);
  const total = details.reduce((sum, item) => sum + (midtransMoney(item.price) * Math.max(1, Number(item.quantity || 1))), 0);
  if (!details.length || total <= 0) {
    return [{ id: 'order-total', price: target, quantity: 1, name: 'Total pesanan' }];
  }
  const diff = target - total;
  if (diff !== 0) {
    details.push({ id: 'adjustment', price: diff, quantity: 1, name: 'Penyesuaian total' });
  }
  return details;
}

async function midtransCreateSnapPayment(input) {
  const amount = midtransMoney(input.amount);
  if (amount <= 0) {
    return { ok: false, status: 409, message: 'Nominal Midtrans tidak valid.', error: 'invalid_amount' };
  }

  const returnUrl = String(process.env.PAYMENT_RETURN_URL || process.env.DOMAIN_PAYMENT_RETURN_URL || process.env.DOMAIN_SITE_URL || 'https://diracgroup.store/pesanan.html').trim();
  const payload = {
    transaction_details: {
      order_id: String(input.gatewayReference || '').trim(),
      gross_amount: amount
    },
    customer_details: {
      first_name: midtransSafeText(input.customer && input.customer.name || 'Customer', 120),
      email: normalizeAuthEmail(input.customer && input.customer.email || ''),
      phone: midtransSafeText(input.customer && input.customer.phone || '', 40)
    },
    item_details: midtransAdjustItemDetailsToAmount(input.items || [], amount),
    callbacks: {
      finish: returnUrl
    },
    custom_field1: String(input.transactionId || '').slice(0, 255),
    custom_field2: String(input.orderId || input.domainOrderId || '').slice(0, 255),
    custom_field3: String(input.serviceType || '').slice(0, 255)
  };

  const enabledPayments = String(process.env.MIDTRANS_ENABLED_PAYMENTS || '').split(',').map((item) => item.trim()).filter(Boolean);
  if (enabledPayments.length) payload.enabled_payments = enabledPayments;

  let response;
  let data;
  try {
    response = await fetch(`${midtransSnapBaseUrl()}/snap/v1/transactions`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: midtransBasicAuthHeader()
      },
      body: JSON.stringify(payload)
    });
    data = await parseFetchResponse(response);
  } catch (error) {
    const safeError = lockedPaymentSafeError(error) || 'midtrans_fetch_failed';
    return {
      ok: false,
      status: 502,
      message: 'Midtrans tidak merespons.',
      error: safeError,
      raw: {
        provider: 'midtrans',
        http_status: 0,
        error: safeError,
        request: {
          order_id: payload.transaction_details.order_id,
          gross_amount: payload.transaction_details.gross_amount,
          enabled_payments: payload.enabled_payments || null,
          return_url: returnUrl,
          notification_url: midtransNotificationUrl(),
          snap_base_url: midtransSnapBaseUrl()
        }
      }
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: response.status || 502,
      message: getUpstreamMessage(data) || 'Midtrans gagal membuat Snap transaction.',
      error: lockedPaymentSafeUpstreamError(data),
      raw: {
        provider: 'midtrans',
        http_status: response.status || 0,
        midtrans: data || null,
        request: {
          order_id: payload.transaction_details.order_id,
          gross_amount: payload.transaction_details.gross_amount,
          enabled_payments: payload.enabled_payments || null,
          return_url: returnUrl,
          notification_url: midtransNotificationUrl(),
          snap_base_url: midtransSnapBaseUrl(),
          debug_patch: DIRAC_MIDTRANS_DEBUG_PATCH
        }
      }
    };
  }

  const token = data && data.token ? String(data.token).trim() : '';
  const redirectUrl = data && data.redirect_url ? String(data.redirect_url).trim() : '';

  return {
    ok: Boolean(token && redirectUrl),
    status: token && redirectUrl ? 200 : 502,
    message: token && redirectUrl ? 'ok' : 'Midtrans tidak mengembalikan token/redirect_url.',
    provider: 'midtrans',
    paymentUrl: redirectUrl,
    invoiceId: token || input.gatewayReference,
    raw: {
      midtrans: data,
      request: {
        order_id: payload.transaction_details.order_id,
        gross_amount: payload.transaction_details.gross_amount,
        return_url: returnUrl,
        notification_url: midtransNotificationUrl(),
        snap_base_url: midtransSnapBaseUrl(),
        debug_patch: DIRAC_MIDTRANS_DEBUG_PATCH
      }
    }
  };
}

async function midtransCreateDomainPaymentInvoice(order, orderItems, customer) {
  const domainOrderId = String(order && order.id || '').trim();
  const customerId = String(order && order.customer_id || '').trim();
  const amount = midtransMoney(customer && customer.totalAmount || order && (order.total_price || order.total_amount || order.total) || 0);

  if (!customerSecurityLooksLikeUuid(domainOrderId) || !customerSecurityLooksLikeUuid(customerId)) {
    return { configured: true, payment_url: null, provider: 'midtrans', error: 'domain_order_or_customer_invalid' };
  }
  if (amount <= 0) {
    return { configured: true, payment_url: null, provider: 'midtrans', error: 'domain_amount_invalid' };
  }

  const orderCode = midtransSafeText(order && (order.order_code || order.order_id) || domainOrderId, 80);
  const gatewayReference = lockedPaymentGenerateReference(`DOM-${orderCode}`);

  const transactionResult = await lockedPaymentInsertTransaction({
    domainOrderId,
    customerId,
    serviceType: 'domain',
    gatewayName: 'midtrans',
    gatewayReference,
    amount,
    currency: 'IDR',
    metadata: {
      source: 'domain_checkout_midtrans',
      amount_source: 'domain_orders.total_price.backend',
      domain_order_id: domainOrderId,
      order_code: orderCode,
      create_payment_started_at: diracNowIso()
    }
  });

  if (!transactionResult.ok) {
    const err = new Error('Gagal menyimpan transaksi Midtrans domain.');
    err.statusCode = transactionResult.status || 500;
    throw err;
  }

  const transaction = Array.isArray(transactionResult.data) ? transactionResult.data[0] : transactionResult.data;
  if (!transaction || !transaction.id) {
    const err = new Error('Transaksi Midtrans domain dibuat, tetapi ID tidak ditemukan.');
    err.statusCode = 500;
    throw err;
  }

  const gateway = await midtransCreateSnapPayment({
    gatewayReference,
    transactionId: transaction.id,
    domainOrderId,
    orderId: domainOrderId,
    orderCode,
    amount,
    currency: 'IDR',
    customer: {
      name: customer && customer.customerName || order.customer_name || 'Customer',
      email: customer && customer.customerEmail || order.customer_email || '',
      phone: customer && customer.customerWhatsapp || order.customer_whatsapp || ''
    },
    items: (orderItems || []).map((item) => ({
      domain_name: item.domain_name,
      title: item.domain_name,
      quantity: item.years || 1,
      price: item.register_price,
      subtotal: item.subtotal
    })),
    serviceType: 'domain'
  });

  if (!gateway.ok || !gateway.paymentUrl) {
    await lockedPaymentMarkTransactionGatewayFailed(transaction.id, gateway.error || gateway.message || 'midtrans_create_failed', gateway.raw || null);
    return {
      configured: true,
      provider: 'midtrans',
      payment_url: null,
      invoice_id: gateway.invoiceId || null,
      payment_transaction_id: transaction.id,
      gateway_reference: gatewayReference,
      error: gateway.message || 'Midtrans gagal membuat payment URL.'
    };
  }

  const patch = await lockedPaymentPatchTransactionUrl(transaction.id, gateway.paymentUrl, gateway.invoiceId, gateway.raw);
  if (!patch.ok) {
    const err = new Error('Midtrans sudah membuat invoice domain, tetapi payment URL gagal disimpan.');
    err.statusCode = patch.status || 500;
    throw err;
  }

  return {
    configured: true,
    provider: 'midtrans',
    payment_url: gateway.paymentUrl,
    invoice_id: gateway.invoiceId || null,
    payment_transaction_id: transaction.id,
    gateway_reference: gatewayReference,
    raw: gateway.raw
  };
}

async function midtransHandleWebhook(req, res) {
  if (!midtransPaymentIsConfigured()) {
    return res.status(503).json({ ok: false, message: 'MIDTRANS_SERVER_KEY belum disetel.' });
  }

  const body = await readBody(req);
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ ok: false, message: 'Payload Midtrans tidak valid.' });
  }

  if (!midtransVerifySignature(body)) {
    return res.status(403).json({ ok: false, message: 'Signature Midtrans tidak valid.' });
  }

  const gatewayReference = midtransSafeText(body.order_id || '', 120);
  const gatewayEventId = midtransGatewayEventId(body);
  const grossAmount = midtransMoney(body.gross_amount);
  const mappedStatus = midtransMappedPaymentStatus(body);
  const success = midtransSuccessStatus(body);

  if (!gatewayReference || !gatewayEventId || grossAmount <= 0) {
    return res.status(400).json({ ok: false, message: 'Payload Midtrans kurang lengkap.' });
  }

  const existingEvent = await midtransFetchGatewayEvent(gatewayEventId);
  if (existingEvent.ok && existingEvent.exists) {
    return res.status(200).json({ ok: true, duplicate: true, message: 'Webhook Midtrans sudah pernah diproses.', gateway_event_id: gatewayEventId });
  }

  const txResult = await midtransFetchPaymentTransaction(gatewayReference);
  if (!txResult.ok) {
    return res.status(txResult.status || 404).json({ ok: false, message: txResult.message || 'Payment transaction tidak ditemukan.' });
  }

  const tx = txResult.transaction;
  const transactionAmount = midtransMoney(tx.amount);
  if (transactionAmount !== grossAmount) {
    await midtransInsertGatewayEventSafe(tx.id, gatewayEventId, 'failed', body, {
      reason: 'amount_mismatch',
      expected_amount: transactionAmount,
      gross_amount: grossAmount
    });
    return res.status(409).json({ ok: false, message: 'Amount Midtrans tidak cocok dengan transaksi database.' });
  }

  const ownerCheck = await midtransVerifyTransactionOwnerAndAmount(tx, grossAmount);
  if (!ownerCheck.ok) {
    await midtransInsertGatewayEventSafe(tx.id, gatewayEventId, 'failed', body, {
      reason: ownerCheck.reason || 'owner_or_amount_mismatch'
    });
    return res.status(ownerCheck.status || 409).json({ ok: false, message: ownerCheck.message || 'Payment tidak cocok dengan order/customer.' });
  }

  const eventStatus = success ? 'processed' : 'received';
  const eventInsert = await midtransInsertGatewayEventSafe(tx.id, gatewayEventId, eventStatus, body, {
    mapped_payment_status: mappedStatus,
    success,
    gateway_reference: gatewayReference
  });

  if (!eventInsert.ok && !eventInsert.duplicate) {
    return res.status(eventInsert.status || 500).json({ ok: false, message: 'Gagal menyimpan event webhook Midtrans.' });
  }

  const txPatch = await midtransPatchPaymentTransaction(tx.id, mappedStatus, body, success);
  if (!txPatch.ok) {
    return res.status(txPatch.status || 500).json({ ok: false, message: 'Gagal update payment transaction dari webhook Midtrans.' });
  }

  let orderPatch = { ok: true, skipped: true };
  let orderMailNotification = orderMailPaidWebhookSkipSummary('midtrans', 'not_paid_status');
  if (success) {
    orderPatch = await midtransPatchRelatedOrderPaid(tx, body);
    if (!orderPatch.ok) {
      return res.status(orderPatch.status || 500).json({ ok: false, message: 'Payment valid, tetapi gagal update status order.' });
    }
    orderMailNotification = await orderMailNotifyPaidOrderFromPaymentSafe({
      provider: 'midtrans',
      tx,
      webhookPayload: body,
      paidAt: body.settlement_time || diracNowIso()
    });
  }

  return res.status(200).json({
    ok: true,
    provider: 'midtrans',
    gateway_reference: gatewayReference,
    gateway_event_id: gatewayEventId,
    payment_transaction_id: tx.id,
    payment_status: mappedStatus,
    order_updated: Boolean(success && orderPatch && orderPatch.ok),
    order_mail_notification: orderMailNotification,
    idempotent: false
  });
}

async function midtransFetchPaymentTransaction(gatewayReference) {
  const select = [
    'id', 'customer_id', 'order_id', 'domain_order_id', 'service_type', 'gateway_name',
    'gateway_reference', 'payment_status', 'amount', 'currency', 'payment_url', 'metadata'
  ].join(',');
  const path = '/rest/v1/payment_transactions?select=' + encodeURIComponent(select)
    + '&gateway_reference=eq.' + encodeURIComponent(gatewayReference)
    + '&limit=1';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status, message: 'Gagal membaca payment transaction.' };
  const rows = Array.isArray(result.data) ? result.data : [];
  const row = rows[0] || null;
  if (!row || !row.id) return { ok: false, status: 404, message: 'Payment transaction tidak ditemukan untuk gateway_reference ini.' };
  return { ok: true, transaction: row };
}

async function midtransVerifyTransactionOwnerAndAmount(tx, amount) {
  if (tx.order_id) {
    const select = 'id,customer_id,total,payment_status,order_status';
    const result = await supabaseFetch('/rest/v1/orders?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(tx.order_id) + '&limit=1', {
      method: 'GET',
      auth: 'service'
    });
    if (!result.ok) return { ok: false, status: result.status, message: 'Gagal membaca order regular.', reason: 'orders_read_failed' };
    const order = Array.isArray(result.data) ? result.data[0] : null;
    if (!order || !order.id) return { ok: false, status: 404, message: 'Order regular tidak ditemukan.', reason: 'order_not_found' };
    if (String(order.customer_id || '') !== String(tx.customer_id || '')) return { ok: false, status: 409, message: 'Customer payment tidak sama dengan customer order.', reason: 'customer_mismatch' };
    if (midtransMoney(order.total) !== midtransMoney(amount)) return { ok: false, status: 409, message: 'Nominal payment tidak sama dengan total order.', reason: 'amount_mismatch_order_total' };
    return { ok: true, orderType: 'regular', order };
  }

  if (tx.domain_order_id) {
    const select = 'id,customer_id,total_price,payment_status,order_status,status';
    const result = await supabaseFetch('/rest/v1/domain_orders?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(tx.domain_order_id) + '&limit=1', {
      method: 'GET',
      auth: 'service'
    });
    if (!result.ok) return { ok: false, status: result.status, message: 'Gagal membaca domain order.', reason: 'domain_orders_read_failed' };
    const order = Array.isArray(result.data) ? result.data[0] : null;
    if (!order || !order.id) return { ok: false, status: 404, message: 'Domain order tidak ditemukan.', reason: 'domain_order_not_found' };
    if (String(order.customer_id || '') !== String(tx.customer_id || '')) return { ok: false, status: 409, message: 'Customer payment tidak sama dengan customer domain order.', reason: 'customer_mismatch_domain' };
    if (midtransMoney(order.total_price) !== midtransMoney(amount)) return { ok: false, status: 409, message: 'Nominal payment tidak sama dengan total domain order.', reason: 'amount_mismatch_domain_total' };
    return { ok: true, orderType: 'domain', order };
  }

  return { ok: false, status: 409, message: 'Payment transaction tidak punya order_id/domain_order_id.', reason: 'missing_order_reference' };
}

async function midtransFetchGatewayEvent(gatewayEventId) {
  const path = '/rest/v1/payment_gateway_events?select=' + encodeURIComponent('id,gateway_event_id')
    + '&gateway_event_id=eq.' + encodeURIComponent(gatewayEventId)
    + '&limit=1';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status };
  const rows = Array.isArray(result.data) ? result.data : [];
  return { ok: true, exists: rows.length > 0, event: rows[0] || null };
}

async function midtransInsertGatewayEventSafe(paymentTransactionId, gatewayEventId, eventStatus, payload, metadata) {
  const basePayload = {
    payment_transaction_id: paymentTransactionId,
    gateway_event_id: gatewayEventId,
    event_status: eventStatus,
    payload,
    metadata: {
      provider: 'midtrans',
      received_at: diracNowIso(),
      signature_verified: true,
      ...(metadata || {})
    }
  };

  const attempts = [
    {
      ...basePayload,
      gateway_name: 'midtrans',
      signature_valid: true,
      received_at: diracNowIso(),
      processed_at: eventStatus === 'processed' ? diracNowIso() : null
    },
    basePayload,
    {
      payment_transaction_id: paymentTransactionId,
      gateway_event_id: gatewayEventId,
      event_status: eventStatus,
      payload
    },
    {
      payment_transaction_id: paymentTransactionId,
      gateway_event_id: gatewayEventId,
      event_status: eventStatus
    }
  ];

  for (const body of attempts) {
    const result = await supabaseFetch('/rest/v1/payment_gateway_events', {
      method: 'POST',
      auth: 'service',
      prefer: 'return=representation',
      body: [body]
    });

    if (result.ok) return { ok: true, data: result.data };

    const msg = lockedPaymentSafeUpstreamError(result.data).toLowerCase();
    if (result.status === 409 || msg.includes('duplicate') || msg.includes('unique')) {
      return { ok: true, duplicate: true, data: result.data };
    }
  }

  return { ok: false, status: 500 };
}

async function midtransPatchPaymentTransaction(transactionId, status, payload, success) {
  const metadata = {
    midtrans_last_notification_at: diracNowIso(),
    midtrans_transaction_id: payload.transaction_id || null,
    midtrans_transaction_status: payload.transaction_status || null,
    midtrans_payment_type: payload.payment_type || null,
    midtrans_fraud_status: payload.fraud_status || null,
    midtrans_status_code: payload.status_code || null,
    midtrans_status_message: payload.status_message || null,
    midtrans_signature_verified: true
  };

  const body = {
    payment_status: status,
    metadata
  };

  if (success) body.paid_at = payload.settlement_time || diracNowIso();

  const first = await supabaseFetch('/rest/v1/payment_transactions?id=eq.' + encodeURIComponent(transactionId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body
  });

  if (first.ok) return first;

  const fallback = await supabaseFetch('/rest/v1/payment_transactions?id=eq.' + encodeURIComponent(transactionId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: { payment_status: status, metadata }
  });

  return fallback;
}

async function midtransPatchRelatedOrderPaid(tx, payload) {
  const paidAt = payload.settlement_time || diracNowIso();

  if (tx.order_id) {
    const path = '/rest/v1/orders?id=eq.' + encodeURIComponent(tx.order_id);
    const first = await supabaseFetch(path, {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: {
        payment_status: 'paid',
        order_status: 'paid',
        paid_at: paidAt
      }
    });
    if (first.ok) return first;
    const second = await supabaseFetch(path, {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: {
        payment_status: 'paid',
        order_status: 'paid'
      }
    });
    if (second.ok) return second;
    return supabaseFetch(path, {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: { payment_status: 'paid' }
    });
  }

  if (tx.domain_order_id) {
    const path = '/rest/v1/domain_orders?id=eq.' + encodeURIComponent(tx.domain_order_id);
    const first = await supabaseFetch(path, {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: {
        payment_status: 'paid',
        order_status: 'paid',
        status: 'paid',
        paid_at: paidAt
      }
    });
    if (first.ok) return first;
    const second = await supabaseFetch(path, {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: {
        payment_status: 'paid',
        order_status: 'paid',
        status: 'paid'
      }
    });
    if (second.ok) return second;
    return supabaseFetch(path, {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: { payment_status: 'paid' }
    });
  }

  return { ok: false, status: 409 };
}



/* ============================================================
   IPAYMU REDIRECT PAYMENT + WEBHOOK - DISABLED - MIDTRANS ONLY v1
   Tujuan:
   - Provider aktif tunggal adalah Midtrans.
   - iPaymu tidak membaca credential, tidak membuat invoice, dan tidak memproses webhook.
   - Wrapper tetap ada agar action lama tidak menyebabkan crash, tetapi selalu mengembalikan disabled.
   ============================================================ */

const __diracIpaymuPaymentPreviousHandler = module.exports;

module.exports = async function ipaymuPaymentWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = ipaymuNormalizeAction(rawAction);

  if (action !== 'ipaymu_health' && action !== 'ipaymu_webhook') {
    return __diracIpaymuPaymentPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  return res.status(410).json({
    ok: false,
    provider: 'ipaymu',
    disabled: true,
    activeProvider: 'midtrans',
    message: 'iPaymu dinonaktifkan. Payment gateway aktif hanya Midtrans.'
  });
};

function ipaymuNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    ipaymu_health: 'ipaymu_health',
    ipaymu_status: 'ipaymu_health',
    ipaymu_webhook: 'ipaymu_webhook',
    ipaymu_callback: 'ipaymu_webhook',
    ipaymu_notify: 'ipaymu_webhook',
    ipaymu_notification: 'ipaymu_webhook',
    payment_ipaymu_webhook: 'ipaymu_webhook'
  };
  return aliases[clean] || clean;
}

function ipaymuIsProduction() {
  return false;
}

function ipaymuSelectedCredentialInfo() {
  return {
    configured: false,
    apiKey: '',
    va: '',
    apiKeySource: 'disabled_midtrans_only',
    vaSource: 'disabled_midtrans_only',
    valueHasOuterWhitespace: false
  };
}

function ipaymuPickEnvValue() {
  return { source: 'disabled_midtrans_only', value: '', hasOuterWhitespace: false };
}

function ipaymuPaymentIsConfigured() {
  return false;
}

function ipaymuCredentials() {
  const err = new Error('iPaymu dinonaktifkan. Payment gateway aktif hanya Midtrans.');
  err.statusCode = 410;
  throw err;
}

function ipaymuBaseUrl() {
  return '';
}

function ipaymuPaymentEndpoint() {
  return '';
}

function ipaymuReturnUrl() {
  return '';
}

function ipaymuCancelUrl() {
  return '';
}

function ipaymuWebhookToken() {
  return '';
}

function ipaymuNotificationUrl() {
  return '';
}

async function ipaymuCreateRedirectPayment() {
  return {
    ok: false,
    status: 410,
    provider: 'ipaymu',
    paymentUrl: '',
    invoiceId: '',
    message: 'iPaymu dinonaktifkan. Payment gateway aktif hanya Midtrans.',
    error: 'ipaymu_disabled'
  };
}

async function ipaymuCreateDomainPaymentInvoice() {
  return {
    configured: false,
    provider: 'ipaymu',
    payment_url: null,
    invoice_id: null,
    error: 'ipaymu_disabled'
  };
}

async function ipaymuHandleWebhook(req, res) {
  return res.status(410).json({
    ok: false,
    provider: 'ipaymu',
    disabled: true,
    activeProvider: 'midtrans',
    message: 'iPaymu dinonaktifkan. Payment gateway aktif hanya Midtrans.'
  });
}

/* ============================================================
   DIRAC EMAIL A2F RESTORE PATCH v1
   - Adds backend email-code 2FA actions for masuk.html restore patch.
   - Routes:
     POST /api/health?action=dirac_mfa_email_start
     POST /api/health?action=dirac_mfa_email_verify
   - Passkey/Auth flow stays on the existing /api/2fa endpoints.
   - Dashboard proof is still HttpOnly cookie only.
   ============================================================ */

const __diracEmailA2FPreviousHandler = module.exports;
const DIRAC_EMAIL_A2F_ACTIONS = new Set([
  'dirac_mfa_email_start',
  'dirac_mfa_email_verify',
  'domain_mfa_email_start',
  'domain_mfa_email_verify'
]);
const DIRAC_EMAIL_A2F_STORE = globalThis.__DIRAC_EMAIL_A2F_STORE__ || new Map();
globalThis.__DIRAC_EMAIL_A2F_STORE__ = DIRAC_EMAIL_A2F_STORE;
const DIRAC_EMAIL_A2F_TTL_MS = Math.max(60_000, Number(process.env.DIRAC_EMAIL_A2F_TTL_MS || 5 * 60_000));
const DIRAC_EMAIL_A2F_MAX_ATTEMPTS = Math.max(3, Number(process.env.DIRAC_EMAIL_A2F_MAX_ATTEMPTS || 5));

module.exports = async function diracEmailA2FRestoreWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  if (!DIRAC_EMAIL_A2F_ACTIONS.has(rawAction)) {
    return __diracEmailA2FPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  try {
    if (rawAction === 'dirac_mfa_email_start' || rawAction === 'domain_mfa_email_start') {
      return diracEmailA2FStart(req, res);
    }
    return diracEmailA2FVerify(req, res);
  } catch (error) {
    return res.status(error && error.statusCode ? error.statusCode : 500).json({
      ok: false,
      message: 'Verifikasi A2F email belum bisa diproses. Silakan coba lagi sebentar lagi.'
    });
  }
};

function diracEmailA2FCleanup(now = Date.now()) {
  if (DIRAC_EMAIL_A2F_STORE.size < 1000) return;
  for (const [key, row] of DIRAC_EMAIL_A2F_STORE.entries()) {
    if (!row || Number(row.expiresAtMs || 0) <= now) DIRAC_EMAIL_A2F_STORE.delete(key);
  }
}

function diracEmailA2FHash(value) {
  return crypto.createHmac('sha256', getCustomerMfaSecret()).update(String(value || '')).digest('hex');
}

function diracEmailA2FMaskEmail(email) {
  const value = normalizeAuthEmail(email);
  const parts = value.split('@');
  if (parts.length !== 2) return 'e••••@mail';
  const name = parts[0] || 'e';
  return `${name.slice(0, 1)}••••${name.length > 4 ? name.slice(-2) : ''}@${parts[1]}`;
}

function diracEmailA2FGenerateCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}


async function diracEmailA2FHasActivePasskeyForUser(user, email) {
  const cleanEmail = normalizeAuthEmail(email || (user && user.email));
  if (!isValidAuthEmail(cleanEmail)) {
    return { ok: false, status: 400, message: 'Email akun tidak valid.' };
  }

  const seen = new Set();
  const rows = [];
  const select = 'id,user_id,email,is_active,created_at,last_used_at';
  const addRows = (list) => {
    for (const row of (Array.isArray(list) ? list : [])) {
      if (!row || row.is_active !== true) continue;
      const key = String(row.id || row.user_id || row.email || '');
      if (!key || seen.has(key)) continue;
      seen.add(key);
      rows.push(row);
    }
  };
  const fetchPasskeyRows = async (filter) => {
    if (!filter) return;
    const path = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(select) + '&is_active=eq.true&' + filter + '&order=created_at.desc&limit=10';
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (result && result.ok) addRows(result.data);
  };

  // Utama: cocokkan email login dengan domain_passkeys.email.
  await fetchPasskeyRows('email=eq.' + encodeURIComponent(cleanEmail));

  // Cadangan aman: kalau requireDomainUser mengembalikan id customer langsung.
  const userId = String(user && user.id || '').trim();
  if (userId && typeof customerSecurityLooksLikeUuid === 'function' && customerSecurityLooksLikeUuid(userId)) {
    await fetchPasskeyRows('user_id=eq.' + encodeURIComponent(userId));
  }

  // Cadangan aman: kalau akun auth terhubung ke customers lewat security_customer_auth_links.
  try {
    if (typeof customerSecurityFetchAuthLink === 'function' && userId) {
      const linkResult = await customerSecurityFetchAuthLink(userId).catch(() => null);
      const linkRows = Array.isArray(linkResult && linkResult.data) ? linkResult.data : [];
      for (const link of linkRows) {
        const cid = String(link && link.customer_id || '').trim();
        if (link && link.link_status === 'active' && customerSecurityLooksLikeUuid(cid)) {
          await fetchPasskeyRows('user_id=eq.' + encodeURIComponent(cid));
        }
      }
    }
  } catch (_) {}

  // Cadangan final: pakai resolver Passkey yang sudah ada, tapi jangan jadikan gagal fatal.
  try {
    if (typeof diracPasskeyA2FResolveOwner === 'function' && typeof diracPasskeyA2FListActivePasskeys === 'function') {
      const owner = await diracPasskeyA2FResolveOwner(user, cleanEmail).catch(() => null);
      if (owner && owner.ok) {
        const ownerRows = await diracPasskeyA2FListActivePasskeys(owner).catch(() => []);
        addRows(ownerRows);
      }
    }
  } catch (_) {}

  if (rows.length > 0) {
    return { ok: true, count: rows.length };
  }
  return {
    ok: false,
    status: 403,
    message: 'Passkey aktif belum ditemukan untuk email akun ini. Login ulang lalu coba lagi.'
  };
}

async function diracEmailA2FStart(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  const email = normalizeAuthEmail(user.email);
  if (!isValidAuthEmail(email)) return res.status(400).json({ ok: false, message: 'Email akun tidak valid.' });

  const passkeyGate = await diracEmailA2FHasActivePasskeyForUser(user, email);
  if (!passkeyGate.ok) {
    return res.status(passkeyGate.status || 403).json({
      ok: false,
      code: 'PASSKEY_REQUIRED_FIRST',
      message: passkeyGate.message || 'Email A2F hanya boleh dipakai setelah Passkey aktif di database.'
    });
  }

  diracEmailA2FCleanup();
  const code = diracEmailA2FGenerateCode();
  const setupToken = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  const record = {
    codeHash: diracEmailA2FHash(`email-a2f-code:${email}:${setupToken}:${code}`),
    emailHash: customerMfaProfileId(email),
    originHash: customerMfaBindingHash('origin', requestOrigin(req)),
    uaHash: customerMfaBindingHash('ua', requestUserAgent(req)),
    expiresAtMs: now + DIRAC_EMAIL_A2F_TTL_MS,
    attempts: 0,
    createdAtMs: now
  };

  const delivered = await diracEmailA2FSendCode(email, code, {
    ttlMinutes: Math.max(1, Math.ceil(DIRAC_EMAIL_A2F_TTL_MS / 60_000)),
    user
  });

  if (!delivered.ok) {
    return res.status(delivered.status || 503).json({
      ok: false,
      code: delivered.code || 'EMAIL_A2F_DELIVERY_NOT_READY',
      message: delivered.message || 'Layanan email A2F belum siap. Set RESEND_API_KEY dan DIRAC_MFA_EMAIL_FROM di environment.'
    });
  }

  DIRAC_EMAIL_A2F_STORE.set(setupToken, record);

  return res.status(200).json({
    ok: true,
    method: 'email',
    setupToken,
    mfaSetupToken: setupToken,
    expires_in: Math.floor(DIRAC_EMAIL_A2F_TTL_MS / 1000),
    masked_email: diracEmailA2FMaskEmail(email),
    message: `Kode A2F sudah dikirim ke ${diracEmailA2FMaskEmail(email)}.`
  });
}

async function diracEmailA2FVerify(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  const body = await readBody(req);
  const email = normalizeAuthEmail(user.email);
  const setupToken = String(body.setupToken || body.mfaSetupToken || body.token || '').trim();
  const code = String(body.code || body.otp || body.email_code || '').replace(/\D/g, '').slice(0, 6);

  if (!setupToken || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ ok: false, message: 'Masukkan kode email 6 digit terbaru.' });
  }

  const record = DIRAC_EMAIL_A2F_STORE.get(setupToken);
  if (!record) return res.status(403).json({ ok: false, message: 'Kode email sudah expired. Kirim ulang kode.' });

  const now = Date.now();
  if (Number(record.expiresAtMs || 0) <= now) {
    DIRAC_EMAIL_A2F_STORE.delete(setupToken);
    return res.status(403).json({ ok: false, message: 'Kode email sudah expired. Kirim ulang kode.' });
  }

  if (!record.emailHash || !safeEqual(String(record.emailHash), customerMfaProfileId(email))) {
    DIRAC_EMAIL_A2F_STORE.delete(setupToken);
    return res.status(403).json({ ok: false, message: 'Kode email tidak cocok dengan akun login.' });
  }

  if (record.originHash) {
    const expectedOriginHash = customerMfaBindingHash('origin', requestOrigin(req));
    if (!expectedOriginHash || !safeEqual(String(record.originHash), expectedOriginHash)) {
      return res.status(403).json({ ok: false, message: 'Kode email harus diverifikasi dari origin yang sama.' });
    }
  }

  if (record.uaHash) {
    const expectedUaHash = customerMfaBindingHash('ua', requestUserAgent(req));
    if (!expectedUaHash || !safeEqual(String(record.uaHash), expectedUaHash)) {
      return res.status(403).json({ ok: false, message: 'Kode email harus diverifikasi dari perangkat/browser yang sama.' });
    }
  }

  record.attempts = Number(record.attempts || 0) + 1;
  if (record.attempts > DIRAC_EMAIL_A2F_MAX_ATTEMPTS) {
    DIRAC_EMAIL_A2F_STORE.delete(setupToken);
    return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan. Kirim ulang kode email.' });
  }

  const expectedHash = diracEmailA2FHash(`email-a2f-code:${email}:${setupToken}:${code}`);
  if (!safeEqual(String(record.codeHash || ''), expectedHash)) {
    DIRAC_EMAIL_A2F_STORE.set(setupToken, record);
    return res.status(403).json({ ok: false, message: 'Kode email belum cocok. Masukkan 6 digit terbaru dari email.' });
  }

  DIRAC_EMAIL_A2F_STORE.delete(setupToken);
  const proof = customerSecurityCreateDashboardMfaToken(req, user, 'email');
  customerSecuritySetDashboardMfaCookie(res, proof);

  return res.status(200).json({
    ok: true,
    verified: true,
    active: true,
    method: 'email',
    message: 'Kode email valid. Akses dashboard sudah diverifikasi.',
    dashboardSession: {
      verified: true,
      expiresAtMs: proof.expiresAtMs,
      activeAtMs: proof.activeAtMs,
      method: 'email',
      transport: 'httponly-secure-cookie-only'
    },
    time: diracNowIso()
  });
}

async function diracEmailA2FSendCode(to, code, options = {}) {
  const ttlMinutes = Number(options.ttlMinutes || 5);
  const from = String(process.env.DIRAC_MFA_EMAIL_FROM || process.env.DIRAC_EMAIL_FROM || process.env.RESEND_FROM || 'Dirac Secure <no-reply@diracgroup.store>').trim();
  const subject = 'Kode A2F Dirac Secure';
  const text = `Kode A2F Dirac Secure Anda: ${code}\n\nKode berlaku ${ttlMinutes} menit. Jangan berikan kode ini kepada siapa pun.`;
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.55;color:#111827">
      <h2 style="margin:0 0 12px">Kode A2F Dirac Secure</h2>
      <p>Masukkan kode berikut untuk melanjutkan ke dashboard:</p>
      <div style="font-size:30px;font-weight:800;letter-spacing:8px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:14px;padding:14px 18px;width:max-content">${code}</div>
      <p>Kode berlaku ${ttlMinutes} menit. Jangan berikan kode ini kepada siapa pun.</p>
    </div>`;

  if (process.env.RESEND_API_KEY) {
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ from, to, subject, text, html })
      });
      if (response.ok) return { ok: true, provider: 'resend' };
      return { ok: false, status: 502, code: 'RESEND_DELIVERY_FAILED', message: 'Gagal mengirim kode email A2F dari Resend.' };
    } catch (_) {
      return { ok: false, status: 502, code: 'RESEND_DELIVERY_FAILED', message: 'Gagal menghubungi layanan email A2F.' };
    }
  }

  if (process.env.BREVO_API_KEY) {
    try {
      const senderEmail = String(process.env.BREVO_SENDER_EMAIL || process.env.DIRAC_MFA_SENDER_EMAIL || '').trim();
      const senderName = String(process.env.BREVO_SENDER_NAME || 'Dirac Secure').trim();
      if (!senderEmail) return { ok: false, status: 503, code: 'BREVO_SENDER_MISSING', message: 'BREVO_SENDER_EMAIL belum diatur.' };
      const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'api-key': process.env.BREVO_API_KEY,
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ sender: { name: senderName, email: senderEmail }, to: [{ email: to }], subject, htmlContent: html, textContent: text })
      });
      if (response.ok) return { ok: true, provider: 'brevo' };
      return { ok: false, status: 502, code: 'BREVO_DELIVERY_FAILED', message: 'Gagal mengirim kode email A2F dari Brevo.' };
    } catch (_) {
      return { ok: false, status: 502, code: 'BREVO_DELIVERY_FAILED', message: 'Gagal menghubungi layanan email A2F.' };
    }
  }

  if (process.env.NODE_ENV !== 'production' && isEnvTrue('DIRAC_DEV_EMAIL_A2F_ECHO')) {
    console.log('[DEV-EMAIL-A2F]', { to, code, ttlMinutes });
    return { ok: true, provider: 'dev_echo' };
  }

  return {
    ok: false,
    status: 503,
    code: 'EMAIL_PROVIDER_NOT_CONFIGURED',
    message: 'Provider email A2F belum dikonfigurasi. Set RESEND_API_KEY + DIRAC_MFA_EMAIL_FROM, atau BREVO_API_KEY + BREVO_SENDER_EMAIL.'
  };
}
/* ============================================================
   DIRAC PASSKEY A2F REAL HOTFIX v2
   - Adds lightweight WebAuthn/Passkey actions through /api/health.
   - Routes used by masuk.html fetch rewrite:
     POST /api/health?action=dirac_mfa_passkey_start
     POST /api/health?action=dirac_mfa_passkey_verify
   - Removes the wrong OTP/Auth error path for Passkey.
   - Dashboard proof remains backend-only HttpOnly cookie.
   ============================================================ */

const __diracPasskeyA2FPreviousHandler = module.exports;
const DIRAC_PASSKEY_A2F_ACTIONS = new Set([
  'dirac_mfa_passkey_start',
  'dirac_mfa_passkey_verify',
  'domain_mfa_passkey_start',
  'domain_mfa_passkey_verify'
]);
const DIRAC_PASSKEY_A2F_TOKEN_TYPE = 'dirac-passkey-a2f-challenge-v2';
const DIRAC_PASSKEY_A2F_TTL_MS = Math.max(60_000, Number(process.env.DIRAC_PASSKEY_A2F_TTL_MS || 5 * 60_000));

module.exports = async function diracPasskeyA2FWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  if (!DIRAC_PASSKEY_A2F_ACTIONS.has(rawAction)) {
    return __diracPasskeyA2FPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan untuk Passkey A2F.' });

  try {
    if (rawAction === 'dirac_mfa_passkey_start' || rawAction === 'domain_mfa_passkey_start') {
      return diracPasskeyA2FStart(req, res);
    }
    return diracPasskeyA2FVerify(req, res);
  } catch (error) {
    const status = error && error.statusCode ? error.statusCode : 500;
    const publicMessage = status >= 500
      ? 'Passkey A2F belum bisa diproses. Cek ENV DIRAC_MFA_SECRET/A2F_SECRET dan coba deploy ulang.'
      : String(error && error.message ? error.message : 'Passkey A2F belum bisa diproses.');
    return res.status(status).json({ ok: false, method: 'passkey', message: publicMessage });
  }
};

function diracPasskeyA2FB64UrlJson(data) {
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

function diracPasskeyA2FSign(payloadBase64) {
  return crypto.createHmac('sha256', getCustomerMfaSecret()).update(String(payloadBase64 || '')).digest('base64url');
}

function diracPasskeyA2FEncodeToken(payload) {
  const payloadBase64 = diracPasskeyA2FB64UrlJson(payload || {});
  return payloadBase64 + '.' + diracPasskeyA2FSign(payloadBase64);
}

function diracPasskeyA2FDecodeToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return null;
  const expected = diracPasskeyA2FSign(parts[0]);
  if (!safeEqual(parts[1], expected)) return null;
  try {
    return JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

function diracPasskeyA2FOriginHostname(origin) {
  try { return new URL(String(origin || '')).hostname.toLowerCase(); } catch (_) { return ''; }
}

function diracPasskeyA2FRpId(req) {
  const explicit = String(process.env.WEBAUTHN_RP_ID || process.env.DIRAC_WEBAUTHN_RP_ID || '').trim().toLowerCase();
  if (explicit) return explicit.replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const host = diracPasskeyA2FOriginHostname(requestOrigin(req)) || 'diracgroup.store';
  if (host === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return host;
  return host.replace(/^www\./, '');
}

function diracPasskeyA2FRpName() {
  return String(process.env.WEBAUTHN_RP_NAME || process.env.DIRAC_WEBAUTHN_RP_NAME || 'Dirac Secure').trim() || 'Dirac Secure';
}

function diracPasskeyA2FUserHandle(user) {
  const raw = String((user && user.id) || (user && user.email) || crypto.randomBytes(16).toString('hex'));
  return crypto.createHash('sha256').update('dirac-passkey-user:' + raw).digest('base64url');
}

function diracPasskeyA2FDecodeClientData(clientDataJSON) {
  const raw = String(clientDataJSON || '').trim();
  if (!raw) return null;
  try {
    return JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch (_) {
    try {
      let normal = raw.replace(/-/g, '+').replace(/_/g, '/');
      while (normal.length % 4) normal += '=';
      return JSON.parse(Buffer.from(normal, 'base64').toString('utf8'));
    } catch (_err) {
      return null;
    }
  }
}

function diracPasskeyA2FPublicError(message) {
  return String(message || '').trim() || 'Passkey belum berhasil dibuat. Ulangi dengan Face ID/sidik jari/PIN perangkat.';
}


function diracPasskeyA2FSafeString(value, maxLen) {
  const clean = String(value || '').trim();
  return clean.slice(0, Math.max(1, Number(maxLen || 2048)));
}

function diracPasskeyA2FBase64UrlToBuffer(value) {
  const raw = String(value || '').trim();
  if (!raw) return Buffer.alloc(0);
  try {
    return Buffer.from(raw, 'base64url');
  } catch (_) {
    try {
      let normal = raw.replace(/-/g, '+').replace(/_/g, '/');
      while (normal.length % 4) normal += '=';
      return Buffer.from(normal, 'base64');
    } catch (_err) {
      return Buffer.alloc(0);
    }
  }
}

function diracPasskeyA2FCredentialId(credential) {
  return diracPasskeyA2FSafeString(
    (credential && (credential.id || credential.rawId)) || '',
    4096
  );
}

function diracPasskeyA2FTransports(credential, response) {
  const values = [];
  const add = (item) => {
    const clean = String(item || '').trim().toLowerCase();
    if (clean && /^[a-z0-9_-]{1,32}$/.test(clean) && !values.includes(clean)) values.push(clean);
  };
  const candidates = [
    response && response.transports,
    credential && credential.transports,
    credential && credential.response && credential.response.transports,
    credential && credential.clientExtensionResults && credential.clientExtensionResults.transports
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) candidate.forEach(add);
  }
  return values.slice(0, 12);
}

function diracPasskeyA2FSignCount(response) {
  const authData = response && response.authenticatorData ? diracPasskeyA2FBase64UrlToBuffer(response.authenticatorData) : Buffer.alloc(0);
  if (authData.length >= 37) {
    try { return Math.max(0, authData.readUInt32BE(33)); } catch (_) { return 0; }
  }
  return 0;
}

function diracPasskeyA2FMinimalCredentialJson({ credential, response, clientData, payload, owner, req, mode }) {
  const nowIso = new Date().toISOString();
  return {
    schema: 'dirac-domain-passkey-v1',
    mode: mode || (payload && payload.mode) || 'registration',
    rp_id: payload && payload.rpId ? String(payload.rpId) : diracPasskeyA2FRpId(req),
    origin: clientData && clientData.origin ? String(clientData.origin) : String((payload && payload.origin) || requestOrigin(req) || ''),
    auth_user_id: owner && owner.authUserId ? String(owner.authUserId) : null,
    customer_id: owner && owner.customerId ? String(owner.customerId) : null,
    credential: {
      id: diracPasskeyA2FCredentialId(credential),
      rawId: diracPasskeyA2FSafeString(credential && credential.rawId, 4096),
      type: diracPasskeyA2FSafeString(credential && credential.type, 64) || 'public-key',
      clientExtensionResults: credential && credential.clientExtensionResults && typeof credential.clientExtensionResults === 'object'
        ? credential.clientExtensionResults
        : {}
    },
    response: {
      clientDataJSON: diracPasskeyA2FSafeString(response && response.clientDataJSON, 8192),
      attestationObject: diracPasskeyA2FSafeString(response && response.attestationObject, 65536),
      authenticatorData: diracPasskeyA2FSafeString(response && response.authenticatorData, 16384),
      signature: diracPasskeyA2FSafeString(response && response.signature, 16384),
      userHandle: diracPasskeyA2FSafeString(response && response.userHandle, 4096),
      transports: diracPasskeyA2FTransports(credential, response)
    },
    client_data: {
      type: clientData && clientData.type ? String(clientData.type) : '',
      challenge_sha256: crypto.createHash('sha256').update(String(clientData && clientData.challenge || '')).digest('hex'),
      origin: clientData && clientData.origin ? String(clientData.origin) : '',
      crossOrigin: clientData && clientData.crossOrigin === true
    },
    saved_at: nowIso,
    user_agent_hash: customerMfaBindingHash('ua', requestUserAgent(req)) || null
  };
}

async function diracPasskeyA2FFetchCustomerById(customerId) {
  const cleanId = String(customerId || '').trim();
  if (!customerSecurityLooksLikeUuid(cleanId)) return { ok: false, status: 400, data: [] };
  const select = ['id', 'email', 'name', 'phone'].join(',');
  const path = '/rest/v1/customers?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(cleanId) + '&limit=1';
  return supabaseFetch(path, { method: 'GET', auth: 'service' });
}

async function diracPasskeyA2FResolveOwner(user, email) {
  const authUserId = String(user && user.id || '').trim();
  const authEmail = normalizeAuthEmail(email || (user && user.email));
  if (!isValidAuthEmail(authEmail)) {
    return { ok: false, status: 400, message: 'Email akun tidak valid untuk Passkey. Login ulang dulu.' };
  }

  let customerId = '';
  let customerEmail = authEmail;

  if (authUserId && typeof customerSecurityFetchAuthLink === 'function') {
    const linkResult = await customerSecurityFetchAuthLink(authUserId).catch((error) => ({ ok: false, status: 500, error }));
    const linkRows = Array.isArray(linkResult && linkResult.data) ? linkResult.data : [];
    const link = linkRows.find((row) => row && row.link_status === 'active' && customerSecurityLooksLikeUuid(row.customer_id));
    if (link) customerId = String(link.customer_id);
  }

  if (customerId) {
    const customerResult = await diracPasskeyA2FFetchCustomerById(customerId).catch((error) => ({ ok: false, status: 500, error }));
    const customerRows = Array.isArray(customerResult && customerResult.data) ? customerResult.data : [];
    if (customerRows[0] && isValidAuthEmail(customerRows[0].email)) {
      customerEmail = normalizeAuthEmail(customerRows[0].email);
    }
    return { ok: true, authUserId, customerId, email: customerEmail, source: 'security_customer_auth_links' };
  }

  if (typeof customerSecurityFetchCustomerByEmail === 'function') {
    const customerResult = await customerSecurityFetchCustomerByEmail(authEmail).catch((error) => ({ ok: false, status: 500, error }));
    const customerRows = Array.isArray(customerResult && customerResult.data) ? customerResult.data : [];
    const customer = customerRows.find((row) => row && customerSecurityLooksLikeUuid(row.id));
    if (customer) {
      return {
        ok: true,
        authUserId,
        customerId: String(customer.id),
        email: isValidAuthEmail(customer.email) ? normalizeAuthEmail(customer.email) : authEmail,
        source: 'customers.email'
      };
    }
  }

  return {
    ok: false,
    status: 409,
    message: 'Akun login belum terhubung ke tabel customers. Passkey tidak disimpan agar tidak salah owner.'
  };
}

function diracPasskeyA2FOwnerMatches(row, owner) {
  if (!row || !owner) return false;
  const rowCustomer = String(row.user_id || '').trim();
  const rowEmail = normalizeAuthEmail(row.email || '');
  return Boolean(
    (owner.customerId && rowCustomer && rowCustomer === String(owner.customerId)) ||
    (owner.email && rowEmail && rowEmail === normalizeAuthEmail(owner.email))
  );
}

async function diracPasskeyA2FListActivePasskeys(owner) {
  const select = ['id', 'user_id', 'email', 'credential_id', 'credential_json', 'transports', 'sign_count', 'is_active', 'created_at', 'last_used_at'].join(',');
  const seen = new Set();
  const rows = [];
  const fetchRows = async (filter) => {
    const path = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(select) + '&is_active=eq.true&' + filter + '&order=created_at.desc&limit=20';
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok) return;
    for (const row of (Array.isArray(result.data) ? result.data : [])) {
      const key = String(row && (row.id || row.credential_id) || '');
      if (!key || seen.has(key) || !diracPasskeyA2FOwnerMatches(row, owner)) continue;
      seen.add(key);
      rows.push(row);
    }
  };

  if (owner && owner.customerId && customerSecurityLooksLikeUuid(owner.customerId)) {
    await fetchRows('user_id=eq.' + encodeURIComponent(owner.customerId));
  }
  if (owner && owner.email && isValidAuthEmail(owner.email)) {
    await fetchRows('email=eq.' + encodeURIComponent(owner.email));
  }

  return rows;
}

async function diracPasskeyA2FFetchByCredentialId(credentialId) {
  const id = diracPasskeyA2FSafeString(credentialId, 4096);
  if (!id) return { ok: true, data: [] };
  const select = ['id', 'user_id', 'email', 'credential_id', 'credential_json', 'transports', 'sign_count', 'is_active', 'created_at', 'last_used_at'].join(',');
  const path = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(select) + '&credential_id=eq.' + encodeURIComponent(id) + '&limit=1';
  return supabaseFetch(path, { method: 'GET', auth: 'service' });
}

async function diracPasskeyA2FSaveRegistration({ owner, credential, response, clientData, payload, req }) {
  const credentialId = diracPasskeyA2FCredentialId(credential);
  if (!credentialId) return { ok: false, status: 400, message: 'Credential Passkey kosong. Coba ulangi.' };
  if (!owner || !owner.customerId || !customerSecurityLooksLikeUuid(owner.customerId)) {
    return { ok: false, status: 409, message: 'Customer owner Passkey tidak valid. Login ulang dulu.' };
  }

  const nowIso = new Date().toISOString();
  const signCount = diracPasskeyA2FSignCount(response);
  const rowBody = {
    user_id: owner.customerId,
    email: owner.email,
    credential_id: credentialId,
    credential_json: diracPasskeyA2FMinimalCredentialJson({ credential, response, clientData, payload, owner, req, mode: 'registration' }),
    transports: diracPasskeyA2FTransports(credential, response),
    sign_count: signCount,
    is_active: true,
    updated_at: nowIso
  };

  const existingResult = await diracPasskeyA2FFetchByCredentialId(credentialId);
  if (!existingResult.ok) {
    return { ok: false, status: existingResult.status || 500, message: 'Gagal mengecek credential Passkey di database.' };
  }

  const existing = Array.isArray(existingResult.data) && existingResult.data[0] ? existingResult.data[0] : null;
  if (existing && !diracPasskeyA2FOwnerMatches(existing, owner)) {
    return { ok: false, status: 409, message: 'Credential Passkey sudah terdaftar pada akun lain.' };
  }

  if (existing && existing.id) {
    const patch = await supabaseFetch('/rest/v1/domain_passkeys?id=eq.' + encodeURIComponent(existing.id), {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: rowBody
    });
    if (!patch.ok) return { ok: false, status: patch.status || 500, message: 'Gagal memperbarui Passkey di database.', upstream: patch.data };
    return { ok: true, created: false, row: Array.isArray(patch.data) ? patch.data[0] : patch.data };
  }

  const created = await supabaseFetch('/rest/v1/domain_passkeys', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [rowBody]
  });
  if (!created.ok) return { ok: false, status: created.status || 500, message: 'Gagal menyimpan Passkey ke database.', upstream: created.data };
  return { ok: true, created: true, row: Array.isArray(created.data) ? created.data[0] : created.data };
}

async function diracPasskeyA2FUpdateUsage({ row, owner, response, credential, clientData, payload, req }) {
  if (!row || !row.id || !diracPasskeyA2FOwnerMatches(row, owner)) {
    return { ok: false, status: 403, message: 'Passkey tidak cocok dengan akun login ini.' };
  }
  const signCount = diracPasskeyA2FSignCount(response);
  const nowIso = new Date().toISOString();
  const body = {
    last_used_at: nowIso,
    updated_at: nowIso,
    is_active: true
  };
  if (signCount > 0) body.sign_count = signCount;
  body.credential_json = {
    ...(row.credential_json && typeof row.credential_json === 'object' ? row.credential_json : {}),
    last_authentication: diracPasskeyA2FMinimalCredentialJson({ credential, response, clientData, payload, owner, req, mode: 'authentication' })
  };

  const patched = await supabaseFetch('/rest/v1/domain_passkeys?id=eq.' + encodeURIComponent(row.id), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body
  });
  if (!patched.ok) return { ok: false, status: patched.status || 500, message: 'Gagal memperbarui penggunaan Passkey.', upstream: patched.data };
  return { ok: true, row: Array.isArray(patched.data) ? patched.data[0] : patched.data };
}

async function diracPasskeyA2FMarkSettingsActive(owner) {
  try {
    if (!owner || !owner.customerId || !customerSecurityLooksLikeUuid(owner.customerId)) return { ok: false, reason: 'missing_customer' };
    const existing = await customerSecurityFetchRows(
      'security_customer_settings',
      ['id', 'customer_id', 'two_factor_enabled', 'two_factor_method'],
      owner.customerId,
      'created_at.desc',
      1
    );
    const body = {
      two_factor_enabled: true,
      two_factor_method: 'passkey',
      last_security_check_at: new Date().toISOString()
    };
    const rows = Array.isArray(existing && existing.data) ? existing.data : [];
    if (rows[0] && rows[0].id) {
      const patched = await supabaseFetch('/rest/v1/security_customer_settings?id=eq.' + encodeURIComponent(rows[0].id), {
        method: 'PATCH',
        auth: 'service',
        prefer: 'return=representation',
        body
      });
      return { ok: Boolean(patched.ok), status: patched.status };
    }
    const created = await supabaseFetch('/rest/v1/security_customer_settings', {
      method: 'POST',
      auth: 'service',
      prefer: 'return=representation',
      body: [{ customer_id: owner.customerId, ...body }]
    });
    return { ok: Boolean(created.ok), status: created.status };
  } catch (error) {
    console.error('[dirac-passkey-settings]', error && error.message ? error.message : error);
    return { ok: false, reason: 'settings_exception' };
  }
}

async function diracPasskeyA2FStart(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, method: 'passkey', message: 'Gunakan POST untuk Passkey A2F.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  const email = normalizeAuthEmail(user.email);
  if (!isValidAuthEmail(email)) {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Email akun tidak valid untuk membuat passkey. Login ulang dulu.' });
  }

  const owner = await diracPasskeyA2FResolveOwner(user, email);
  if (!owner.ok) {
    return res.status(owner.status || 409).json({ ok: false, method: 'passkey', message: owner.message || 'Akun belum siap untuk Passkey.' });
  }

  const now = Date.now();
  const challenge = crypto.randomBytes(32).toString('base64url');
  const rpId = diracPasskeyA2FRpId(req);
  const origin = requestOrigin(req);
  const userHandle = diracPasskeyA2FUserHandle({ id: owner.customerId, email: owner.email });
  const activePasskeys = await diracPasskeyA2FListActivePasskeys(owner);
  const hasActivePasskey = activePasskeys.length > 0;
  const mode = hasActivePasskey ? 'authentication' : 'registration';
  const payload = {
    type: DIRAC_PASSKEY_A2F_TOKEN_TYPE,
    method: 'passkey',
    mode,
    challenge,
    rpId,
    origin,
    authUserId: owner.authUserId || String(user.id || ''),
    customerId: owner.customerId,
    emailHash: customerMfaProfileId(owner.email),
    uaHash: customerMfaBindingHash('ua', requestUserAgent(req)),
    issuedAtMs: now,
    expiresAtMs: now + DIRAC_PASSKEY_A2F_TTL_MS
  };
  const setupToken = diracPasskeyA2FEncodeToken(payload);

  const basePublicKey = {
    challenge,
    rpId,
    timeout: 60000,
    userVerification: 'required'
  };

  if (hasActivePasskey) {
    return res.status(200).json({
      ok: true,
      method: 'passkey',
      passkeyMode: 'authentication',
      needsRegistration: false,
      setupToken,
      mfaSetupToken: setupToken,
      expires_in: Math.floor(DIRAC_PASSKEY_A2F_TTL_MS / 1000),
      publicKey: {
        ...basePublicKey,
        allowCredentials: activePasskeys
          .filter((row) => row && row.credential_id)
          .map((row) => ({
            type: 'public-key',
            id: String(row.credential_id),
            transports: Array.isArray(row.transports) ? row.transports : []
          }))
      },
      message: 'Passkey aktif ditemukan. Browser akan membuka Face ID, sidik jari, atau PIN untuk masuk.'
    });
  }

  return res.status(200).json({
    ok: true,
    method: 'passkey',
    passkeyMode: 'registration',
    needsRegistration: true,
    setupToken,
    mfaSetupToken: setupToken,
    expires_in: Math.floor(DIRAC_PASSKEY_A2F_TTL_MS / 1000),
    publicKey: {
      challenge,
      rp: { name: diracPasskeyA2FRpName(), id: rpId },
      user: { id: userHandle, name: owner.email, displayName: owner.email },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        requireResidentKey: false,
        userVerification: 'required'
      },
      extensions: { credProps: true }
    },
    message: 'Browser akan membuka Face ID, sidik jari, atau PIN untuk membuat Passkey.'
  });
}

async function diracPasskeyA2FVerify(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, method: 'passkey', message: 'Gunakan POST untuk verifikasi Passkey A2F.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

  const body = await readBody(req);
  const email = normalizeAuthEmail(user.email);
  const owner = await diracPasskeyA2FResolveOwner(user, email);
  if (!owner.ok) {
    return res.status(owner.status || 409).json({ ok: false, method: 'passkey', message: owner.message || 'Akun belum siap untuk Passkey.' });
  }

  const setupToken = String(body.setupToken || body.mfaSetupToken || body.token || '').trim();
  const payload = diracPasskeyA2FDecodeToken(setupToken);
  if (!payload || payload.type !== DIRAC_PASSKEY_A2F_TOKEN_TYPE || payload.method !== 'passkey') {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Challenge Passkey tidak valid. Tekan Buat passkey sekarang sekali lagi.' });
  }
  if (Number(payload.expiresAtMs || 0) <= Date.now()) {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Challenge Passkey sudah expired. Ulangi dari tombol Passkey.' });
  }
  if (!payload.emailHash || !safeEqual(String(payload.emailHash), customerMfaProfileId(owner.email))) {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Passkey harus dibuat dari akun login yang sama.' });
  }
  if (payload.customerId && owner.customerId && String(payload.customerId) !== String(owner.customerId)) {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Customer owner Passkey tidak cocok. Login ulang dulu.' });
  }
  if (payload.uaHash) {
    const expectedUaHash = customerMfaBindingHash('ua', requestUserAgent(req));
    if (!expectedUaHash || !safeEqual(String(payload.uaHash), expectedUaHash)) {
      return res.status(403).json({ ok: false, method: 'passkey', message: 'Passkey harus diselesaikan dari browser/perangkat yang sama.' });
    }
  }

  const credential = body && body.credential && typeof body.credential === 'object' ? body.credential : null;
  const response = credential && credential.response && typeof credential.response === 'object' ? credential.response : null;
  const clientData = response ? diracPasskeyA2FDecodeClientData(response.clientDataJSON) : null;

  if (!credential || !response || !clientData) {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Data Passkey dari browser tidak lengkap. Coba ulangi Face ID/sidik jari/PIN.' });
  }
  if (String(clientData.challenge || '') !== String(payload.challenge || '')) {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Challenge Passkey tidak cocok. Minta challenge baru.' });
  }
  if (clientData.crossOrigin === true) {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Passkey harus dibuat dari origin website utama.' });
  }
  const clientType = String(clientData.type || '').toLowerCase();
  const payloadMode = String(payload.mode || body.passkeyMode || '').toLowerCase();
  const isAuthentication = payloadMode === 'authentication';
  if (isAuthentication && clientType !== 'webauthn.get') {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Respons browser bukan login Passkey yang valid.' });
  }
  if (!isAuthentication && clientType !== 'webauthn.create') {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Respons browser bukan pendaftaran Passkey yang valid.' });
  }
  const clientOrigin = normalizeDashboardMfaOrigin(clientData.origin || '');
  const expectedOrigin = normalizeDashboardMfaOrigin(payload.origin || requestOrigin(req));
  if (expectedOrigin && clientOrigin && clientOrigin !== expectedOrigin) {
    return res.status(403).json({ ok: false, method: 'passkey', message: 'Origin Passkey tidak cocok dengan domain login.' });
  }
  if (!isAuthentication && !response.attestationObject) {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Browser tidak mengirim attestation Passkey. Coba ulangi.' });
  }
  if (isAuthentication && (!response.authenticatorData || !response.signature)) {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Browser tidak mengirim bukti login Passkey. Coba ulangi.' });
  }

  const credentialId = diracPasskeyA2FCredentialId(credential);
  if (!credentialId) {
    return res.status(400).json({ ok: false, method: 'passkey', message: 'Credential Passkey kosong. Coba ulangi.' });
  }

  let dbWrite = null;
  let registeredNow = false;
  if (isAuthentication) {
    const existingResult = await diracPasskeyA2FFetchByCredentialId(credentialId);
    const row = existingResult.ok && Array.isArray(existingResult.data) ? existingResult.data[0] : null;
    if (!row || row.is_active !== true || !diracPasskeyA2FOwnerMatches(row, owner)) {
      return res.status(403).json({ ok: false, method: 'passkey', message: 'Passkey tidak terdaftar untuk akun ini. Buat Passkey dulu dari akun yang benar.' });
    }
    dbWrite = await diracPasskeyA2FUpdateUsage({ row, owner, response, credential, clientData, payload, req });
  } else {
    dbWrite = await diracPasskeyA2FSaveRegistration({ owner, credential, response, clientData, payload, req });
    registeredNow = Boolean(dbWrite && dbWrite.ok && dbWrite.created);
  }

  if (!dbWrite || !dbWrite.ok) {
    return res.status(dbWrite && dbWrite.status ? dbWrite.status : 500).json({
      ok: false,
      method: 'passkey',
      message: diracPasskeyA2FPublicError(dbWrite && dbWrite.message ? dbWrite.message : 'Passkey belum tersimpan ke database.')
    });
  }

  await diracPasskeyA2FMarkSettingsActive(owner);

  const proof = customerSecurityCreateDashboardMfaToken(req, user, 'passkey');
  customerSecuritySetDashboardMfaCookie(res, proof);

  return res.status(200).json({
    ok: true,
    verified: true,
    active: true,
    method: 'passkey',
    passkey_registered: true,
    passkeyMode: isAuthentication ? 'authentication' : 'registration',
    needsRegistration: false,
    database_saved: true,
    registered_now: registeredNow,
    owner_bound: true,
    owner_source: owner.source,
    credential_id_hint: crypto.createHash('sha256').update(String(credentialId)).digest('hex').slice(0, 12),
    message: isAuthentication
      ? 'Passkey tersimpan berhasil diverifikasi. Akses dashboard sudah dibuka.'
      : 'Passkey berhasil diaktifkan dan tersimpan di database. Akses dashboard sudah diverifikasi.',
    dashboardSession: {
      verified: true,
      expiresAtMs: proof.expiresAtMs,
      activeAtMs: proof.activeAtMs,
      method: 'passkey',
      transport: 'httponly-secure-cookie-only'
    },
    time: diracNowIso()
  });
}




/* ============================================================
   DIRAC PASSKEY DB STATUS FOR EMAIL BACKUP UNLOCK v1
   - Read-only status endpoint for masuk.html.
   - Does not expose credential_id / credential_json.
   - Lets UI unlock Email backup only when domain_passkeys has active row.
   ============================================================ */

const __diracPasskeyDbStatusPreviousHandler = module.exports;
const DIRAC_PASSKEY_DB_STATUS_ACTIONS = new Set([
  'dirac_mfa_passkey_status',
  'domain_mfa_passkey_status',
  'dirac_passkey_status',
  'domain_passkey_status'
]);

module.exports = async function diracPasskeyDbStatusWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  if (!DIRAC_PASSKEY_DB_STATUS_ACTIONS.has(rawAction)) {
    return __diracPasskeyDbStatusPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });
  if (req.method !== 'GET' && req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  try {
    const user = await requireDomainUser(req, res);
    if (!user) return;

    const email = normalizeAuthEmail(user.email);
    if (!isValidAuthEmail(email)) {
      return res.status(400).json({ ok: false, active: false, method: 'passkey', message: 'Email akun tidak valid.' });
    }

    // Primary status check: domain_passkeys.email must match the currently logged-in account email.
    // This is read-only and does not expose credential_id/credential_json.
    const directSelect = 'id,user_id,email,is_active,created_at,last_used_at';
    const directPath = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(directSelect)
      + '&is_active=eq.true&email=eq.' + encodeURIComponent(email)
      + '&order=created_at.desc&limit=20';
    const directResult = await supabaseFetch(directPath, { method: 'GET', auth: 'service' }).catch(() => null);
    const directRows = directResult && directResult.ok && Array.isArray(directResult.data) ? directResult.data : [];
    if (directRows.length > 0) {
      return res.status(200).json({
        ok: true,
        method: 'passkey',
        active: true,
        passkey_active: true,
        has_passkey: true,
        passkey_count: directRows.length,
        owner_bound: true,
        owner_source: 'domain_passkeys.email',
        customer_id_present: Boolean(directRows[0] && directRows[0].user_id),
        email_present: true,
        message: 'Passkey aktif ditemukan di database. Email A2F boleh dipakai sebagai cadangan.'
      });
    }

    const owner = await diracPasskeyA2FResolveOwner(user, email);
    if (!owner.ok) {
      return res.status(200).json({
        ok: true,
        active: false,
        method: 'passkey',
        passkey_active: false,
        has_passkey: false,
        passkey_count: 0,
        owner_bound: false,
        owner_source: 'not_resolved',
        message: 'Passkey aktif belum ditemukan untuk email login ini.'
      });
    }

    const rows = await diracPasskeyA2FListActivePasskeys(owner);
    const count = Array.isArray(rows) ? rows.length : 0;
    return res.status(200).json({
      ok: true,
      method: 'passkey',
      active: count > 0,
      passkey_active: count > 0,
      has_passkey: count > 0,
      passkey_count: count,
      owner_bound: true,
      owner_source: owner.source || '',
      customer_id_present: Boolean(owner.customerId),
      email_present: Boolean(owner.email),
      message: count > 0
        ? 'Passkey aktif ditemukan di database. Email A2F boleh dipakai sebagai cadangan.'
        : 'Passkey aktif belum ditemukan. Buat Passkey dulu sebelum memakai Email A2F.'
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      active: false,
      method: 'passkey',
      message: 'Status Passkey belum bisa dicek. Coba login ulang lalu ulangi.'
    });
  }
};

/* ============================================================
   UNIVERSAL PAYMENT GATEWAY FOR PESANAN.HTML - APPEND ONLY
   Scope:
   - Payment gateway only.
   - Login, hash, endpoint auth, dashboard MFA/A2F, cookies, and security guards are not modified.
   - Frontend may only identify the order; amount stays locked from database.
   - Supports regular orders table and domain_orders table from pesanan.html.
   - No invoice/localStorage source is trusted.
   ============================================================ */

const __diracUniversalPesananPaymentPreviousHandler = module.exports;
const DIRAC_UNIVERSAL_PESANAN_PAYMENT_ACTIONS = new Set(['create_payment', 'my_orders']);

module.exports = async function diracUniversalPesananPaymentWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = diracUniversalPesananPaymentNormalizeAction(rawAction);

  if (!DIRAC_UNIVERSAL_PESANAN_PAYMENT_ACTIONS.has(action)) {
    return __diracUniversalPesananPaymentPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  try {
    if (action === 'my_orders') {
      if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });
      return await diracUniversalPesananReadOrders(req, res);
    }

    if (action === 'create_payment') {
      if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
      return await diracUniversalPesananCreatePayment(req, res);
    }
  } catch (error) {
    console.error('[universal-pesanan-payment]', lockedPaymentSafeError(error));
    return res.status(error && error.statusCode ? error.statusCode : 500).json({
      ok: false,
      message: 'Payment belum dapat diproses dengan aman.',
      error: lockedPaymentPublicError(error)
    });
  }

  return __diracUniversalPesananPaymentPreviousHandler(req, res);
};

function diracUniversalPesananPaymentNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    create_payment: 'create_payment',
    create_payment_order: 'create_payment',
    pay_order: 'create_payment',
    order_payment: 'create_payment',
    bayar_pesanan: 'create_payment',
    checkout_payment: 'create_payment',
    my_orders: 'my_orders',
    pesanan: 'my_orders',
    pesanan_saya: 'my_orders',
    customer_orders: 'my_orders',
    orders_saya: 'my_orders',
    my_invoices: 'my_orders',
    invoice_saya: 'my_orders'
  };
  return aliases[clean] || clean;
}

function diracUniversalPesananGatewayConfigured() {
  // MIDTRANS ONLY v1: status gateway hanya mengikuti konfigurasi Midtrans.
  return Boolean(midtransPaymentIsConfigured());
}

async function diracUniversalPesananReadOrders(req, res) {
  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;
  const user = access.user || {};

  const authUserId = String(user.id || '').trim();
  const userEmail = normalizeAuthEmail(user.email || '');
  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId) || !userEmail || !isValidAuthEmail(userEmail)) {
    return res.status(401).json({ ok: false, message: 'Sesi login tidak valid.' });
  }

  const owner = await myOrdersResolveOwner(authUserId, userEmail);
  if (!owner || !Array.isArray(owner.customerIds) || !owner.customerIds.length) {
    return res.status(403).json({
      ok: false,
      service: 'dirac-my-orders',
      ownership_locked: true,
      direct_frontend_table_access: false,
      frontend_customer_id_ignored: true,
      message: 'Akun login belum terhubung ke customer profile aktif. Pesanan dikunci aman agar tidak salah owner.'
    });
  }

  const genericOrders = await myOrdersFetchGenericOrders(owner, userEmail);
  const domainOrders = await myOrdersFetchDomainOrders(owner, userEmail);
  const allOrders = [...genericOrders.orders, ...domainOrders.orders]
    .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
    .slice(0, 120);

  const decoratedOrders = await diracUniversalPesananDecorateOrders(allOrders);
  const summary = myOrdersBuildSummary(decoratedOrders);
  const gatewayConfigured = diracUniversalPesananGatewayConfigured();

  return res.status(200).json({
    ok: true,
    service: 'dirac-my-orders',
    dashboard_mfa_required: true,
    dashboard_mfa_source: access.mfa && access.mfa.source || '',
    user: sanitizeUser(user),
    ownership_locked: true,
    direct_frontend_table_access: false,
    frontend_customer_id_ignored: true,
    payment_gateway_configured: gatewayConfigured,
    payment_note: gatewayConfigured
      ? 'Payment gateway aktif. Semua invoice eligible dibuatkan payment dari nominal database, bukan dari browser.'
      : 'Payment gateway Midtrans belum aktif. Isi MIDTRANS_SERVER_KEY atau MIDTRANS_SANDBOX_SERVER_KEY di backend.',
    owner: {
      customer_id_available: Boolean(owner.customerIds.length),
      customer_ids_count: owner.customerIds.length,
      source: owner.sources.join(',') || 'auth_email_only'
    },
    summary,
    orders: decoratedOrders,
    diagnostics: {
      generic_orders_ready: genericOrders.ok,
      domain_orders_ready: domainOrders.ok,
      generic_orders_error: genericOrders.error || null,
      domain_orders_error: domainOrders.error || null,
      payment_gateway_ready: gatewayConfigured
    },
    time: diracNowIso()
  });
}

async function diracUniversalPesananDecorateOrders(orders) {
  const rows = Array.isArray(orders) ? orders : [];
  const txMap = await diracUniversalPesananFetchReusableTransactionsForOrders(rows);
  const gatewayConfigured = diracUniversalPesananGatewayConfigured();

  return rows.map((order) => {
    const copy = { ...order };
    const key = diracUniversalPesananOrderTxKey(copy);
    const tx = key ? txMap.get(key) : null;
    const canPay = gatewayConfigured && diracUniversalPesananOrderCanPay(copy);

    if (tx && tx.payment_url) {
      copy.payment_url = String(tx.payment_url);
      copy.payment_transaction_id = tx.id || null;
      copy.gateway_reference = tx.gateway_reference || null;
      copy.payment_provider = tx.gateway_name || null;
      copy.payment_gateway_configured = gatewayConfigured;
      copy.can_pay = diracUniversalPesananOrderCanPay(copy);
      copy.payment_message = 'Payment sudah tersedia. Tekan tombol untuk melanjutkan pembayaran.';
      return copy;
    }

    copy.payment_url = copy.payment_url || null;
    copy.payment_gateway_configured = gatewayConfigured;
    copy.can_pay = canPay;
    copy.payment_message = canPay
      ? 'Tekan Bayar Sekarang. Backend akan membuat payment memakai total database, bukan nominal dari browser.'
      : (gatewayConfigured
        ? 'Invoice ini belum eligible untuk payment otomatis.'
        : 'Payment gateway belum aktif di backend.');
    return copy;
  });
}

function diracUniversalPesananOrderTxKey(order) {
  if (!order || !order.id) return '';
  if (order.type === 'domain_order' || order.service_type === 'domain') return 'domain:' + String(order.id);
  return 'regular:' + String(order.id);
}

async function diracUniversalPesananFetchReusableTransactionsForOrders(orders) {
  const map = new Map();
  const regularIds = [];
  const domainIds = [];

  (Array.isArray(orders) ? orders : []).forEach((order) => {
    if (!order || !customerSecurityLooksLikeUuid(order.id)) return;
    if (order.type === 'domain_order' || order.service_type === 'domain') domainIds.push(String(order.id));
    else regularIds.push(String(order.id));
  });

  await diracUniversalPesananFillTxMap(map, 'regular', regularIds);
  await diracUniversalPesananFillTxMap(map, 'domain', domainIds);
  return map;
}

async function diracUniversalPesananFillTxMap(map, type, ids) {
  const cleanIds = Array.from(new Set((ids || []).filter(customerSecurityLooksLikeUuid))).slice(0, 120);
  if (!cleanIds.length) return;
  const column = type === 'domain' ? 'domain_order_id' : 'order_id';
  const select = 'id,order_id,domain_order_id,gateway_name,gateway_reference,payment_status,amount,currency,payment_url,expired_at,created_at';
  const path = '/rest/v1/payment_transactions?select=' + encodeURIComponent(select)
    + '&' + column + '=in.(' + cleanIds.map(encodeURIComponent).join(',') + ')'
    + '&order=created_at.desc&limit=240';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data)) return;

  const now = Date.now();
  result.data.forEach((tx) => {
    if (!tx || !tx.payment_url) return;
    if (tx.expired_at) {
      const expires = new Date(tx.expired_at).getTime();
      if (Number.isFinite(expires) && expires <= now) return;
    }
    const id = type === 'domain' ? tx.domain_order_id : tx.order_id;
    if (!id) return;
    const key = type + ':' + String(id);
    if (!map.has(key)) map.set(key, tx);
  });
}

async function diracUniversalPesananCreatePayment(req, res) {
  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;
  const user = access.user || {};
  const body = await readBody(req);
  const query = (req && req.query) || {};

  const requestedOrderId = lockedPaymentCleanText(
    body.order_id || body.orderId || body.order_code || body.orderCode || body.invoice_code || body.invoiceCode || body.id ||
    query.order_id || query.orderId || query.order_code || query.orderCode || query.invoice_code || query.invoiceCode || query.id ||
    '',
    140
  );
  const requestedType = diracUniversalPesananNormalizeRequestedType(
    body.order_type || body.orderType || body.type || body.service_type || body.serviceType ||
    query.order_type || query.orderType || query.type || query.service_type || query.serviceType ||
    ''
  );

  if (!requestedOrderId) {
    return res.status(400).json({ ok: false, message: 'order_id wajib dikirim. Nominal tidak boleh dikirim dari frontend.' });
  }

  if (
    body.amount !== undefined ||
    body.total !== undefined ||
    body.subtotal !== undefined ||
    body.payment_status !== undefined ||
    body.order_status !== undefined ||
    body.paid !== undefined ||
    body.completed !== undefined ||
    body.payment_url !== undefined
  ) {
    console.warn('[universal-pesanan-payment] ignored frontend payment fields', {
      hasAmount: body.amount !== undefined,
      hasTotal: body.total !== undefined,
      hasSubtotal: body.subtotal !== undefined,
      hasPaymentStatus: body.payment_status !== undefined,
      hasOrderStatus: body.order_status !== undefined,
      hasPaid: body.paid !== undefined,
      hasCompleted: body.completed !== undefined,
      hasPaymentUrl: body.payment_url !== undefined
    });
  }

  const authUserId = String(user.id || '').trim();
  const userEmail = normalizeAuthEmail(user.email || '');
  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId) || !userEmail || !isValidAuthEmail(userEmail)) {
    return res.status(401).json({ ok: false, message: 'Sesi login tidak valid.' });
  }

  const owner = await sessionOwnershipCheckoutResolveCustomerOwner({
    authUserId,
    email: userEmail,
    fullName: userEmail,
    phone: ''
  });

  if (!owner.ok || !owner.customer || !owner.customer.id) {
    return res.status(owner.status || 409).json({
      ok: false,
      message: owner.message || 'Customer ownership belum siap. Login ulang atau hubungi admin.'
    });
  }

  const customer = owner.customer;
  const customerId = String(customer.id || '').trim();
  if (!customerSecurityLooksLikeUuid(customerId)) {
    return res.status(409).json({ ok: false, message: 'Customer ownership tidak valid.' });
  }

  const lookup = await diracUniversalPesananFindOwnedOrder(requestedOrderId, requestedType, customerId);
  if (!lookup.ok) {
    return res.status(lookup.status || 404).json({ ok: false, message: lookup.message || 'Order tidak ditemukan untuk akun ini.' });
  }

  const paymentInput = await diracUniversalPesananBuildPaymentInput(lookup, customer, userEmail);
  if (!paymentInput.ok) {
    return res.status(paymentInput.status || 409).json({ ok: false, message: paymentInput.message || 'Order belum bisa dibuatkan payment.' });
  }

  const gatewayConfigured = diracUniversalPesananGatewayConfigured();
  if (!gatewayConfigured) {
    return res.status(503).json({
      ok: false,
      payment_gateway_configured: false,
      message: 'Payment gateway Midtrans belum disetel. Isi MIDTRANS_SERVER_KEY atau MIDTRANS_SANDBOX_SERVER_KEY di Environment Variables Vercel.'
    });
  }

  const existing = await diracUniversalPesananFindReusableTransaction({
    kind: paymentInput.kind,
    orderId: paymentInput.orderId,
    domainOrderId: paymentInput.domainOrderId,
    customerId,
    amount: paymentInput.amount
  });

  if (existing.ok && existing.transaction && existing.transaction.payment_url) {
    return res.status(200).json({
      ok: true,
      reused: true,
      message: 'Payment sudah pernah dibuat untuk order ini. Menggunakan payment URL yang sama.',
      order_kind: paymentInput.kind,
      order_id: paymentInput.orderRefId,
      order_code: paymentInput.orderCode,
      service_type: paymentInput.serviceType,
      payment_transaction_id: existing.transaction.id,
      gateway_reference: existing.transaction.gateway_reference || null,
      amount: paymentInput.amount,
      currency: String(existing.transaction.currency || 'IDR').toUpperCase(),
      payment_status: existing.transaction.payment_status || 'unpaid',
      payment_url: existing.transaction.payment_url,
      payment_provider: existing.transaction.gateway_name || null,
      amount_source: paymentInput.amountSource,
      ownership_locked: true,
      amount_locked: true,
      frontend_ignored_fields: ['amount', 'total', 'subtotal', 'payment_status', 'order_status', 'paid', 'completed', 'payment_url', 'customer_id']
    });
  }

  const gatewayName = lockedPaymentGatewayName();
  const gatewayReference = lockedPaymentGenerateReference(`${paymentInput.referencePrefix}-${paymentInput.orderCode}`);
  const transactionResult = await lockedPaymentInsertTransaction({
    orderId: paymentInput.kind === 'regular' ? paymentInput.orderId : null,
    domainOrderId: paymentInput.kind === 'domain' ? paymentInput.domainOrderId : null,
    customerId,
    serviceType: paymentInput.serviceType,
    gatewayName,
    gatewayReference,
    amount: paymentInput.amount,
    currency: 'IDR',
    metadata: {
      order_kind: paymentInput.kind,
      order_code: paymentInput.orderCode,
      amount_source: paymentInput.amountSource,
      item_total: paymentInput.itemTotal,
      create_payment_started_at: diracNowIso(),
      frontend_amount_ignored: true,
      frontend_invoice_storage_trusted: false,
      owner_source: owner.source || 'backend_auth_link'
    }
  });

  if (!transactionResult.ok) {
    return res.status(transactionResult.status || 500).json({
      ok: false,
      message: 'Gagal menyimpan transaksi payment.',
      error: lockedPaymentSafeUpstreamError(transactionResult.data)
    });
  }

  const transaction = Array.isArray(transactionResult.data) ? transactionResult.data[0] : transactionResult.data;
  if (!transaction || !transaction.id) {
    return res.status(500).json({ ok: false, message: 'Transaksi payment dibuat, tetapi ID tidak ditemukan.' });
  }

  const gateway = await lockedPaymentCreateGatewayInvoice({
    endpoint: lockedPaymentGatewayEndpoint(),
    gatewayName,
    gatewayReference,
    transactionId: transaction.id,
    orderId: paymentInput.orderRefId,
    domainOrderId: paymentInput.domainOrderId || undefined,
    orderCode: paymentInput.orderCode,
    amount: paymentInput.amount,
    currency: 'IDR',
    customer: paymentInput.customer,
    items: paymentInput.items,
    serviceType: paymentInput.serviceType
  });

  if (!gateway.ok || !gateway.paymentUrl) {
    await lockedPaymentMarkTransactionGatewayFailed(transaction.id, gateway.error || gateway.message || 'gateway_create_failed', gateway.raw || null);
    return res.status(gateway.status || 502).json({
      ok: false,
      message: gateway.message || 'Gateway gagal membuat URL pembayaran.',
      payment_transaction_id: transaction.id,
      amount: paymentInput.amount,
      currency: 'IDR'
    });
  }

  const patchResult = await lockedPaymentPatchTransactionUrl(transaction.id, gateway.paymentUrl, gateway.invoiceId, gateway.raw);
  if (!patchResult.ok) {
    return res.status(patchResult.status || 500).json({
      ok: false,
      message: 'Gateway sudah membuat invoice, tetapi payment URL gagal disimpan ke database.',
      payment_transaction_id: transaction.id,
      payment_url: gateway.paymentUrl,
      error: lockedPaymentSafeUpstreamError(patchResult.data)
    });
  }

  return res.status(200).json({
    ok: true,
    message: 'Payment berhasil dibuat. Nominal dikunci dari database.',
    order_kind: paymentInput.kind,
    order_id: paymentInput.orderRefId,
    order_code: paymentInput.orderCode,
    service_type: paymentInput.serviceType,
    payment_transaction_id: transaction.id,
    gateway_reference: gatewayReference,
    amount: paymentInput.amount,
    currency: 'IDR',
    payment_status: 'unpaid',
    payment_url: gateway.paymentUrl,
    payment_provider: gateway.provider || gatewayName,
    invoice_id: gateway.invoiceId || null,
    amount_source: paymentInput.amountSource,
    ownership_locked: true,
    amount_locked: true,
    frontend_invoice_storage_trusted: false,
    frontend_ignored_fields: ['amount', 'total', 'subtotal', 'payment_status', 'order_status', 'paid', 'completed', 'payment_url', 'customer_id'],
    webhook_required_checks: ['signature', 'gateway_event_id_unique', 'amount_equals_database_total', 'currency_IDR', 'paid_or_settled_status']
  });
}

function diracUniversalPesananNormalizeRequestedType(value) {
  const clean = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (clean === 'domain' || clean === 'domain_order' || clean === 'domain_orders') return 'domain';
  if (clean === 'regular' || clean === 'standard' || clean === 'standard_order' || clean === 'orders') return 'regular';
  return '';
}

async function diracUniversalPesananFindOwnedOrder(inputOrderId, requestedType, customerId) {
  const attempts = requestedType === 'domain'
    ? ['domain', 'regular']
    : requestedType === 'regular'
      ? ['regular', 'domain']
      : ['regular', 'domain'];

  let last = null;
  for (const type of attempts) {
    const result = type === 'domain'
      ? await diracUniversalPesananFetchOwnedDomainOrder(inputOrderId, customerId)
      : await diracUniversalPesananFetchOwnedRegularOrder(inputOrderId, customerId);
    if (result.ok) return result;
    last = result;
  }
  return last || { ok: false, status: 404, message: 'Order tidak ditemukan.' };
}

async function diracUniversalPesananFetchOwnedRegularOrder(inputOrderId, customerId) {
  const clean = lockedPaymentCleanText(inputOrderId, 140);
  const filters = [];
  if (customerSecurityLooksLikeUuid(clean)) filters.push(`id.eq.${clean}`);
  if (clean) filters.push(`order_id.eq.${clean}`);

  if (!filters.length) return { ok: false, status: 400, message: 'Order ID regular tidak valid.' };

  const select = 'id,order_id,customer_id,customer_name,customer_email,customer_phone,service_type,subtotal,total,payment_method,payment_status,order_status,created_at';
  const path = '/rest/v1/orders?select=' + encodeURIComponent(select)
    + '&customer_id=eq.' + encodeURIComponent(customerId)
    + '&or=' + encodeURIComponent(`(${filters.join(',')})`)
    + '&limit=1';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status || 500, message: 'Gagal membaca order regular.' };
  const row = Array.isArray(result.data) ? result.data[0] : null;
  if (!row || !row.id) return { ok: false, status: 404, message: 'Order regular tidak ditemukan atau bukan milik akun ini.' };
  return { ok: true, kind: 'regular', order: row };
}

async function diracUniversalPesananFetchOwnedDomainOrder(inputOrderId, customerId) {
  const clean = lockedPaymentCleanText(inputOrderId, 140);
  const candidate = clean.replace(/^DOM-/i, '');
  const filters = [];

  if (customerSecurityLooksLikeUuid(clean)) filters.push(`id.eq.${clean}`);
  if (customerSecurityLooksLikeUuid(candidate)) filters.push(`id.eq.${candidate}`);

  if (!filters.length && /^DOM-[A-F0-9]{8}$/i.test(clean)) {
    const prefix = clean.slice(4).toLowerCase();
    const select = 'id,customer_id,customer_name,customer_whatsapp,customer_email,owner_email,domain_name,total_price,currency,order_status,status,payment_status,created_at';
    const listPath = '/rest/v1/domain_orders?select=' + encodeURIComponent(select)
      + '&customer_id=eq.' + encodeURIComponent(customerId)
      + '&order=created_at.desc&limit=100';
    const listResult = await supabaseFetch(listPath, { method: 'GET', auth: 'service' });
    if (!listResult.ok) return { ok: false, status: listResult.status || 500, message: 'Gagal membaca domain order.' };
    const row = (Array.isArray(listResult.data) ? listResult.data : []).find((item) => String(item && item.id || '').toLowerCase().startsWith(prefix));
    if (!row || !row.id) return { ok: false, status: 404, message: 'Domain order tidak ditemukan atau bukan milik akun ini.' };
    return { ok: true, kind: 'domain', order: row };
  }

  if (!filters.length) return { ok: false, status: 400, message: 'Order ID domain tidak valid.' };

  const select = 'id,customer_id,customer_name,customer_whatsapp,customer_email,owner_email,domain_name,total_price,currency,order_status,status,payment_status,created_at';
  const path = '/rest/v1/domain_orders?select=' + encodeURIComponent(select)
    + '&customer_id=eq.' + encodeURIComponent(customerId)
    + '&or=' + encodeURIComponent(`(${filters.join(',')})`)
    + '&limit=1';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return { ok: false, status: result.status || 500, message: 'Gagal membaca domain order.' };
  const row = Array.isArray(result.data) ? result.data[0] : null;
  if (!row || !row.id) return { ok: false, status: 404, message: 'Domain order tidak ditemukan atau bukan milik akun ini.' };
  return { ok: true, kind: 'domain', order: row };
}

async function diracUniversalPesananBuildPaymentInput(lookup, customer, userEmail) {
  if (!lookup || !lookup.ok || !lookup.order) return { ok: false, status: 404, message: 'Order tidak ditemukan.' };
  if (lookup.kind === 'domain') return diracUniversalPesananBuildDomainPaymentInput(lookup.order, customer, userEmail);
  return diracUniversalPesananBuildRegularPaymentInput(lookup.order, customer, userEmail);
}

async function diracUniversalPesananBuildRegularPaymentInput(order, customer, userEmail) {
  const orderId = String(order.id || '').trim();
  const orderCode = lockedPaymentCleanText(order.order_id || orderId, 100);
  const serviceType = lockedPaymentNormalizeServiceType(order.service_type || 'order');
  const amount = lockedPaymentMoney(order.total ?? order.subtotal ?? 0);
  const paymentStatus = lockedPaymentStatus(order.payment_status || 'unpaid');
  const orderStatus = lockedPaymentStatus(order.order_status || 'pending');

  if (!customerSecurityLooksLikeUuid(orderId)) return { ok: false, status: 409, message: 'Order ID database tidak valid.' };
  if (!diracUniversalPesananCanPayByStatus(paymentStatus, orderStatus, amount)) {
    return { ok: false, status: 409, message: `Order belum bisa dibayar. Status pembayaran: ${paymentStatus}, status order: ${orderStatus}.` };
  }

  const itemPack = await diracUniversalPesananFetchRegularItems(orderId, amount, serviceType);
  return {
    ok: true,
    kind: 'regular',
    orderId,
    domainOrderId: null,
    orderRefId: orderId,
    orderCode,
    referencePrefix: 'ORD',
    serviceType,
    amount,
    amountSource: 'orders.total.database',
    itemTotal: itemPack.totalItem,
    customer: {
      name: lockedPaymentCleanText(order.customer_name || customer.name || userEmail, 120),
      email: normalizeAuthEmail(order.customer_email || customer.email || userEmail),
      phone: lockedPaymentCleanText(order.customer_phone || customer.phone || '', 80)
    },
    items: itemPack.items
  };
}

async function diracUniversalPesananBuildDomainPaymentInput(order, customer, userEmail) {
  const domainOrderId = String(order.id || '').trim();
  const orderCode = lockedPaymentCleanText(order.id || domainOrderId, 100);
  const amount = lockedPaymentMoney(order.total_price || 0);
  const paymentStatus = lockedPaymentStatus(order.payment_status || 'unpaid');
  const orderStatus = lockedPaymentStatus(order.order_status || order.status || 'pending');

  if (!customerSecurityLooksLikeUuid(domainOrderId)) return { ok: false, status: 409, message: 'Domain order ID database tidak valid.' };
  if (!diracUniversalPesananCanPayByStatus(paymentStatus, orderStatus, amount)) {
    return { ok: false, status: 409, message: `Domain order belum bisa dibayar. Status pembayaran: ${paymentStatus}, status order: ${orderStatus}.` };
  }

  const itemPack = await diracUniversalPesananFetchDomainItems(domainOrderId, amount, order.domain_name);
  return {
    ok: true,
    kind: 'domain',
    orderId: null,
    domainOrderId,
    orderRefId: domainOrderId,
    orderCode: 'DOM-' + domainOrderId.slice(0, 8).toUpperCase(),
    referencePrefix: 'DOM',
    serviceType: 'domain',
    amount,
    amountSource: 'domain_orders.total_price.database',
    itemTotal: itemPack.totalItem,
    customer: {
      name: lockedPaymentCleanText(order.customer_name || customer.name || userEmail, 120),
      email: normalizeAuthEmail(order.customer_email || order.owner_email || customer.email || userEmail),
      phone: lockedPaymentCleanText(order.customer_whatsapp || customer.phone || '', 80)
    },
    items: itemPack.items
  };
}

async function diracUniversalPesananFetchRegularItems(orderId, amount, serviceType) {
  const select = 'id,order_id,product_doc_id,product_title,quantity,unit_price,cost_price';
  const path = '/rest/v1/order_items?select=' + encodeURIComponent(select) + '&order_id=eq.' + encodeURIComponent(orderId);
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  const rows = result && result.ok && Array.isArray(result.data) ? result.data : [];
  const productsById = await diracUniversalPesananFetchProductsForOrderItems(rows);
  const items = [];
  let total = 0;

  rows.forEach((row, index) => {
    const productKey = lockedPaymentCleanText(row && row.product_doc_id || '', 120);
    const product = productsById.get(productKey) || {};
    const quantity = lockedPaymentPositiveInteger(row && row.quantity, 1, 9999);
    const unitPrice = lockedPaymentMoney(row && row.unit_price);
    const title = lockedPaymentCleanText(row && row.product_title || product.title || product.name || myOrdersServiceLabel(serviceType) || 'Item pesanan', 180);
    if (!title || quantity <= 0 || unitPrice <= 0) return;
    const subtotal = quantity * unitPrice;
    total += subtotal;
    items.push({
      id: String(row.id || `item-${index + 1}`),
      product_doc_id: productKey || null,
      title,
      quantity,
      unit_price: unitPrice,
      subtotal,
      image_url: orderMailAssetUrl(product.image_url || product.img || ''),
      description: orderMailCleanText(product.description || product.notes || product.long_description || product.category || '', 220),
      category: orderMailCleanText(product.category || '', 80),
      fragrance_type: orderMailCleanText(product.fragrance_type || '', 80)
    });
  });

  if (!items.length || lockedPaymentMoney(total) !== lockedPaymentMoney(amount)) {
    return {
      items: [{
        id: 'order-total',
        product_doc_id: null,
        title: myOrdersServiceLabel(serviceType) || 'Total pesanan',
        quantity: 1,
        unit_price: amount,
        subtotal: amount,
        image_url: orderMailDefaultProductImageUrl(),
        description: ''
      }],
      totalItem: amount
    };
  }

  return { items, totalItem: total };
}

async function diracUniversalPesananFetchProductsForOrderItems(rows) {
  const ids = Array.from(new Set((rows || [])
    .map((row) => lockedPaymentCleanText(row && row.product_doc_id || '', 120))
    .filter(Boolean))).slice(0, 30);
  const productsById = new Map();
  for (const id of ids) {
    const result = await supabaseFetch(
      '/rest/v1/products?select=' + encodeURIComponent('doc_id,firebase_id,title,name,img,image_url,description,notes,long_description,category,fragrance_type') +
      '&or=' + encodeURIComponent('(doc_id.eq.' + id + ',firebase_id.eq.' + id + ')') +
      '&limit=1',
      { method: 'GET', auth: 'service' }
    ).catch(() => null);
    const product = result && result.ok && Array.isArray(result.data) ? result.data[0] : null;
    if (product) {
      if (product.doc_id) productsById.set(lockedPaymentCleanText(product.doc_id, 120), product);
      if (product.firebase_id) productsById.set(lockedPaymentCleanText(product.firebase_id, 120), product);
      productsById.set(id, product);
    }
  }
  return productsById;
}

async function diracUniversalPesananFetchDomainItems(domainOrderId, amount, fallbackDomainName) {
  const select = 'id,order_id,domain_name,extension,years,register_price,subtotal';
  const path = '/rest/v1/domain_order_items?select=' + encodeURIComponent(select) + '&order_id=eq.' + encodeURIComponent(domainOrderId);
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  const rows = result && result.ok && Array.isArray(result.data) ? result.data : [];
  const items = [];
  let total = 0;

  rows.forEach((row, index) => {
    const quantity = lockedPaymentPositiveInteger(row && row.years, 1, 10);
    const subtotal = lockedPaymentMoney(row && (row.subtotal || row.register_price));
    const unitPrice = quantity > 0 ? Math.max(1, Math.round(subtotal / quantity)) : subtotal;
    const title = lockedPaymentCleanText(row && row.domain_name || fallbackDomainName || 'Domain order', 180);
    if (!title || quantity <= 0 || unitPrice <= 0) return;
    total += unitPrice * quantity;
    items.push({
      id: String(row.id || `domain-${index + 1}`),
      domain_name: title,
      title,
      quantity,
      unit_price: unitPrice,
      price: unitPrice,
      subtotal: unitPrice * quantity
    });
  });

  if (!items.length || lockedPaymentMoney(total) !== lockedPaymentMoney(amount)) {
    const title = lockedPaymentCleanText(fallbackDomainName || 'Domain order', 180);
    return {
      items: [{
        id: 'domain-total',
        domain_name: title,
        title,
        quantity: 1,
        unit_price: amount,
        price: amount,
        subtotal: amount
      }],
      totalItem: amount
    };
  }

  return { items, totalItem: total };
}

function diracUniversalPesananCanPayByStatus(paymentStatus, orderStatus, amount) {
  const pay = lockedPaymentStatus(paymentStatus);
  const order = lockedPaymentStatus(orderStatus);
  if (lockedPaymentMoney(amount) <= 0) return false;
  if (['paid', 'success', 'settled', 'settlement', 'capture', 'refunded'].includes(pay)) return false;
  if (['completed', 'cancelled', 'canceled', 'failed', 'expired', 'refunded'].includes(order)) return false;
  return ['unpaid', 'pending', 'pending_payment', 'created', 'unknown'].includes(pay) || !pay;
}

function diracUniversalPesananOrderCanPay(order) {
  if (!order) return false;
  return diracUniversalPesananCanPayByStatus(order.payment_status, order.order_status, order.total);
}

async function diracUniversalPesananFindReusableTransaction(input) {
  const customerId = String(input && input.customerId || '').trim();
  const amount = lockedPaymentMoney(input && input.amount);
  const isDomain = input && input.kind === 'domain';
  const orderId = String(isDomain ? input.domainOrderId : input.orderId || '').trim();

  if (!customerSecurityLooksLikeUuid(customerId) || !customerSecurityLooksLikeUuid(orderId) || amount <= 0) {
    return { ok: true, transaction: null };
  }

  const column = isDomain ? 'domain_order_id' : 'order_id';
  const select = 'id,order_id,domain_order_id,customer_id,service_type,gateway_name,gateway_reference,payment_status,amount,currency,payment_url,expired_at,created_at';
  const statuses = ['unpaid', 'pending', 'created'].join(',');
  const path = '/rest/v1/payment_transactions?select=' + encodeURIComponent(select)
    + '&' + column + '=eq.' + encodeURIComponent(orderId)
    + '&customer_id=eq.' + encodeURIComponent(customerId)
    + '&amount=eq.' + encodeURIComponent(String(amount))
    + '&payment_status=in.(' + statuses + ')'
    + '&order=created_at.desc&limit=8';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  if (!result || !result.ok) return { ok: false, status: result && result.status || 500 };

  const rows = Array.isArray(result.data) ? result.data : [];
  const now = Date.now();
  const reusable = rows.find((row) => {
    if (!row || !row.payment_url) return false;
    if (!row.expired_at) return true;
    const expires = new Date(row.expired_at).getTime();
    return Number.isFinite(expires) && expires > now;
  });

  return { ok: true, transaction: reusable || null };
}


/* ============================================================
   ORDER EMAIL NOTIFICATION - APPEND ONLY - v13
   Scope:
   - Order notification email only.
   - Does not read or modify SMTP_USER/SMTP_PASS used by admin panel.
   - Does not touch login/hash/A2F/passkey/cookies/payment security.
   - Customer email uses ORDER_CUSTOMER_* ENV.
   - Owner/store email uses ORDER_OWNER_* ENV.
   ============================================================ */

const DIRAC_ORDER_MAIL_PATCH = 'order-mail-v17-owner-direct-health32';
const __diracOrderMailPreviousHandler = module.exports;

module.exports = async function diracOrderMailWrapper(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (rawAction !== 'order_mail_health' && rawAction !== 'order_email_health') {
    return __diracOrderMailPreviousHandler(req, res);
  }

  const cors = setCors(req, res, { isDomainAction: true });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  return res.status(200).json({
    ok: true,
    service: 'dirac-order-mail',
    debugPatch: DIRAC_ORDER_MAIL_PATCH,
    customer: orderMailPublicConfigInfo('customer'),
    owner: orderMailPublicConfigInfo('owner'),
    adminPanelSmtpUntouched: true,
    adminPanelEnvNamesIgnored: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASS'],
    note: 'Endpoint ini hanya mengecek ENV ORDER_CUSTOMER_* dan ORDER_OWNER_*. Secret/app password tidak ditampilkan.'
  });
};


function orderMailPendingPaymentSkipSummary(source) {
  return {
    ok: true,
    attempted: false,
    skipped: true,
    reason: 'email_sent_only_after_paid_webhook',
    source: orderMailCleanText(source || 'checkout', 80),
    customer: { enabled: orderMailCustomerEnabled(), configured: orderMailSmtpConfig('customer').configured, sent: false, skipped: true, reason: 'wait_paid_webhook', error: null },
    owner: { enabled: orderMailOwnerEnabled(), configured: orderMailSmtpConfig('owner').configured, sent: false, skipped: true, reason: 'wait_paid_webhook', error: null }
  };
}

function orderMailPaidWebhookSkipSummary(provider, reason) {
  return {
    ok: true,
    attempted: false,
    skipped: true,
    reason: orderMailCleanText(reason || 'not_paid_status', 120),
    provider: orderMailCleanText(provider || 'payment_gateway', 40),
    paid_webhook_only: true,
    customer: { enabled: orderMailCustomerEnabled(), configured: orderMailSmtpConfig('customer').configured, sent: false, skipped: true, error: null },
    owner: { enabled: orderMailOwnerEnabled(), configured: orderMailSmtpConfig('owner').configured, sent: false, skipped: true, error: null }
  };
}

async function orderMailNotifyPaidOrderFromPaymentSafe(input) {
  const provider = orderMailCleanText(input && input.provider || 'payment_gateway', 40);
  const tx = input && input.tx && typeof input.tx === 'object' ? input.tx : null;
  const paidAt = orderMailCleanText(input && input.paidAt || diracNowIso(), 80);

  try {
    if (!tx || !tx.id) return orderMailPaidWebhookSkipSummary(provider, 'payment_transaction_missing');

    const context = await orderMailBuildPaidInvoiceContextFromBackend(tx, provider, paidAt);
    if (!context.ok) {
      const skipped = orderMailPaidWebhookSkipSummary(provider, context.reason || 'paid_order_context_missing');
      skipped.ok = context.soft !== false;
      skipped.error = context.message || null;
      return skipped;
    }

    const notify = await orderMailNotifyNewOrderSafe(context.mail);
    notify.provider = provider;
    notify.paid_webhook_only = true;
    notify.payment_transaction_id = orderMailCleanText(tx.id || '', 120);
    notify.gateway_reference = orderMailCleanText(tx.gateway_reference || '', 140);
    return notify;
  } catch (error) {
    const failed = orderMailPaidWebhookSkipSummary(provider, 'paid_invoice_email_failed');
    failed.ok = false;
    failed.error = orderMailSafeError(error);
    return failed;
  }
}

async function orderMailBuildPaidInvoiceContextFromBackend(tx, provider, paidAt) {
  if (tx.order_id) return orderMailBuildPaidRegularInvoiceContext(tx, provider, paidAt);
  if (tx.domain_order_id) return orderMailBuildPaidDomainInvoiceContext(tx, provider, paidAt);
  return { ok: false, reason: 'missing_order_reference', message: 'Payment transaction tidak punya order_id/domain_order_id.' };
}

async function orderMailBuildPaidRegularInvoiceContext(tx, provider, paidAt) {
  const orderId = String(tx.order_id || '').trim();
  if (!orderId) return { ok: false, reason: 'regular_order_id_missing' };

  const select = 'id,order_id,customer_id,customer_name,customer_phone,customer_email,service_type,subtotal,total,payment_status,order_status,created_at';
  const result = await supabaseFetch('/rest/v1/orders?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(orderId) + '&limit=1', {
    method: 'GET',
    auth: 'service'
  }).catch((error) => ({ ok: false, status: 500, data: { message: orderMailSafeError(error) } }));

  if (!result.ok) return { ok: false, reason: 'regular_order_read_failed', message: lockedPaymentSafeUpstreamError(result.data) };
  const order = Array.isArray(result.data) ? result.data[0] : null;
  if (!order || !order.id) return { ok: false, reason: 'regular_order_not_found' };

  const amount = orderMailMoney(tx.amount || order.total || order.subtotal || 0);
  const serviceType = orderMailCleanText(order.service_type || tx.service_type || 'order', 80);
  const itemPack = await diracUniversalPesananFetchRegularItems(order.id, amount, serviceType).catch(() => ({ items: [], totalItem: 0 }));
  const customerFallback = await orderMailFetchCustomerFallback(order.customer_id);
  const customerEmail = orderMailNormalizeEmail(order.customer_email || customerFallback.email || '');

  return {
    ok: true,
    mail: {
      source: provider + '_paid_webhook',
      kind: 'paid_invoice',
      order: {
        id: order.id,
        code: order.order_id || order.id,
        service_type: serviceType,
        total: amount,
        subtotal: orderMailMoney(order.subtotal || amount),
        currency: String(tx.currency || 'IDR').toUpperCase(),
        order_status: 'paid',
        payment_status: 'paid',
        created_at: paidAt || order.created_at || diracNowIso()
      },
      customer: {
        name: order.customer_name || customerFallback.name || 'Customer',
        email: customerEmail,
        phone: order.customer_phone || customerFallback.phone || ''
      },
      items: Array.isArray(itemPack.items) && itemPack.items.length ? itemPack.items : [{ title: serviceType, quantity: 1, unit_price: amount, subtotal: amount }],
      payment: {
        url: '',
        provider,
        invoice_id: tx.gateway_reference || tx.id || ''
      }
    }
  };
}

async function orderMailBuildPaidDomainInvoiceContext(tx, provider, paidAt) {
  const domainOrderId = String(tx.domain_order_id || '').trim();
  if (!domainOrderId) return { ok: false, reason: 'domain_order_id_missing' };

  const select = 'id,customer_id,customer_name,customer_whatsapp,customer_email,owner_email,domain_name,total_price,currency,order_status,status,payment_status,created_at';
  const result = await supabaseFetch('/rest/v1/domain_orders?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(domainOrderId) + '&limit=1', {
    method: 'GET',
    auth: 'service'
  }).catch((error) => ({ ok: false, status: 500, data: { message: orderMailSafeError(error) } }));

  if (!result.ok) return { ok: false, reason: 'domain_order_read_failed', message: lockedPaymentSafeUpstreamError(result.data) };
  const order = Array.isArray(result.data) ? result.data[0] : null;
  if (!order || !order.id) return { ok: false, reason: 'domain_order_not_found' };

  const amount = orderMailMoney(tx.amount || order.total_price || 0);
  const itemPack = await diracUniversalPesananFetchDomainItems(order.id, amount, order.domain_name).catch(() => ({ items: [], totalItem: 0 }));
  const customerFallback = await orderMailFetchCustomerFallback(order.customer_id);
  const customerEmail = orderMailNormalizeEmail(order.customer_email || order.owner_email || customerFallback.email || '');

  return {
    ok: true,
    mail: {
      source: provider + '_paid_webhook',
      kind: 'paid_invoice',
      order: {
        id: order.id,
        code: 'DOM-' + String(order.id || '').slice(0, 8).toUpperCase(),
        service_type: 'domain',
        total: amount,
        subtotal: amount,
        currency: String(order.currency || tx.currency || 'IDR').toUpperCase(),
        order_status: 'paid',
        payment_status: 'paid',
        created_at: paidAt || order.created_at || diracNowIso()
      },
      customer: {
        name: order.customer_name || customerFallback.name || 'Customer',
        email: customerEmail,
        phone: order.customer_whatsapp || customerFallback.phone || ''
      },
      items: Array.isArray(itemPack.items) && itemPack.items.length ? itemPack.items : [{ title: order.domain_name || 'Domain order', quantity: 1, unit_price: amount, subtotal: amount }],
      payment: {
        url: '',
        provider,
        invoice_id: tx.gateway_reference || tx.id || ''
      }
    }
  };
}

async function orderMailFetchCustomerFallback(customerId) {
  const id = String(customerId || '').trim();
  if (!id || !customerSecurityLooksLikeUuid(id)) return { name: '', email: '', phone: '' };
  const result = await supabaseFetch('/rest/v1/customers?select=' + encodeURIComponent('id,name,email,phone') + '&id=eq.' + encodeURIComponent(id) + '&limit=1', {
    method: 'GET',
    auth: 'service'
  }).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data) || !result.data.length) return { name: '', email: '', phone: '' };
  const row = result.data[0] || {};
  return {
    name: orderMailCleanText(row.name || '', 120),
    email: orderMailNormalizeEmail(row.email || ''),
    phone: orderMailCleanText(row.phone || '', 80)
  };
}

async function orderMailNotifyNewOrderSafe(input) {
  const summary = {
    ok: true,
    debugPatch: DIRAC_ORDER_MAIL_PATCH,
    attempted: false,
    customer: { enabled: orderMailCustomerEnabled(), configured: orderMailSmtpConfig('customer').configured, sent: false, skipped: false, error: null },
    owner: { enabled: orderMailOwnerEnabled(), configured: orderMailSmtpConfig('owner').configured, sent: false, skipped: false, error: null }
  };

  try {
    const order = orderMailNormalizeOrderInput(input);
    const messages = orderMailBuildNewOrderMessages(order);

    if (summary.customer.enabled && summary.customer.configured && order.customer.email) {
      summary.attempted = true;
      const customerConfig = orderMailSmtpConfig('customer');
      const customerResult = await orderMailSendViaSmtpSafe(customerConfig, {
        to: [order.customer.email],
        subject: messages.customerSubject,
        text: messages.customerText,
        html: messages.customerHtml,
        fromName: customerConfig.fromName,
        fromEmail: customerConfig.fromEmail
      });
      summary.customer.sent = Boolean(customerResult.ok);
      summary.customer.error = customerResult.ok ? null : customerResult.error;
    } else {
      summary.customer.skipped = true;
      summary.customer.reason = !summary.customer.enabled
        ? 'disabled'
        : (!summary.customer.configured ? 'smtp_not_configured' : 'customer_email_missing');
    }

    if (summary.owner.enabled && summary.owner.configured && orderMailSmtpConfig('owner').recipients.length) {
      summary.attempted = true;
      const ownerConfig = orderMailSmtpConfig('owner');
      const ownerResult = await orderMailSendViaSmtpSafe(ownerConfig, {
        to: ownerConfig.recipients,
        subject: messages.ownerSubject,
        text: messages.ownerText,
        html: messages.ownerHtml,
        fromName: ownerConfig.fromName,
        fromEmail: ownerConfig.fromEmail
      });
      summary.owner.sent = Boolean(ownerResult.ok);
      summary.owner.error = ownerResult.ok ? null : ownerResult.error;
      summary.owner.recipient_count = ownerConfig.recipients.length;
    } else {
      summary.owner.skipped = true;
      summary.owner.reason = !summary.owner.enabled
        ? 'disabled'
        : (!summary.owner.configured ? 'smtp_not_configured' : 'owner_email_missing');
    }
  } catch (error) {
    summary.ok = false;
    summary.error = orderMailSafeError(error);
  }

  return summary;
}

function orderMailCustomerEnabled() {
  return orderMailEnvTrue(process.env.ORDER_CUSTOMER_EMAIL_ENABLED, false);
}

function orderMailOwnerEnabled() {
  return orderMailEnvTrue(process.env.ORDER_OWNER_EMAIL_ENABLED, false);
}

function orderMailEnvTrue(value, fallback) {
  if (value === undefined || value === null || value === '') return Boolean(fallback);
  const clean = String(value).trim().toLowerCase();
  return clean === 'true' || clean === '1' || clean === 'yes' || clean === 'on' || clean === 'enabled';
}

function orderMailSmtpConfig(kind) {
  const prefix = kind === 'owner' ? 'ORDER_OWNER' : 'ORDER_CUSTOMER';
  const host = String(process.env[`${prefix}_SMTP_HOST`] || '').trim();
  const port = Math.trunc(Number(process.env[`${prefix}_SMTP_PORT`] || 465));
  const secure = orderMailEnvTrue(process.env[`${prefix}_SMTP_SECURE`], true);
  const user = String(process.env[`${prefix}_SMTP_USER`] || '').trim();
  const pass = String(process.env[`${prefix}_SMTP_PASS`] || '').trim().replace(/\s+/g, '');
  const fromName = orderMailCleanText(process.env[`${prefix}_FROM_NAME`] || 'Dirac Group', 80);
  const fromEmail = orderMailNormalizeEmail(process.env[`${prefix}_FROM_EMAIL`] || user);
  const recipients = kind === 'owner' ? orderMailParseEmailList(process.env.ORDER_OWNER_EMAIL || '') : [];

  return {
    kind,
    host,
    port: Number.isFinite(port) && port > 0 ? port : 465,
    secure,
    user,
    pass,
    fromName,
    fromEmail,
    recipients,
    configured: Boolean(host && user && pass && fromEmail)
  };
}

function orderMailPublicConfigInfo(kind) {
  const config = orderMailSmtpConfig(kind);
  const enabled = kind === 'owner' ? orderMailOwnerEnabled() : orderMailCustomerEnabled();
  return {
    enabled,
    configured: config.configured,
    host: config.host || null,
    port: config.port || null,
    secure: config.secure,
    userPresent: Boolean(config.user),
    passPresent: Boolean(config.pass),
    fromEmailPresent: Boolean(config.fromEmail),
    ownerRecipientCount: kind === 'owner' ? config.recipients.length : undefined
  };
}

function orderMailNormalizeOrderInput(input) {
  const row = input && typeof input === 'object' ? input : {};
  const order = row.order && typeof row.order === 'object' ? row.order : {};
  const customer = row.customer && typeof row.customer === 'object' ? row.customer : {};
  const payment = row.payment && typeof row.payment === 'object' ? row.payment : {};
  const items = Array.isArray(row.items) ? row.items : [];

  const code = orderMailCleanText(order.code || order.order_code || order.order_id || order.id || 'ORDER', 120);
  const total = orderMailMoney(order.total ?? order.total_price ?? order.amount ?? order.subtotal ?? 0);
  const currency = orderMailCleanText(order.currency || 'IDR', 12).toUpperCase() || 'IDR';

  return {
    source: orderMailCleanText(row.source || 'checkout_order', 60),
    kind: orderMailCleanText(row.kind || order.kind || order.service_type || 'regular', 40),
    order: {
      id: orderMailCleanText(order.id || '', 120),
      code,
      service_type: orderMailCleanText(order.service_type || row.kind || 'order', 80),
      total,
      subtotal: orderMailMoney(order.subtotal ?? total),
      currency,
      order_status: orderMailCleanText(order.order_status || 'pending', 40),
      payment_status: orderMailCleanText(order.payment_status || 'unpaid', 40),
      created_at: orderMailCleanText(order.created_at || diracNowIso(), 60)
    },
    customer: {
      name: orderMailCleanText(customer.name || customer.customer_name || 'Customer', 120),
      email: orderMailNormalizeEmail(customer.email || customer.customer_email || ''),
      phone: orderMailCleanText(customer.phone || customer.whatsapp || customer.customer_phone || customer.customer_whatsapp || '', 80)
    },
    payment: {
      url: orderMailCleanUrl(payment.url || payment.payment_url || ''),
      provider: orderMailCleanText(payment.provider || payment.payment_provider || '', 60),
      invoice_id: orderMailCleanText(payment.invoice_id || payment.id || '', 120)
    },
    items: items.slice(0, 30).map((item, index) => ({
      title: orderMailCleanText(item && (item.title || item.product_title || item.name || item.domain_name) || `Item ${index + 1}`, 180),
      quantity: orderMailPositiveInt(item && (item.quantity || item.qty || item.years) || 1, 1, 9999),
      unit_price: orderMailMoney(item && (item.unit_price ?? item.price ?? item.register_price ?? 0)),
      subtotal: orderMailMoney(item && (item.subtotal ?? 0)),
      description: orderMailCleanText(item && (item.description || item.notes || item.extension || item.product_doc_id) || '', 220),
      image_url: orderMailAssetUrl(item && (item.image_url || item.image || item.img) || ''),
      category: orderMailCleanText(item && item.category || '', 80),
      fragrance_type: orderMailCleanText(item && item.fragrance_type || '', 80)
    })).filter((item) => item.title)
  };
}

function orderMailBuildNewOrderMessages(data) {
  const serviceLabel = orderMailServiceLabel(data.order.service_type || data.kind);
  const total = orderMailFormatCurrency(data.order.total, data.order.currency);
  const created = orderMailFormatDate(data.order.created_at);
  const itemsText = orderMailItemsText(data.items, data.order.currency);
  const itemsHtml = orderMailItemsHtml(data.items, data.order.currency);
  const productCardsHtml = orderMailProductCardsHtml(data.items, data.order.currency);
  const paymentLine = data.payment.url ? `\nLink pembayaran: ${data.payment.url}` : '';
  const paymentHtml = data.payment.url
    ? `<p style="margin:18px 0 0"><a href="${orderMailEscapeHtml(data.payment.url)}" style="display:inline-block;padding:12px 18px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:10px;font-size:14px;font-weight:700">Buka Link Pembayaran</a></p>`
    : '';

  const paid = ['paid', 'success', 'settled', 'settlement', 'capture'].includes(String(data.order.payment_status || '').toLowerCase());
  const customerSubject = paid
    ? `Invoice ${data.order.code} sudah dibayar - Dirac Group`
    : `Pesanan ${data.order.code} diterima - Dirac Group`;
  const ownerSubject = paid
    ? `Pembayaran berhasil ${data.order.code} - ${serviceLabel}`
    : `Order baru ${data.order.code} - ${serviceLabel}`;
  const customerIntro = paid
    ? 'Pembayaran kamu sudah berhasil kami terima. Berikut invoice dan rincian pesanan kamu.'
    : 'Pesanan kamu sudah kami terima. Berikut rincian pesanan dan informasi pembayaran kamu.';
  const ownerIntro = paid
    ? 'Ada pembayaran order yang sudah berhasil dan valid dari webhook payment gateway.'
    : 'Ada order baru masuk.';
  const statusLabel = paid ? 'paid / sudah dibayar' : data.order.payment_status;
  const orderUrl = orderMailOrderUrl(data.order.code);

  const customerText = [
    `Halo ${data.customer.name || 'Customer'},`,
    '',
    customerIntro,
    `Kode pesanan: ${data.order.code}`,
    `Layanan: ${serviceLabel}`,
    `Total: ${total}`,
    `Status: ${statusLabel}`,
    `Waktu pembayaran: ${created}`,
    paymentLine.trim(),
    '',
    'Rincian:',
    itemsText,
    '',
    'Lihat pesanan: https://diracgroup.store/pesanan.html',
    'Hubungi support: support@diracgroup.store',
    'Butuh bantuan WhatsApp: https://wa.me/6287892523968',
    'Dirac Group'
  ].filter((line) => line !== '').join('\n');

  const ownerText = [
    ownerIntro,
    '',
    `Kode pesanan: ${data.order.code}`,
    `Jenis: ${serviceLabel}`,
    `Customer: ${data.customer.name || '-'}`,
    `Email: ${data.customer.email || '-'}`,
    `HP/WA: ${data.customer.phone || '-'}`,
    `Total: ${total}`,
    `Status bayar: ${statusLabel}`,
    `Waktu pembayaran: ${created}`,
    paymentLine.trim(),
    '',
    'Rincian:',
    itemsText
  ].filter((line) => line !== '').join('\n');

  const customerHtml = orderMailHtmlShell(customerSubject, `
    <p style="margin:0 0 12px;font-size:15px;line-height:1.7;color:#334155">Halo <strong>${orderMailEscapeHtml(data.customer.name || 'Customer')}</strong>,</p>
    <p style="margin:0 0 18px;font-size:15px;line-height:1.7;color:#334155">${orderMailEscapeHtml(customerIntro)}</p>
    ${orderMailInfoTable([
      ['Kode pesanan', data.order.code],
      ['Layanan', serviceLabel],
      ['Total', total],
      ['Status', statusLabel],
      ['Waktu pembayaran', created],
      ['Referensi pembayaran', data.payment.invoice_id || '-']
    ])}
    ${paymentHtml}
    ${productCardsHtml}
    <h3 style="margin:22px 0 12px;font-size:16px;color:#0f172a">Rincian pesanan</h3>
    ${itemsHtml}
  `, { badge: paid ? 'PAID' : 'ORDER', total, showActions: true, showPromoImage: true });

  const ownerHtml = orderMailHtmlShell(ownerSubject, `
    <p style="margin:0 0 18px;font-size:15px;line-height:1.7;color:#334155">${orderMailEscapeHtml(ownerIntro)}</p>
    ${orderMailInfoTable([
      ['Kode pesanan', data.order.code],
      ['Jenis', serviceLabel],
      ['Customer', data.customer.name || '-'],
      ['Email', data.customer.email || '-'],
      ['HP/WA', data.customer.phone || '-'],
      ['Total', total],
      ['Status bayar', statusLabel],
      ['Waktu pembayaran', created],
      ['Referensi pembayaran', data.payment.invoice_id || '-']
    ])}
    ${paymentHtml}
    ${productCardsHtml}
    <h3 style="margin:22px 0 12px;font-size:16px;color:#0f172a">Rincian pesanan</h3>
    ${itemsHtml}
  `, { badge: paid ? 'PAID' : 'OWNER', total, showActions: false, showPromoImage: false });

  return { customerSubject, ownerSubject, customerText, ownerText, customerHtml, ownerHtml };
}

function orderMailAssetBaseUrl() {
  return String(process.env.ORDER_EMAIL_ASSET_BASE_URL || process.env.DOMAIN_SITE_URL || process.env.SITE_URL || SITE_URL || 'https://diracgroup.store').trim().replace(/\/+$/, '');
}
function orderMailAssetUrl(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.length > 600) return '';
  if (/^https?:\/\//i.test(raw)) return orderMailCleanUrl(raw);
  if (/^\/\//.test(raw)) return orderMailCleanUrl('https:' + raw);
  const base = orderMailAssetBaseUrl();
  const path = raw.startsWith('/') ? raw : '/' + raw;
  return orderMailCleanUrl(base + path);
}
function orderMailDefaultProductImageUrl() {
  return orderMailAssetUrl(process.env.ORDER_EMAIL_DEFAULT_PRODUCT_IMAGE_URL || '');
}
function orderMailOrderUrl(orderCode) {
  // EMAIL TEMPLATE ONLY: link "Lihat pesanan" wajib selalu ke halaman pesanan resmi.
  // Tidak memakai query, payment URL, localStorage, atau data frontend.
  return 'https://diracgroup.store/pesanan.html';
}
function orderMailHtmlShell(title, body, options = {}) {
  const badge = orderMailEscapeHtml(options.badge || 'PAID');
  const total = orderMailEscapeHtml(options.total || '');
  const orderUrl = 'https://diracgroup.store/pesanan.html';
  const supportEmail = 'support@diracgroup.store';
  const whatsappUrl = 'https://wa.me/6287892523968';
  const promoImage = 'https://diracgroup.store/email.webp';
  const showActions = options.showActions !== false;
  const showPromoImage = options.showPromoImage !== false;
  const actionsHtml = showActions ? `
        <div style="margin-top:24px;text-align:left">
          <a href="${orderMailEscapeHtml(orderUrl)}" style="display:inline-block;background:#2563eb;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;text-decoration:none;font-size:14px;font-weight:900;padding:13px 18px;border-radius:10px;margin:0 8px 8px 0">Lihat pesanan</a>
          <a href="mailto:${supportEmail}" style="display:inline-block;background:#eef2ff;color:#1e3a8a!important;-webkit-text-fill-color:#1e3a8a!important;text-decoration:none;font-size:14px;font-weight:900;padding:13px 18px;border-radius:10px;margin:0 8px 8px 0">Hubungi support</a>
          <a href="${orderMailEscapeHtml(whatsappUrl)}" style="display:inline-block;background:#22c55e;color:#06230f!important;-webkit-text-fill-color:#06230f!important;text-decoration:none;font-size:14px;font-weight:900;padding:13px 18px;border-radius:10px;margin:0 0 8px 0">Butuh bantuan</a>
        </div>` : '';
  const promoHtml = showPromoImage ? `
      <tr>
        <td style="padding:0 32px 26px;background:#ffffff">
          <a href="${orderMailEscapeHtml(orderUrl)}" style="text-decoration:none;border:0">
            <img src="${orderMailEscapeHtml(promoImage)}" width="616" alt="Dirac Group" style="display:block;width:100%;max-width:616px;height:auto;border:0;border-radius:14px;background:#f8fafc;outline:none;text-decoration:none">
          </a>
        </td>
      </tr>` : '';

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>${orderMailEscapeHtml(title)}</title>
</head>
<body style="margin:0!important;padding:0!important;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;color:#0f172a">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#eef2f7;margin:0;padding:24px 0">
    <tr>
      <td align="center" style="padding:0 12px">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:680px;background:#ffffff;border-radius:18px;overflow:hidden;border:1px solid #dbe3ef;box-shadow:0 8px 30px rgba(15,23,42,.08)">
          <tr>
            <td bgcolor="#0b3dd9" style="background:#0b3dd9;padding:30px 32px;background-image:linear-gradient(135deg,#081f5f 0%,#1d4ed8 58%,#0ea5e9 100%)">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td valign="top" style="color:#ffffff!important">
                    <div style="font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#dbeafe!important;-webkit-text-fill-color:#dbeafe!important;margin-bottom:10px;font-weight:800">DIRAC GROUP</div>
                    <div style="font-size:28px;line-height:1.22;font-weight:900;color:#ffffff!important;-webkit-text-fill-color:#ffffff!important;text-shadow:0 2px 4px rgba(0,0,0,.48);mso-line-height-rule:exactly">${orderMailEscapeHtml(title)}</div>
                    ${total ? `<div style="margin-top:12px;font-size:15px;line-height:1.5;color:#e0f2fe!important;-webkit-text-fill-color:#e0f2fe!important">Total pembayaran: <strong style="color:#ffffff!important;-webkit-text-fill-color:#ffffff!important">${total}</strong></div>` : ''}
                  </td>
                  <td valign="top" align="right" style="padding-left:12px">
                    <span style="display:inline-block;background:#dcfce7;color:#166534!important;-webkit-text-fill-color:#166534!important;font-size:12px;font-weight:900;padding:8px 14px;border-radius:999px;white-space:nowrap">${badge}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:28px 32px;background:#ffffff;color:#0f172a">
              ${body}
              ${actionsHtml}
            </td>
          </tr>
          ${promoHtml}
          <tr>
            <td style="background:#e8eeff;padding:24px 32px;text-align:center;color:#475569!important;-webkit-text-fill-color:#475569!important;font-size:14px;line-height:1.8">
              Email ini dikirim otomatis oleh sistem Dirac Group.<br>
              Hubungi support hanya ke <a href="mailto:${supportEmail}" style="color:#2563eb!important;-webkit-text-fill-color:#2563eb!important;text-decoration:none;font-weight:900">${supportEmail}</a><br>
              <a href="${orderMailEscapeHtml(whatsappUrl)}" style="display:inline-block;margin-top:12px;background:#22c55e;color:#06230f!important;-webkit-text-fill-color:#06230f!important;text-decoration:none;font-size:14px;font-weight:900;padding:12px 18px;border-radius:10px">Butuh bantuan</a><br><br>
              © 2026 Dirac Group. All rights reserved.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function orderMailInfoTable(rows) {
  const body = (rows || []).map(([key, value]) => `<tr><td style="padding:13px 16px;border-bottom:1px solid #e5e7eb;color:#64748b;width:42%;font-size:14px">${orderMailEscapeHtml(key)}</td><td style="padding:13px 16px;border-bottom:1px solid #e5e7eb;color:#0f172a;font-size:14px;font-weight:700">${orderMailEscapeHtml(value)}</td></tr>`).join('');
  return `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="border-collapse:separate;border-spacing:0;width:100%;margin:14px 0 20px;border:1px solid #e5e7eb;border-radius:14px;overflow:hidden;background:#f8fafc">${body}</table>`;
}
function orderMailItemsText(items, currency = 'IDR') {
  const rows = Array.isArray(items) && items.length ? items : [{ title: 'Total pesanan', quantity: 1, unit_price: 0, subtotal: 0 }];
  return rows.map((item, index) => {
    const subtotal = item.subtotal || (item.unit_price * item.quantity) || 0;
    return `${index + 1}. ${item.title} x${item.quantity} - ${orderMailFormatCurrency(subtotal, currency)}`;
  }).join('\n');
}
function orderMailItemsHtml(items, currency = 'IDR') {
  const rows = Array.isArray(items) && items.length ? items : [{ title: 'Total pesanan', quantity: 1, unit_price: 0, subtotal: 0 }];
  const body = rows.map((item, index) => {
    const subtotal = item.subtotal || (item.unit_price * item.quantity) || 0;
    return `<tr><td style="padding:12px 14px;border-bottom:1px solid #e5e7eb;color:#334155;font-size:14px">${index + 1}</td><td style="padding:12px 14px;border-bottom:1px solid #e5e7eb;color:#0f172a;font-size:14px;font-weight:700">${orderMailEscapeHtml(item.title)}${item.description ? `<div style="font-size:12px;font-weight:400;color:#64748b;margin-top:4px;line-height:1.5">${orderMailEscapeHtml(item.description)}</div>` : ''}</td><td style="padding:12px 14px;border-bottom:1px solid #e5e7eb;text-align:center;color:#334155;font-size:14px">${orderMailEscapeHtml(item.quantity)}</td><td style="padding:12px 14px;border-bottom:1px solid #e5e7eb;text-align:right;color:#0f172a;font-size:14px;font-weight:800">${orderMailEscapeHtml(orderMailFormatCurrency(subtotal, currency))}</td></tr>`;
  }).join('');
  return `<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="border-collapse:separate;border-spacing:0;width:100%;border:1px solid #e5e7eb;border-radius:14px;overflow:hidden;background:#ffffff"><thead><tr><th style="padding:12px 14px;text-align:left;background:#f1f5f9;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em">#</th><th style="padding:12px 14px;text-align:left;background:#f1f5f9;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em">Item</th><th style="padding:12px 14px;text-align:center;background:#f1f5f9;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em">Qty</th><th style="padding:12px 14px;text-align:right;background:#f1f5f9;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em">Subtotal</th></tr></thead><tbody>${body}</tbody></table>`;
}
function orderMailProductCardsHtml(items, currency = 'IDR') {
  const rows = (Array.isArray(items) ? items : []).filter((item) => item && (item.image_url || item.title)).slice(0, 3);
  if (!rows.length) return '';
  const cards = rows.map((item) => {
    const image = orderMailAssetUrl(item.image_url || item.img || '') || orderMailDefaultProductImageUrl();
    const amount = orderMailFormatCurrency(item.subtotal || ((item.unit_price || 0) * (item.quantity || 1)), currency);
    return `<tr><td style="padding:18px;border-bottom:1px solid #e5e7eb"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr>${image ? `<td width="128" valign="top" style="padding-right:16px"><img src="${orderMailEscapeHtml(image)}" width="112" alt="${orderMailEscapeHtml(item.title || 'Produk')}" style="display:block;width:112px;max-width:112px;height:auto;border-radius:14px;border:1px solid #e5e7eb;background:#f8fafc"></td>` : ''}<td valign="top"><div style="font-size:16px;line-height:1.45;font-weight:800;color:#0f172a;margin-bottom:6px">${orderMailEscapeHtml(item.title || 'Item pesanan')}</div>${item.description ? `<div style="font-size:13px;line-height:1.6;color:#64748b;margin-bottom:10px">${orderMailEscapeHtml(item.description)}</div>` : ''}<div style="font-size:13px;color:#64748b">Qty <strong style="color:#0f172a">${orderMailEscapeHtml(item.quantity || 1)}</strong> · Subtotal <strong style="color:#0f172a">${orderMailEscapeHtml(amount)}</strong></div></td></tr></table></td></tr>`;
  }).join('');
  return `<h3 style="margin:22px 0 12px;font-size:16px;color:#0f172a">Produk yang dibeli</h3><table role="presentation" cellspacing="0" cellpadding="0" border="0" style="border-collapse:separate;border-spacing:0;width:100%;border:1px solid #e5e7eb;border-radius:14px;overflow:hidden;background:#ffffff">${cards}</table>`;
}

async function orderMailSendViaSmtpSafe(config, message) {
  try {
    return await orderMailSendViaSmtp(config, message);
  } catch (error) {
    return { ok: false, error: orderMailSafeError(error) };
  }
}

async function orderMailSendViaSmtp(config, message) {
  if (!config || !config.configured) return { ok: false, error: 'smtp_not_configured' };
  const recipients = Array.from(new Set((message.to || []).map(orderMailNormalizeEmail).filter(Boolean))).slice(0, 50);
  if (!recipients.length) return { ok: false, error: 'recipient_missing' };

  const tls = require('tls');
  const net = require('net');
  const host = config.host;
  const port = config.port || (config.secure ? 465 : 587);
  const timeoutMs = Math.max(3000, Math.min(20000, Number(process.env.ORDER_SMTP_TIMEOUT_MS || 9000)));

  return await new Promise((resolve, reject) => {
    let socket;
    let buffer = '';
    let settled = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      if (socket) {
        socket.removeAllListeners();
        try { socket.end(); } catch (_) {}
        try { socket.destroy(); } catch (_) {}
      }
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error instanceof Error ? error : new Error(String(error || 'smtp_failed')));
    };
    const done = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const resetTimer = () => {
      clearTimeout(timer);
      timer = setTimeout(() => fail(new Error('smtp_timeout')), timeoutMs);
    };
    const readResponse = () => new Promise((resolveRead) => {
      const wait = () => {
        const lines = buffer.split(/\r?\n/);
        for (let i = 0; i < lines.length; i += 1) {
          if (/^\d{3} /.test(lines[i])) {
            const responseLines = lines.slice(0, i + 1);
            buffer = lines.slice(i + 1).join('\n');
            return resolveRead({ code: Number(lines[i].slice(0, 3)), text: responseLines.join('\n') });
          }
        }
        setTimeout(wait, 10);
      };
      wait();
    });
    const command = async (line, expected) => {
      resetTimer();
      socket.write(line + '\r\n');
      const response = await readResponse();
      const expectedList = Array.isArray(expected) ? expected : [expected];
      if (!expectedList.includes(response.code)) {
        throw new Error(`smtp_${response.code}_${orderMailCleanText(response.text, 120)}`);
      }
      return response;
    };

    const run = async () => {
      resetTimer();
      socket = config.secure
        ? tls.connect({ host, port, servername: host, rejectUnauthorized: true })
        : net.connect({ host, port });
      socket.setEncoding('utf8');
      socket.on('error', fail);
      socket.on('data', (chunk) => { buffer += chunk.toString('utf8'); });
      await new Promise((resolveConnect) => socket.once(config.secure ? 'secureConnect' : 'connect', resolveConnect));
      const greet = await readResponse();
      if (greet.code !== 220) throw new Error(`smtp_greeting_${greet.code}`);
      await command('EHLO diracgroup.store', 250);
      if (!config.secure) {
        await command('STARTTLS', 220);
        socket.removeAllListeners('data');
        socket.removeAllListeners('error');
        buffer = '';
        socket = tls.connect({ socket, servername: host, rejectUnauthorized: true });
        socket.setEncoding('utf8');
        socket.on('error', fail);
        socket.on('data', (chunk) => { buffer += chunk.toString('utf8'); });
        await new Promise((resolveSecure) => socket.once('secureConnect', resolveSecure));
        await command('EHLO diracgroup.store', 250);
      }
      await command('AUTH PLAIN ' + Buffer.from(`\u0000${config.user}\u0000${config.pass}`).toString('base64'), 235);
      await command(`MAIL FROM:<${config.fromEmail}>`, 250);
      for (const recipient of recipients) await command(`RCPT TO:<${recipient}>`, [250, 251]);
      await command('DATA', 354);
      socket.write(orderMailBuildMimeMessage({ ...message, to: recipients, fromName: message.fromName || config.fromName, fromEmail: message.fromEmail || config.fromEmail }) + '\r\n.\r\n');
      const dataResponse = await readResponse();
      if (dataResponse.code !== 250) throw new Error(`smtp_data_${dataResponse.code}_${orderMailCleanText(dataResponse.text, 120)}`);
      try { await command('QUIT', 221); } catch (_) {}
      done({ ok: true, recipient_count: recipients.length });
    };

    run().catch(fail);
  });
}

function orderMailBuildMimeMessage(message) {
  const boundary = 'DIRAC_' + crypto.randomBytes(12).toString('hex');
  const from = `${orderMailHeaderName(message.fromName || 'Dirac Group')} <${orderMailNormalizeEmail(message.fromEmail || '')}>`;
  const to = (message.to || []).map((email) => `<${orderMailNormalizeEmail(email)}>`).join(', ');
  const subject = orderMailHeaderName(message.subject || 'Dirac Group Order');
  const msgId = `<${Date.now()}.${crypto.randomBytes(8).toString('hex')}@diracgroup.store>`;
  const text = orderMailBase64Body(message.text || '');
  const html = orderMailBase64Body(message.html || '<p>Dirac Group</p>');

  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${msgId}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    text,
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    html,
    `--${boundary}--`,
    ''
  ].join('\r\n');
}

function orderMailHeaderName(value) {
  const text = orderMailCleanText(value, 160).replace(/[\r\n]+/g, ' ');
  if (/^[\x20-\x7E]*$/.test(text)) return text;
  return '=?UTF-8?B?' + Buffer.from(text, 'utf8').toString('base64') + '?=';
}

function orderMailBase64Body(value) {
  return Buffer.from(String(value || ''), 'utf8').toString('base64').replace(/.{1,76}/g, '$&\r\n').trim();
}

function orderMailParseEmailList(value) {
  return Array.from(new Set(String(value || '').split(/[;,\s]+/).map(orderMailNormalizeEmail).filter(Boolean))).slice(0, 50);
}

function orderMailNormalizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!email || email.length > 254) return '';
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) return '';
  return email;
}

function orderMailCleanUrl(value) {
  const url = String(value || '').trim();
  if (!/^https:\/\//i.test(url)) return '';
  return url.slice(0, 1000);
}

function orderMailCleanText(value, maxLength) {
  return String(value || '').replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, Math.max(1, Number(maxLength || 120)));
}

function orderMailEscapeHtml(value) {
  return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

function orderMailMoney(value) {
  const number = Number(String(value || 0).replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.round(number);
}

function orderMailPositiveInt(value, fallback, max) {
  const number = Math.trunc(Number(value));
  if (!Number.isFinite(number) || number < 1) return fallback || 1;
  return Math.min(number, max || 9999);
}

function orderMailFormatCurrency(value, currency) {
  const amount = orderMailMoney(value);
  const cur = orderMailCleanText(currency || 'IDR', 12).toUpperCase() || 'IDR';
  try {
    return new Intl.NumberFormat('id-ID', { style: 'currency', currency: cur, maximumFractionDigits: 0 }).format(amount);
  } catch (_) {
    return `${cur} ${amount.toLocaleString('id-ID')}`;
  }
}

function orderMailFormatDate(value) {
  const date = new Date(value || Date.now());
  try {
    return new Intl.DateTimeFormat('id-ID', {
      timeZone: 'Asia/Jakarta',
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: false,
      timeZoneName: 'short'
    }).format(Number.isFinite(date.getTime()) ? date : new Date());
  } catch (_) {
    return (Number.isFinite(date.getTime()) ? date : new Date()).toISOString();
  }
}

function orderMailServiceLabel(value) {
  const clean = orderMailCleanText(value, 80).toLowerCase();
  if (clean === 'parfum') return 'Parfum';
  if (clean === 'domain') return 'Domain';
  if (clean.includes('website')) return 'Jasa Website';
  if (clean.includes('digital')) return 'Layanan Digital';
  if (clean.includes('pengembangan')) return 'Pengembangan Website';
  return clean ? clean.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase()) : 'Order';
}

function orderMailSafeError(error) {
  const message = String(error && error.message ? error.message : error || 'email_error');
  if (/password|pass|secret|token|authorization|apikey|api_key/i.test(message)) return 'email_internal_error';
  return orderMailCleanText(message, 160);
}


/* ============================================================
   DIRAC SENSITIVE POST ORIGIN GUARD - APPEND ONLY v1
   Tujuan:
   - Menambah pagar CSRF ringan untuk POST sensitif tanpa mengubah isi handler.
   - domain_logout dilindungi di outer wrapper, tetapi logic logout/cookie/A2F lama
     tetap utuh: revoke session tetap best-effort, clearSessionCookies tetap asli.
   - Login, hash password, MFA/A2F core, email template, webhook payment gateway,
     dan cookie helper tidak disentuh.
   - Browser normal tetap aman: Origin valid diterima; jika Origin tidak dikirim,
     Referer valid diterima; jika dua-duanya tidak ada, default fail-open agar
     logout mobile/Safari/keepalive tidak rusak. Bisa dibuat ketat via ENV:
     DIRAC_SENSITIVE_POST_ORIGIN_REQUIRE_HEADER=true
   ============================================================ */

const DIRAC_SENSITIVE_POST_ORIGIN_GUARD_PATCH = 'sensitive-post-origin-guard-v1';
const __diracSensitivePostOriginGuardPreviousHandler = module.exports;

const DIRAC_SENSITIVE_POST_ORIGIN_ACTIONS = new Set([
  'domain_logout',
  'domain_checkout',
  'checkout_order',
  'create_payment',
  'customer_security_revoke_session',
  'customer_security_revoke_other_sessions',
  'customer_security_account_request',
  'customer_security_recovery_codes_generate',
  'customer_security_recovery_code_verify',
  'dirac_mfa_email_start',
  'dirac_mfa_email_verify',
  'dirac_mfa_passkey_start',
  'dirac_mfa_passkey_verify'
]);

module.exports = async function diracSensitivePostOriginGuardWrapper(req, res) {
  const method = String((req && req.method) || '').toUpperCase();
  const rawAction = String((req && req.query && req.query.action) || '').trim();
  const action = diracSensitivePostOriginNormalizeAction(rawAction);

  if (method === 'POST' && DIRAC_SENSITIVE_POST_ORIGIN_ACTIONS.has(action)) {
    const guard = diracSensitivePostOriginCheck(req, action);
    if (!guard.ok) {
      try {
        if (typeof diracApplySecurityResponseHeaders === 'function') diracApplySecurityResponseHeaders(res);
      } catch (_) {}
      try { res.setHeader('Cache-Control', 'no-store'); } catch (_) {}
      try { res.setHeader('X-Content-Type-Options', 'nosniff'); } catch (_) {}
      return res.status(403).json({
        ok: false,
        code: guard.code || 'SENSITIVE_POST_ORIGIN_BLOCKED',
        message: 'Permintaan ditolak karena asal request tidak valid.',
        source: 'sensitive_post_origin_guard'
      });
    }
  }

  return __diracSensitivePostOriginGuardPreviousHandler(req, res);
};

function diracSensitivePostOriginNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    domain_logout: 'domain_logout',
    logout_domain: 'domain_logout',
    domain_checkout: 'domain_checkout',
    domain_create_order: 'domain_checkout',
    create_order: 'domain_checkout',
    checkout_order: 'checkout_order',
    public_checkout: 'checkout_order',
    parfum_checkout: 'checkout_order',
    digital_checkout: 'checkout_order',
    layanan_digital_checkout: 'checkout_order',
    jasa_website_checkout: 'checkout_order',
    pengembangan_checkout: 'checkout_order',
    create_checkout_order: 'checkout_order',
    create_payment: 'create_payment',
    create_payment_order: 'create_payment',
    pay_order: 'create_payment',
    order_payment: 'create_payment',
    checkout_payment: 'create_payment',
    bayar_pesanan: 'create_payment',
    customer_security_revoke_session: 'customer_security_revoke_session',
    customer_security_revoke_other_sessions: 'customer_security_revoke_other_sessions',
    customer_security_account_request: 'customer_security_account_request',
    customer_security_recovery_codes_generate: 'customer_security_recovery_codes_generate',
    customer_security_recovery_code_verify: 'customer_security_recovery_code_verify',
    dirac_mfa_email_start: 'dirac_mfa_email_start',
    domain_mfa_email_start: 'dirac_mfa_email_start',
    dirac_mfa_email_verify: 'dirac_mfa_email_verify',
    domain_mfa_email_verify: 'dirac_mfa_email_verify',
    dirac_mfa_passkey_start: 'dirac_mfa_passkey_start',
    domain_mfa_passkey_start: 'dirac_mfa_passkey_start',
    dirac_mfa_passkey_verify: 'dirac_mfa_passkey_verify',
    domain_mfa_passkey_verify: 'dirac_mfa_passkey_verify'
  };
  return aliases[clean] || clean;
}

function diracSensitivePostOriginCheck(req, action) {
  if (isEnvTrue('DIRAC_SENSITIVE_POST_ORIGIN_GUARD_DISABLED')) {
    return { ok: true, source: 'guard_disabled' };
  }

  const scopedDisabledKey = 'DIRAC_SENSITIVE_POST_ORIGIN_GUARD_DISABLED_' + String(action || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  if (isEnvTrue(scopedDisabledKey)) {
    return { ok: true, source: 'scope_guard_disabled' };
  }

  const headers = (req && req.headers) || {};
  const secFetchSite = String(headers['sec-fetch-site'] || headers['Sec-Fetch-Site'] || '').trim().toLowerCase();
  if (secFetchSite === 'cross-site') {
    return { ok: false, code: 'SENSITIVE_POST_CROSS_SITE_BLOCKED', source: 'sec_fetch_site' };
  }

  const originHeader = String(headers.origin || headers.Origin || '').trim();
  const refererHeader = String(headers.referer || headers.referrer || headers.Referer || headers.Referrer || '').trim();
  const allowedOrigins = diracSensitivePostAllowedOrigins();

  if (originHeader) {
    const origin = diracSensitivePostNormalizeOrigin(originHeader);
    return origin && allowedOrigins.has(origin)
      ? { ok: true, source: 'origin', origin }
      : { ok: false, code: 'SENSITIVE_POST_ORIGIN_BLOCKED', source: 'origin' };
  }

  if (refererHeader) {
    const refererOrigin = diracSensitivePostNormalizeOrigin(refererHeader);
    return refererOrigin && allowedOrigins.has(refererOrigin)
      ? { ok: true, source: 'referer', origin: refererOrigin }
      : { ok: false, code: 'SENSITIVE_POST_REFERER_BLOCKED', source: 'referer' };
  }

  if (isEnvTrue('DIRAC_SENSITIVE_POST_ORIGIN_REQUIRE_HEADER')) {
    return { ok: false, code: 'SENSITIVE_POST_ORIGIN_HEADER_REQUIRED', source: 'missing_origin_referer' };
  }

  return { ok: true, source: 'missing_origin_fail_open' };
}

function diracSensitivePostAllowedOrigins() {
  const values = [];
  try {
    if (typeof getAllowedOrigins === 'function') values.push(...getAllowedOrigins());
  } catch (_) {}

  values.push(
    process.env.SITE_URL,
    process.env.DOMAIN_SITE_URL,
    process.env.NEXT_PUBLIC_SITE_URL,
    process.env.VERCEL_PROJECT_PRODUCTION_URL,
    process.env.VERCEL_URL,
    'https://diracgroup.store',
    'https://www.diracgroup.store'
  );

  return new Set(values.map(diracSensitivePostNormalizeOrigin).filter(Boolean));
}

function diracSensitivePostNormalizeOrigin(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.toLowerCase() === 'null') return '';

  let candidate = raw;
  if (/^[a-z0-9.-]+(?::\d+)?$/i.test(candidate)) candidate = 'https://' + candidate;

  try {
    const url = new URL(candidate);
    if (url.protocol !== 'https:' && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(url.origin)) return '';
    return url.origin.toLowerCase();
  } catch (_) {
    return '';
  }
}
