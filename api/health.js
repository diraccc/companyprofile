'use strict';

const crypto = require('crypto');

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
  'domain_orders'
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
  'domain-logout': 'domain_logout'
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
    const legacyBody = await readBody(req);
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

  if (isAdminRequest(req) || process.env.AI_PUBLIC_HEALTH_DETAILS === 'true') {
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
  res.setHeader(
    'Access-Control-Allow-Headers',
    options.isDomainAction
      ? [
          'Content-Type',
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
          'Idempotency-Key',
          'X-Idempotency-Key',
          'X-Dirac-Device-Id',
          'X-Device-Id',
          'content-type',
          'authorization',
          'x-domain-refresh',
          'x-refresh-token',
          'x-dirac-mfa-proof',
          'x-dashboard-mfa-proof',
          'x-dirac-dashboard-mfa',
          'idempotency-key',
          'x-idempotency-key',
          'x-dirac-device-id',
          'x-device-id'
        ].join(', ')
      : 'Content-Type, X-Dirac-Admin, content-type, x-dirac-admin'
  );
  if (options.isDomainAction) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Expose-Headers', 'X-Domain-Access-Token, X-Domain-Refresh-Token, X-Domain-Token-Refreshed, Retry-After');
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
const CUSTOMER_MFA_SESSION_TYPE = 'dirac-customer-mfa-session-v1';


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

async function handleDomainAction(action, req, res) {
  try {
    if (action === 'domain_health') return domainHealth(req, res);
    if (action === 'hostinger_check') return hostingerCheckDomain(req, res);
    if (action === 'domain_login') return domainLogin(req, res);
    if (action === 'domain_register') return domainRegister(req, res);
    if (action === 'domain_me') return domainMe(req, res);
    if (action === 'domain_dashboard_me') return domainDashboardMe(req, res);
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

async function domainHealth(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  return res.status(200).json({
    ok: true,
    service: 'dirac-domain',
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

  const domain = normalizeDomain(req.query && req.query.domain);
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

  const body = preloadedBody || await readBody(req);
  const email = normalizeAuthEmail(body.email || body.identifier || body.customer_email);
  const password = String(body.password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Email dan password wajib diisi.' });
  }

  if (!isValidAuthEmail(email)) {
    return res.status(400).json({ ok: false, message: 'Login server memakai email. Masukkan alamat email yang valid.' });
  }

  const result = await supabaseFetch('/auth/v1/token?grant_type=password', {
    method: 'POST',
    auth: 'anon',
    body: { email, password }
  });

  if (!result.ok) {
    return res.status(result.status).json({
      ok: false,
      message: result.data.error_description || result.data.msg || result.data.message || 'Login gagal.'
    });
  }

  setSessionCookies(res, result.data);

  return res.status(200).json({
    ok: true,
    message: 'Login berhasil.',
    user: sanitizeUser(result.data.user),
    session: {
      access_token: result.data.access_token,
      refresh_token: result.data.refresh_token,
      expires_in: result.data.expires_in
    }
  });
}

async function domainRegister(req, res, preloadedBody) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  const body = preloadedBody || await readBody(req);
  const email = normalizeAuthEmail(body.email || body.identifier || body.customer_email);
  const password = String(body.password || '');
  const fullName = String(body.full_name || body.fullName || body.name || '').trim();
  const whatsapp = normalizePhone(body.whatsapp || body.phone || body.customer_whatsapp || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Email dan password wajib diisi.' });
  }

  if (!isValidAuthEmail(email)) {
    return res.status(400).json({ ok: false, message: 'Pendaftaran server memakai email. Masukkan alamat email yang valid.' });
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

  const result = await supabaseFetch('/auth/v1/signup', {
    method: 'POST',
    auth: 'anon',
    body: signupBody
  });

  if (!result.ok) {
    return res.status(result.status).json({
      ok: false,
      message: result.data.error_description || result.data.msg || result.data.message || 'Pendaftaran gagal.'
    });
  }

  if (result.data.access_token && result.data.refresh_token) {
    setSessionCookies(res, result.data);
  }

  return res.status(200).json({
    ok: true,
    message: result.data.access_token
      ? 'Akun berhasil dibuat dan login otomatis.'
      : 'Akun berhasil dibuat. Silakan cek email verifikasi jika diperlukan.',
    needs_email_confirmation: !result.data.access_token,
    user: sanitizeUser(result.data.user),
    session: result.data.access_token ? {
      access_token: result.data.access_token,
      refresh_token: result.data.refresh_token,
      expires_in: result.data.expires_in
    } : null
  });
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

  return { user, mfa };
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
      verified: true,
      method: mfa.method || '',
      verifiedAtMs: mfa.verifiedAtMs || 0,
      expiresAtMs: mfa.expiresAtMs || 0,
      source: mfa.source || ''
    }
  });
}

async function domainLogout(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

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

  const orderResult = await supabaseFetch('/rest/v1/domain_orders', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      user_id: user.id,
      customer_name: customerName,
      customer_whatsapp: customerWhatsapp,
      customer_email: customerEmail,
      owner_email: ownerEmail,
      dns_method: dnsMethod,
      nameserver_1: nameserver1,
      nameserver_2: nameserver2,
      target_platform: targetPlatform,
      customer_note: customerNote,
      total_amount: totalAmount,
      currency: 'IDR',
      order_status: 'pending',
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
      provider: 'payment_gateway',
      error: String(paymentError && paymentError.message ? paymentError.message : paymentError)
    };
  }

  return res.status(200).json({
    ok: true,
    message: payment && payment.payment_url
      ? 'Pesanan domain berhasil dibuat. Lanjutkan pembayaran otomatis.'
      : 'Pesanan domain berhasil dibuat. Payment gateway belum mengembalikan URL pembayaran.',
    order_id: order.id,
    total_amount: totalAmount,
    currency: 'IDR',
    payment_status: 'unpaid',
    order_status: 'pending_payment',
    payment_url: payment && payment.payment_url ? payment.payment_url : null,
    invoice_id: payment && payment.invoice_id ? payment.invoice_id : null,
    payment_provider: payment && payment.provider ? payment.provider : null,
    payment_gateway_configured: Boolean(payment && payment.configured),
    payment_error: payment && payment.error ? payment.error : null,
    items: orderItems
  });
}


async function maybeCreateDomainPaymentInvoice(order, orderItems, customer) {
  const endpoint = String(process.env.DOMAIN_PAYMENT_CREATE_URL || '').trim();
  if (!endpoint) return { configured: false, payment_url: null };

  const payload = {
    order_id: order && order.id,
    amount: Number(customer && customer.totalAmount || 0),
    currency: 'IDR',
    customer: {
      name: customer && customer.customerName || '',
      phone: customer && customer.customerWhatsapp || '',
      email: customer && customer.customerEmail || ''
    },
    items: orderItems.map((item) => ({
      domain_name: item.domain_name,
      years: item.years,
      price: item.register_price,
      subtotal: item.subtotal
    })),
    return_url: String(process.env.DOMAIN_PAYMENT_RETURN_URL || process.env.DOMAIN_SITE_URL || 'https://diracgroup.store/dashboard.html'),
    callback_url: String(process.env.DOMAIN_PAYMENT_CALLBACK_URL || '')
  };

  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  };
  const secret = String(process.env.DOMAIN_PAYMENT_CREATE_SECRET || '').trim();
  if (secret) headers['Authorization'] = `Bearer ${secret}`;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload)
  });
  const data = await parseFetchResponse(response);
  if (!response.ok) {
    const err = new Error(getUpstreamMessage(data) || 'Payment gateway gagal membuat invoice.');
    err.statusCode = response.status || 502;
    throw err;
  }

  return {
    configured: true,
    provider: String(data.provider || data.payment_provider || 'payment_gateway'),
    invoice_id: data.invoice_id || data.id || data.external_id || null,
    payment_url: data.payment_url || data.invoice_url || data.redirect_url || data.checkout_url || null,
    raw: data
  };
}

async function domainOrders(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const access = await requireDomainDashboardAccess(req, res);
  if (!access) return;

  const { user } = access;

  const select = [
    'id',
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
    'total_amount',
    'currency',
    'order_status',
    'payment_status',
    'domain_order_items(id,domain_name,extension,years,register_price,renewal_price,subtotal)'
  ].join(',');

  const path = `/rest/v1/domain_orders?select=${encodeURIComponent(select)}&user_id=eq.${encodeURIComponent(user.id)}&order=created_at.desc`;

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
  const headerToken = getBearerToken(req);
  const headerRefreshToken = String((req.headers && (req.headers['x-domain-refresh'] || req.headers['x-refresh-token'])) || '').trim();

  const accessToken = headerToken || cookies[ACCESS_COOKIE];
  const refreshToken = headerRefreshToken || cookies[REFRESH_COOKIE];

  if (accessToken) {
    const userResult = await supabaseFetch('/auth/v1/user', {
      method: 'GET',
      auth: 'anon',
      bearer: accessToken
    });

    if (userResult.ok && userResult.data && userResult.data.id) {
      return userResult.data;
    }
  }

  if (refreshToken) {
    const refreshResult = await supabaseFetch('/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      auth: 'anon',
      body: { refresh_token: refreshToken }
    });

    if (refreshResult.ok && refreshResult.data && refreshResult.data.access_token) {
      setSessionCookies(res, refreshResult.data);
      res.setHeader('X-Domain-Access-Token', refreshResult.data.access_token);
      res.setHeader('X-Domain-Refresh-Token', refreshResult.data.refresh_token);
      res.setHeader('X-Domain-Token-Refreshed', 'true');
      return refreshResult.data.user;
    }
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

function requestOrigin(req) {
  return String((req && req.headers && (req.headers.origin || req.headers.referer)) || '').trim().replace(/\/$/, '');
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
  if (cookieToken) return { token: cookieToken, source: 'cookie' };

  const headerToken = String(
    (req && req.headers && (
      req.headers['x-dirac-mfa-proof'] ||
      req.headers['x-dashboard-mfa-proof'] ||
      req.headers['x-dirac-dashboard-mfa']
    )) || ''
  ).trim();
  if (headerToken) return { token: headerToken, source: 'signed-header' };

  return { token: '', source: 'missing' };
}

function verifyCustomerDashboardMfaCookie(req, user) {
  const proof = getCustomerDashboardMfaToken(req);
  const payload = decodeCustomerDashboardMfaToken(proof.token);
  const email = normalizeAuthEmail(user && user.email);

  if (!payload || payload.type !== CUSTOMER_MFA_SESSION_TYPE) {
    return { ok: false, message: 'Sesi A2F backend tidak ditemukan. Login dan verifikasi A2F ulang. Jika browser memblokir third-party cookie, paket v2 memakai proof header bertanda tangan.' };
  }

  if (!payload.expiresAtMs || Date.now() > Number(payload.expiresAtMs)) {
    return { ok: false, message: 'Sesi A2F backend sudah expired. Login dan verifikasi A2F ulang.' };
  }

  if (!email || !payload.emailHash || !safeEqual(String(payload.emailHash), customerMfaProfileId(email))) {
    return { ok: false, message: 'Sesi A2F backend tidak cocok dengan akun login.' };
  }

  if (payload.originHash) {
    const expectedOriginHash = customerMfaBindingHash('origin', requestOrigin(req));
    if (!expectedOriginHash || !safeEqual(String(payload.originHash), expectedOriginHash)) {
      return { ok: false, message: 'Sesi A2F backend tidak cocok dengan origin website ini. Login ulang dari domain resmi.' };
    }
  }

  if (payload.uaHash) {
    const expectedUaHash = customerMfaBindingHash('ua', requestUserAgent(req));
    if (!expectedUaHash || !safeEqual(String(payload.uaHash), expectedUaHash)) {
      return { ok: false, message: 'Sesi A2F backend tidak cocok dengan browser/perangkat ini. Login ulang dari browser yang sama.' };
    }
  }

  return {
    ok: true,
    method: String(payload.method || ''),
    verifiedAtMs: Number(payload.verifiedAtMs || 0),
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
  return String(data.error || data.message || data.detail || data.title || '').slice(0, 220);
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

function normalizeAuthEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidAuthEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

function normalizePhone(value) {
  return String(value || '').trim().replace(/[^+\d]/g, '');
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

  header.split(';').map((item) => item.trim()).filter(Boolean).forEach((item) => {
    const index = item.indexOf('=');
    if (index === -1) {
      cookies[item] = '';
      return;
    }

    const key = item.slice(0, index);
    const value = decodeURIComponent(item.slice(index + 1));
    cookies[key] = value;
  });

  return cookies;
}

function makeCookie(name, value, options = {}) {
  const sameSite = String(process.env.DOMAIN_COOKIE_SAMESITE || (process.env.NODE_ENV === 'development' ? 'Lax' : 'None')).trim();
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    `SameSite=${sameSite}`
  ];

  if (sameSite.toLowerCase() === 'none' || process.env.NODE_ENV !== 'development') {
    parts.push('Secure');
  }

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }

  return parts.join('; ');
}

function setSessionCookies(res, session) {
  const maxAge = 60 * 60 * 24 * 7;

  res.setHeader('Set-Cookie', [
    makeCookie(ACCESS_COOKIE, session.access_token, { maxAge }),
    makeCookie(REFRESH_COOKIE, session.refresh_token, { maxAge })
  ]);
}

function clearSessionCookies(res) {
  res.setHeader('Set-Cookie', [
    makeCookie(ACCESS_COOKIE, '', { maxAge: 0 }),
    makeCookie(REFRESH_COOKIE, '', { maxAge: 0 }),
    makeCookie(CUSTOMER_MFA_COOKIE, '', { maxAge: 0 })
  ]);
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
    const user = await requireDomainUser(req, res);
    if (!user) return;

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
    'match_confidence',
    'verified_at'
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
    const user = await requireDomainUser(req, res);
    if (!user) return;

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

  const settingsResult = await customerSecurityFetchRows(
    'security_customer_settings',
    [
      'email_verified',
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
  );

  if (!settingsResult.ok) return { ok: false, status: settingsResult.status, section: 'settings', data: settingsResult.data };

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
  );

  if (!sessionsResult.ok) return { ok: false, status: sessionsResult.status, section: 'sessions', data: sessionsResult.data };

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
  );

  if (!loginLogsResult.ok) return { ok: false, status: loginLogsResult.status, section: 'login_logs', data: loginLogsResult.data };

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
  );

  if (!eventsResult.ok) return { ok: false, status: eventsResult.status, section: 'events', data: eventsResult.data };

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
  );

  if (!requestsResult.ok) return { ok: false, status: requestsResult.status, section: 'account_requests', data: requestsResult.data };

  const settingsRows = Array.isArray(settingsResult.data) ? settingsResult.data : [];
  const sessions = Array.isArray(sessionsResult.data) ? sessionsResult.data : [];
  const loginLogs = Array.isArray(loginLogsResult.data) ? loginLogsResult.data : [];
  const events = Array.isArray(eventsResult.data) ? eventsResult.data : [];
  const accountRequests = Array.isArray(requestsResult.data) ? requestsResult.data : [];

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
      }
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
    match_confidence: 'verified',
    verified_at: new Date().toISOString()
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
  const tokenMaterial = headerToken || cookies[ACCESS_COOKIE] || headerRefreshToken || cookies[REFRESH_COOKIE] || '';

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
        requireMfa: false,
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
        mfa_required_for_write: true,
        mfa_verified_now: Boolean(access.mfa && access.mfa.ok),
        guarded_actions_ready: true,
        rate_limit_mode: 'memory_local_basic',
        write_guard: 'mfa_required',
        customer_id_source: 'security_customer_auth_links',
        message: 'Guard customer security aktif. Aksi write tetap membutuhkan MFA/re-auth.',
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
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'user_not_verified');
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
const CUSTOMER_SECURITY_RECOVERY_SPECIAL_LETTERS = 'ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖØÙÚÛÜÝŸàáâãäåæçèéêëìíîïñòóôõöøùúûüýÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĴĵĶķŁłŃńŇňŌōŎŏŐőŒœŔŕŘřŚśŜŝŞşŠšŢţŤťŪūŬŭŮůŰűŲųŴŵŶŷŹźŻżŽž';
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
      verified: false,
      code: 'RECOVERY_CODE_USED',
      message: 'Recovery code sudah dipakai atau expired.'
    };
  }
  if (clean.includes('expired') || clean.includes('revoked')) {
    return {
      ok: false,
      verified: false,
      code: 'RECOVERY_CODE_EXPIRED',
      message: 'Recovery code sudah expired. Gunakan kode recovery lain.'
    };
  }
  if (clean.includes('format') || clean.includes('length')) {
    return {
      ok: false,
      verified: false,
      code: 'RECOVERY_CODE_FORMAT_INVALID',
      message: 'Format recovery code tidak valid. Tempel 1 kode penuh dari file TXT.'
    };
  }
  if (clean.includes('mfa') || clean.includes('proof') || clean.includes('session')) {
    return {
      ok: false,
      verified: false,
      code: 'SESSION_REQUIRED',
      message: 'Sesi login tidak valid. Silakan login ulang.'
    };
  }
  return {
    ok: false,
    verified: false,
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
  const access = await customerSecurityRequireAccess(req, res, { action, requireMfa: false, rateLimit: { limit: 20, windowMs: 60_000 } });
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
    verifiedAtMs: now,
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
    verifiedAtMs: payload.verifiedAtMs,
    maxAgeSeconds
  };
}

function customerSecuritySetDashboardMfaCookie(res, proof) {
  const token = proof && proof.token ? String(proof.token) : '';
  const maxAge = Math.max(1, Math.floor(Number(proof && proof.maxAgeSeconds || 0)));
  if (!token || !maxAge) return;
  res.setHeader('Set-Cookie', [
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
    verified: true,
    method: 'recovery_code',
    message: 'Recovery code valid. Akses dashboard diverifikasi.',
    dashboardSession: {
      proofToken: proof.token,
      expiresAtMs: proof.expiresAtMs,
      verifiedAtMs: proof.verifiedAtMs,
      method: 'recovery_code'
    },
    mfaProofToken: proof.token,
    dashboardMfaProofToken: proof.token,
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
     verified = true
     status = active/enabled/verified atau kosong.
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
  const verified = adminRow.verified === true || String(adminRow.verified || '').toLowerCase() === 'true';
  const status = String(adminRow.status || '').trim().toLowerCase();
  const activeStatus = !status || status === 'active' || status === 'enabled' || status === 'verified';

  if (!verified || !activeStatus) {
    res.status(403).json({
      ok: false,
      message: 'Admin belum verified atau status tidak aktif.'
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
    uid: String(adminRow.uid || userId || ''),
    email: email || String(adminRow.email || ''),
    role,
    verified,
    status,
    canWrite,
    auth_user: user
  };
}

async function adminSecurityRequireSupabaseUser(req) {
  const token = adminSecurityGetSupabaseAccessToken(req);

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

  const firebaseToken = adminSecurityGetFirebaseToken(req) || token;
  if (firebaseToken) {
    const verified = await adminSecurityVerifyFirebaseIdTokenNoEnv(firebaseToken);
    if (verified && verified.ok && verified.payload) {
      const payload = verified.payload;
      return {
        id: String(payload.user_id || payload.sub || ''),
        user_id: String(payload.user_id || payload.sub || ''),
        email: normalizeAuthEmail(payload.email || ''),
        provider: 'firebase',
        raw: payload
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
  const select = encodeURIComponent('id,user_id,uid,email,role,verified,status,created_at,updated_at');
  const queries = [];

  if (customerSecurityLooksLikeUuid(userId)) {
    queries.push('/rest/v1/admin_users?select=' + select + '&user_id=eq.' + encodeURIComponent(userId) + '&limit=1');
  }
  if (userId) {
    queries.push('/rest/v1/admin_users?select=' + select + '&uid=eq.' + encodeURIComponent(userId) + '&limit=1');
  }
  if (email) {
    queries.push('/rest/v1/admin_users?select=' + select + '&email=ilike.' + encodeURIComponent(email) + '&limit=1');
  }

  for (const path of queries) {
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
    const rows = result && result.ok && Array.isArray(result.data) ? result.data : [];
    if (rows[0]) return rows[0];
  }

  return null;
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
      recovery_events_generated: eventRows.filter((row) => String(row.event_type || '') === 'recovery_codes_generated').length,
      recovery_events_used: eventRows.filter((row) => String(row.event_type || '') === 'recovery_code_used').length,
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
    verified: Boolean(admin && admin.verified),
    status: String(admin && admin.status || ''),
    can_write: Boolean(admin && admin.canWrite)
  };
}

function adminSecuritySafeErrorSupabase(error) {
  return String(error && error.message ? error.message : error).slice(0, 180);
}
