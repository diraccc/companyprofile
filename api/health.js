'use strict';

const DEFAULT_ALLOWED_ORIGINS = [
  'https://diracgroup.store',
  'https://www.diracgroup.store',
  'https://companyprofilee-ochre.vercel.app'
];

const DOMAIN_ACTIONS = new Set([
  'domain_login',
  'domain_register',
  'domain_me',
  'domain_logout',
  'domain_check',
  'domain_checkout',
  'domain_orders'
]);

module.exports = async function handler(req, res) {
  const action = String((req.query && req.query.action) || '').trim();
  const isDomainAction = DOMAIN_ACTIONS.has(action);

  const cors = setCors(req, res, { isDomainAction });
  if (req.method === 'OPTIONS') return res.status(cors.allowed ? 200 : 403).end();
  if (!cors.allowed) return res.status(403).json({ ok: false, message: 'Origin tidak diizinkan.' });

  if (isDomainAction) {
    return handleDomainAction(action, req, res);
  }

  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Method tidak diizinkan.' });

  const payload = {
    ok: true,
    service: 'dirac-ai',
    chatEndpoint: '/api/chat',
    time: new Date().toISOString()
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
  res.setHeader('Access-Control-Allow-Headers', options.isDomainAction ? 'Content-Type, X-Dirac-Admin, Authorization, X-Domain-Refresh, X-Refresh-Token' : 'Content-Type, X-Dirac-Admin');
  if (options.isDomainAction) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Expose-Headers', 'X-Domain-Access-Token, X-Domain-Refresh-Token, X-Domain-Token-Refreshed');
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

/* ============================================================
   DOMAIN ROUTER TAMBAHAN
   Endpoint tetap memakai file lama:
   /api/health?action=domain_login
   /api/health?action=domain_register
   /api/health?action=domain_me
   /api/health?action=domain_logout
   /api/health?action=domain_check&domain=contoh.com
   /api/health?action=domain_checkout
   /api/health?action=domain_orders
   ============================================================ */

const ACCESS_COOKIE = process.env.DOMAIN_SESSION_COOKIE || 'dirac_domain_session';
const REFRESH_COOKIE = process.env.DOMAIN_REFRESH_COOKIE || 'dirac_domain_refresh';

async function handleDomainAction(action, req, res) {
  try {
    if (action === 'domain_login') return domainLogin(req, res);
    if (action === 'domain_register') return domainRegister(req, res);
    if (action === 'domain_me') return domainMe(req, res);
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

async function domainLogin(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  const body = await readBody(req);
  const email = String(body.email || '').trim();
  const password = String(body.password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Email dan password wajib diisi.' });
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

async function domainRegister(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });

  const body = await readBody(req);
  const email = String(body.email || '').trim();
  const password = String(body.password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Email dan password wajib diisi.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ ok: false, message: 'Password minimal 6 karakter.' });
  }

  const result = await supabaseFetch('/auth/v1/signup', {
    method: 'POST',
    auth: 'anon',
    body: { email, password }
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

  const user = await requireDomainUser(req, res);
  if (!user) return;

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
    return res.status(400).json({ ok: false, message: 'Nama dan WhatsApp wajib diisi.' });
  }

  if (!items.length) {
    return res.status(400).json({ ok: false, message: 'Keranjang domain masih kosong.' });
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

    const years = Number(item.years || 1);

    if (years < 1) {
      return res.status(400).json({ ok: false, message: 'Durasi pembelian minimal 1 tahun.' });
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

  return res.status(200).json({
    ok: true,
    message: 'Pesanan domain berhasil dibuat.',
    order_id: order.id,
    total_amount: totalAmount,
    currency: 'IDR',
    items: orderItems
  });
}

async function domainOrders(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Gunakan GET.' });

  const user = await requireDomainUser(req, res);
  if (!user) return;

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
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax'
  ];

  if (process.env.NODE_ENV !== 'development') {
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
    makeCookie(REFRESH_COOKIE, '', { maxAge: 0 })
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
