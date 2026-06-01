'use strict';

const DEFAULT_ALLOWED_ORIGINS = [
  'https://diracgroup.store',
  'https://www.diracgroup.store',
  'https://companyprofilee-ochre.vercel.app'
];

const DOMAIN_ACTIONS = new Set([
  'domain_health',
  'hostinger_check',
  'domain_login',
  'domain_register',
  'domain_me',
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
  'domain_get_orders': 'domain_orders'
});

module.exports = async function handler(req, res) {
  const rawAction = String((req.query && req.query.action) || '').trim();
  const action = normalizeDomainAction(rawAction);
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
    time: new Date().toISOString()
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
