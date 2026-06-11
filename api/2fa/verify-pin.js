'use strict';

// PATCH FINAL HARDENING:
// Endpoint legacy verify-pin dinonaktifkan agar PIN/device-token statis tidak menjadi jalur publik.
// Flow A2F resmi tetap lewat /api/2fa/start-step dan /api/2fa/verify-step.

function getAllowedOrigins() {
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  return fromEnv.length ? fromEnv : [
    'https://diracgroup.store',
    'https://www.diracgroup.store',
    'https://companyprofilee-expk.vercel.app',
    'https://companyprofilee-ochre.vercel.app'
  ];
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return getAllowedOrigins().includes(origin);
}

function setCors(req, res) {
  const origin = String((req && req.headers && req.headers.origin) || '');
  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || 'https://diracgroup.store');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Cache-Control', 'no-store');
  return isAllowedOrigin(origin);
}

module.exports = async function handler(req, res) {
  const corsOk = setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(corsOk ? 200 : 403).end();
  if (!corsOk) return res.status(403).json({ success: false, ok: false, error: 'Origin tidak diizinkan' });
  return res.status(410).json({
    success: false,
    ok: false,
    disabled: true,
    error: 'Endpoint legacy verify-pin sudah dinonaktifkan. Gunakan /api/2fa/start-step dan /api/2fa/verify-step.'
  });
};
