'use strict';

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  return res.status(200).json({
    ok: true,
    service: 'dirac-ai-health',
    time: new Date().toISOString(),
    siteUrl: process.env.SITE_URL || 'https://diracgroup.store',
    checkResiUrl: process.env.CHECK_RESI_URL || 'https://diracgroup.store/cekresi.html',
    providers: {
      gemini: hasAny('GEMINI_API_KEY', 'GEMINI_API_KEYS'),
      groq: hasAny('GROQ_API_KEY', 'GROQ_API_KEYS'),
      openai: hasAny('OPENAI_API_KEY', 'OPENAI_API_KEYS')
    },
    models: {
      gemini: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
      groq: process.env.GROQ_MODEL || 'llama-3.1-8b-instant',
      openai: process.env.OPENAI_MODEL || 'gpt-4o-mini'
    }
  });
};

function setCors(req, res) {
  const allowedOrigins = new Set([
    'https://diracgroup.store',
    'https://www.diracgroup.store',
    'https://companyprofilee-ochre.vercel.app'
  ]);

  const origin = req.headers && req.headers.origin;

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');
}

function hasAny(singleName, listName) {
  if (process.env[singleName]) return true;
  if (process.env[listName]) return true;

  for (let i = 1; i <= 5; i++) {
    if (process.env[`${singleName}_${i}`]) return true;
  }

  return false;
}
