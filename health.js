'use strict';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ ok: false, message: 'Method tidak diizinkan.' });

  return res.status(200).json({
    ok: true,
    service: 'dirac-ai',
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEYS || process.env.GEMINI_API_KEY_1),
    groqConfigured: Boolean(process.env.GROQ_API_KEY || process.env.GROQ_API_KEYS || process.env.GROQ_API_KEY_1),
    openAiConfigured: Boolean(process.env.OPENAI_API_KEY),
    siteUrl: process.env.SITE_URL || 'https://diracgroup.store',
    chatEndpoint: '/api/chat',
    time: new Date().toISOString()
  });
};
