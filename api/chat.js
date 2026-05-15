'use strict';

const SITE_URL = process.env.SITE_URL || 'https://diracgroup.store';
const CHECK_RESI_URL = process.env.CHECK_RESI_URL || 'https://diracgroup.store/cekresi.html';
const WA_URL = process.env.WHATSAPP_URL || 'https://wa.me/6287892523968';
const DEFAULT_TIMEOUT = Number(process.env.AI_TIMEOUT_MS || 18000);
const memory = globalThis.__DIRAC_AI_MEMORY__ || (globalThis.__DIRAC_AI_MEMORY__ = { rate: new Map() });

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method === 'GET') return res.status(200).json({ ok: true, service: 'dirac-ai-chat', geminiConfigured: hasGemini(), groqConfigured: hasGroq(), openAiConfigured: hasOpenAI(), time: new Date().toISOString() });
  if (req.method !== 'POST') return res.status(405).json(reply('error', 'Method tidak diizinkan.'));

  const traceId = 'dirac_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
  const startedAt = Date.now();

  try {
    const body = req.body || {};
    const message = String(body.message || '').trim().slice(0, 1200);
    const products = Array.isArray(body.products) ? body.products.slice(0, 100) : [];
    const cart = Array.isArray(body.cart) ? body.cart.slice(0, 30) : [];
    const history = Array.isArray(body.history) ? body.history.slice(-16) : [];
    const sessionId = cleanId(req.headers['x-dirac-session'] || body.sessionId || 'anonymous');
    if (!message) return res.status(400).json(reply('error', 'Pertanyaan masih kosong.', { traceId }));

    const limited = rateLimit(clientIp(req), sessionId);
    if (!limited.allowed) return res.status(429).json(reply('rate_limited', 'AI sedang ramai dipakai. Coba lagi sebentar ya.', { traceId, retryAfterSeconds: limited.retryAfterSeconds }));

    const norm = normalize(message);
    if (isSpam(norm)) return res.status(200).json(reply('conversation', 'Pesannya terlihat seperti spam. Tulis pertanyaan dengan jelas ya.', { traceId }));
    if (isPromptInjection(norm)) return res.status(200).json(reply('security', 'Saya tidak bisa mengikuti instruksi untuk mengabaikan sistem, membuka rahasia, atau menampilkan API key. Silakan tanya hal lain.', { traceId }));

    const context = extractContext([history.map((h) => h && h.content || '').join(' '), message].join(' '));
    const intent = detectIntent(norm, normalize(history.map((h) => h && h.content || '').join(' ')), context);
    const direct = directAnswer(intent, norm, cart, traceId);
    if (direct) return res.status(200).json(direct);

    if (intent.name === 'recommendation_needs_info') {
      const questions = missingQuestions(context).slice(0, 3);
      return res.status(200).json(reply('recommendation', infoReply(context, questions), { traceId, needMoreInfo: true, questions, analytics: meta(intent, startedAt, 'router') }));
    }

    const useProducts = intent.name === 'recommendation_ready' || intent.name === 'product_search';
    const scored = useProducts ? scoreProducts(products, context, norm).slice(0, 6) : [];
    if (useProducts && scored.length && !hasAnyProvider()) {
      const top = scored.slice(0, 3).map((x) => x.product);
      return res.status(200).json(reply('commerce', productReply(top, context), { traceId, provider: 'local-product-matcher', showProducts: true, products: publicProducts(top), analytics: meta(intent, startedAt, 'local-product-matcher') }));
    }
    if (!hasAnyProvider()) return res.status(200).json(reply('fallback', 'AI utama belum aktif karena API key belum disetel di Vercel. Saya masih bisa bantu link website, cek resi, cara checkout, dan rekomendasi dasar.', { traceId }));

    const prompt = buildPrompt({ message, history, cart, intent, context, products: useProducts ? scored.slice(0, 12).map((x) => x.product) : [] });
    const ai = await callAI({ prompt, general: intent.name === 'general', search: shouldUseSearch(norm, intent), startedAt });
    const top = useProducts ? scored.slice(0, 3).map((x) => x.product) : [];
    return res.status(200).json(reply(useProducts ? 'commerce' : intent.mode, ai.text, {
      traceId,
      provider: ai.provider,
      showProducts: useProducts && top.length > 0,
      products: useProducts ? publicProducts(top) : [],
      analytics: { intent: intent.name, source: ai.provider, failoverUsed: ai.failoverUsed, attempts: ai.attempts, ms: Date.now() - startedAt }
    }));
  } catch (error) {
    return res.status(500).json(reply('error', 'Terjadi kendala pada server AI. Silakan coba lagi.', { traceId, detail: safeError(error) }));
  }
};

function reply(mode, text, extra = {}) { return { mode, provider: null, showProducts: false, products: [], links: [], needMoreInfo: false, questions: [], reply: text, ...extra }; }
function setCors(req, res) { const allowed = new Set(['https://diracgroup.store', 'https://www.diracgroup.store', 'https://companyprofilee-ochre.vercel.app']); const origin = req.headers && req.headers.origin; res.setHeader('Access-Control-Allow-Origin', origin && allowed.has(origin) ? origin : '*'); res.setHeader('Vary', 'Origin'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Dirac-Session'); res.setHeader('Cache-Control', 'no-store'); }
function normalize(v) { return String(v || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim(); }
function cleanId(v) { return String(v || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80) || 'anonymous'; }
function clientIp(req) { return String(req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket && req.socket.remoteAddress || 'unknown').split(',')[0].trim().slice(0, 80); }
function safeError(e) { return String(e && e.message || e || 'Unknown error').replace(/AIza[0-9A-Za-z_-]+/g, '[redacted]').replace(/gsk_[0-9A-Za-z_-]+/g, '[redacted]').replace(/sk-[0-9A-Za-z_-]+/g, '[redacted]').slice(0, 500); }
function meta(intent, startedAt, source) { return { intent: intent.name, source, ms: Date.now() - startedAt }; }
function isSpam(n) { return /(.)\1{18,}/.test(n.replace(/\s/g, '')) || n.length > 20 && new Set(n.replace(/\s/g, '').split('')).size <= 2; }
function isPromptInjection(n) { return /\b(abaikan instruksi|ignore previous|ignore all|developer message|system prompt|api key|secret key|tampilkan token|bocorkan)\b/.test(n); }

function rateLimit(ip, session) { const now = Date.now(); const key = ip + ':' + session; const bucket = memory.rate.get(key) || { minute: [], hour: [] }; bucket.minute = bucket.minute.filter((t) => now - t < 60000); bucket.hour = bucket.hour.filter((t) => now - t < 3600000); const m = Number(process.env.AI_RATE_LIMIT_PER_MINUTE || 20); const h = Number(process.env.AI_RATE_LIMIT_PER_HOUR || 100); if (bucket.minute.length >= m || bucket.hour.length >= h) return { allowed: false, retryAfterSeconds: bucket.minute.length >= m ? 60 : 600 }; bucket.minute.push(now); bucket.hour.push(now); memory.rate.set(key, bucket); if (memory.rate.size > 1000) memory.rate.delete(memory.rate.keys().next().value); return { allowed: true }; }

function detectIntent(n, hist, context) {
  if (/^(halo|hallo|helo|hello|hai|hi|hii|hiii|hlo|hllo|lo|yo|yoi|p|pp|test|tes|permisi|salam|assalamualaikum|assalamu alaikum|pagi|siang|sore|malam|selamat pagi|selamat siang|selamat sore|selamat malam)$/.test(n)) return { name: 'greeting', mode: 'conversation' };
  if (/^(makasih|terima kasih|terimakasih|thanks|thank you|thx|sip|oke|ok|okay|baik|mantap|siap|noted|gas|nice|keren)$/.test(n)) return { name: 'thanks', mode: 'conversation' };
  if (/^(goblok+|goblog+|tolol+|bodoh+|bego+|anjing+|bangsat+|kampret+)$/i.test(n)) return { name: 'calm_down', mode: 'conversation' };
  if (/^(siapa kamu|kamu siapa|ini siapa|ini ai apa|kamu bot|kamu robot|kamu bisa apa|bisa apa|fitur kamu apa|jelaskan dirimu)$/.test(n)) return { name: 'identity', mode: 'conversation' };
  if (/^(apa kabar|gimana kabarnya|kamu apa kabar|lagi apa|sedang apa|hai apa kabar|halo apa kabar)$/.test(n)) return { name: 'smalltalk', mode: 'conversation' };
  if (/\b(presiden indonesia|presiden ri|presiden republik indonesia)\b/.test(n)) return { name: 'president_id', mode: 'conversation' };
  if (/\b(website|web|situs|link|company profile|profil perusahaan|profile perusahaan|alamat web|alamat website)\b/.test(n) && !/\b(parfum|produk|resi|checkout|beli)\b/.test(n)) return { name: 'website', mode: 'link' };
  if (/\b(resi|cek resi|lacak|tracking|paket|pengiriman|kurir|jne|jnt|j t|sicepat|anteraja|pos|ninja|lion|sap|id express|tiki)\b/.test(n)) return { name: 'tracking', mode: 'link' };
  if (/\b(komplain|keluhan|belum sampai|belum dikirim|rusak|salah barang|refund|retur|return|admin|cs|customer service|bantuan admin)\b/.test(n)) return { name: 'support', mode: 'support' };
  if (/\b(keranjang|cart|checkout|check out|beli|order|pesan|bayar|whatsapp|wa|cara beli|mau beli)\b/.test(n) && !/\b(parfum|produk|rekomendasi|aroma|wangi)\b/.test(n)) return { name: 'checkout', mode: 'checkout' };
  const rec = /\b(rekomendasi|rekomendasikan|saran|sarankan|pilihkan|pilih|cocok|suggest|recommend|mau parfum|pengen parfum|butuh parfum)\b/.test(n) || /\b(rekomendasi|parfum buat apa|aroma apa|budget berapa)\b/.test(hist);
  const product = /\b(produk|parfum|perfume|wangi|aroma|botol|ml|stok|ready|harga|budget|mahal|murah)\b/.test(n);
  const infoCount = [context.usage, context.scent, context.gender, context.budget].filter(Boolean).length;
  if (!rec && infoCount > 0 && infoCount < 3) return { name: 'recommendation_needs_info', mode: 'recommendation' };
  if (rec && infoCount < 3) return { name: 'recommendation_needs_info', mode: 'recommendation' };
  if (rec && infoCount >= 3) return { name: 'recommendation_ready', mode: 'commerce' };
  if (product) return { name: 'product_search', mode: 'commerce' };
  return { name: 'general', mode: 'conversation' };
}

function directAnswer(intent, n, cart, traceId) {
  if (intent.name === 'greeting') return reply('conversation', 'Halo! Saya Dirac AI Assistant. Mau ngobrol dulu atau butuh bantuan seputar parfum, checkout, website, dan cek resi?', { traceId, provider: 'router' });
  if (intent.name === 'thanks') return reply('conversation', 'Sama-sama. Kalau nanti butuh bantuan lagi, tinggal chat saja ya.', { traceId, provider: 'router' });
  if (intent.name === 'calm_down') return reply('conversation', 'Saya paham Anda kesal. Saya akan bantu jawab lebih tepat. Tulis pertanyaannya dengan jelas, nanti saya jawab langsung tanpa menawarkan produk kalau memang bukan soal belanja.', { traceId, provider: 'router' });
  if (intent.name === 'identity') return reply('conversation', 'Saya Dirac AI Assistant. Saya bisa diajak ngobrol seperti AI biasa, bantu jawab pertanyaan umum, bantu pilih parfum pelan-pelan, arahkan checkout, beri link website, dan arahkan cek resi.', { traceId, provider: 'router' });
  if (intent.name === 'smalltalk') return reply('conversation', 'Kabar saya baik. Anda sendiri bagaimana? Kita bisa ngobrol dulu, tidak harus langsung bahas produk.', { traceId, provider: 'router' });
  if (intent.name === 'president_id') return reply('conversation', 'Presiden Indonesia saat ini adalah Prabowo Subianto. Wakil presidennya adalah Gibran Rakabuming Raka. Mereka menjabat untuk periode 2024-2029.', { traceId, provider: 'router' });
  if (intent.name === 'website') return reply('link', 'Website resmi Dirac Group ada di sini:\n' + SITE_URL, { traceId, provider: 'router', links: [{ label: 'Buka website Dirac Group', url: SITE_URL }] });
  if (intent.name === 'tracking') return reply('link', 'Untuk cek resi, buka halaman Cek Resi Dirac Group lalu masukkan nomor resi dan pilih kurir:\n' + CHECK_RESI_URL, { traceId, provider: 'router', links: [{ label: 'Buka Cek Resi', url: CHECK_RESI_URL }] });
  if (intent.name === 'support') return reply('support', 'Maaf atas kendalanya. Kirim nomor order/resi dan detail masalah ke admin agar dibantu lebih cepat:\n' + WA_URL, { traceId, provider: 'router', links: [{ label: 'Chat Admin WhatsApp', url: WA_URL }] });
  if (intent.name === 'checkout') return reply('checkout', cart && cart.length ? 'Untuk checkout, buka keranjang lalu klik Checkout WhatsApp. Pesanan akan dirangkum otomatis.' : 'Cara beli: pilih produk, klik Tambah, buka keranjang, isi data, lalu Checkout WhatsApp.', { traceId, provider: 'router', links: [{ label: 'Chat Admin WhatsApp', url: WA_URL }] });
  if (/\b(jam operasional|admin buka|buka jam|jam buka)\b/.test(n)) return reply('faq', 'Admin melayani setiap hari pukul 09.00-21.00 WIB. Pesan di luar jam tersebut akan dibalas pada jam kerja berikutnya.', { traceId, provider: 'router' });
  if (/\b(privasi|data pribadi|password|otp)\b/.test(n)) return reply('faq', 'Jangan kirim password, OTP, atau data sensitif di chat. Data pembeli hanya digunakan untuk proses pesanan, pengiriman, dan komunikasi layanan.', { traceId, provider: 'router' });
  return null;
}

function extractContext(text) { const n = normalize(text); return { usage: match(n, { harian: ['harian','sehari hari','daily','kuliah','sekolah'], kantor: ['kantor','kerja','meeting'], formal: ['formal','acara','pesta','malam','date','kencan'], hadiah: ['hadiah','kado','gift'] }), scent: match(n, { fresh: ['fresh','segar','citrus','aquatic','clean','dingin'], sweet: ['manis','sweet','vanilla','fruity','buah'], woody: ['woody','oud','amber','musk','leather'], floral: ['floral','rose','bunga'], strong: ['strong','kuat','tahan lama','awet'], soft: ['soft','lembut','kalem'] }), gender: match(n, { pria: ['pria','laki','lelaki','cowok','cowo','maskulin'], wanita: ['wanita','perempuan','cewek','cewe','feminim'], unisex: ['unisex','netral'] }), budget: (n.match(/(?:rp\s*)?(\d{2,4})\s*(rb|ribu|k|jt|juta)?/i) || [null])[0] || (/\b(budget|murah|mahal|dibawah|di bawah|max|maksimal)\b/.test(n) ? 'mentioned' : null) }; }
function match(n, groups) { for (const [label, terms] of Object.entries(groups)) if (terms.some((t) => new RegExp('(^|\\s)' + esc(normalize(t)) + '(?=\\s|$)').test(n))) return label; return null; }
function esc(v) { return String(v).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function missingQuestions(c) { const q = []; if (!c.usage) q.push('Parfum ini mau dipakai buat apa: harian, kantor, formal, malam, atau hadiah?'); if (!c.scent) q.push('Aroma yang disukai apa: fresh, manis, woody, floral, soft, atau strong?'); if (!c.gender) q.push('Untuk pria, wanita, atau unisex?'); if (!c.budget) q.push('Budget kira-kira berapa?'); return q; }
function infoReply(c, questions) { const known = []; if (c.usage) known.push('kebutuhan: ' + c.usage); if (c.scent) known.push('aroma: ' + c.scent); if (c.gender) known.push('untuk: ' + c.gender); if (c.budget) known.push('budget: ' + c.budget); return (known.length ? 'Oke, saya catat ' + known.join(', ') + '. ' : 'Boleh. ') + 'Supaya rekomendasinya tidak asal, jawab dulu ini ya: ' + questions.join(' '); }
function scoreProducts(products, context, n) { const terms = normalize(n).split(' ').filter((t) => t.length > 2); const boosts = [context.usage, context.scent, context.gender].filter(Boolean); const map = { harian:['fresh','clean','soft','citrus','daily','segar'], kantor:['fresh','clean','woody','soft','office','elegan'], formal:['woody','oud','amber','musk','elegan','strong'], hadiah:['best seller','unisex','fresh','sweet','soft'], fresh:['fresh','citrus','aquatic','clean','segar'], sweet:['sweet','vanilla','fruity','manis'], woody:['woody','oud','amber','musk'], floral:['floral','rose'], pria:['pria','men','masculine','maskulin','woody','fresh'], wanita:['wanita','women','feminim','floral','sweet'], unisex:['unisex','fresh','clean','musk'] }; boosts.slice().forEach((b) => { if (map[b]) boosts.push(...map[b]); }); return products.map((p) => { const hay = normalize([p.id,p.title,p.name,p.category,p.desc,p.description,p.longDesc,p.notes,p.status].join(' ')); let score = 0; terms.forEach((t) => { if (hay.includes(t)) score += 4; if (normalize(p.title || p.name).includes(t)) score += 6; }); boosts.forEach((b) => { if (hay.includes(normalize(b))) score += 7; }); if (p.isTopSeller) score += 8; if (isSold(p)) score -= 100; return { product:p, score }; }).filter((x) => x.score > 0 && !isSold(x.product)).sort((a,b) => b.score - a.score); }
function isSold(p) { return /\b(sold|sold out|kosong|habis|not ready|tidak menjual)\b/.test(normalize(p && p.status)); }
function publicProducts(list) { return list.slice(0, 4).map((p) => ({ id:p.id, title:p.title || p.name || 'Produk Dirac', name:p.name || p.title || 'Produk Dirac', price:Number(p.price || 0), img:p.img || p.image || '', category:p.category || '', status:p.status || 'ready', notes:p.notes || '', desc:p.desc || p.description || '' })); }
function productReply(list, c) { const names = list.slice(0,3).map((p) => p.title || p.name || 'Produk Dirac').join(', '); return names ? 'Saya pilihkan ' + names + '. Silakan lihat kartu produk di bawah ini dan cek detail sebelum checkout.' : 'Saya belum menemukan produk yang cocok. Coba sebutkan aroma, penggunaan, gender, dan budget lebih detail.'; }
function shouldUseSearch(n, intent) { return intent.name === 'general' && /\b(siapa|apa|kapan|dimana|berapa|berita|terbaru|sekarang|saat ini|hari ini|current|presiden|menteri|ceo|harga|jadwal)\b/.test(n); }
function buildPrompt({ message, history, cart, intent, context, products }) { const date = new Date().toISOString().slice(0,10); const hist = history.map((h) => (h && h.role === 'assistant' ? 'AI' : 'User') + ': ' + String(h && h.content || '').slice(0,500)).join('\n') || '-'; const productText = products.length ? products.map((p,i) => [String(i+1)+'. '+(p.title||p.name||'Produk Dirac'), 'Kategori: '+(p.category||'-'), 'Harga: Rp'+Number(p.price||0).toLocaleString('id-ID'), 'Status: '+(p.status||'ready'), 'Notes: '+(p.notes||'-'), 'Deskripsi: '+(p.desc||p.description||'-')].join(' | ')).join('\n') : ''; const cartText = cart && cart.length ? cart.map((x) => '- '+(x.title||x.name||'Produk')+' x'+(x.qty||1)).join('\n') : 'Keranjang kosong.'; let sys = 'Kamu adalah Dirac AI Assistant. Jawab bahasa Indonesia yang natural, ramah, jelas, dan akurat.'; if (intent.name === 'general') sys += ' Kamu bisa diajak ngobrol seperti AI biasa. Jangan menawarkan produk atau checkout kecuali diminta. Tanggal sistem: '+date+'. Untuk Presiden Indonesia saat ini: Prabowo Subianto.'; else if (intent.name === 'recommendation_ready' || intent.name === 'product_search') sys += ' Kamu adalah konsultan parfum. Gunakan hanya data produk yang diberikan, hindari sold/kosong/not ready, rekomendasikan maksimal 3 produk, jangan mengarang harga/stok.'; else sys += ' Gali kebutuhan user pelan-pelan dan jangan langsung jualan jika belum jelas.'; return [sys, 'Intent: '+intent.name, 'Konteks: '+JSON.stringify(context), 'Riwayat:\n'+hist, productText ? 'Data produk relevan:\n'+productText : '', productText ? 'Keranjang:\n'+cartText : '', 'Pertanyaan user:\n'+message].filter(Boolean).join('\n\n'); }
function hasGemini() { return keys('GEMINI_API_KEYS','GEMINI_API_KEY').length > 0; } function hasGroq() { return keys('GROQ_API_KEYS','GROQ_API_KEY').length > 0; } function hasOpenAI() { return keys('OPENAI_API_KEYS','OPENAI_API_KEY').length > 0; } function hasAnyProvider() { return hasGemini() || hasGroq() || hasOpenAI(); }
function keys(listName, oneName) { const out = []; if (process.env[listName]) out.push(...process.env[listName].split(',').map((x) => x.trim()).filter(Boolean)); if (process.env[oneName]) out.push(process.env[oneName]); for (let i=1;i<=5;i++) if (process.env[oneName+'_'+i]) out.push(process.env[oneName+'_'+i]); return Array.from(new Set(out)); }
async function callAI({ prompt, general, search }) { const attempts = []; let first = null; for (const key of keys('GEMINI_API_KEYS','GEMINI_API_KEY')) { for (const model of Array.from(new Set([process.env.GEMINI_MODEL || 'gemini-2.5-flash','gemini-2.5-flash','gemini-2.0-flash','gemini-1.5-flash']))) { for (const useSearch of (search && !model.includes('1.5') ? [true,false] : [false])) { try { first = first || 'gemini'; const text = await gemini(key, model, prompt, general, useSearch); return { provider:'gemini:'+model, text, attempts, failoverUsed: first !== 'gemini' || attempts.length>0 }; } catch(e) { attempts.push({provider:'gemini',model,status:e.status||0,message:safeError(e)}); if (!failover(e.status||500)) break; } } } } for (const key of keys('GROQ_API_KEYS','GROQ_API_KEY')) { for (const model of Array.from(new Set([process.env.GROQ_MODEL || 'llama-3.1-8b-instant','llama-3.1-8b-instant','llama-3.3-70b-versatile']))) { try { first = first || 'groq'; const text = await groq(key, model, prompt, general); return { provider:'groq:'+model, text, attempts, failoverUsed: first !== 'groq' || attempts.length>0 }; } catch(e) { attempts.push({provider:'groq',model,status:e.status||0,message:safeError(e)}); if (!failover(e.status||500)) break; } } } for (const key of keys('OPENAI_API_KEYS','OPENAI_API_KEY')) { for (const model of Array.from(new Set([process.env.OPENAI_MODEL || 'gpt-4o-mini','gpt-4o-mini']))) { try { first = first || 'openai'; const text = await openai(key, model, prompt, general); return { provider:'openai:'+model, text, attempts, failoverUsed: first !== 'openai' || attempts.length>0 }; } catch(e) { attempts.push({provider:'openai',model,status:e.status||0,message:safeError(e)}); if (!failover(e.status||500)) break; } } } throw new Error(attempts.map((a)=>a.provider+':'+a.status+':'+a.message).slice(-6).join(' | ') || 'No AI provider configured'); }
function failover(status) { return status === 0 || status === 408 || status === 409 || status === 425 || status === 429 || status >= 500; }
async function gemini(key, model, prompt, general, useSearch) { const body = { contents:[{role:'user',parts:[{text:prompt}]}], generationConfig:{temperature:general?0.55:0.35,topP:0.9,maxOutputTokens:general?850:950} }; if (useSearch) body.tools = [{ google_search:{} }]; const r = await fetchTimeout('https://generativelanguage.googleapis.com/v1beta/models/'+encodeURIComponent(model)+':generateContent?key='+encodeURIComponent(key), {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); const d = await safeJson(r); if (!r.ok) { const e = new Error(d && d.error && d.error.message || 'Gemini API error '+r.status); e.status = r.status; throw e; } const text = d && d.candidates && d.candidates[0] && d.candidates[0].content && Array.isArray(d.candidates[0].content.parts) ? d.candidates[0].content.parts.map((p)=>p.text||'').join('').trim() : ''; if (!text) { const e = new Error('Gemini response empty'); e.status = 502; throw e; } return text; }
async function groq(key, model, prompt, general) { const r = await fetchTimeout('https://api.groq.com/openai/v1/chat/completions', {method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},body:JSON.stringify({model,messages:[{role:'system',content:'Kamu adalah Dirac AI Assistant. Jawab bahasa Indonesia natural dan jangan menawarkan produk kecuali user membahas produk/parfum.'},{role:'user',content:prompt}],temperature:general?0.55:0.35,max_tokens:general?850:950})}); const d = await safeJson(r); if(!r.ok){ const e=new Error(d&&d.error&&d.error.message||'Groq API error '+r.status); e.status=r.status; throw e; } const text = d&&d.choices&&d.choices[0]&&d.choices[0].message ? String(d.choices[0].message.content||'').trim() : ''; if(!text){ const e=new Error('Groq response empty'); e.status=502; throw e; } return text; }
async function openai(key, model, prompt, general) { const r = await fetchTimeout('https://api.openai.com/v1/chat/completions', {method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},body:JSON.stringify({model,messages:[{role:'system',content:'Kamu adalah Dirac AI Assistant. Jawab bahasa Indonesia natural dan jangan menawarkan produk kecuali user membahas produk/parfum.'},{role:'user',content:prompt}],temperature:general?0.55:0.35,max_tokens:general?850:950})}); const d = await safeJson(r); if(!r.ok){ const e=new Error(d&&d.error&&d.error.message||'OpenAI API error '+r.status); e.status=r.status; throw e; } const text = d&&d.choices&&d.choices[0]&&d.choices[0].message ? String(d.choices[0].message.content||'').trim() : ''; if(!text){ const e=new Error('OpenAI response empty'); e.status=502; throw e; } return text; }
async function fetchTimeout(url, options) { const c = new AbortController(); const t = setTimeout(()=>c.abort(), DEFAULT_TIMEOUT); try { return await fetch(url, {...options, signal:c.signal}); } finally { clearTimeout(t); } }
async function safeJson(r) { try { return await r.json(); } catch (_) { return {}; } }
