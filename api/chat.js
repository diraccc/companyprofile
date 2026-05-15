module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ reply: 'Method tidak diizinkan.' });
  }

  try {
    const body = req.body || {};
    const message = String(body.message || '').trim();
    const products = Array.isArray(body.products) ? body.products.slice(0, 80) : [];
    const cart = Array.isArray(body.cart) ? body.cart.slice(0, 30) : [];
    const history = Array.isArray(body.history) ? body.history.slice(-8) : [];

    if (!message) {
      return res.status(400).json({ reply: 'Pertanyaan masih kosong.' });
    }

    const normalize = (value) => String(value || '')
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const normalizedMessage = normalize(message);
    const isGreetingOnly = /^(halo|hallo|hai|hi|hello|helo|pagi|selamat pagi|siang|selamat siang|sore|selamat sore|malam|selamat malam|permisi|assalamualaikum|test|tes)$/.test(normalizedMessage);

    if (isGreetingOnly) {
      return res.status(200).json({
        reply: 'Halo! Ada yang bisa saya bantu? Saya bisa bantu cari parfum, rekomendasi aroma, cek isi keranjang, atau arahkan cek resi.'
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        reply: 'AI belum aktif karena GEMINI_API_KEY belum disetel di Vercel Environment Variables.'
      });
    }

    const productText = products.map((p, index) => {
      return [
        `${index + 1}. ${p.title || 'Produk Dirac'}`,
        `Kategori: ${p.category || '-'}`,
        `Harga: Rp${Number(p.price || 0).toLocaleString('id-ID')}`,
        `Status: ${p.status || 'ready'}`,
        `Notes: ${p.notes || '-'}`,
        `Deskripsi: ${p.desc || '-'}`
      ].join(' | ');
    }).join('\n');

    const cartText = cart.length
      ? cart.map(item => `- ${item.title || 'Produk'} x${item.qty || 1}`).join('\n')
      : 'Keranjang kosong atau tidak dikirim.';

    const historyText = history.map(item => {
      const role = item.role === 'assistant' ? 'AI' : 'User';
      return `${role}: ${String(item.content || '').slice(0, 500)}`;
    }).join('\n');

    const systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website katalog parfum Dirac Group.
Jawab dalam bahasa Indonesia yang ramah, singkat, jelas, dan membantu penjualan.
Jika user hanya menyapa seperti halo/hai/hello, balas sapaan singkat dan tawarkan bantuan. Jangan langsung rekomendasikan produk untuk sapaan saja.
Gunakan data produk yang diberikan. Jangan mengarang stok, harga, atau produk di luar data.
Jika user ingin cek resi, arahkan ke halaman https://diracgroup.store/cekresi.html.
Jika user ingin checkout, arahkan untuk memakai keranjang dan tombol checkout WhatsApp di website.
Jika merekomendasikan produk, sebutkan nama produk, karakter aroma, harga jika ada, dan alasan singkat.
Jangan menampilkan markdown tabel panjang.
`.trim();

    const userPrompt = `
${systemPrompt}

Riwayat singkat:
${historyText || '-'}

Data produk:
${productText || 'Data produk tidak tersedia.'}

Keranjang:
${cartText}

Pertanyaan user:
${message}
`.trim();

    const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

    const geminiResponse = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          {
            role: 'user',
            parts: [{ text: userPrompt }]
          }
        ],
        generationConfig: {
          temperature: 0.35,
          topP: 0.9,
          maxOutputTokens: 900
        }
      })
    });

    const data = await geminiResponse.json();

    if (!geminiResponse.ok) {
      return res.status(geminiResponse.status).json({
        reply: 'AI sedang gagal dipanggil dari server. Periksa GEMINI_API_KEY, GEMINI_MODEL, dan log Vercel.',
        detail: data?.error?.message || 'Unknown Gemini API error'
      });
    }

    const reply = data?.candidates?.[0]?.content?.parts
      ?.map(part => part.text || '')
      .join('')
      .trim();

    return res.status(200).json({
      reply: reply || 'Maaf, AI belum menghasilkan jawaban. Silakan coba pertanyaan lain.'
    });
  } catch (error) {
    return res.status(500).json({
      reply: 'Terjadi kendala pada server AI. Silakan coba lagi.',
      detail: error?.message || String(error)
    });
  }
};
