module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      reply: 'Method tidak diizinkan.'
    });
  }

  try {
    const body = req.body || {};
    const message = String(body.message || '').trim();
    const products = Array.isArray(body.products) ? body.products.slice(0, 80) : [];
    const cart = Array.isArray(body.cart) ? body.cart.slice(0, 30) : [];
    const history = Array.isArray(body.history) ? body.history.slice(-8) : [];

    if (!message) {
      return res.status(400).json({
        reply: 'Pertanyaan masih kosong.'
      });
    }

    const normalize = (value) => String(value || '')
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const normalizedMessage = normalize(message);

    const isVeryShortGreeting = /^(halo|hallo|helo|hello|hai|hi|hii|hiii|hlo|hllo|lo|yo|yoi|p|pp|test|tes|permisi|pagi|siang|sore|malam|assalamualaikum|assalamu alaikum|salam)$/.test(normalizedMessage);

    const isThanksOnly = /^(makasih|terima kasih|thanks|thank you|thx|sip|oke|ok|okay|baik|mantap|siap|noted|gas)$/.test(normalizedMessage);

    const isSmallTalkOnly = /^(apa kabar|gimana kabarnya|kamu apa kabar|lagi apa|siapa kamu|kamu siapa|ini apa|bisa apa|kamu bisa apa|fitur kamu apa|tolong jelaskan dirimu)$/.test(normalizedMessage);

    const hasTrackingIntent = /\b(resi|cek resi|lacak|tracking|paket|pengiriman|kurir|jne|jnt|sicepat|anteraja|pos|ninja|lion|sap)\b/.test(normalizedMessage);

    const hasCartIntent = /\b(keranjang|cart|checkout|beli|order|pesan|bayar|whatsapp|wa|tambah ke keranjang)\b/.test(normalizedMessage);

    const hasProductIntent = /\b(produk|parfum|perfume|rekomendasi|rekomendasikan|saran|carikan|cari|wangi|aroma|fresh|manis|formal|maskulin|feminim|unisex|hadiah|kado|best seller|bestseller|terlaris|murah|mahal|harga|budget|stok|ready|ml|botol|premium|pria|wanita|cowok|cewek|harian|kantor|pesta|date|elegan|soft|strong|tahan lama)\b/.test(normalizedMessage);

    const shouldStayConversationOnly =
      !hasProductIntent &&
      !hasTrackingIntent &&
      !hasCartIntent;

    if (isVeryShortGreeting) {
      return res.status(200).json({
        mode: 'conversation',
        reply: 'Halo! Saya Dirac AI Assistant. Ada yang ingin ditanyakan dulu? Saya bisa ngobrol, bantu jelaskan produk, rekomendasi parfum, bantu checkout, atau arahkan cek resi.'
      });
    }

    if (isThanksOnly) {
      return res.status(200).json({
        mode: 'conversation',
        reply: 'Sama-sama. Kalau nanti butuh bantuan cari parfum, cek keranjang, atau cek resi, tinggal tanya saja ya.'
      });
    }

    if (isSmallTalkOnly) {
      return res.status(200).json({
        mode: 'conversation',
        reply: 'Saya Dirac AI Assistant. Saya bisa diajak ngobrol dulu, lalu kalau Anda butuh saya juga bisa bantu cari parfum, rekomendasi aroma, bantu checkout, dan arahkan cek resi.'
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      if (shouldStayConversationOnly) {
        return res.status(200).json({
          mode: 'conversation',
          reply: 'Saya aktif sebagai asisten Dirac. Untuk saat ini saya bisa bantu percakapan dasar. Supaya jawaban AI lebih pintar, GEMINI_API_KEY perlu disetel di Vercel.'
        });
      }

      return res.status(500).json({
        reply: 'AI belum aktif karena GEMINI_API_KEY belum disetel di Vercel Environment Variables.'
      });
    }

    const productText = products.map((p, index) => {
      return [
        `${index + 1}. ${p.title || p.name || 'Produk Dirac'}`,
        `Kategori: ${p.category || '-'}`,
        `Harga: Rp${Number(p.price || 0).toLocaleString('id-ID')}`,
        `Status: ${p.status || 'ready'}`,
        `Notes: ${p.notes || '-'}`,
        `Deskripsi: ${p.desc || p.description || '-'}`
      ].join(' | ');
    }).join('\n');

    const cartText = cart.length
      ? cart.map((item) => {
          return `- ${item.title || item.name || 'Produk'} x${item.qty || 1}`;
        }).join('\n')
      : 'Keranjang kosong atau tidak dikirim.';

    const historyText = history.map((item) => {
      const role = item.role === 'assistant' ? 'AI' : 'User';
      return `${role}: ${String(item.content || '').slice(0, 500)}`;
    }).join('\n');

    let systemPrompt = '';

    if (shouldStayConversationOnly) {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website Dirac Group.
Jawab dalam bahasa Indonesia yang santai, ramah, natural, dan singkat.
User sedang ngobrol biasa, jadi jangan langsung menawarkan produk.
Jangan menampilkan kartu produk.
Jangan membuat daftar rekomendasi produk kecuali user jelas meminta rekomendasi atau mencari produk.
Boleh jelaskan bahwa kamu bisa membantu ngobrol, cari parfum, rekomendasi aroma, bantu checkout, dan arahkan cek resi.
Jika user bertanya di luar parfum, jawab sewajarnya secara singkat dan tetap sopan.
`.trim();
    } else {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website katalog parfum Dirac Group.
Jawab dalam bahasa Indonesia yang ramah, jelas, dan membantu.
Gunakan data produk yang diberikan. Jangan mengarang stok, harga, atau produk di luar data.
Jika user hanya ngobrol atau menyapa, jangan rekomendasikan produk.
Jika user ingin cek resi, arahkan ke halaman https://diracgroup.store/cekresi.html.
Jika user ingin checkout, arahkan untuk memakai keranjang dan tombol checkout WhatsApp di website.
Jika user meminta rekomendasi produk, sebutkan nama produk, karakter aroma, harga jika tersedia, dan alasan singkat.
Jangan menampilkan markdown tabel panjang.
`.trim();
    }

    const userPrompt = `
${systemPrompt}

Riwayat singkat:
${historyText || '-'}

${shouldStayConversationOnly ? '' : `Data produk:\n${productText || 'Data produk tidak tersedia.'}`}

${shouldStayConversationOnly ? '' : `Keranjang:\n${cartText}`}

Pertanyaan user:
${message}
`.trim();

    const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';

    const geminiUrl =
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

    const geminiResponse = await fetch(geminiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        contents: [
          {
            role: 'user',
            parts: [
              {
                text: userPrompt
              }
            ]
          }
        ],
        generationConfig: {
          temperature: shouldStayConversationOnly ? 0.55 : 0.35,
          topP: 0.9,
          maxOutputTokens: shouldStayConversationOnly ? 450 : 900
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
      ?.map((part) => part.text || '')
      .join('')
      .trim();

    return res.status(200).json({
      mode: shouldStayConversationOnly ? 'conversation' : 'commerce',
      reply: reply || 'Maaf, AI belum menghasilkan jawaban. Silakan coba pertanyaan lain.'
    });

  } catch (error) {
    return res.status(500).json({
      reply: 'Terjadi kendala pada server AI. Silakan coba lagi.',
      detail: error?.message || String(error)
    });
  }
};
