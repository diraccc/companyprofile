module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({
      mode: 'error',
      showProducts: false,
      products: [],
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
        mode: 'error',
        showProducts: false,
        products: [],
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

    const isGreetingOnly = /^(halo|hallo|helo|hello|hai|hi|hii|hiii|hlo|hllo|lo|yo|yoi|p|pp|test|tes|permisi|salam|assalamualaikum|assalamu alaikum|pagi|siang|sore|malam|selamat pagi|selamat siang|selamat sore|selamat malam)$/.test(normalizedMessage);

    const isThanksOnly = /^(makasih|terima kasih|thanks|thank you|thx|sip|oke|ok|okay|baik|mantap|siap|noted|gas|nice|wah keren)$/.test(normalizedMessage);

    const isIdentityQuestion = /^(siapa kamu|kamu siapa|ini siapa|ini ai apa|kamu bot|kamu robot|kamu bisa apa|bisa apa|fitur kamu apa|jelaskan dirimu|tolong jelaskan dirimu)$/.test(normalizedMessage);

    const isSmallTalkOnly = /^(apa kabar|gimana kabarnya|kamu apa kabar|lagi apa|sedang apa|hai apa kabar|halo apa kabar|hlo apa kabar)$/.test(normalizedMessage);

    const hasTrackingIntent = /\b(resi|cek resi|lacak|tracking|paket|pengiriman|kurir|jne|jnt|j t|sicepat|anteraja|pos|ninja|lion|sap|id express|tiki)\b/.test(normalizedMessage);

    const hasCartIntent = /\b(keranjang|cart|checkout|check out|beli|order|pesan|bayar|whatsapp|wa|tambah ke keranjang|cara beli|mau beli)\b/.test(normalizedMessage);

    const recommendationWords = /\b(rekomendasi|rekomendasikan|saran|sarankan|pilihkan|pilih|cocok|suggest|recommend)\b/.test(normalizedMessage);

    const productWords = /\b(produk|parfum|perfume|wangi|aroma|botol|ml|stok|ready|harga|budget|mahal|murah)\b/.test(normalizedMessage);

    const specificUseWords = /\b(harian|sehari hari|kantor|kerja|formal|acara|pesta|date|kencan|malam|siang|outdoor|indoor|kuliah|sekolah|hadiah|kado|pria|wanita|cowok|cewek|unisex|suami|istri|pacar|teman|fresh|manis|soft|strong|tahan lama|maskulin|feminim|elegan|sporty|dingin|citrus|woody|vanilla|amber|musk|oud|rose|floral)\b/.test(normalizedMessage);

    const hasBudgetOrPrice = /\b(\d+\s*(rb|ribu|jt|juta)|rp|harga|budget|maksimal|max|dibawah|di bawah|sekitar|murah|mahal)\b/.test(normalizedMessage);

    const hasProductIntent = productWords || recommendationWords;

    const isBroadRecommendationRequest =
      recommendationWords &&
      /\b(parfum|perfume|wangi|aroma)\b/.test(normalizedMessage) &&
      !specificUseWords &&
      !hasBudgetOrPrice;

    const isGeneralConversation =
      !hasProductIntent &&
      !hasTrackingIntent &&
      !hasCartIntent;

    if (isGreetingOnly) {
      return res.status(200).json({
        mode: 'conversation',
        showProducts: false,
        products: [],
        reply: 'Halo! Saya Dirac AI Assistant. Mau ngobrol dulu atau butuh bantuan seputar parfum, checkout, dan cek resi?'
      });
    }

    if (isThanksOnly) {
      return res.status(200).json({
        mode: 'conversation',
        showProducts: false,
        products: [],
        reply: 'Sama-sama. Kalau nanti butuh bantuan lagi, tinggal chat saja ya.'
      });
    }

    if (isIdentityQuestion) {
      return res.status(200).json({
        mode: 'conversation',
        showProducts: false,
        products: [],
        reply: 'Saya Dirac AI Assistant. Saya bisa diajak ngobrol biasa, bantu jelaskan produk, bantu pilih parfum, bantu arahkan checkout, dan arahkan cek resi.'
      });
    }

    if (isSmallTalkOnly) {
      return res.status(200).json({
        mode: 'conversation',
        showProducts: false,
        products: [],
        reply: 'Kabar saya baik. Anda sendiri bagaimana? Kalau mau, kita bisa ngobrol dulu atau saya bantu pilih parfum yang cocok.'
      });
    }

    if (isBroadRecommendationRequest) {
      return res.status(200).json({
        mode: 'conversation',
        showProducts: false,
        products: [],
        reply: 'Boleh. Parfumnya mau dipakai buat apa dulu? Untuk harian, kerja/kantor, acara formal, hadiah, atau malam? Anda lebih suka aroma fresh, manis, soft, strong, pria, wanita, atau unisex? Budget-nya juga boleh disebutkan.'
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      if (isGeneralConversation) {
        return res.status(200).json({
          mode: 'conversation',
          showProducts: false,
          products: [],
          reply: 'Saya bisa bantu ngobrol dasar. Untuk jawaban AI yang lebih pintar, GEMINI_API_KEY perlu disetel di Vercel Environment Variables.'
        });
      }

      return res.status(500).json({
        mode: 'error',
        showProducts: false,
        products: [],
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
      ? cart.map((item) => `- ${item.title || item.name || 'Produk'} x${item.qty || 1}`).join('\n')
      : 'Keranjang kosong atau tidak dikirim.';

    const historyText = history.map((item) => {
      const role = item.role === 'assistant' ? 'AI' : 'User';
      return `${role}: ${String(item.content || '').slice(0, 500)}`;
    }).join('\n');

    let systemPrompt = '';

    if (isGeneralConversation) {
      systemPrompt = `
Kamu adalah Dirac AI Assistant.
Jawab seperti AI biasa yang ramah, natural, dan bisa diajak ngobrol.
Jawab pertanyaan umum user secara langsung jika kamu tahu.
Jangan menawarkan produk.
Jangan merekomendasikan parfum.
Jangan menampilkan daftar produk.
Jangan menyebut keranjang, checkout, atau cek resi kecuali user menanyakannya.
Gunakan bahasa Indonesia yang jelas dan tidak terlalu panjang.
`.trim();
    } else if (hasTrackingIntent) {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website Dirac Group.
User menanyakan cek resi, paket, kurir, atau pengiriman.
Arahkan user ke halaman cek resi: https://diracgroup.store/cekresi.html
Jangan merekomendasikan produk kecuali user juga meminta produk.
Jawab singkat dan jelas.
`.trim();
    } else if (hasCartIntent && !hasProductIntent) {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website Dirac Group.
User menanyakan cara beli, checkout, keranjang, atau WhatsApp.
Bantu arahkan user memakai tombol keranjang dan checkout WhatsApp di website.
Jangan merekomendasikan produk kecuali user meminta rekomendasi produk.
Jawab singkat, jelas, dan ramah.
`.trim();
    } else {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website katalog parfum Dirac Group.
Jangan langsung menawarkan produk jika kebutuhan user masih terlalu umum.
Kalau user minta rekomendasi tetapi belum jelas kebutuhannya, tanya dulu: parfum untuk apa, suka aroma apa, pria/wanita/unisex, dan budget berapa.
Kalau user sudah menyebut kebutuhan cukup jelas, baru rekomendasikan produk berdasarkan data produk.
Gunakan hanya data produk yang diberikan. Jangan mengarang stok, harga, atau produk di luar data.
Jika merekomendasikan produk, sebutkan nama produk, karakter aroma, harga jika tersedia, dan alasan singkat.
Jangan menampilkan markdown tabel panjang.
Jawab dalam bahasa Indonesia yang ramah dan natural.
`.trim();
    }

    const promptParts = [
      systemPrompt,
      '',
      `Riwayat singkat:\n${historyText || '-'}`,
      '',
      isGeneralConversation ? '' : `Data produk:\n${productText || 'Data produk tidak tersedia.'}`,
      '',
      isGeneralConversation ? '' : `Keranjang:\n${cartText}`,
      '',
      `Pertanyaan user:\n${message}`
    ].filter(Boolean);

    const userPrompt = promptParts.join('\n').trim();

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
          temperature: isGeneralConversation ? 0.6 : 0.35,
          topP: 0.9,
          maxOutputTokens: isGeneralConversation ? 650 : 900
        }
      })
    });

    const data = await geminiResponse.json();

    if (!geminiResponse.ok) {
      return res.status(geminiResponse.status).json({
        mode: 'error',
        showProducts: false,
        products: [],
        reply: 'AI sedang gagal dipanggil dari server. Periksa GEMINI_API_KEY, GEMINI_MODEL, dan log Vercel.',
        detail: data?.error?.message || 'Unknown Gemini API error'
      });
    }

    const reply = data?.candidates?.[0]?.content?.parts
      ?.map((part) => part.text || '')
      .join('')
      .trim();

    return res.status(200).json({
      mode: isGeneralConversation ? 'conversation' : 'commerce',
      showProducts: false,
      products: [],
      reply: reply || 'Maaf, AI belum menghasilkan jawaban. Silakan coba pertanyaan lain.'
    });

  } catch (error) {
    return res.status(500).json({
      mode: 'error',
      showProducts: false,
      products: [],
      reply: 'Terjadi kendala pada server AI. Silakan coba lagi.',
      detail: error?.message || String(error)
    });
  }
};
