module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      mode: 'error',
      showProducts: false,
      products: [],
      links: [],
      reply: 'Method tidak diizinkan.'
    });
  }

  try {
    const body = req.body || {};
    const message = String(body.message || '').trim();
    const products = Array.isArray(body.products) ? body.products.slice(0, 100) : [];
    const cart = Array.isArray(body.cart) ? body.cart.slice(0, 30) : [];
    const history = Array.isArray(body.history) ? body.history.slice(-12) : [];

    if (!message) {
      return res.status(400).json({
        mode: 'error',
        showProducts: false,
        products: [],
        links: [],
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
    const normalizedHistory = normalize(history.map((item) => item.content || '').join(' '));

    const json = (status, payload) => {
      return res.status(status).json({
        mode: 'conversation',
        showProducts: false,
        products: [],
        links: [],
        ...payload
      });
    };

    const isGreetingOnly =
      /^(halo|hallo|helo|hello|hai|hi|hii|hiii|hlo|hllo|lo|yo|yoi|p|pp|test|tes|permisi|salam|assalamualaikum|assalamu alaikum|pagi|siang|sore|malam|selamat pagi|selamat siang|selamat sore|selamat malam)$/.test(normalizedMessage);

    const isThanksOnly =
      /^(makasih|terima kasih|terimakasih|thanks|thank you|thx|sip|oke|ok|okay|baik|mantap|siap|noted|gas|nice|wah keren|keren)$/.test(normalizedMessage);

    const isIdentityQuestion =
      /^(siapa kamu|kamu siapa|ini siapa|ini ai apa|kamu bot|kamu robot|kamu bisa apa|bisa apa|fitur kamu apa|jelaskan dirimu|tolong jelaskan dirimu)$/.test(normalizedMessage);

    const isSmallTalkOnly =
      /^(apa kabar|gimana kabarnya|kamu apa kabar|lagi apa|sedang apa|hai apa kabar|halo apa kabar|hlo apa kabar)$/.test(normalizedMessage);

    const hasInsultOnly =
      /^(goblok+|goblog+|tolol+|bodoh+|bego+|anjing+|bangsat+|kampret+|kontol+|memek+|goblokx+|tololx+|bodohx+|begox+)$/i.test(normalizedMessage);

    const hasWebsiteIntent =
      /\b(website|web|situs|link|company profile|profil perusahaan|profile perusahaan|company|diracgroup store|dirac group store|alamat web|alamat website)\b/.test(normalizedMessage);

    const hasTrackingIntent =
      /\b(resi|cek resi|lacak|tracking|paket|pengiriman|kurir|jne|jnt|j t|sicepat|anteraja|pos|ninja|lion|sap|id express|tiki)\b/.test(normalizedMessage);

    const hasCartIntent =
      /\b(keranjang|cart|checkout|check out|beli|order|pesan|bayar|whatsapp|wa|tambah ke keranjang|cara beli|mau beli)\b/.test(normalizedMessage);

    const recommendationWords =
      /\b(rekomendasi|rekomendasikan|saran|sarankan|pilihkan|pilih|cocok|suggest|recommend)\b/.test(normalizedMessage);

    const productWords =
      /\b(produk|parfum|perfume|wangi|aroma|botol|ml|stok|ready|harga|budget|mahal|murah)\b/.test(normalizedMessage);

    const useWords =
      /\b(harian|sehari hari|daily|kantor|kerja|formal|acara|pesta|date|kencan|malam|siang|outdoor|indoor|kuliah|sekolah|hadiah|kado)\b/.test(normalizedMessage);

    const scentWords =
      /\b(fresh|segar|manis|sweet|soft|lembut|strong|kuat|tahan lama|maskulin|feminim|elegan|sporty|dingin|citrus|woody|vanilla|amber|musk|oud|rose|floral|buah|fruity|aquatic|spicy)\b/.test(normalizedMessage);

    const genderWords =
      /\b(pria|laki|lelaki|cowok|cowo|wanita|perempuan|cewek|cewe|unisex|suami|istri|pacar|teman)\b/.test(normalizedMessage);

    const budgetWords =
      /\b(\d+\s*(rb|ribu|jt|juta)|rp|harga|budget|maksimal|max|dibawah|di bawah|sekitar|murah|mahal)\b/.test(normalizedMessage);

    const asksIndonesiaPresident =
      /\b(presiden indonesia|presiden ri|presiden republik indonesia)\b/.test(normalizedMessage);

    const asksCurrent =
      /\b(sekarang|saat ini|current|terbaru|hari ini|2024|2025|2026)\b/.test(normalizedMessage);

    const hasProductIntent = productWords || recommendationWords;

    const hasRecommendationContext =
      recommendationWords ||
      /\b(rekomendasi|rekomendasikan|saran|sarankan|parfum buat apa|parfumnya mau buat apa|aroma apa|budget berapa|mau dipakai buat apa|dipakai buat apa)\b/.test(normalizedHistory);

    const recommendationSignalCount = [
      useWords,
      scentWords,
      genderWords,
      budgetWords
    ].filter(Boolean).length;

    if (isGreetingOnly) {
      return json(200, {
        mode: 'conversation',
        reply: 'Halo! Saya Dirac AI Assistant. Mau ngobrol dulu atau butuh bantuan seputar parfum, checkout, website, dan cek resi?'
      });
    }

    if (isThanksOnly) {
      return json(200, {
        mode: 'conversation',
        reply: 'Sama-sama. Kalau nanti butuh bantuan lagi, tinggal chat saja ya.'
      });
    }

    if (hasInsultOnly) {
      return json(200, {
        mode: 'conversation',
        reply: 'Saya paham Anda lagi kesal. Saya akan bantu jawab lebih tepat. Coba tulis pertanyaannya lagi dengan jelas, nanti saya jawab langsung.'
      });
    }

    if (isIdentityQuestion) {
      return json(200, {
        mode: 'conversation',
        reply: 'Saya Dirac AI Assistant. Saya bisa diajak ngobrol seperti AI biasa, bantu jawab pertanyaan umum, bantu pilih parfum pelan-pelan, arahkan checkout, beri link website, dan arahkan cek resi.'
      });
    }

    if (isSmallTalkOnly) {
      return json(200, {
        mode: 'conversation',
        reply: 'Kabar saya baik. Anda sendiri bagaimana? Kita bisa ngobrol dulu, tidak harus langsung bahas produk.'
      });
    }

    if (asksIndonesiaPresident) {
      return json(200, {
        mode: 'conversation',
        reply: 'Presiden Indonesia saat ini adalah Prabowo Subianto. Wakil presidennya adalah Gibran Rakabuming Raka. Mereka menjabat untuk periode 2024-2029.'
      });
    }

    if (hasWebsiteIntent && !hasProductIntent && !hasTrackingIntent && !hasCartIntent) {
      return json(200, {
        mode: 'link',
        links: [
          {
            label: 'Buka website Dirac Group',
            url: 'https://diracgroup.store'
          }
        ],
        reply: 'Website resmi Dirac Group ada di sini:\nhttps://diracgroup.store'
      });
    }

    if (hasTrackingIntent) {
      return json(200, {
        mode: 'link',
        links: [
          {
            label: 'Buka Cek Resi',
            url: 'https://diracgroup.store/cekresi.html'
          }
        ],
        reply: 'Untuk cek resi, buka halaman Cek Resi Dirac Group lalu masukkan nomor resi dan pilih kurir:\nhttps://diracgroup.store/cekresi.html'
      });
    }

    if (
      recommendationWords &&
      /\b(parfum|perfume|wangi|aroma)\b/.test(normalizedMessage) &&
      recommendationSignalCount === 0
    ) {
      return json(200, {
        mode: 'conversation',
        reply: 'Boleh. Parfumnya mau buat apa dulu? Misalnya untuk harian, kerja/kantor, acara formal, hadiah, atau dipakai malam. Anda juga bisa sebut suka aroma fresh, manis, soft, strong, pria/wanita/unisex, dan budgetnya.'
      });
    }

    const isAskingRecommendation =
      hasRecommendationContext &&
      (
        recommendationWords ||
        productWords ||
        useWords ||
        scentWords ||
        genderWords ||
        budgetWords
      );

    if (
      isAskingRecommendation &&
      recommendationSignalCount > 0 &&
      recommendationSignalCount < 3
    ) {
      const missing = [];

      if (!useWords) missing.push('dipakai buat apa');
      if (!scentWords) missing.push('suka aroma apa');
      if (!genderWords) missing.push('untuk pria, wanita, atau unisex');
      if (!budgetWords) missing.push('budget berapa');

      return json(200, {
        mode: 'conversation',
        reply: `Oke, saya catat. Supaya rekomendasinya tidak asal, boleh tambah info ${missing.slice(0, 3).join(', ')}? Setelah itu baru saya pilihkan yang paling cocok.`
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return json(200, {
        mode: 'conversation',
        reply: 'Saya bisa bantu ngobrol dasar, tetapi jawaban AI pintar belum aktif karena GEMINI_API_KEY belum disetel di Vercel Environment Variables.'
      });
    }

    const isGeneralConversation =
      !hasProductIntent &&
      !hasTrackingIntent &&
      !hasCartIntent &&
      !hasWebsiteIntent;

    const shouldUseProductData =
      hasProductIntent &&
      recommendationSignalCount >= 3;

    const shouldUseGoogleSearch =
      isGeneralConversation &&
      (
        asksCurrent ||
        /\b(siapa|apa|kapan|dimana|berapa|berita|terbaru|sekarang|saat ini)\b/.test(normalizedMessage)
      );

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
Kamu adalah Dirac AI Assistant, tetapi kamu juga harus bisa diajak ngobrol seperti AI biasa.
Jawab pertanyaan umum user secara langsung, natural, dan ramah.
Jangan menawarkan produk.
Jangan merekomendasikan parfum.
Jangan menampilkan daftar produk.
Jangan mengarahkan checkout kecuali user memintanya.
Jika user bertanya informasi yang bisa berubah seperti pejabat, presiden, harga, jadwal, atau berita terbaru, gunakan informasi terbaru jika tersedia dan jangan memakai data lama.
Untuk pertanyaan presiden Indonesia, jawaban yang benar adalah Prabowo Subianto, bukan Joko Widodo.
Gunakan bahasa Indonesia yang jelas, santai, dan tidak terlalu panjang.
`.trim();
    } else if (hasCartIntent && !hasProductIntent) {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website Dirac Group.
User menanyakan cara beli, checkout, keranjang, atau WhatsApp.
Bantu arahkan user memakai tombol keranjang dan checkout WhatsApp di website.
Jangan merekomendasikan produk kecuali user meminta rekomendasi produk.
Jawab singkat, jelas, dan ramah.
`.trim();
    } else if (shouldUseProductData) {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk katalog parfum Dirac Group.
User sudah memberi kebutuhan parfum cukup jelas, jadi boleh bantu memilih berdasarkan data produk.
Gunakan hanya data produk yang diberikan.
Jangan mengarang stok, harga, atau produk di luar data.
Rekomendasikan maksimal 3 produk yang paling relevan.
Sebutkan alasan singkat, aroma/kegunaan yang cocok, dan harga jika tersedia.
Jangan pakai markdown tabel panjang.
Jawab natural dalam bahasa Indonesia.
`.trim();
    } else {
      systemPrompt = `
Kamu adalah Dirac AI Assistant untuk website Dirac Group.
Ngobrol dulu dan gali kebutuhan user secara natural.
Jangan langsung menawarkan produk jika kebutuhan belum jelas.
Jika user membahas parfum tapi belum detail, tanya dulu parfum untuk apa, suka aroma apa, untuk siapa, dan budget berapa.
Jawab singkat, ramah, dan natural.
`.trim();
    }

    const promptParts = [
      systemPrompt,
      '',
      `Riwayat singkat:\n${historyText || '-'}`,
      '',
      shouldUseProductData ? `Data produk:\n${productText || 'Data produk tidak tersedia.'}` : '',
      shouldUseProductData ? `Keranjang:\n${cartText}` : '',
      '',
      `Pertanyaan user:\n${message}`
    ].filter(Boolean);

    const userPrompt = promptParts.join('\n').trim();

    const preferredModel = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    const modelCandidates = Array.from(new Set([
      preferredModel,
      'gemini-2.5-flash',
      'gemini-2.0-flash',
      'gemini-1.5-flash'
    ]));

    let lastError = null;
    let reply = '';

    for (const model of modelCandidates) {
      const attempts = shouldUseGoogleSearch && !model.includes('1.5')
        ? [{ useSearch: true }, { useSearch: false }]
        : [{ useSearch: false }];

      for (const attempt of attempts) {
        const geminiUrl =
          `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

        const requestBody = {
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
            temperature: isGeneralConversation ? 0.55 : 0.38,
            topP: 0.9,
            maxOutputTokens: isGeneralConversation ? 700 : 900
          }
        };

        if (attempt.useSearch) {
          requestBody.tools = [
            {
              google_search: {}
            }
          ];
        }

        const geminiResponse = await fetch(geminiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        });

        const data = await geminiResponse.json().catch(() => ({}));

        if (!geminiResponse.ok) {
          lastError = data?.error?.message || `Gemini API error ${geminiResponse.status}`;
          continue;
        }

        reply = data?.candidates?.[0]?.content?.parts
          ?.map((part) => part.text || '')
          .join('')
          .trim();

        if (reply) break;

        lastError = 'Gemini response empty';
      }

      if (reply) break;
    }

    if (!reply) {
      return json(502, {
        mode: 'error',
        reply: 'AI sedang gagal dipanggil dari server. Periksa GEMINI_API_KEY, GEMINI_MODEL, dan log Vercel.',
        detail: lastError || 'Unknown Gemini API error'
      });
    }

    return json(200, {
      mode: shouldUseProductData ? 'commerce' : 'conversation',
      reply
    });
  } catch (error) {
    return res.status(500).json({
      mode: 'error',
      showProducts: false,
      products: [],
      links: [],
      reply: 'Terjadi kendala pada server AI. Silakan coba lagi.',
      detail: error?.message || String(error)
    });
  }
};
