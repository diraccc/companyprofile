export default async function handler(req, res) {

  const { kode, nama, produk } = req.body;

  const response = await fetch("https://api.fonnte.com/send", {
    method: "POST",
    headers: {
      "Authorization": process.env.FONNTE_TOKEN,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      target: "6287892523968",
      message:
`Pesanan Baru

Kode: ${kode}
Nama: ${nama}
Produk: ${produk}`
    })
  });

  const data = await response.text();

  res.status(200).json({
    success: true,
    data
  });

}
