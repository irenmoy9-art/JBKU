JB KU — PAKET PWA / ANDROID

ISI FOLDER
- index.html            Aplikasi web asli, sudah ditambahkan metadata PWA.
- manifest.json         Nama aplikasi, ikon, warna, mode layar penuh.
- service-worker.js     Cache dasar untuk membuka shell aplikasi saat offline.
- icons/                Ikon aplikasi 192/512 px, maskable, dan Apple Touch Icon.

CARA MENJALANKAN SEBAGAI PWA
1. Upload seluruh isi folder ini ke hosting HTTPS (contoh: domain/hosting sendiri).
2. Pastikan index.html, manifest.json, service-worker.js, dan folder icons berada
   pada folder/path yang sama.
3. Buka URL HTTPS tersebut di Chrome Android.
4. Pilih menu Chrome > Install app / Tambahkan ke layar utama.

CARA MEMBUAT APK
Manifest PWA bukan file APK dan tidak dapat mengompilasi APK sendirian.
Cara praktis:
1. Deploy folder ini ke URL HTTPS milik Anda.
2. Buka https://www.pwabuilder.com/ lalu masukkan URL aplikasi.
3. Ikuti pemeriksaan PWA dan pilih paket Android.
4. Unduh proyek/paket Android yang dihasilkan dan ikuti instruksi penandatanganan
   (signing) untuk membuat APK/AAB.

Alternatif developer: gunakan Bubblewrap (Trusted Web Activity) dengan URL HTTPS
dan Digital Asset Links pada domain. APK final tetap perlu dibangun dan ditandatangani.

CATATAN PENTING
- Aplikasi ini memakai layanan Supabase eksternal, sehingga fitur data/login tetap
  memerlukan koneksi internet dan layanan backend tersebut.
- Cache offline yang disediakan hanya untuk kerangka aplikasi dan ikon; data
  Supabase tidak disimpan offline.
- Ikon diambil dari gambar logo yang Anda unggah.
- Sebelum dipublikasikan, uji semua fitur pada URL HTTPS dan pastikan domain/backend
  yang dipakai memang milik/diizinkan untuk Anda.
