# JB KU - folder PWA

Isi folder:
- index.html              : website JB KU (tidak diubah)
- manifest.webmanifest    : nama, warna, ikon aplikasi
- sw.js                   : service worker (offline + klik notifikasi)
- icon-192.png, icon-512.png : ikon yang dipanggil index.html
- icons/                  : semua ukuran ikon (termasuk maskable & apple-touch)
- vercel.json             : header khusus sw.js dan manifest
- .well-known/assetlinks.json : tempat kode verifikasi Android (diisi nanti)

## A. Pasang di GitHub (lewat browser, tanpa install apa pun)
1. Login github.com > klik "+" > "New repository".
2. Nama: jbku-pwa, pilih Private, klik "Create repository".
3. Klik "uploading an existing file".
4. Ekstrak zip, buka foldernya, pilih SEMUA isi (bukan foldernya) lalu seret ke GitHub.
   Pastikan folder "icons" dan ".well-known" ikut. File index.html berukuran 7,7 MB, masih di bawah batas 25 MB upload browser.
5. Klik "Commit changes".

Catatan: file yang diawali titik (.well-known, .gitignore) kadang tersembunyi di HP/PC.
Kalau tidak ikut terupload, buat manual: "Add file" > "Create new file", ketik
.well-known/assetlinks.json, isi: []

## B. Hubungkan ke Vercel
1. vercel.com > Add New > Project > pilih repo jbku-pwa > Import.
2. Framework: Other. Build command dan Output directory dikosongkan. Klik Deploy.
3. Untuk domain .my.id: Project > Settings > Domains > Add, ikuti DNS yang ditampilkan.
4. Setiap kali file di GitHub diubah, Vercel otomatis memperbarui website.
   Kalau tampilan tidak berubah, naikkan angka VERSION di sw.js (jbku-v1 jadi jbku-v2).

## C. Cek PWA sebelum ke PWABuilder
1. Buka website lewat Chrome HP > menu titik tiga > "Instal aplikasi" / "Tambahkan ke layar utama".
2. Di Chrome PC: F12 > Application > Manifest dan Service Workers harus tanpa error.

## D. Buat APK / AAB di PWABuilder
1. Buka pwabuilder.com, tempel alamat website (https://...), klik Start.
2. Tunggu skor. Merah/kuning di Manifest atau Service Worker: klik detailnya.
3. Klik "Package for stores" > Android > Generate.
4. Isi: Package ID (contoh my.id.jbku.app), App name JB KU, Version 1 / 1.0.0, Signing key: "Create new".
5. Download zip hasilnya. SIMPAN file .keystore dan signing-key-info.txt di tempat aman
   (jangan upload ke GitHub). Tanpa keystore, aplikasi tidak bisa diperbarui di Play Store.
6. File .apk bisa langsung dipasang di HP. File .aab dipakai untuk Google Play.

## E. Hilangkan bar alamat di aplikasi Android (Digital Asset Links)
1. Buka signing-key-info.txt, salin "SHA-256 fingerprint".
2. Buat isi .well-known/assetlinks.json di GitHub:
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "my.id.jbku.app",
    "sha256_cert_fingerprints": ["ISI_FINGERPRINT_DI_SINI"]
  }
}]
3. Commit, tunggu deploy Vercel, lalu cek: https://DOMAIN-ANDA/.well-known/assetlinks.json
   Kalau memakai Google Play App Signing, tambahkan juga fingerprint dari Play Console.

## F. iPhone
PWABuilder juga menyediakan paket iOS, tetapi butuh Mac, Xcode, dan akun Apple Developer berbayar.
Cara gratis: buka di Safari > Bagikan > "Tambahkan ke Layar Utama".
