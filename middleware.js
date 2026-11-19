// JBKu · penjaga halaman (Vercel Routing Middleware, jalan sebelum file 7 MB dikirim)
// - bot/pemindai/alat serangan ditolak dengan balasan beberapa byte saja
// - pengunjung baru harus lolos tantangan JavaScript ringan (±0,2 detik) sebelum halaman dikirim
// - perayap pratinjau (WhatsApp, Telegram, dll.) hanya diberi kartu pratinjau mungil
import { ipOf, clientId, issue, verify, cookie, limited, BITS, POW_JS } from './api/_jbgate.js';

export const config = {
  matcher: ['/((?!api/|_vercel/|icons/|.*\\.(?:png|jpe?g|webp|gif|svg|ico|css|js|mjs|json|webmanifest|txt|xml|woff2?|ttf|map|apk|mp4|webm|mp3)$).*)'],
};

const BAD_UA = /(curl|wget|python|aiohttp|httpx|go-http|okhttp|java\/|libwww|scrapy|httpclient|axios|node-fetch|undici|masscan|zgrab|nmap|nikto|sqlmap|nuclei|wpscan|dirbuster|gobuster|ffuf|hydra|slowloris|loic|hping|headless|phantomjs|puppeteer|playwright|selenium|semrush|ahrefs|mj12|dotbot|petalbot|bytespider|gptbot|ccbot|claudebot|amazonbot|dataforseo|blexbot)/i;
const PREVIEW_UA = /(whatsapp|facebookexternalhit|facebot|telegrambot|twitterbot|discordbot|slackbot|linkedinbot|line-poker|googlebot|bingbot|duckduckbot|applebot)/i;
const BAD_PATH = /(\.(php\d?|aspx?|jsp|cgi|env|git|sql|bak|ini|log|ya?ml|sh)(\/|$)|\/(wp-|wordpress|xmlrpc|phpmyadmin|cgi-bin|vendor\/|\.aws|\.ssh|\.svn|actuator|solr|boaform|autodiscover))/i;

const SEC = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'SAMEORIGIN',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=(), microphone=(), payment=(), usb=(), bluetooth=(), serial=()',
  'cross-origin-opener-policy': 'same-origin-allow-popups',
};
const tiny = (status, body = '', h = {}) => new Response(body, { status, headers: { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8', ...SEC, ...h } });
const pass = () => new Response(null, { headers: { 'x-middleware-next': '1', ...SEC } });
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function previewCard(url) {
  const slug = decodeURIComponent((url.searchParams.get('toko') || url.pathname.split('/').filter(Boolean)[0] || '')).replace(/[^a-z0-9-]/gi, '').slice(0, 32);
  const title = slug ? slug + ' · JBKu' : 'JBKu';
  return new Response(`<!doctype html><html lang="id"><head><meta charset="utf-8"><title>${esc(title)}</title><meta property="og:title" content="${esc(title)}"><meta property="og:description" content="Toko akun game terpercaya di JBKu."><meta property="og:type" content="website"><meta property="og:image" content="${esc(url.origin)}/icons/icon-512.png"><meta name="twitter:card" content="summary"></head><body><h1>${esc(title)}</h1></body></html>`, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=600', ...SEC } });
}

function challengePage(c, bits) {
  return new Response(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex"><meta name="theme-color" content="#08090b"><title>JBKu</title>
<style>html,body{height:100%;margin:0;background:#08090b;color:#f4f5f7;font:500 14px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}body{display:grid;place-content:center;justify-items:center;gap:22px}
.m{font:900 italic 44px/0.82 "Arial Black",Impact,system-ui,sans-serif;letter-spacing:-.02em;transform:skewX(-6deg)}.m b{display:block;color:#1a7bff}
.t{width:168px;height:3px;background:#1b1e24;overflow:hidden}.t i{display:block;height:100%;width:40%;background:#1a7bff;animation:s 1s cubic-bezier(.6,0,.4,1) infinite}@keyframes s{0%{transform:translateX(-100%)}100%{transform:translateX(260%)}}
small{letter-spacing:.18em;text-transform:uppercase;font-size:10.5px;color:#8a909c}a{color:#6fb0ff}</style></head>
<body><div class="m" aria-label="JBKu">JB<b>KU</b></div><div class="t"><i></i></div><small id="s">Memeriksa koneksi aman</small>
<noscript><small>Aktifkan JavaScript untuk membuka JBKu.</small></noscript>
<script>${POW_JS}
(function(){var done=function(t){document.cookie="jb_pass="+encodeURIComponent(t)+";path=/;max-age=43200;samesite=lax"+(location.protocol==="https:"?";secure":"");try{localStorage.setItem("jb_pass",t)}catch(e){}
if(!navigator.cookieEnabled||document.cookie.indexOf("jb_pass=")<0){document.getElementById("s").textContent="Aktifkan cookie untuk membuka JBKu";return}
var k="jb_gate_n",n=+(sessionStorage.getItem(k)||0);if(n>3){document.getElementById("s").innerHTML='Gagal memverifikasi. <a href="">Coba lagi</a>';sessionStorage.removeItem(k);return}sessionStorage.setItem(k,n+1);location.reload()};
jbSolve(${JSON.stringify(c)},${bits},done)})();</script></body></html>`, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex', ...SEC } });
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const ua = req.headers.get('user-agent') || '';
  const ip = ipOf(req);

  if (BAD_PATH.test(url.pathname)) return tiny(404);
  if (req.method !== 'GET' && req.method !== 'HEAD') return tiny(405);
  if (url.pathname.length > 200 || url.search.length > 1200) return tiny(414);
  if (!ua || ua.length < 12 || BAD_UA.test(ua)) return tiny(403);
  if (limited('pg|' + ip, 60)) return tiny(429, 'Terlalu banyak permintaan. Coba lagi sebentar.', { 'retry-after': '30' });
  if (PREVIEW_UA.test(ua)) return previewCard(url);

  const cid = clientId(req);
  if (await verify(cid, cookie(req, 'jb_pass'))) return pass();
  if (limited('ch|' + ip, 20)) return tiny(429, 'Terlalu banyak permintaan.', { 'retry-after': '60' });
  return challengePage(await issue(cid), BITS());
}
