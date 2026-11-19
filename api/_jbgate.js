// JBKu gate — dipakai bersama oleh middleware.js dan api/sb.js
// Token = tantangan bertanda tangan (HMAC) + bukti kerja (proof-of-work) yang dihitung browser.
// Tanpa JavaScript asli + CPU, bot tidak bisa mendapat token, dan token terikat ke IP + User-Agent.
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');

export const env = (k, d = '') => (typeof process !== 'undefined' && process.env && process.env[k]) || d;
export const SECRET = () => env('JB_GATE_SECRET') || env('SB_KEY') || 'jbku-ganti-saya';
export const BITS = () => Math.min(22, Math.max(8, parseInt(env('JB_POW_BITS', '15'), 10) || 15));
export const TTL = 12 * 3600 * 1000;

let keyP = null, keyFor = '';
async function hmac(msg) {
  const s = SECRET();
  if (!keyP || keyFor !== s) { keyFor = s; keyP = crypto.subtle.importKey('raw', enc.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); }
  return hex(await crypto.subtle.sign('HMAC', await keyP, enc.encode(msg))).slice(0, 32);
}

export function ipOf(req) {
  const h = req.headers;
  return (h.get('x-real-ip') || (h.get('x-forwarded-for') || '').split(',')[0] || '0.0.0.0').trim();
}
// IP dilonggarkan ke /24 (IPv4) atau /48 (IPv6) supaya pindah menara seluler tidak selalu mengulang tantangan
export function clientId(req) {
  const ip = ipOf(req);
  const net = ip.includes(':') ? ip.split(':').slice(0, 3).join(':') : ip.split('.').slice(0, 3).join('.');
  return net + '|' + (req.headers.get('user-agent') || '').slice(0, 160);
}

export async function issue(cid) {
  const ts = Date.now().toString(36);
  const r = hex(crypto.getRandomValues(new Uint8Array(8)));
  return ts + '.' + r + '.' + (await hmac(ts + '.' + r + '.' + cid));
}

function zeroBits(buf) {
  const a = new Uint8Array(buf); let n = 0;
  for (let i = 0; i < a.length; i++) { if (a[i] === 0) { n += 8; continue; } n += Math.clz32(a[i]) - 24; break; }
  return n;
}

const okCache = new Map(); // token -> exp (hemat CPU: verifikasi kripto hanya sekali per token per isolate)
export async function verify(cid, token) {
  if (!token || token.length > 120) return false;
  const now = Date.now(), ck = token + '|' + cid, hit = okCache.get(ck);
  if (hit) { if (hit > now) return true; okCache.delete(ck); }
  const p = token.split('.');
  if (p.length !== 4 || !/^\d{1,12}$/.test(p[3])) return false;
  const ts = parseInt(p[0], 36);
  if (!ts || now - ts > TTL || ts - now > 60000) return false;
  if ((await hmac(p[0] + '.' + p[1] + '.' + cid)) !== p[2]) return false;
  const d = await crypto.subtle.digest('SHA-256', enc.encode(p[0] + '.' + p[1] + '.' + p[2] + '.' + p[3]));
  if (zeroBits(d) < BITS()) return false;
  if (okCache.size > 5000) okCache.clear();
  okCache.set(ck, ts + TTL);
  return true;
}

export function cookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : '';
}

// Pembatas laju per IP (memori isolate — lapis tambahan; pembatas utama tetap Vercel Firewall)
const buckets = new Map();
export function limited(key, max, winMs = 60000) {
  const now = Date.now(); let b = buckets.get(key);
  if (!b || now - b.t > winMs) { b = { t: now, n: 0 }; buckets.set(key, b); }
  b.n++;
  if (buckets.size > 20000) { for (const [k, v] of buckets) if (now - v.t > winMs) buckets.delete(k); }
  return b.n > max;
}

// SHA-256 sinkron mungil untuk browser (dipakai halaman tantangan). Mengembalikan jumlah bit nol di depan.
export const POW_JS = `function jbZ(s){var K=jbZ.K||(jbZ.K=function(){var k=[],n=2,i=0;for(;i<64;n++){var p=1;for(var d=2;d*d<=n;d++)if(n%d===0){p=0;break}if(p)k[i++]=(Math.pow(n,1/3)%1*4294967296)|0}return k}());var l=s.length,L=((l+8>>6)+1)<<4,w=new Int32Array(L),i,j;for(i=0;i<l;i++)w[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);w[l>>2]|=128<<(24-(l&3)*8);w[L-1]=l*8;var h0=1779033703,h1=-1150833019,h2=1013904242,h3=-1521486534,h4=1359893119,h5=-1694144372,h6=528734635,h7=1541459225,W=new Int32Array(64);for(i=0;i<L;i+=16){var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;for(j=0;j<64;j++){if(j<16)W[j]=w[i+j];else{var x=W[j-15],y=W[j-2];W[j]=(W[j-16]+((x>>>7|x<<25)^(x>>>18|x<<14)^(x>>>3))+W[j-7]+((y>>>17|y<<15)^(y>>>19|y<<13)^(y>>>10)))|0}var t1=(h+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7))+((e&f)^(~e&g))+K[j]+W[j])|0,t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0}return h0===0?32+Math.clz32(h1):Math.clz32(h0)}
function jbSolve(c,bits,done){var n=0;(function step(){var end=Date.now()+14;while(Date.now()<end){if(jbZ(c+"."+n)>=bits)return done(c+"."+n);n++}setTimeout(step,0)})()}`;
