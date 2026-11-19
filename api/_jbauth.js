// JBKu · sesi server (dipakai api/login.js dan api/sb.js). File berawalan "_" tidak menjadi alamat publik.
// Environment Variables Vercel yang dipakai:
//   JB_SESSION_SECRET = teks acak panjang (minimal 32 karakter) — WAJIB
//   SB_SERVICE_KEY    = kunci service_role / secret Supabase — sangat disarankan (wajib sebelum policy anon dihapus)
//   SB_URL, SB_KEY    = sama seperti sebelumnya
import { env } from './_jbgate.js';

const te = new TextEncoder();
const td = new TextDecoder();
const DAY = 864e5;
export const RECHECK_MS = 10 * 60 * 1000;   // tiap 10 menit status akun dicek ulang ke database
const TTL_LONG = 30 * DAY, TTL_SHORT = 1 * DAY;
export const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

const b64u = (buf) => { let s = ''; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const ub64u = (s) => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s), a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; };
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => new Uint8Array((String(h).match(/../g) || []).map((x) => parseInt(x, 16)));

export function secret() { const s = env('JB_SESSION_SECRET') || ''; return s.length >= 32 ? s : ''; }
let _k = null, _ks = '';
async function hkey() { const s = secret(); if (!s) return null; if (_k && _ks === s) return _k; _k = await crypto.subtle.importKey('raw', te.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']); _ks = s; return _k; }

export async function credTag(u) { const k = await hkey(); return hex(await crypto.subtle.sign('HMAC', k, te.encode('cred|' + (u.salt || '') + '|' + (u.hash || '') + '|' + (u.iter || '')))).slice(0, 20); }

async function sign(p) { const k = await hkey(); const body = b64u(te.encode(JSON.stringify(p))); return body + '.' + b64u(await crypto.subtle.sign('HMAC', k, te.encode(body))); }

/** token sesi untuk satu akun */
export async function issueFor(u, remember, now = Date.now()) {
  return sign({ u: String(u.id), r: u.role === 'admin' ? 'admin' : String(u.role || 'member'), e: now + (remember ? TTL_LONG : TTL_SHORT), k: now + RECHECK_MS, c: await credTag(u), m: remember ? 1 : 0 });
}
/** null bila token palsu / rusak / kedaluwarsa */
export async function readToken(tok, now = Date.now()) {
  try {
    const k = await hkey(); if (!k || typeof tok !== 'string' || tok.length > 600) return null;
    const i = tok.indexOf('.'); if (i < 1) return null;
    const ok = await crypto.subtle.verify('HMAC', k, ub64u(tok.slice(i + 1)), te.encode(tok.slice(0, i)));
    if (!ok) return null;
    const p = JSON.parse(td.decode(ub64u(tok.slice(0, i))));
    if (!p || !ID_RE.test(String(p.u)) || !(p.e > now)) return null;
    return p;
  } catch (e) { return null; }
}

export async function pbkdf2(pw, saltHex, iter) {
  const key = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unhex(saltHex), iterations: iter, hash: 'SHA-256' }, key, 256));
}
export function same(a, b) { a = String(a); b = String(b); let d = a.length ^ b.length; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i % (b.length || 1)); return d === 0; }

// ---------- database (dipanggil dari server, bukan dari browser) ----------
export const svcKey = () => env('SB_SERVICE_KEY') || env('SB_KEY');
export const hasSvc = () => !!env('SB_SERVICE_KEY');
export const qv = (x) => '"' + String(x).replace(/["\\]/g, '') + '"';
export const inList = (ids) => 'in.(' + ids.map(qv).join(',') + ')';
export function db(pathAndQuery, init = {}) {
  const base = (env('SB_URL') || '').replace(/\/+$/, ''), key = svcKey();
  const h = new Headers(init.headers || {});
  h.set('apikey', key); h.set('authorization', 'Bearer ' + key);
  if (init.body && !h.has('content-type')) h.set('content-type', 'application/json');
  return fetch(base + '/rest/v1/' + pathAndQuery, { ...init, headers: h, redirect: 'manual' });
}
const P = (o) => new URLSearchParams(o).toString();
/** {ok:true,user|null} atau {ok:false} bila database tidak terjangkau */
export async function getUser(id) {
  try {
    const r = await db('jb_rows?' + P({ select: 'id,data', kind: 'eq.users', id: 'eq.' + id, limit: '1' }));
    if (!r.ok) return { ok: false };
    const b = await r.json(); const d = b[0] && b[0].data;
    return { ok: true, user: d && typeof d === 'object' ? { ...d, id: String(b[0].id) } : null };
  } catch (e) { return { ok: false }; }
}
export async function findByUsername(un) {
  const r = await db('jb_rows?' + P({ select: 'id,data', kind: 'eq.users', 'data->>username': 'ilike.' + un, limit: '20' }));
  if (!r.ok) throw new Error('db ' + r.status);
  const b = await r.json(), low = un.toLowerCase();
  const hit = b.find((x) => x && x.data && String(x.data.username || '').trim().toLowerCase() === low);
  return hit ? { ...hit.data, id: String(hit.id) } : null;
}

// ---------- CORS & balasan ----------
const METHODS = ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'];
export function cors(req) {
  const o = req.headers.get('origin');
  if (!o) return { ok: true, h: {} };
  let sameHost = false;
  try { sameHost = new URL(o).host === new URL(req.url).host; } catch (e) {}
  const extra = (env('JB_ALLOWED_ORIGINS') || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!sameHost && !extra.includes(o)) return { ok: false, h: {} };
  return { ok: true, h: sameHost ? {} : {
    'access-control-allow-origin': o, vary: 'Origin',
    'access-control-allow-headers': 'content-type,prefer,range,x-upsert,cache-control,x-jb-pass,x-jb-sess,x-jb-admin,accept-profile,content-profile',
    'access-control-allow-methods': METHODS.join(','), 'access-control-expose-headers': 'content-range,x-jb-gate,x-jb-pub,x-jb-sess,x-jb-auth', 'access-control-max-age': '600',
  } };
}
export const json = (status, body, h = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...h } });
