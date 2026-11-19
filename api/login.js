// JBKu · login di server (Vercel Edge Function)  →  POST /api/login  {username,password,remember}
// Password diperiksa DI SINI, bukan di browser. Bila benar, server memberi token sesi bertanda tangan.
// Tanpa token itu, /api/sb tidak mau membuka data akun atau menerima perubahan apa pun.
import { env, ipOf, clientId, issue, verify, cookie, limited, BITS } from './_jbgate.js';
import { cors, json, secret, db, findByUsername, issueFor, pbkdf2, same, ID_RE } from './_jbauth.js';

export const config = { runtime: 'edge' };

const BAD = 'Username atau password salah. Perhatikan huruf besar/kecil.';
const LOCK_AT = 5;                       // mulai dikunci setelah 5x salah
const lockMs = (n) => Math.min(15 * 60e3, 30e3 * Math.pow(2, Math.max(0, n - LOCK_AT)));
const lockId = (un) => 'u_' + un.toLowerCase().replace(/[^a-z0-9._@-]/g, '_').slice(0, 64);

async function lockGet(id) {
  try { const r = await db('jb_rows?select=data&kind=eq._lock&id=eq.' + encodeURIComponent(id) + '&limit=1'); if (!r.ok) return null; const b = await r.json(); return (b[0] && b[0].data) || null; } catch (e) { return null; }
}
async function lockSet(id, data) {
  try { await db('jb_rows?on_conflict=kind,id', { method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify([{ kind: '_lock', id, data }]) }); } catch (e) {}
}
async function lockDel(id) { try { await db('jb_rows?kind=eq._lock&id=eq.' + encodeURIComponent(id), { method: 'DELETE' }); } catch (e) {} }

export default async function handler(req) {
  const c = cors(req);
  if (!c.ok) return json(403, { error: 'origin ditolak' });
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: c.h });
  if (req.method !== 'POST') return json(405, { error: 'metode ditolak' }, c.h);
  if (!secret()) return json(503, { error: 'Server belum diatur (JB_SESSION_SECRET kosong / kurang dari 32 karakter di Vercel)' }, c.h);
  if (!env('SB_URL') || !env('SB_KEY')) return json(503, { error: 'Server belum diatur (SB_URL / SB_KEY kosong di Vercel)' }, c.h);

  const ip = ipOf(req);
  if (limited('all|' + ip, 600)) return json(429, { error: 'Terlalu banyak permintaan' }, { ...c.h, 'retry-after': '30' });

  // gerbang anti-bot yang sama dengan /api/sb
  const cid = clientId(req);
  const pass = req.headers.get('x-jb-pass') || cookie(req, 'jb_pass');
  if (!(await verify(cid, pass))) {
    if (limited('gate|' + ip, 40)) return json(429, { error: 'Terlalu banyak permintaan' }, { ...c.h, 'retry-after': '60' });
    return json(401, { gate: 1, c: await issue(cid), bits: BITS() }, { ...c.h, 'x-jb-gate': '1' });
  }
  if (limited('login|' + ip, 20)) return json(429, { error: 'Terlalu banyak percobaan login. Tunggu sebentar lalu coba lagi.' }, { ...c.h, 'retry-after': '60' });

  let body;
  try { const t = await req.text(); if (t.length > 4096) throw 0; body = JSON.parse(t); } catch (e) { return json(400, { error: 'Permintaan tidak valid' }, c.h); }
  const un = String((body && body.username) || '').trim();
  const pw = String((body && body.password) || '');
  if (!un || !pw || un.length > 64 || pw.length > 200 || /[*%(),\\]/.test(un)) return json(401, { error: BAD }, c.h);

  const lid = lockId(un), now = Date.now();
  const L = (await lockGet(lid)) || { n: 0, until: 0 };
  if (L.until > now) return json(429, { error: 'Terlalu banyak percobaan. Coba lagi ' + Math.ceil((L.until - now) / 1e3) + ' detik.' }, { ...c.h, 'retry-after': String(Math.ceil((L.until - now) / 1e3)) });

  let u;
  try { u = await findByUsername(un); } catch (e) { return json(502, { error: 'Server database sedang lambat / tidak terjangkau. Password belum dicek, coba lagi sebentar.' }, c.h); }

  let ok = false;
  if (u && u.salt && u.hash && ID_RE.test(u.id)) {
    const iter = Math.min(Math.max(+u.iter || 15e4, 1e3), 1e6);
    ok = same(await pbkdf2(pw, u.salt, iter), u.hash);
    const pw2 = pw.trim();
    if (!ok && pw2 && pw2 !== pw) ok = same(await pbkdf2(pw2, u.salt, iter), u.hash);
  } else {
    await pbkdf2(pw, '00112233445566778899aabbccddeeff', 15e4); // waktu respons tetap sama walau akun tidak ada
  }
  if (!ok) {
    const n = (L.n || 0) + 1;
    await lockSet(lid, { n, until: n >= LOCK_AT ? now + lockMs(n) : 0, at: now });
    return json(401, { error: n >= LOCK_AT ? 'Password salah ' + n + 'x. Tunggu ' + Math.round(lockMs(n) / 1e3) + ' detik lalu coba lagi.' : BAD }, c.h);
  }
  if (L.n) await lockDel(lid);
  if (!u.active) return json(403, { error: 'Akun dinonaktifkan oleh admin.' }, c.h);

  const token = await issueFor(u, !!(body && body.remember));
  return json(200, { ok: true, token, user: u }, c.h);
}
