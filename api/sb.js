// JBKu · proxy database (Vercel Edge Function)
// Kunci Supabase HANYA ada di Environment Variables Vercel — tidak pernah dikirim ke browser.
//   SB_URL   = https://xxxx.supabase.co            (proyek utama)
//   SB_KEY   = kunci publishable/anon BARU (hasil rotasi)
//   SB2_URL, SB2_KEY = proyek "Jual Aja" (opsional)
//   JB_GATE_SECRET   = teks acak panjang (opsional tapi disarankan)
//   JB_ALLOWED_ORIGINS = asal lain yang boleh memanggil (opsional, pisahkan koma; mis. untuk APK)
import { env, ipOf, clientId, issue, verify, cookie, limited, BITS } from './_jbgate.js';

export const config = { runtime: 'edge' };

const RULES = {
  a: /^(rest\/v1\/(jb_rows|mk_[a-z_]{1,40}|rpc\/mk_[a-z_]{1,40})|storage\/v1\/object\/(public\/)?market(\/[\w.\-\/]{0,300})?)$/,
  b: /^functions\/v1\/jbku-bridge$/,
};
const METHODS = ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'];
const FWD = ['content-type', 'prefer', 'range', 'range-unit', 'accept', 'accept-profile', 'content-profile', 'x-upsert', 'cache-control', 'x-client-info', 'x-jb-admin'];
const BACK = ['content-type', 'content-range', 'preference-applied', 'location'];
const MAX_BODY = 8 * 1024 * 1024;

function cors(req) {
  const o = req.headers.get('origin');
  if (!o) return { ok: true, h: {} };
  let same = false;
  try { same = new URL(o).host === new URL(req.url).host; } catch (e) {}
  const extra = env('JB_ALLOWED_ORIGINS').split(',').map((s) => s.trim()).filter(Boolean);
  if (!same && !extra.includes(o)) return { ok: false, h: {} };
  return { ok: true, h: same ? {} : {
    'access-control-allow-origin': o, vary: 'Origin',
    'access-control-allow-headers': 'content-type,prefer,range,x-upsert,cache-control,x-jb-pass,x-jb-admin,accept-profile,content-profile',
    'access-control-allow-methods': METHODS.join(','), 'access-control-expose-headers': 'content-range,x-jb-gate,x-jb-pub', 'access-control-max-age': '600',
  } };
}

const json = (status, body, h = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...h } });

export default async function handler(req) {
  const c = cors(req);
  if (!c.ok) return json(403, { error: 'origin ditolak' });
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: c.h });
  if (!METHODS.includes(req.method)) return json(405, { error: 'metode ditolak' }, c.h);

  const ip = ipOf(req);
  if (limited('all|' + ip, 600)) return json(429, { error: 'Terlalu banyak permintaan' }, { ...c.h, 'retry-after': '30' });

  // 1) gerbang anti-bot
  const cid = clientId(req);
  const pass = req.headers.get('x-jb-pass') || cookie(req, 'jb_pass');
  if (!(await verify(cid, pass))) {
    if (limited('gate|' + ip, 40)) return json(429, { error: 'Terlalu banyak permintaan' }, { ...c.h, 'retry-after': '60' });
    return json(401, { gate: 1, c: await issue(cid), bits: BITS() }, { ...c.h, 'x-jb-gate': '1' });
  }

  // 2) pembatas laju per IP
  const write = req.method !== 'GET' && req.method !== 'HEAD';
  if (limited((write ? 'w|' : 'r|') + ip, write ? 90 : 240)) return json(429, { error: 'Terlalu banyak permintaan, coba sebentar lagi' }, { ...c.h, 'retry-after': '20' });

  // 3) hanya jalur yang memang dipakai aplikasi
  const u = new URL(req.url);
  const p = u.searchParams.get('__p') || '';
  u.searchParams.delete('__p');
  const m = /^([ab])\/(.+)$/.exec(p);
  if (!m || p.includes('..') || !RULES[m[1]].test(m[2])) return json(404, { error: 'tidak ditemukan' }, c.h);
  const base = m[1] === 'a' ? env('SB_URL') : env('SB2_URL');
  const key = m[1] === 'a' ? env('SB_KEY') : env('SB2_KEY');
  if (!base || !key) return json(503, { error: 'Server belum diatur (SB_URL / SB_KEY kosong di Vercel)' }, c.h);

  const path = m[2], qs = u.searchParams, raw = decodeURIComponent(u.search);
  if (path.startsWith('rest/v1/')) {
    // tidak boleh hapus/ubah massal tanpa filter baris yang jelas
    if ((req.method === 'DELETE' || req.method === 'PATCH') && !/(\bid=(eq|in)\.|\bkey=eq\.|data->>uid=eq\.|chat_id=eq\.|user_id=eq\.|post_id=eq\.)/.test(raw)) return json(403, { error: 'Perubahan massal diblokir' }, c.h);
    if (path === 'rest/v1/jb_rows' && req.method === 'GET') {
      if (!/\b(kind|id)=(eq|in)\./.test(raw)) return json(403, { error: 'Query tanpa filter diblokir' }, c.h);
      const lim = parseInt(qs.get('limit') || '0', 10);
      if (!lim || lim > 1000) qs.set('limit', '1000');
    }
  }
  const len = parseInt(req.headers.get('content-length') || '0', 10);
  if (len > MAX_BODY) return json(413, { error: 'Data terlalu besar' }, c.h);

  const h = new Headers();
  for (const k of FWD) { const v = req.headers.get(k); if (v) h.set(k, v); }
  h.set('apikey', key);
  h.set('authorization', 'Bearer ' + key);
  const q = qs.toString();
  let body;
  if (write) { body = await req.arrayBuffer(); if (body.byteLength > MAX_BODY) return json(413, { error: 'Data terlalu besar' }, c.h); }

  let r;
  try { r = await fetch(base.replace(/\/+$/, '') + '/' + path + (q ? '?' + q : ''), { method: req.method, headers: h, body, redirect: 'manual' }); }
  catch (e) { return json(502, { error: 'Database tidak terjangkau' }, c.h); }

  const out = new Headers({ 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...c.h });
  for (const k of BACK) { const v = r.headers.get(k); if (v) out.set(k, v); }
  if (path.startsWith('storage/')) out.set('x-jb-pub', base.replace(/\/+$/, ''));
  return new Response(r.body, { status: r.status, headers: out });
}
