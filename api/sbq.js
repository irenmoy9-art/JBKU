// JBKu · api/sbq.js — jalur khusus QRIS Bersama & Trafik Skin SG (Vercel Edge Function)
// File BARU. Taruh di folder api/ di samping sb.js. File lain tidak perlu diubah.
//
// Aturan:
//   - wajib lolos gerbang anti-bot dan wajib login (token sesi x-jb-sess)
//   - p_uid / p_admin SELALU diisi dari sesi login, bukan dari kiriman HP
//   - fungsi admin (qb_admin, qb_decide, qb_fee_set, sg_skin_save) hanya untuk sesi admin
//   - hanya 10 fungsi di daftar RPC yang bisa dipanggil
//   - database dipanggil lewat db() yang sama dengan jb_rows (kunci service_role)
import { ipOf, clientId, issue, verify, cookie, limited, BITS } from './_jbgate.js';
import { cors, json, secret, db, getUser, readToken, issueFor, credTag } from './_jbauth.js';

export const config = { runtime: 'edge' };

const BACK = ['content-type', 'content-range', 'preference-applied', 'location'];
const MAX_BODY = 8 * 1024 * 1024;
const MAX_BODY_USER = 4 * 1024 * 1024;
const PATH_RE = /^a\/rest\/v1\/rpc\/((?:qb|sg)_[a-z_]{1,40})$/;

export default async function handler(req) {
  const c = cors(req);
  if (!c.ok) return json(403, { error: 'origin ditolak' });
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: c.h });
  if (req.method !== 'POST') return json(405, { error: 'metode ditolak' }, c.h);

  const ip = ipOf(req);
  if (limited('all|' + ip, 600)) return json(429, { error: 'Terlalu banyak permintaan' }, { ...c.h, 'retry-after': '30' });

  // gerbang anti-bot (sama dengan sb.js)
  const cid = clientId(req);
  const pass = req.headers.get('x-jb-pass') || cookie(req, 'jb_pass');
  if (!(await verify(cid, pass))) {
    if (limited('gate|' + ip, 40)) return json(429, { error: 'Terlalu banyak permintaan' }, { ...c.h, 'retry-after': '60' });
    return json(401, { gate: 1, c: await issue(cid), bits: BITS() }, { ...c.h, 'x-jb-gate': '1' });
  }
  if (limited('w|' + ip, 90)) return json(429, { error: 'Terlalu banyak permintaan, coba sebentar lagi' }, { ...c.h, 'retry-after': '20' });

  const u = new URL(req.url);
  const m = PATH_RE.exec(u.searchParams.get('__p') || '');
  if (!m) return json(404, { error: 'tidak ditemukan' }, c.h);
  const len = parseInt(req.headers.get('content-length') || '0', 10);
  if (len > MAX_BODY) return json(413, { error: 'Data terlalu besar' }, c.h);

  try { return await rpcCall(req, m[1], c.h); }
  catch (e) { return json(502, { error: 'Database tidak terjangkau' }, c.h); }
}

// ---- QRIS Bersama & Trafik Skin SG ----
// u = p_uid diisi dari sesi login, a = khusus admin dan p_admin diisi dari sesi login
const RPC = {
  qb_me: 'u', qb_deposit: 'u', qb_withdraw: 'u', qb_proof: 'u',
  qb_admin: 'a', qb_decide: 'a', qb_fee_set: 'a',
  sg_board: '', sg_put: 'u', sg_skin_save: 'a',
};

async function rpcCall(req, fn, ch) {
  const mode = RPC[fn];
  if (mode === undefined) return json(404, { error: 'tidak ditemukan' }, ch);
  if (req.method !== 'POST') return json(405, { error: 'metode ditolak' }, ch);
  if (!secret()) return json(503, { error: 'Server belum diatur (JB_SESSION_SECRET kosong / kurang dari 32 karakter di Vercel)' }, ch);
  const H = { ...ch };
  const relogin = () => json(401, { error: 'Sesi habis. Silakan login ulang.' }, { ...H, 'x-jb-auth': '1' });

  // siapa pemanggilnya: hanya dari token sesi, bukan dari isi permintaan
  const tok = req.headers.get('x-jb-sess') || '';
  let sess = tok ? await readToken(tok) : null;
  if (!sess) return relogin();
  if (Date.now() > sess.k) {
    const g = await getUser(sess.u);
    if (g.ok) {
      const d = g.user;
      if (!d || !d.active || (await credTag(d)) !== sess.c) return relogin();
      const nt = await issueFor(d, !!sess.m);
      H['x-jb-sess'] = nt; sess = await readToken(nt);
    }
  }
  const me = String(sess.u), admin = sess.r === 'admin';
  if (mode === 'a' && !admin) return json(403, { error: 'Khusus admin' }, H);

  const buf = await req.arrayBuffer();
  if (buf.byteLength > (admin ? MAX_BODY : MAX_BODY_USER)) return json(413, { error: 'Data terlalu besar' }, H);
  let a = {};
  if (buf.byteLength) { try { a = JSON.parse(new TextDecoder().decode(buf)); } catch (e) { return json(400, { error: 'Data tidak valid' }, H); } }
  if (!a || typeof a !== 'object' || Array.isArray(a)) return json(400, { error: 'Data tidak valid' }, H);
  if (mode === 'u') a.p_uid = me;      // member tidak bisa memakai id orang lain
  if (mode === 'a') a.p_admin = me;    // id admin selalu dari sesi admin yang login

  const r = await db('rpc/' + fn, { method: 'POST', headers: new Headers({ 'content-type': 'application/json' }), body: JSON.stringify(a) });
  const out = new Headers({ 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...H });
  for (const k of BACK) { const v = r.headers.get(k); if (v) out.set(k, v); }
  return new Response(r.body, { status: r.status, headers: out });
}
