// JBKu · proxy database v4 (Vercel Edge Function) — sekarang dengan sesi server & izin per peran.
// Kunci Supabase HANYA ada di Environment Variables Vercel — tidak pernah dikirim ke browser.
//   SB_URL   = https://xxxx.supabase.co            (proyek utama)
//   SB_KEY   = kunci publishable/anon (untuk mk_*, storage)
//   SB_SERVICE_KEY   = kunci service_role/secret → dipakai KHUSUS tabel jb_rows setelah izin diperiksa di sini
//   JB_SESSION_SECRET = teks acak ≥32 karakter (tanda tangan token sesi) — WAJIB
//   SB2_URL, SB2_KEY = proyek "Jual Aja" (opsional)
//   JB_GATE_SECRET, JB_ALLOWED_ORIGINS = seperti sebelumnya
//
// Aturan tabel jb_rows (ringkas):
//   tanpa login : hanya BACA etalase publik (shop, shopinfo, media by id). Tidak bisa tulis/hapus apa pun.
//   member/reseller : baca akun sendiri + akun admin (tanpa salt/hash), login-perangkat sendiri, notifs;
//                     tulis akun SENDIRI (role/active/exp/username dikunci server), logins sendiri, toko sendiri, media.
//   admin : semuanya, kecuali menghapus akun admin dan hapus/ubah massal tanpa filter.
import { env, ipOf, clientId, issue, verify, cookie, limited, BITS } from './_jbgate.js';
import { cors, json, secret, svcKey, db, qv, inList, getUser, readToken, issueFor, credTag, ID_RE } from './_jbauth.js';

export const config = { runtime: 'edge' };

const RULES = {
  a: /^(rest\/v1\/(jb_rows|mk_[a-z_]{1,40}|rpc\/mk_[a-z_]{1,40})|storage\/v1\/object\/(public\/)?market(\/[\w.\-\/]{0,300})?)$/,
  b: /^functions\/v1\/jbku-bridge$/,
};
const METHODS = ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'];
const FWD = ['content-type', 'prefer', 'range', 'range-unit', 'accept', 'accept-profile', 'content-profile', 'x-upsert', 'cache-control', 'x-client-info', 'x-jb-admin'];
const BACK = ['content-type', 'content-range', 'preference-applied', 'location'];
const MAX_BODY = 8 * 1024 * 1024;
const MAX_BODY_USER = 4 * 1024 * 1024;

const KIND_RE = /^[a-z_]{1,24}$/;
const PUBLIC_READ = ['shop', 'shopinfo', 'media'];
const EMPTY_IF_ANON = ['users', 'logins', 'notifs'];
// kolom akun yang hanya boleh diubah admin
const FROZEN = ['role', 'username', 'active', 'exp', 'maxDev', 'vipUi', 'createdAt'];
const FROZEN_RE = /^(rs|resell|ban|paus|stop|suspend)/i;
const CRED = ['salt', 'hash', 'iter'];
const PRIVATE = ['email', 'phone', 'hp', 'wa_pribadi', 'note', 'notes', 'createdAt', 'lastLogin', 'ip', 'devices'];
const PRIVATE_PROFILE = ['vault', 'email', 'phone', 'note', 'notes', 'bank', 'rek', 'pin'];
const USER_SELECT = new Set(['id', 'data', 'id,data', 'kind,id,data', 'id,updated_at', 'id,data,updated_at', 'h:data->>hash,un:data->>username,a:data->>active']);
const USER_KEYS = new Set(['select', 'kind', 'id', 'order', 'limit', 'offset', 'or', 'data->>username', 'data->>role']);
const PATH_RE = /^data(->>?[\w-]{1,40}){1,4}$/;
const MASS_KEYS = ['id', 'key', 'chat_id', 'user_id', 'post_id', 'owner_id', 'data->>uid'];
const isFilter = (v) => /^(eq|in)\./.test(v || '');

function kindsOf(qs) {
  const all = qs.getAll('kind');
  if (all.length !== 1) return null;
  const v = all[0]; let list = null;
  if (v.startsWith('eq.')) list = [v.slice(3)];
  else if (/^in\.\(.*\)$/.test(v)) list = v.slice(4, -1).split(',').map((s) => s.trim().replace(/^"|"$/g, ''));
  if (!list || !list.length || list.some((k) => !KIND_RE.test(k))) return null;
  return list;
}
const idsOf = (v) => (v.startsWith('eq.') ? [v.slice(3)] : v.slice(4, -1).split(',').map((s) => s.trim().replace(/^"|"$/g, '')).filter(Boolean));

async function lookup(kind, ids, select) {
  const out = [];
  for (let i = 0; i < ids.length; i += 80) {
    const p = new URLSearchParams({ select, kind: 'eq.' + kind, id: inList(ids.slice(i, i + 80)), limit: '200' });
    const r = await db('jb_rows?' + p);
    if (!r.ok) throw new Error('db ' + r.status);
    out.push(...(await r.json()));
  }
  return out;
}

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

  const path = m[2], qs = u.searchParams;
  const len = parseInt(req.headers.get('content-length') || '0', 10);
  if (len > MAX_BODY) return json(413, { error: 'Data terlalu besar' }, c.h);

  // 4) tabel utama: izin diperiksa per akun
  if (m[1] === 'a' && path === 'rest/v1/jb_rows') {
    try { return await rows(req, qs, c.h); }
    catch (e) { return json(502, { error: 'Database tidak terjangkau' }, c.h); }
  }

  // 5) jalur lain (mk_*, storage, bridge) diteruskan seperti sebelumnya
  if (path.startsWith('rest/v1/') && (req.method === 'DELETE' || req.method === 'PATCH')) {
    // filter dibaca per-parameter (bukan mencari teks), jadi tidak bisa dikelabui lewat nilai kolom lain
    if (!MASS_KEYS.some((k) => qs.getAll(k).some(isFilter))) return json(403, { error: 'Perubahan massal diblokir' }, c.h);
  }
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

// =====================================================================================
//  jb_rows
// =====================================================================================
async function rows(req, qs, ch) {
  if (!secret()) return json(503, { error: 'Server belum diatur (JB_SESSION_SECRET kosong / kurang dari 32 karakter di Vercel)' }, ch);
  const H = { ...ch };                                   // header balasan (bisa ditambah token baru)
  const deny = (msg) => json(403, { error: msg || 'Tidak diizinkan' }, H);
  const relogin = () => json(401, { error: 'Sesi habis. Silakan login ulang.' }, { ...H, 'x-jb-auth': '1' });

  // ---- siapa pemanggilnya ----
  const tok = req.headers.get('x-jb-sess') || '';
  let sess = tok ? await readToken(tok) : null;
  if (tok && !sess) return relogin();
  if (sess && Date.now() > sess.k) {                     // cek ulang berkala: akun masih aktif? password belum diganti?
    const g = await getUser(sess.u);
    if (g.ok) {
      const d = g.user;
      if (!d || !d.active || (await credTag(d)) !== sess.c) return relogin();
      const nt = await issueFor(d, !!sess.m);
      H['x-jb-sess'] = nt; sess = await readToken(nt);
    }
  }
  const me = sess ? String(sess.u) : '';
  const admin = !!sess && sess.r === 'admin';
  const method = req.method;

  const fwd = (extra) => { const h = new Headers(); for (const k of FWD) { const v = req.headers.get(k); if (v) h.set(k, v); } if (extra) for (const k in extra) h.set(k, extra[k]); return h; };
  const back = (r, body) => { const out = new Headers({ 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...H }); for (const k of BACK) { const v = r.headers.get(k); if (v) out.set(k, v); } return new Response(body === undefined ? r.body : body, { status: r.status, headers: out }); };

  // ================= BACA =================
  if (method === 'GET' || method === 'HEAD') {
    const kinds = kindsOf(qs);
    if (!kinds) return deny('Query tanpa filter diblokir');
    const lim = parseInt(qs.get('limit') || '0', 10);
    if (!lim || lim > 1000) qs.set('limit', '1000');
    let scrub = kinds.includes('users');                 // data akun selalu disaring, termasuk untuk admin

    if (!admin) {
      if (kinds.length > 1 && kinds.some((k) => k === 'users' || k === 'logins')) return deny();
      for (const k of kinds) {
        if (PUBLIC_READ.includes(k)) { if (k === 'media' && !qs.getAll('id').some(isFilter)) return deny(); continue; }
        if (!sess) {
          if (EMPTY_IF_ANON.includes(k)) return json(200, [], H);     // belum login: tidak ada data akun
          return relogin();
        }
        if (k === 'notifs') continue;
        if (k === 'logins') { qs.delete('and'); qs.set('data->>uid', 'eq.' + me); continue; }
        if (k !== 'users') return deny();

        // ---- akun: hanya milik sendiri + baris admin (tanpa kredensial) ----
        const sel = qs.get('select') || '';
        if (sel === 'id' && !qs.has('or') && !qs.has('and')) {
          // cek "kode sudah dipakai akun lain?" → hanya mengembalikan id, hanya perbandingan sama-dengan
          for (const [name, val] of qs.entries()) {
            if (['select', 'kind', 'limit', 'offset', 'order'].includes(name)) continue;
            if (name === 'id' && isFilter(val)) continue;
            if (!PATH_RE.test(name) || !val.startsWith('eq.') || /(hash|salt|iter)$/i.test(name)) return deny();
          }
          qs.set('limit', String(Math.min(parseInt(qs.get('limit') || '5', 10) || 5, 5)));
          continue;
        }
        if (!USER_SELECT.has(sel)) return deny();
        for (const [name, val] of qs.entries()) {
          if (!USER_KEYS.has(name)) return deny();
          if (name === 'or' && val !== '(id.eq.' + me + ',data->>role.eq.admin)') return deny();
          if (name === 'data->>role' && val !== 'eq.admin') return deny();
          if (name === 'data->>username' && (!/^(eq|ilike)\./.test(val) || /[*%]/.test(val))) return deny();
          if (name === 'id' && !isFilter(val)) return deny();
          if (name === 'order' && !/^[a-z_.,]{1,40}$/.test(val)) return deny();
        }
        qs.set('and', /hash|salt/i.test(sel) ? '(id.eq.' + me + ')' : '(or(id.eq.' + me + ',data->>role.eq.admin))');
      }
    }

    const r = await db('jb_rows?' + qs.toString(), { method, headers: fwd() });
    if (!scrub || method === 'HEAD' || !r.ok) return back(r);
    let list;
    try { list = await r.json(); } catch (e) { return back(r, '[]'); }
    if (Array.isArray(list)) for (const row of list) {
      const d = row && row.data;
      if (!d || typeof d !== 'object') continue;
      if (row.kind !== undefined ? row.kind !== 'users' : !(kinds.length === 1 && kinds[0] === 'users')) continue;
      const rid = row.id !== undefined ? String(row.id) : String(d.id);
      if (rid === me) continue;
      for (const f of CRED) delete d[f];                  // kredensial orang lain tidak pernah dikirim, ke admin sekalipun
      if (!admin) {                                       // member/reseller hanya melihat versi publik akun admin
        d.username = 'admin';
        for (const f of PRIVATE) delete d[f];
        if (d.profile && typeof d.profile === 'object') for (const f of PRIVATE_PROFILE) delete d.profile[f];
      }
    }
    return back(r, JSON.stringify(list));
  }

  // ================= TULIS / HAPUS: wajib login =================
  if (!sess) return relogin();

  // ---- PATCH: tidak dipakai aplikasi; hanya admin dan wajib menunjuk baris ----
  if (method === 'PATCH') {
    if (!admin) return deny();
    const kinds = kindsOf(qs);
    if (!kinds || kinds.length !== 1 || !qs.getAll('id').some(isFilter)) return deny('Perubahan massal diblokir');
    const r = await db('jb_rows?' + qs.toString(), { method, headers: fwd(), body: await req.arrayBuffer() });
    return back(r);
  }

  // ---- DELETE ----
  if (method === 'DELETE') {
    const kinds = kindsOf(qs);
    if (!kinds || kinds.length !== 1) return deny('Perubahan massal diblokir');
    const kind = kinds[0];
    const f = new URLSearchParams(); let n = 0;
    for (const [name, val] of qs.entries()) {
      if (name === 'kind') continue;
      if ((name === 'id' || name === 'data->>sid' || name === 'data->>uid') && isFilter(val)) { f.append(name, val); n++; continue; }
      return deny('Perubahan massal diblokir');
    }
    if (!n) return deny('Perubahan massal diblokir');
    if (!admin && !['shop', 'shopinfo', 'logins'].includes(kind)) return deny();

    if (admin && kind !== 'users') {
      f.set('kind', 'eq.' + kind);
      return back(await db('jb_rows?' + f.toString(), { method, headers: fwd() }));
    }
    // cari dulu baris yang kena, periksa kepemilikan, lalu hapus berdasarkan id pasti
    const s = new URLSearchParams(f); s.set('kind', 'eq.' + kind); s.set('limit', '1000');
    s.set('select', 'id,uid:data->>uid,sid:data->>sid,role:data->>role');
    const fr = await db('jb_rows?' + s.toString());
    if (!fr.ok) return back(fr);
    const hit = await fr.json();
    if (admin) {                                                    // kind === 'users'
      if (hit.some((x) => x.role === 'admin')) return deny('Akun admin tidak bisa dihapus dari aplikasi');
      if (hit.length > 50) return deny('Maksimal 50 akun per sekali hapus');
    } else if (kind === 'logins') { if (hit.some((x) => x.uid !== me)) return deny(); }
    else if (kind === 'shopinfo') { if (hit.some((x) => String(x.id) !== me)) return deny(); }
    else {                                                          // shop
      const orphan = hit.filter((x) => x.uid == null && x.sid != null);
      if (hit.some((x) => x.uid != null ? x.uid !== me : x.sid == null)) return deny();
      if (orphan.length) {
        const par = await lookup('shop', [...new Set(orphan.map((x) => String(x.sid)))], 'id,uid:data->>uid');
        if (par.some((x) => x.uid !== me)) return deny();          // foto HD milik stok orang lain
      }
    }
    const ids = hit.map((x) => String(x.id));
    for (let i = 0; i < ids.length; i += 80) {
      const d = new URLSearchParams({ kind: 'eq.' + kind, id: inList(ids.slice(i, i + 80)) });
      const r = await db('jb_rows?' + d.toString(), { method: 'DELETE' });
      if (!r.ok) return back(r);
    }
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store', ...H } });
  }

  // ---- POST (simpan / perbarui baris) ----
  const oc = qs.get('on_conflict');
  for (const name of qs.keys()) if (name !== 'on_conflict') return deny();
  if (oc && oc !== 'kind,id') return deny();
  const buf = await req.arrayBuffer();
  if (buf.byteLength > (admin ? MAX_BODY : MAX_BODY_USER)) return json(413, { error: 'Data terlalu besar' }, H);
  let list;
  try { list = JSON.parse(new TextDecoder().decode(buf)); } catch (e) { return json(400, { error: 'Data tidak valid' }, H); }
  if (!Array.isArray(list)) list = [list];
  if (!list.length || list.length > 100) return json(400, { error: 'Data tidak valid' }, H);
  for (const x of list) {
    if (!x || typeof x !== 'object' || !KIND_RE.test(String(x.kind)) || typeof x.id !== 'string' || !x.id || x.id.length > 200 || !x.data || typeof x.data !== 'object' || Array.isArray(x.data)) return json(400, { error: 'Data tidak valid' }, H);
    for (const k of Object.keys(x)) if (k !== 'kind' && k !== 'id' && k !== 'data') delete x[k];
  }

  // akun: ambil versi server untuk menjaga kredensial & kolom terkunci
  const userRows = list.filter((x) => x.kind === 'users');
  let credChanged = null;
  if (userRows.length) {
    if (!admin && userRows.some((x) => x.id !== me)) return deny('Hanya admin yang boleh mengubah akun lain');
    const cur = new Map((await lookup('users', userRows.map((x) => x.id), 'id,data')).map((x) => [String(x.id), x.data || {}]));
    for (const x of userRows) {
      const old = cur.get(x.id), d = x.data;
      if (d.id !== undefined && String(d.id) !== x.id) return deny();
      if (!admin) {
        if (!old) return deny();
        for (const fk of FROZEN) { if (fk in old) d[fk] = old[fk]; else delete d[fk]; }
        for (const fk of Object.keys(d)) if (FROZEN_RE.test(fk) && !(fk in old)) delete d[fk];
        for (const fk of Object.keys(old)) if (FROZEN_RE.test(fk)) d[fk] = old[fk];
      }
      // baris tanpa salt/hash tidak boleh menimpa kredensial yang sudah ada (mencegah akun terkunci)
      if (old && old.hash && old.salt && !(d.hash && d.salt)) for (const fk of CRED) { if (fk in old) d[fk] = old[fk]; else delete d[fk]; }
      if (d.hash && !/^[0-9a-f]{64}$/.test(String(d.hash))) return deny();
      if (x.id === me && old && (old.hash !== d.hash || old.salt !== d.salt)) credChanged = d;
    }
  }

  if (!admin) {
    const shop = list.filter((x) => x.kind === 'shop');
    let own = null;
    if (shop.length) {
      const need = new Set();
      for (const x of shop) { need.add(x.id); if (x.data.sid != null) need.add(String(x.data.sid)); }
      own = new Map((await lookup('shop', [...need], 'id,uid:data->>uid')).map((x) => [String(x.id), x.uid]));
    }
    const mainOk = new Set();
    for (const x of shop) if (x.data.hd === undefined && x.data.sid === undefined) {
      if (x.data.uid !== me || /~hd\d+$/.test(x.id)) return deny();
      if (own.has(x.id) && own.get(x.id) !== me) return deny('Stok ini milik akun lain');
      mainOk.add(x.id);
    }
    for (const x of list) {
      const d = x.data;
      if (x.kind === 'users') continue;
      if (x.kind === 'shop') {
        if (mainOk.has(x.id)) continue;
        const sid = String(d.sid);
        if (d.sid == null || !/^\d{1,2}$/.test(String(d.hd)) || x.id !== sid + '~hd' + d.hd || 'uid' in d) return deny();
        if (!(mainOk.has(sid) || own.get(sid) === me)) return deny('Stok ini milik akun lain');
        continue;
      }
      if (x.kind === 'shopinfo') { if (x.id !== me || d.uid !== me) return deny(); continue; }
      if (x.kind === 'logins') { if (!x.id.startsWith(me + '_') || d.uid !== me) return deny(); continue; }
      if (x.kind === 'media') {
        const ks = Object.keys(d);
        if (!/^m_[A-Za-z0-9_-]{6,80}$/.test(x.id) || ks.length !== 1 || ks[0] !== 'u' || typeof d.u !== 'string' || !d.u.startsWith('data:') || d.u.length > 3e6) return deny();
        continue;
      }
      return deny('Hanya admin yang boleh mengubah data ini');
    }
  }

  // media beralamat-isi: tidak pernah menimpa yang sudah ada
  const groups = [[list.filter((x) => x.kind !== 'media'), 'resolution=merge-duplicates,return=minimal'], [list.filter((x) => x.kind === 'media'), 'resolution=ignore-duplicates,return=minimal']];
  let last = null;
  for (const [g, prefer] of groups) {
    if (!g.length) continue;
    last = await db('jb_rows?on_conflict=kind,id', { method: 'POST', headers: fwd({ prefer, 'content-type': 'application/json' }), body: JSON.stringify(g) });
    if (!last.ok) return back(last);
  }
  if (credChanged) H['x-jb-sess'] = await issueFor({ ...credChanged, id: me, role: sess.r }, !!sess.m);  // ganti password sendiri: sesi perangkat ini tetap hidup
  return back(last);
}
