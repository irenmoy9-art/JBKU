// JBKu service worker — aplikasi disimpan di HP: dibuka instan, tetap jalan saat sinyal lemah / server sibuk.
const C='jbku-v3';
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{
  const r=e.request,u=new URL(r.url);
  if(r.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/'))return;
  if(r.mode==='navigate'){
    e.respondWith(fetch(r).then(res=>{
      // simpan hanya halaman aplikasi asli (±7 MB), bukan halaman tantangan anti-bot
      const n=+res.headers.get('content-length')||0;
      if(res.ok&&(n===0||n>200000)){const cp=res.clone();cp.text().then(t=>{if(t.length>200000&&t.includes('id="jbCover"'))caches.open(C).then(c=>c.put(u.pathname,new Response(t,{headers:{'content-type':'text/html; charset=utf-8'}})))})}
      return res}).catch(()=>caches.open(C).then(c=>c.match(u.pathname)).then(x=>x||Response.error())));
    return}
  if(/\.(png|webp|jpg|svg|woff2|webmanifest)$/.test(u.pathname))e.respondWith(caches.open(C).then(c=>c.match(r).then(x=>x||fetch(r).then(res=>{if(res.ok)c.put(r,res.clone());return res}))));
});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(self.clients.matchAll({type:'window'}).then(l=>l.length?l[0].focus():self.clients.openWindow('/')))});
