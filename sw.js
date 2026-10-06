'use strict';
const VERSION='0.1.1', CACHE='agauth-'+VERSION;
const ASSETS=['./',
'manifest.webmanifest',
'config.js',
'assets/style.css',
'assets/icon.svg',
'assets/protocol.js',
'assets/peer-protocol.js',
'assets/peer-ui.js',
'assets/vault.js',
'assets/authenticator.js',
'assets/jsQR.js',
'assets/qrcode.js'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS.map(url=>new Request(url,{cache:'reload'}))))));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('message',event=>{if(event.data?.type==='ACTIVATE')self.skipWaiting();if(event.data?.type==='STATUS')event.waitUntil(caches.open(CACHE).then(async cache=>{const all=await Promise.all(ASSETS.map(url=>cache.match(url)));if(all.every(Boolean))event.source?.postMessage({type:'READY',version:VERSION});}));});
self.addEventListener('fetch',event=>{const u=new URL(event.request.url);if(event.request.method!=='GET'||u.origin!==self.location.origin)return;const rel=u.pathname.startsWith(self.registration.scope)?u.pathname.slice(self.registration.scope.length):null;if(rel===null||!ASSETS.includes(rel==='.'||rel===''?'./':rel))return;event.respondWith(caches.open(CACHE).then(async cache=>(await cache.match(event.request))||fetch(event.request)));});
