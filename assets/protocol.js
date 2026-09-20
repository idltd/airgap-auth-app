// Protocol v1: only closed, flat objects containing strings and safe integers.
export const utf8 = new TextEncoder();
export function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,''); }
export function unb64(s, length=0) { if (typeof s!=='string'||!/^[A-Za-z0-9_-]+$/.test(s)) throw Error('Invalid encoding'); let b; try { b=Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0)); } catch { throw Error('Invalid encoding'); } if ((length&&b.length!==length)||b64(b)!==s) throw Error('Invalid encoding'); return b; }
export function canonical(o) { if (!o||Array.isArray(o)||typeof o!=='object') throw Error('Invalid object'); const keys=Object.keys(o).sort(); for(const k of keys) {const v=o[k];if(typeof v!=='string'&&!Number.isSafeInteger(v))throw Error('Invalid value');if(typeof v==='string'&&v!==v.toWellFormed())throw Error('Invalid Unicode');} return '{'+keys.map(k=>JSON.stringify(k)+':'+JSON.stringify(o[k])).join(',')+'}'; }
export function origin(s,local=false) { const u=new URL(s); if(u.username||u.password||u.pathname!=='/'||u.search||u.hash||/[\\\s?#]/.test(s)||!(u.protocol==='https:'||(local&&u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname))))throw Error('Invalid origin');return u.origin; }
export async function key(root,site,id,direction) { const salt=await crypto.subtle.digest('SHA-256',utf8.encode('agauth/v1\0'+site+'\0'+id)); const k=await crypto.subtle.importKey('raw',root,'HKDF',false,['deriveBits']); return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt,info:utf8.encode(direction)},k,256)); }
async function hmacKey(k,usage){return crypto.subtle.importKey('raw',k,{name:'HMAC',hash:'SHA-256'},false,[usage]);}
export async function mac(k,o){return new Uint8Array(await crypto.subtle.sign('HMAC',await hmacKey(k,'sign'),utf8.encode(canonical(o))));}
export async function verify(k,o,m){try{return await crypto.subtle.verify('HMAC',await hmacKey(k,'verify'),unb64(m,32),utf8.encode(canonical(o)));}catch{return false;}}
export function decimal(m){let n=0n;for(const b of m.slice(0,8))n=(n<<8n)|BigInt(b);return (n%10000000000n).toString().padStart(10,'0');}
export async function code(k,o){return decimal(await mac(k,o));}
export function normalizeCode(s){if(!/^\d{5}[ -]?\d{5}$/.test(s))throw Error('Enter ten digits, optionally separated in the middle');return s.replace(/[ -]/g,'');}
export function displayCode(s){return s.slice(0,5)+' '+s.slice(5);}
export function transcript(o,kind,phone){const r={v:1,kind,origin:o.origin,keyId:o.keyId,expiresAt:o.expiresAt};if(kind==='enrollment-confirmation')r.enrollmentId=o.enrollmentId;else{r.sessionId=o.sessionId;r.serverNonce=o.serverNonce;}if(kind==='site-response'){r.phoneCode=phone;r.result='accepted';}return r;}
export function unsigned(o){const r={...o};delete r.challengeMac;return r;}
export function qr(o){return 'agauth:1:'+b64(utf8.encode(canonical(o)));}
export function parseQR(text,now=Math.floor(Date.now()/1000),local=false){
 if(!text.startsWith('agauth:1:')||text.length>5500)throw Error('Unsupported QR');const raw=unb64(text.slice(9));if(raw.length>4096)throw Error('QR too large');const json=new TextDecoder('utf-8',{fatal:true}).decode(raw);const o=JSON.parse(json);if(canonical(o)!==json)throw Error('QR must use canonical JSON without duplicate fields');
 const common=['v','kind','issuer','accountLabel','origin','keyId','issuedAt','expiresAt'];let extra;if(o.kind==='enrollment')extra=['enrollmentId','rootSecret'];else if(o.kind==='authentication-challenge')extra=['sessionId','serverNonce','operation','challengeMac'];else throw Error('Unsupported QR kind');const fields=[...common,...extra];if(Object.keys(o).length!==fields.length||fields.some(k=>!Object.hasOwn(o,k))||o.v!==1)throw Error('Invalid QR fields');
 for(const k of fields){if(['v','issuedAt','expiresAt'].includes(k)){if(!Number.isSafeInteger(o[k])||o[k]<0)throw Error('Invalid time');}else if(typeof o[k]!=='string'||!o[k]||utf8.encode(o[k]).length>512)throw Error('Invalid field');}
 if(origin(o.origin,local)!==o.origin)throw Error('Noncanonical origin');unb64(o.keyId,16);if(o.issuedAt>now+30||o.expiresAt<=now||o.expiresAt<=o.issuedAt||o.expiresAt-o.issuedAt>(o.kind==='enrollment'?600:120))throw Error('QR expired or invalid time');
 if(o.kind==='enrollment'){unb64(o.enrollmentId,16);unb64(o.rootSecret,32);}else{unb64(o.sessionId,16);unb64(o.serverNonce,32);unb64(o.challengeMac,32);}return o;
}
