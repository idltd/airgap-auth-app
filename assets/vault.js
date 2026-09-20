import {b64,unb64,utf8} from './protocol.js';
let database;
async function db(){if(database)return database;database=await new Promise((resolve,reject)=>{const r=indexedDB.open('agauth-vault',2);r.onupgradeneeded=()=>{for(const [name,options]of [['settings',undefined],['credentials',{keyPath:'keyId'}],['peers',{keyPath:'peerId'}],['peer-replays',undefined]])if(!r.result.objectStoreNames.contains(name))r.result.createObjectStore(name,options);};r.onsuccess=()=>{r.result.onversionchange=()=>{r.result.close();database=null;};resolve(r.result);};r.onerror=()=>{database=null;reject(Error('Local storage unavailable'));};r.onblocked=()=>reject(Error('Close other authenticator tabs to finish the storage upgrade. Do not clear browser data.'));});return database;}
async function transaction(store,mode,fn){const d=await db();return new Promise((resolve,reject)=>{const t=d.transaction(store,mode);let result;try{const r=fn(t.objectStore(store));r.onsuccess=()=>{result=r.result;};}catch(e){reject(e);return;}t.oncomplete=()=>resolve(result);t.onerror=()=>reject(Error('Local storage failed'));t.onabort=()=>reject(Error('Local storage transaction aborted'));});}
export const metadata=()=>transaction('settings','readonly',s=>s.get('vault'));
export const list=()=>transaction('credentials','readonly',s=>s.getAll());
export const remove=id=>transaction('credentials','readwrite',s=>s.delete(id));
async function derivePRF(output){const k=await crypto.subtle.importKey('raw',output,'HKDF',false,['deriveKey']);return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:utf8.encode('agauth/v1/vault'),info:utf8.encode('vault-wrapping')},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
async function derivePassphrase(pass,m){const k=await crypto.subtle.importKey('raw',utf8.encode(pass),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:unb64(m.salt,16),iterations:m.iterations},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
const salt=utf8.encode('agauth/v1/webauthn-prf/vault');
async function prf(id){const c=await navigator.credentials.get({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rpId:location.hostname,allowCredentials:[{id:unb64(id),type:'public-key'}],userVerification:'required',extensions:{prf:{eval:{first:salt}}},timeout:60000}});const out=c.getClientExtensionResults().prf?.results?.first;if(!out||out.byteLength!==32)throw Error('This passkey did not return PRF output. No automatic fallback is enabled.');return derivePRF(out);}
export async function setup(mode,pass,allowDemo){if(await metadata())throw Error('Vault already exists');let m,k;if(mode==='passphrase'){if(!allowDemo)throw Error('Demo fallback disabled');if(pass.length<16)throw Error('Use a local passphrase of at least 16 characters');m={version:1,mode,salt:b64(crypto.getRandomValues(new Uint8Array(16))),iterations:600000};k=await derivePassphrase(pass,m);}else{if(!window.PublicKeyCredential)throw Error('WebAuthn unavailable');const c=await navigator.credentials.create({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rp:{name:'Airgap Auth',id:location.hostname},user:{id:crypto.getRandomValues(new Uint8Array(16)),name:'Airgap vault',displayName:'Airgap vault'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'required',userVerification:'required'},extensions:{prf:{}},timeout:60000}});if(!c.getClientExtensionResults().prf?.enabled)throw Error('PRF unsupported by this passkey. Vault was not created.');m={version:1,mode:'prf',credentialId:b64(c.rawId)};k=await prf(m.credentialId);}
 m.check=await encrypt(k,{purpose:'vault-check'},'agauth/v1/vault-check');await transaction('settings','readwrite',s=>s.put(m,'vault'));const saved=await metadata();if(JSON.stringify(saved)!==JSON.stringify(m))throw Error('Vault setup did not persist');await navigator.storage?.persist?.();return m;
}
export async function unlock(pass){const m=await metadata();if(!m||m.version!==1)throw Error('Vault not set up or unsupported vault version');const k=m.mode==='prf'?await prf(m.credentialId):await derivePassphrase(pass,m);try{const check=await decrypt(k,m.check,'agauth/v1/vault-check');if(check.purpose!=='vault-check')throw Error();}catch{throw Error('Vault could not be unlocked');}return k;}
async function encrypt(key,value,aad){const iv=crypto.getRandomValues(new Uint8Array(12));const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(aad)},key,utf8.encode(JSON.stringify(value)));return{iv:b64(iv),cipher:b64(cipher)};}
async function decrypt(key,value,aad){const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(value.iv,12),additionalData:utf8.encode(aad)},key,unb64(value.cipher));return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));}
const aad=c=>'agauth/v1/credential\0'+c.keyId+'\0'+c.origin;
export async function save(key,o){const record={keyId:o.keyId,origin:o.origin,issuer:o.issuer,accountLabel:o.accountLabel,version:1};record.sealed=await encrypt(key,{rootSecret:o.rootSecret,keyId:o.keyId,origin:o.origin},aad(record));await transaction('credentials','readwrite',s=>s.put(record));const saved=await transaction('credentials','readonly',s=>s.get(o.keyId));if(JSON.stringify(record)!==JSON.stringify(saved))throw Error('Credential was not saved');await open(key,saved);}
export async function open(key,c){const secret=await decrypt(key,c.sealed,aad(c));if(secret.keyId!==c.keyId||secret.origin!==c.origin)throw Error('Credential integrity failure');return unb64(secret.rootSecret,32);}

export const peers=()=>transaction('peers','readonly',s=>s.getAll());
export const removePeer=id=>transaction('peers','readwrite',s=>s.delete(id));
const peerAAD=c=>'agauth/peer/v1/contact\0'+JSON.stringify([c.peerId,c.ownKeyId,c.ownPublic,c.peerPublic,c.label,c.createdAt]);
export async function savePeer(key,contact,privateKey){
  const record={...contact,version:1};
  record.sealed=await encrypt(key,{privateKey},peerAAD(record));
  // add (not put) prevents silently replacing a previously paired identity.
  await transaction('peers','readwrite',s=>s.add(record));
  const saved=await transaction('peers','readonly',s=>s.get(record.peerId));
  if(JSON.stringify(saved)!==JSON.stringify(record))throw Error('Contact was not saved');
  await openPeer(key,saved);return saved;
}
export async function openPeer(key,contact){
  if(contact.version!==1)throw Error('Unsupported contact version');
  const secret=await decrypt(key,contact.sealed,peerAAD(contact));
  return secret.privateKey;
}
export const sealPeerDraft=(key,identity)=>encrypt(key,identity,'agauth/peer/v1/draft');
export const openPeerDraft=(key,sealed)=>decrypt(key,sealed,'agauth/peer/v1/draft');
export async function seenPeerSession(peerId,sessionId){return !!await transaction('peer-replays','readonly',s=>s.get(peerId+':'+sessionId));}
export async function consumePeerSession(peerId,sessionId,expiresAt){
  const d=await db();
  await new Promise((resolve,reject)=>{
    const t=d.transaction('peer-replays','readwrite'),s=t.objectStore('peer-replays');
    s.add(expiresAt,peerId+':'+sessionId);
    const cursor=s.openCursor(),now=Math.floor(Date.now()/1000);
    cursor.onsuccess=()=>{const c=cursor.result;if(c){if(c.value<=now)c.delete();c.continue();}};
    t.oncomplete=resolve;t.onerror=()=>reject(Error('This exchange was already used or could not be recorded'));t.onabort=t.onerror;
  });
}
