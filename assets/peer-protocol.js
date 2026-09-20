// Separate from website protocol v1: signed, flat peer transcripts.
import {b64,unb64,utf8,canonical} from './protocol.js';

export const PREFIX='agauth-peer:1:';
export const now=()=>Math.floor(Date.now()/1000);
export const random=n=>b64(crypto.getRandomValues(new Uint8Array(n)));
const algorithm={name:'ECDSA',namedCurve:'P-256'};
const signing={name:'ECDSA',hash:'SHA-256'};
const common=['v','kind','sessionId','fromKeyId','issuedAt','expiresAt','signature'];
const fields={
  'peer-pair-invite':['fromPublic','fromName'],
  'peer-pair-response':['toKeyId','fromPublic','fromName','inviteHash','nonce'],
  'peer-pair-confirm':['toKeyId','inviteHash','responseHash'],
  'peer-verify-request':['toKeyId','nonce'],
  'peer-verify-response':['toKeyId','requestHash','nonce'],
  'peer-verify-confirm':['toKeyId','requestHash','responseHash'],
};
export function unsigned(o){const result={...o};delete result.signature;return result;}
export function encode(o){return PREFIX+b64(utf8.encode(canonical(o)));}
export function validate(o,at=now()){
  const extra=fields[o.kind];
  if(!extra||o.v!==1)throw Error('Unsupported phone-to-phone message');
  const expected=[...common,...extra];
  if(Object.keys(o).length!==expected.length||expected.some(k=>!Object.hasOwn(o,k)))throw Error('Invalid peer message fields');
  for(const k of ['issuedAt','expiresAt'])if(!Number.isSafeInteger(o[k])||o[k]<0)throw Error('Invalid peer message time');
  const life=o.kind.startsWith('peer-pair-')?600:180;
  if(o.issuedAt>at+30||o.expiresAt<=at||o.expiresAt<=o.issuedAt||o.expiresAt-o.issuedAt>life)throw Error('Peer QR expired or phone clocks disagree');
  for(const k of ['sessionId','fromKeyId','toKeyId'])if(expected.includes(k))unb64(o[k],16);
  for(const k of ['nonce','inviteHash','requestHash','responseHash'])if(expected.includes(k))unb64(o[k],32);
  unb64(o.signature,64);
  if(expected.includes('fromPublic')){const pub=unb64(o.fromPublic,65);if(pub[0]!==4)throw Error('Invalid peer public key');}
  if(expected.includes('fromName')&&(typeof o.fromName!=='string'||!o.fromName.trim()||utf8.encode(o.fromName).length>80||o.fromName!==o.fromName.toWellFormed()||/[\u0000-\u001f\u007f]/.test(o.fromName)))throw Error('Enter a name of up to 80 UTF-8 bytes');
  return o;
}
export function parse(text,at=now()){
  if(!text.startsWith(PREFIX)||text.length>5500)throw Error('Not a phone-to-phone QR');
  const bytes=unb64(text.slice(PREFIX.length));if(bytes.length>4096)throw Error('Peer QR too large');
  const json=new TextDecoder('utf-8',{fatal:true}).decode(bytes),o=JSON.parse(json);
  if(canonical(o)!==json)throw Error('Peer QR must use canonical JSON without duplicate fields');
  return validate(o,at);
}
export async function identity(){
  const keys=await crypto.subtle.generateKey(algorithm,true,['sign','verify']);
  return {keyId:random(16),publicKey:b64(await crypto.subtle.exportKey('raw',keys.publicKey)),privateKey:await crypto.subtle.exportKey('jwk',keys.privateKey)};
}
export async function sign(privateJWK,o){
  const key=await crypto.subtle.importKey('jwk',privateJWK,algorithm,false,['sign']);
  const signature=b64(await crypto.subtle.sign(signing,key,utf8.encode(canonical(unsigned(o)))));
  return validate({...unsigned(o),signature});
}
export async function verify(publicKey,o){
  try{validate(o);const key=await crypto.subtle.importKey('raw',unb64(publicKey,65),algorithm,false,['verify']);
    return await crypto.subtle.verify(signing,key,unb64(o.signature,64),utf8.encode(canonical(unsigned(o))));
  }catch{return false;}
}
// Hash the entire signed message so every response binds the exact preceding QR.
export async function hash(o){return b64(await crypto.subtle.digest('SHA-256',utf8.encode(canonical(o))));}
export async function checkCode(invite,response){
  const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',utf8.encode('agauth/peer/v1/pair-check\0'+await hash(invite)+'\0'+await hash(response))));
  return Array.from(bytes.slice(0,8),b=>b.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{4}/g).join(' ');
}
export function base(kind,id,sessionId,expiresAt){return {v:1,kind,sessionId,fromKeyId:id,issuedAt:now(),expiresAt};}
export async function requireReply(o,previous,kind,publicKey,hashField){
  validate(o);validate(previous);
  if(o.kind!==kind||o.sessionId!==previous.sessionId||o.toKeyId!==previous.fromKeyId||o.expiresAt!==previous.expiresAt||o[hashField]!==await hash(previous)||!await verify(publicKey,o))throw Error('This reply does not authenticate the pending exchange');
}
export function requireContact(o,c){
  if(o.fromKeyId!==c.peerId||o.toKeyId!==c.ownKeyId)throw Error('This QR belongs to a different pairing');
}
