import * as p from './peer-protocol.js';
import * as vault from './vault.js';

export function createPeerUI({unlock,run,message,onChange,scan,canStart}){
  const $=id=>document.getElementById(id);
  let state=null;
  const label=()=>{
    const value=$('peer-contact-label').value.trim();
    if(!value||new TextEncoder().encode(value).length>80)throw Error('Choose a contact name of up to 80 UTF-8 bytes');
    return value;
  };
  const myName=()=>{
    const value=$('peer-my-name').value.trim();
    if(!value||new TextEncoder().encode(value).length>80)throw Error('Enter your name before pairing');
    return value;
  };
  function live(current){
    if(state!==current||!current||current.expiresAt<=p.now())throw Error('Exchange expired or cancelled. Start again.');
  }
  async function display(o){
    if(typeof window.qrcode!=='function')throw Error('Offline QR encoder unavailable. Reconnect and update the app.');
    const text=p.encode(o),qr=window.qrcode(0,'M');qr.addData(text,'Byte');qr.make();
    const svg=new DOMParser().parseFromString(qr.createSvgTag({cellSize:4,margin:16,scalable:true}),'image/svg+xml');
    $('peer-qr').replaceChildren(document.importNode(svg.documentElement,true));
    $('peer-qr-text').value=text;
    $('peer-output').hidden=false;
  }
  function screen(title,instructions,{approve='',scanning=false,contact='',check='',match=false}={}){
    $('peer-flow').hidden=false;$('peer-title').textContent=title;$('peer-instructions').textContent=instructions;
    $('peer-approve').textContent=approve;$('peer-approve').hidden=!approve;
    $('peer-scan-next').hidden=!scanning;
    $('peer-contact-fields').hidden=!contact;
    if(contact)$('peer-contact-label').value=contact;
    $('peer-check').textContent=check;$('peer-comparison').hidden=!check;
    $('peer-match-fields').hidden=!match;$('peer-matches').checked=false;
    $('peer-output').hidden=true;$('peer-qr').replaceChildren();$('peer-qr-text').value='';
    $('peer-paste').hidden=!scanning;$('peer-paste-text').value='';
    $('peer-countdown').textContent='';
    $('peer-approve').disabled=false;
    onChange();
    requestAnimationFrame(()=>$('peer-flow').scrollIntoView({behavior:'smooth',block:'start'}));
  }
  function contactRecord(id,remote,localLabel){return {peerId:remote.fromKeyId,ownKeyId:id.keyId,ownPublic:id.publicKey,peerPublic:remote.fromPublic,label:localLabel,createdAt:p.now()};}
  async function startPair(){
    if(!canStart()||state)throw Error('Finish the current exchange first');
    const name=myName(),key=await unlock('Create a private pairing identity');
    const id=await p.identity(),expiresAt=p.now()+600;
    const invite=await p.sign(id.privateKey,{...p.base('peer-pair-invite',id.keyId,p.random(16),expiresAt),fromPublic:id.publicKey,fromName:name});
    const sealed=await vault.sealPeerDraft(key,id);
    state={stage:'pair-offer',invite,sealed,expiresAt};
    screen('Pair a new phone','Ask the other person to open People, enter their name, and scan this QR. Then scan the reply on their phone.',{scanning:true});
    await display(invite);
  }
  async function startVerify(c){
    if(!canStart()||state)throw Error('Finish the current exchange first');
    const key=await unlock('Verify with '+c.label),privateKey=await vault.openPeer(key,c),expiresAt=p.now()+180;
    const request=await p.sign(privateKey,{...p.base('peer-verify-request',c.ownKeyId,p.random(16),expiresAt),toKeyId:c.peerId,nonce:p.random(32)});
    state={stage:'verify-request',c,request,expiresAt};
    screen('Verify '+c.label,'Ask this contact to scan your QR with their authenticator. Then scan their signed reply.',{scanning:true});
    await display(request);
  }
  async function receive(text){
    const o=p.parse(text);
    if(state)live(state);
    if(o.kind==='peer-pair-invite'){
      if(state)throw Error('Finish or cancel the current exchange first');
      myName();
      if(!await p.verify(o.fromPublic,o))throw Error('Pairing QR signature is invalid');
      if((await vault.peers()).some(c=>c.peerId===o.fromKeyId))throw Error('This pairing is already saved. Use Verify for that contact.');
      state={stage:'pair-invite-review',invite:o,expiresAt:o.expiresAt};
      screen('New pairing request','This is a new, untrusted identity claiming the name “'+o.fromName+'”. Only accept while pairing with the intended person. Choose the contact name you want to save.',{contact:o.fromName,approve:'Accept pairing and show my reply'});
      return;
    }
    if(o.kind==='peer-pair-response'){
      const current=state;
      if(current?.stage!=='pair-offer')throw Error('Start a pairing before scanning its reply');
      await p.requireReply(o,current.invite,'peer-pair-response',o.fromPublic,'inviteHash');live(current);
      if(o.fromKeyId===current.invite.fromKeyId)throw Error('Cannot pair a key with itself');
      current.response=o;current.check=await p.checkCode(current.invite,o);current.stage='pair-review';
      screen('Compare both screens','Ask the other person to read their check code. Both codes must match exactly before you save this contact.',{contact:o.fromName,check:current.check,match:true,approve:'Codes match — save and show final QR'});
      return;
    }
    if(o.kind==='peer-pair-confirm'){
      const current=state;
      if(current?.stage!=='pair-response')throw Error('No pairing is waiting for this final QR');
      await p.requireReply(o,current.response,'peer-pair-confirm',current.invite.fromPublic,'responseHash');live(current);
      if(o.fromKeyId!==current.invite.fromKeyId||o.inviteHash!==await p.hash(current.invite))throw Error('Pairing confirmation does not match');
      current.stage='pair-final-review';
      screen('Finish pairing with '+current.label,'The other phone confirmed this exchange. Compare the check code with its screen, then save the contact here.',{check:current.check,match:true,approve:'Codes match — save this contact'});
      return;
    }
    if(o.kind==='peer-verify-request'){
      if(state)throw Error('Finish or cancel the current exchange first');
      const c=(await vault.peers()).find(c=>c.peerId===o.fromKeyId&&c.ownKeyId===o.toKeyId);
      if(!c)throw Error('Unknown phone or replaced key. Pair together first.');
      if(await vault.seenPeerSession(c.peerId,o.sessionId))throw Error('This verification request was already used');
      const key=await unlock('Unlock to check the requesting phone');
      await vault.openPeer(key,c);
      if(!await p.verify(c.peerPublic,o))throw Error('Known-phone signature did not verify');
      p.validate(o);
      state={stage:'verify-review',c,request:o,expiresAt:o.expiresAt};
      screen('Request signed by '+c.label,'The signature matches your saved contact. Approve a fresh response; final verification requires their reply to your new challenge.',{approve:'Approve and show my response'});
      return;
    }
    if(o.kind==='peer-verify-response'){
      const current=state;if(current?.stage!=='verify-request')throw Error('No verification is waiting for this response');
      p.requireContact(o,current.c);
      await p.requireReply(o,current.request,'peer-verify-response',current.c.peerPublic,'requestHash');live(current);
      current.response=o;current.stage='verify-confirm-review';
      screen(current.c.label+' verified','Their saved key answered your fresh challenge. Approve the final QR so their phone can also complete verification.',{approve:'Approve final confirmation'});
      return;
    }
    if(o.kind==='peer-verify-confirm'){
      const current=state;if(current?.stage!=='verify-response')throw Error('No verification is waiting for a final confirmation');
      p.requireContact(o,current.c);
      await p.requireReply(o,current.response,'peer-verify-confirm',current.c.peerPublic,'responseHash');live(current);
      if(o.requestHash!==await p.hash(current.request))throw Error('Final confirmation belongs to another request');
      const name=current.c.label;
      state=null;screen('Mutual verification complete',name+' answered this phone’s fresh challenge and confirmed your response. Both phones proved their paired keys.');
      message('Mutual verification complete — '+name);await refresh();return;
    }
    throw Error('Unexpected peer message');
  }
  async function approve(){
    const current=state;live(current);
    if(['pair-review','pair-final-review'].includes(current.stage)&&!$('peer-matches').checked)throw Error('Compare the check codes on both phones and confirm that they match');
    const chosenLabel=['pair-invite-review','pair-review'].includes(current.stage)?label():current.label;
    const key=await unlock('Approve phone-to-phone exchange');live(current);
    if(current.stage==='pair-invite-review'){
      const id=await p.identity(),invite=current.invite;
      const response=await p.sign(id.privateKey,{...p.base('peer-pair-response',id.keyId,invite.sessionId,invite.expiresAt),toKeyId:invite.fromKeyId,fromPublic:id.publicKey,fromName:myName(),inviteHash:await p.hash(invite),nonce:p.random(32)});
      current.sealed=await vault.sealPeerDraft(key,id);current.response=response;current.label=chosenLabel;current.check=await p.checkCode(invite,response);current.stage='pair-response';
      screen('Show this reply','Let the other phone scan this QR. Compare the check codes aloud, then scan its final pairing QR.',{scanning:true,check:current.check});await display(response);return;
    }
    if(current.stage==='pair-review'){
      const id=await vault.openPeerDraft(key,current.sealed),invite=current.invite,response=current.response;
      const final=await p.sign(id.privateKey,{...p.base('peer-pair-confirm',id.keyId,invite.sessionId,invite.expiresAt),toKeyId:response.fromKeyId,inviteHash:await p.hash(invite),responseHash:await p.hash(response)});
      live(current);await vault.savePeer(key,contactRecord(id,response,chosenLabel),id.privateKey);
      current.sealed=null;current.stage='pair-saved';
      screen('Contact saved here','Have the other phone scan this final QR and confirm the matching check code to finish saving its contact.',{check:current.check});await display(final);message('Saved '+chosenLabel+'. Finish the exchange on the other phone.');return;
    }
    if(current.stage==='pair-final-review'){
      const id=await vault.openPeerDraft(key,current.sealed);live(current);
      await vault.savePeer(key,contactRecord(id,current.invite,current.label),id.privateKey);
      const name=current.label;state=null;screen('Pairing complete','Saved '+name+'. You can now verify each other later, with either phone starting.');message('Pairing complete — '+name);await refresh();return;
    }
    if(current.stage==='verify-review'){
      const privateKey=await vault.openPeer(key,current.c),request=current.request;
      const response=await p.sign(privateKey,{...p.base('peer-verify-response',current.c.ownKeyId,request.sessionId,request.expiresAt),toKeyId:current.c.peerId,requestHash:await p.hash(request),nonce:p.random(32)});
      live(current);await vault.consumePeerSession(current.c.peerId,request.sessionId,request.expiresAt);
      current.response=response;current.stage='verify-response';
      screen('Show your response to '+current.c.label,'Let their phone scan this reply, then scan their final confirmation. Verification is not complete on this phone yet.',{scanning:true});await display(response);return;
    }
    if(current.stage==='verify-confirm-review'){
      const privateKey=await vault.openPeer(key,current.c),request=current.request,response=current.response;
      const final=await p.sign(privateKey,{...p.base('peer-verify-confirm',current.c.ownKeyId,request.sessionId,request.expiresAt),toKeyId:current.c.peerId,requestHash:await p.hash(request),responseHash:await p.hash(response)});
      live(current);current.stage='verify-confirmed';
      screen(current.c.label+' verified','Your phone verified their fresh response. Have them scan this final QR to complete verification on their phone.');await display(final);message('Known key verified — '+current.c.label);return;
    }
    throw Error('This step has already been completed');
  }
  async function refresh(){
    const container=$('peer-contacts');container.replaceChildren();
    const contacts=await vault.peers();contacts.sort((a,b)=>a.label.localeCompare(b.label));
    for(const c of contacts){
      const row=document.createElement('div');row.className='credential';
      const name=document.createElement('strong');name.textContent=c.label;
      const verify=document.createElement('button');verify.textContent='Verify';verify.addEventListener('click',()=>run(()=>startVerify(c)));
      const remove=document.createElement('button');remove.className='secondary';remove.textContent='Forget';remove.addEventListener('click',()=>run(async()=>{if(state)throw Error('Finish the current exchange first');if(confirm('Forget '+c.label+'? Pair together again to recognise a replacement key. This does not remove your record from their phone.')){await vault.removePeer(c.peerId);await refresh();}}));
      row.append(name,document.createElement('br'),verify,remove);container.append(row);
    }
    if(!contacts.length)container.textContent='No paired people yet.';
  }
  $('peer-start').addEventListener('click',()=>run(startPair));
  $('peer-approve').addEventListener('click',()=>run(approve));
  $('peer-scan').addEventListener('click',()=>run(scan));
  $('peer-scan-next').addEventListener('click',()=>run(scan));
  $('peer-read-paste').addEventListener('click',()=>run(async()=>{const text=$('peer-paste-text').value.trim();$('peer-paste-text').value='';await receive(text);}));
  $('peer-read-incoming').addEventListener('click',()=>run(async()=>{const text=$('peer-incoming').value.trim();$('peer-incoming').value='';await receive(text);}));
  $('peer-finish').addEventListener('click',()=>run(async()=>{state=null;$('peer-flow').hidden=true;$('peer-qr').replaceChildren();$('peer-qr-text').value='';await onChange();}));
  setInterval(()=>{if(!state)return;const left=Math.max(0,state.expiresAt-p.now());$('peer-countdown').textContent=left?'Expires in '+left+' seconds':'Expired — finish and start again';$('peer-approve').disabled=!left;if(!left){$('peer-qr').replaceChildren();$('peer-qr-text').value='';$('peer-scan-next').hidden=true;}},1000);
  return {receive,refresh,active:()=>!!state,clear:()=>{state=null;}};
}
