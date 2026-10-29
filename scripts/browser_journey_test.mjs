// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Real-browser WebAuthn ceremonies use Chromium's standard virtual-authenticator
// testing interface, not a server authentication bypass or a fake response UI.
import assert from "node:assert/strict";
import {spawn,execFileSync} from "node:child_process";
import {readFileSync,mkdirSync,mkdtempSync,rmSync} from "node:fs";
import {join,resolve} from "node:path";
import {setTimeout as delay} from "node:timers/promises";

const root=resolve(import.meta.dirname,".."),fixture=JSON.parse(readFileSync(0,"utf8"));
const executable=process.env.MEMBER_BROWSER;assert.ok(executable,"MEMBER_BROWSER is required");
const expected=/^version = "([^"]+)"$/m.exec(readFileSync(join(root,"scripts/browser.toml"),"utf8"))[1];
assert.equal(execFileSync(executable,["--version"],{encoding:"utf8",timeout:10000}).trim(),expected);
const node=/^node_version = "([^"]+)"$/m.exec(readFileSync(join(root,"scripts/wasm.toml"),"utf8"))[1];assert.equal(process.version,node);
mkdirSync(join(root,".cache/tests"),{recursive:true});const profile=mkdtempSync(join(root,".cache/tests/journey-"));
const child=spawn(executable,["--headless","--remote-debugging-pipe",`--user-data-dir=${profile}`,`--ignore-certificate-errors-spki-list=${fixture.pins}`,"--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-sync","--disable-extensions","--disable-breakpad","--disable-crash-reporter","about:blank"],{stdio:["ignore","ignore","pipe","pipe","pipe"]});
let buffer=Buffer.alloc(0),sequence=0,exited=false;const pending=new Map(),listeners=new Set();let diagnostics="";
child.stderr.on("data",(b)=>{if(diagnostics.length<4096)diagnostics+=b.toString();});
function fail(){exited=true;for(const entry of pending.values()){clearTimeout(entry.timer);entry.reject(new Error("browser pipe closed: "+diagnostics.slice(0,1024)));}pending.clear();}
child.once("exit",fail);child.once("error",fail);child.stdio[3].on("error",fail);child.stdio[4].on("error",fail);
child.stdio[4].on("data",(data)=>{buffer=Buffer.concat([buffer,data]);if(buffer.length>2*1024*1024){child.kill("SIGKILL");return;}let end;while((end=buffer.indexOf(0))!==-1){const message=JSON.parse(buffer.subarray(0,end).toString());buffer=buffer.subarray(end+1);if(message.id){const entry=pending.get(message.id);if(!entry)continue;clearTimeout(entry.timer);pending.delete(message.id);if(message.error)entry.reject(new Error(`Browser command failed: ${entry.method}`));else entry.resolve(message.result);}else for(const listener of listeners)listener(message);}});
function send(method,params={},sessionId){if(exited)return Promise.reject(new Error("browser unavailable"));const id=++sequence;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`Timed out: ${method}`));},120000);pending.set(id,{resolve,reject,timer,method});child.stdio[3].write(JSON.stringify({id,method,params,sessionId})+"\0");});}
async function evaluate(page,expression){const out=await send("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true,userGesture:true},page.sessionId);if(out.exceptionDetails)throw new Error("Page evaluation failed");return out.result.value;}
async function until(page,expression,label){const deadline=Date.now()+45000;while(Date.now()<deadline){if(exited)throw new Error("browser exited: "+diagnostics);if(await evaluate(page,expression))return;await delay(50);}const status=await evaluate(page,"document.getElementById('status')?.textContent");throw new Error(`${label}: ${status}`);}
async function activate(page){await send("Target.activateTarget",{targetId:page.targetId});await until(page,"document.visibilityState==='visible'","foreground page");}
const identity="https://identity.localhost:8443",anonymous="https://submit.localhost:8444";
const passphrase="Synthetic local unlock phrase é and independent words";
const answer="Synthetic confidential browser answer: improve the shared review process.";
let submitted=null,submitCount=0,lastAssertion=null;const urls=new Map(),leaks=new Set();
listeners.add((m)=>{
  if(m.method==="Network.requestWillBeSent"){
    const r=m.params.request;urls.set(m.sessionId+":"+m.params.requestId,r.url);const u=new URL(r.url);
    // DevTools also reports local data/about resources. They do not contact an
    // origin. Every actual network-origin request still requires exact matching.
    if(![identity,anonymous].includes(u.origin)&&!["devtools:","data:","about:"].includes(u.protocol))leaks.add("unexpected-origin-scheme:"+u.protocol);
    if(r.postData&&(r.postData.includes(passphrase)||r.postData.includes(answer)))leaks.add("sensitive-request-body");
    if(u.origin===anonymous&&r.headers?.Referer)leaks.add("anonymous-referrer:"+u.pathname);
    if(u.origin===anonymous&&u.pathname==="/api/browser/submit"&&r.method==="POST"){submitted=JSON.parse(r.postData);submitCount++;if(Object.keys(submitted).sort().join()!=="envelope,round,token")leaks.add("anonymous-submit-extra-fields");}
    if(u.origin===identity&&u.pathname==="/api/browser/auth/login/finish"&&r.postData)lastAssertion=JSON.parse(r.postData);
  }
  if(m.method==="Network.requestWillBeSentExtraInfo"&&urls.get(m.sessionId+":"+m.params.requestId)?.startsWith(anonymous)){
    for(const key of Object.keys(m.params.headers))if(["cookie","authorization","referer"].includes(key.toLowerCase()))leaks.add("anonymous-credential-header:"+key.toLowerCase());
  }
});
async function attach(targetId){const {sessionId}=await send("Target.attachToTarget",{targetId,flatten:true});const page={targetId,sessionId};await send("Network.enable",{},sessionId);await send("Page.enable",{},sessionId);return page;}
async function page(context,url=identity+"/"){const {targetId}=await send("Target.createTarget",{url:"about:blank",browserContextId:context});const p=await attach(targetId);await send("WebAuthn.enable",{enableUI:false},p.sessionId);await send("WebAuthn.addVirtualAuthenticator",{options:{protocol:"ctap2",transport:"internal",hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}},p.sessionId);await send("Page.navigate",{url},p.sessionId);await activate(p);await until(p,"document.readyState==='complete'&&document.getElementById('status')","page startup");return p;}
async function set(page,id,value){await evaluate(page,`document.getElementById(${JSON.stringify(id)}).value=${JSON.stringify(value)}`);}
async function click(page,id){await evaluate(page,`document.getElementById(${JSON.stringify(id)}).click()`);}
async function register(page,name,bootstrap=""){await until(page,"!document.getElementById('register').disabled","registration ready");await set(page,"username",name);await set(page,"bootstrap",bootstrap);await click(page,"register");await until(page,`document.getElementById('account').textContent.includes(${JSON.stringify(name)})`,"verified registration");}
const lifetime=setTimeout(()=>child.kill("SIGKILL"),240000);
try{
  const adminContext=(await send("Target.createBrowserContext")).browserContextId;
  const reviewerContext=(await send("Target.createBrowserContext")).browserContextId;
  const memberContext=(await send("Target.createBrowserContext")).browserContextId;
  const administrator=await page(adminContext);await register(administrator,"administrator",fixture.bootstrap);fixture.bootstrap="";
  assert.equal(await evaluate(administrator,"import('/assets/common.mjs').then(m=>m.api('/api/browser/me')).then(m=>m.administrator)"),true,"bootstrap administrator role must persist");
  const reviewer=await page(reviewerContext);await register(reviewer,"reviewer_one");
  const member=await page(memberContext);await register(member,"member_one");
  const rejectedAuthentication=await evaluate(member,`import('/assets/common.mjs').then(async m=>{await m.api('/api/browser/auth/login/begin',{name:'member_one',bootstrap:''});return fetch('/api/browser/auth/login/finish',{method:'POST',headers:{'Content-Type':'application/json','X-Anonce-CSRF':'1'},body:'{}'}).then(r=>r.status);})`);assert.equal(rejectedAuthentication,403,"malformed assertion must not authenticate");
  await click(member,"login");await until(member,"document.getElementById('status').textContent.startsWith('Account authenticated')","verified passkey sign-in");assert.ok(lastAssertion);
  const replay=await evaluate(member,`fetch('/api/browser/auth/login/finish',{method:'POST',headers:{'Content-Type':'application/json','X-Anonce-CSRF':'1'},body:JSON.stringify(${JSON.stringify(lastAssertion)})}).then(r=>r.status)`);assert.equal(replay,403,"consumed authentication ceremony must reject replay");
  // Registration/sign-in, CSRF rejection and the ordinary browser vault flow.
  const csrf=await evaluate(member,`fetch('/api/browser/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.status)`);assert.equal(csrf,403);
  await set(member,"passphrase",passphrase);await set(member,"confirmation","different synthetic confirmation");await click(member,"setup");await until(member,"document.getElementById('status').textContent.startsWith('Operation failed')","password confirmation rejection");
  await set(member,"passphrase",passphrase);await set(member,"confirmation",passphrase);await click(member,"setup");await until(member,"document.getElementById('status').textContent.startsWith('Encrypted member backup stored')","browser member setup and persistence");
  assert.equal(await evaluate(member,"[...document.querySelectorAll('input[type=password]')].every(e=>e.value==='')"),true);
  const stored=await evaluate(member,"import('/assets/common.mjs').then(m=>m.api('/api/browser/backup'))");assert.equal(typeof stored.backup,"string");
  await evaluate(member,`import('/assets/common.mjs').then(m=>m.localRecord('member-public:member_one','${"A".repeat(43)}'))`);await click(member,"cancel");await set(member,"passphrase",passphrase);await click(member,"unlock");await until(member,"document.getElementById('status').textContent.startsWith('Operation failed')","wrong-key expected binding rejection");
  await evaluate(member,`import('/assets/common.mjs').then(m=>m.localRecord('member-public:member_one',${JSON.stringify(stored.public_key)}))`);
  await click(member,"cancel");await set(member,"passphrase","wrong synthetic passphrase");await click(member,"unlock");await until(member,"document.getElementById('status').textContent.startsWith('Operation failed')","wrong-password restoration rejection");
  await set(member,"passphrase",passphrase);await click(member,"unlock");await until(member,"document.getElementById('status').textContent.startsWith('Member key restored')","expected-key restoration");
  await activate(administrator);await click(administrator,"invite");await until(administrator,"document.getElementById('invitation').textContent.startsWith('Single-use')","authorized membership invitation");const code=await evaluate(administrator,"document.getElementById('invitation').textContent.match(/[A-Za-z0-9_-]{43}/)[0]");
  await activate(member);await set(member,"passphrase",passphrase);await click(member,"unlock");await until(member,"document.getElementById('status').textContent.startsWith('Member key restored')","restore after background locking");await set(member,"code",code);await click(member,"enroll");await until(member,"document.getElementById('status').textContent.startsWith('Membership verified')","single-use enrollment");
  await activate(administrator);
  const now=Date.now();await set(administrator,"question","Describe one improvement.");await set(administrator,"reviewer","reviewer_one");await set(administrator,"opens",new Date(now-60000).toISOString().slice(0,16));await set(administrator,"closes",new Date(now+3600000).toISOString().slice(0,16));await set(administrator,"review-until",new Date(now+86400000).toISOString().slice(0,16));await set(administrator,"limit","1");
  assert.deepEqual(await evaluate(administrator,"[...document.getElementById('round').elements].filter(e=>!e.validity.valid).map(e=>({id:e.id,message:e.validationMessage}))"),[],"draft fields must satisfy native browser validation");
  await evaluate(administrator,"document.getElementById('round').requestSubmit()");await until(administrator,"document.getElementById('status').textContent.startsWith('Draft created')","authorized draft creation");
  const round=await evaluate(administrator,"import('/assets/common.mjs').then(m=>m.api('/api/browser/rounds')).then(r=>r[0].id)");
  await activate(reviewer);await click(reviewer,"refresh");await until(reviewer,"document.getElementById('review-pass-'+"+JSON.stringify(round)+")!==null","assigned reviewer form");await set(reviewer,`review-pass-${round}`,passphrase);await set(reviewer,`review-confirm-${round}`,passphrase);await evaluate(reviewer,"document.getElementById('review-pass-'+"+JSON.stringify(round)+").form.requestSubmit()");await until(reviewer,"document.getElementById('status').textContent.startsWith('Round reviewer key prepared')","local reviewer key and encrypted browser persistence");
  await activate(administrator);await click(administrator,"refresh");await until(administrator,"document.getElementById('rounds').textContent.includes('reviewer key prepared')","reviewer readiness");await evaluate(administrator,"[...document.querySelectorAll('#rounds button')].find(b=>b.textContent.startsWith('Confirm one-response')).click()");await until(administrator,"document.getElementById('status').textContent.startsWith('Published the common')","signed publication and anonymous provisioning");
  // The member's authenticated session remains identity-side while a separate
  // context prepares blind state, encrypts, submits, and verifies acceptance.
  const response=await page(memberContext,anonymous+"/?round="+round);await until(response,"!document.getElementById('authorize').disabled","verified common bulletin");
  await click(response,"authorize");let popupInfo;
  const deadline=Date.now()+15000;while(Date.now()<deadline){popupInfo=(await send("Target.getTargets")).targetInfos.find(t=>t.type==="page"&&t.url===identity+"/?round="+round);if(popupInfo)break;await delay(25);}assert.ok(popupInfo,"identity authorization window opened");
  const popup=await attach(popupInfo.targetId);await activate(popup);await until(popup,"!document.getElementById('authorization').hidden","bounded exact-origin handoff");await set(popup,"passphrase",passphrase);await click(popup,"unlock");await until(popup,"!document.getElementById('issue').disabled","local member restoration in identity context");await click(popup,"issue");
  await activate(response);await until(response,"!document.getElementById('submit').disabled","blind signature finalization");await set(response,"answer",answer);await click(response,"submit");await until(response,"document.getElementById('status').textContent.startsWith('Encrypted response accepted')","anonymous encrypted submission and locally verified acceptance");assert.ok(submitted);assert.equal(submitCount,1);
  // Exact retries and conflicting duplicate spending race the actual HTTP/store.
  const retries=await evaluate(response,`Promise.all(Array.from({length:6},()=>fetch('/api/browser/submit',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify(${JSON.stringify(submitted)})}).then(async r=>({status:r.status,body:await r.json()}))))`);assert.ok(retries.every(r=>r.status===200));assert.ok(retries.every(r=>r.body.receipt===retries[0].body.receipt));
  const changed={...submitted,envelope:(submitted.envelope[0]==="A"?"B":"A")+submitted.envelope.slice(1)};const conflict=await evaluate(response,`fetch('/api/browser/submit',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify(${JSON.stringify(changed)})}).then(r=>r.status)`);assert.equal(conflict,409);
  const unauthorized=await evaluate(response,`fetch('/api/browser/review/read',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({round:${JSON.stringify(round)},proof:'${"A".repeat(43)}'})}).then(r=>r.status)`);assert.equal(unauthorized,403);
   await activate(reviewer);await click(reviewer,"refresh");await until(reviewer,"document.getElementById('rounds').textContent.includes('Published.')","published reviewer view");await set(reviewer,`review-pass-${round}`,passphrase);await evaluate(reviewer,"document.getElementById('review-pass-'+"+JSON.stringify(round)+").form.requestSubmit()");await until(reviewer,"document.querySelector('.plaintext')?.textContent.includes("+JSON.stringify(answer)+")","authorized retrieval and local reviewer decryption");
   // The same local record reader must isolate a corrupted envelope while an
   // actual reviewer worker still decrypts the later valid stored answer.
   await click(reviewer,"cancel");
   const isolated=await evaluate(reviewer,`(async()=>{
     const {ReviewWorker}=await import('/assets/review-client.mjs');const {readReviewRecords,reviewOwnerActive}=await import('/assets/review-records.mjs');const m=await import('/assets/common.mjs');
     const w=new ReviewWorker(true);try{if(!await w.ready)throw new Error('worker unavailable');const r=(await m.api('/api/browser/rounds')).find(r=>r.id===${JSON.stringify(round)});const stored=await m.localRecord('review:reviewer_one:'+r.id);const config=await m.api('/api/browser/config');const password=m.textBytes(${JSON.stringify(passphrase)});
       let unlocked;try{unlocked=await w.call('reviewerUnlock',password,m.decode(stored.backup,108),m.decode(r.bulletin,564,1587),m.decode(config.bulletin_key,32));}finally{password.fill(0);}if(!unlocked)throw new Error('unlock failed');
       const challenge=await m.api('/api/browser/review/challenge',{round:r.id,cursor:m.encode(new Uint8Array(16))},config.submission_origin);const proof=await w.call('proof',m.decode(challenge.challenge,81));let page;try{page=await m.api('/api/browser/review/read',{round:r.id,proof:m.encode(proof.bytes)},config.submission_origin);}finally{proof.bytes.fill(0);}
       const valid=page.records[0],changed=m.decode(valid.envelope,4145);changed[changed.length-1]^=1;const output=document.querySelector('.plaintext');output.replaceChildren();
       const rejected=await readReviewRecords(w,[{envelope:m.encode(changed)},valid],()=>reviewOwnerActive(w,w,document.visibilityState,Date.parse(r.review_until)),text=>{const p=document.createElement('p');p.textContent=text??'Encrypted answer unavailable';output.append(p);});
       const expired=reviewOwnerActive(w,w,document.visibilityState,Date.now());return {rejected,text:output.textContent,expired,closed:w.closed};
     }finally{w.close();}
   })()`);assert.equal(isolated.rejected,1);assert.ok(isolated.text.includes('Encrypted answer unavailable'));assert.ok(isolated.text.includes(answer),'corrupted ciphertext must not suppress a later valid answer');assert.equal(isolated.expired,false);assert.equal(isolated.closed,true,'review expiry must terminate the owner rather than reject an individual answer');
  assert.deepEqual([...leaks],[],"no passphrases, plaintext answers, credential cookies or external requests crossed the boundary");
  const cookies=(await send("Storage.getCookies",{browserContextId:memberContext})).cookies.filter(c=>c.name==="__Host-anonce-session");assert.equal(cookies.length,1);assert.equal(cookies[0].domain,"identity.localhost");assert.equal(cookies[0].secure,true);assert.equal(cookies[0].httpOnly,true);assert.equal(cookies[0].sameSite,"Strict");
  // Separate browser contexts may have independently visible windows. Open a
  // second tab in the reviewer's own context to cause a real hidden transition.
  await page(reviewerContext);await until(reviewer,"document.visibilityState==='hidden'","reviewer tab hidden");
  await until(reviewer,"document.querySelector('.plaintext')?.textContent===''","background reviewer plaintext cleanup");
  await activate(member);
  await click(member,"logout");await until(member,"document.getElementById('status')?.textContent.startsWith('Create an account or sign in')","browser logout and local disposal");
  assert.equal(await evaluate(member,"fetch('/api/browser/me',{credentials:'same-origin'}).then(r=>r.status)"),401,"revoked browser session must not resolve");
  console.log("PASS: administrator publication → verified member blind authorization/encrypted acceptance → authorized local reviewer decryption; browser vault persistence/restoration, CSRF, single-use enrollment, exact retry races, duplicate-spend conflict and unauthorized review.");
}finally{clearTimeout(lifetime);if(!exited){await send("Browser.close").catch(()=>{});}if(!exited)child.kill("SIGKILL");rmSync(profile,{recursive:true,force:true});}
