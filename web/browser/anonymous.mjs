// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import {ReviewWorker} from "./review-client.mjs";
import {$,api,decode,encode,handle,say,textBytes} from "./common.mjs";

let config,worker,popup,blinded,authorized=false,submitted=false;
const round=new URL(location.href).searchParams.get("round");
$("cancel").onclick=()=>{worker?.close();popup?.close();$("answer").value="";$("authorize").disabled=$("submit").disabled=$("retry").disabled=true;say("Local authorization, unsent answer and retry state discarded. A reserved allowance is not refunded.");};
addEventListener("pagehide",()=>worker?.close());
$("authorize").onclick=handle(async()=>{
  if(blinded)throw new Error("already attempted");$("authorize").disabled=true;
  // Open during the user gesture, before asynchronous preparation, so the
  // browser does not require a popup-blocking exception.
  popup=window.open(`${config.identity_origin}/?round=${round}`,"_blank","popup");if(!popup)throw new Error("popup unavailable");
  const bulletin=await api(`/api/browser/bulletin?round=${round}`);const prepared=await worker.call("prepare",decode(bulletin.bulletin,564,1587),decode(config.bulletin_key,32));if(!prepared)throw new Error("preparation failed");blinded=encode(prepared.blinded);
  popup.postMessage({type:"issue",round,blinded},config.identity_origin);
  say("Complete sign-in, membership verification and local unlocking in the account window, then explicitly authorize the response.");
});
addEventListener("message",handle(async(event)=>{
  if(!config||event.origin!==config.identity_origin||event.source!==popup||!event.data||event.data.round!==round)return;
  if(event.data.type==="ready"&&Object.keys(event.data).length===2){if(blinded)popup.postMessage({type:"issue",round,blinded},config.identity_origin);return;}
  if(event.data.type!=="issued"||Object.keys(event.data).length!==3||authorized)return;
  const result=await worker.call("finalize",decode(event.data.signature,384));if(!result)throw new Error("authorization invalid");authorized=true;$("submit").disabled=false;popup.close();say("Anonymous authorization verified locally. Write your answer, then encrypt and submit it.");
}));
async function send(result){
  let response;try{response=await api("/api/browser/submit",{round,token:encode(result.token),envelope:encode(result.envelope)});}finally{result.token.fill(0);}
  const verified=await worker.call("receipt",decode(response.receipt,200));if(!verified?.verified)throw new Error("acceptance verification failed");
  $("receipt").textContent=`Signed storage acceptance verified. This is not a transparency-log inclusion proof. Receipt (kept only on this page):\n${response.receipt}`;$("retry").disabled=true;say("Encrypted response accepted. Its signed round, token and exact-ciphertext binding were verified locally.");
}
$("answer-form").onsubmit=handle(async()=>{
  if(!authorized||submitted)throw new Error("not authorized");const text=textBytes($("answer").value,4000);let result;
  try{result=await worker.call("encrypt",text);}finally{text.fill(0);}
  if(!result)throw new Error("encryption failed");submitted=true;$("answer").value="";$("submit").disabled=true;$("retry").disabled=false;await send(result);
});
$("retry").onclick=handle(async()=>{const result=await worker.call("submission");if(!result)throw new Error("no pending ciphertext");await send(result);});
handle(async()=>{
  config=await api("/api/browser/config");$("account-home").href=config.identity_origin;$("account-home").hidden=false;
  if(!round){say("Open a shared review link, or choose a review from the account and available reviews page.");return;}decode(round,16);
  const result=await api(`/api/browser/bulletin?round=${round}`);worker=new ReviewWorker();if(!await worker.ready)throw new Error("worker unavailable");const inspected=await worker.call("inspect",decode(result.bulletin,564,1587),decode(config.bulletin_key,32));if(!inspected||encode(inspected.id)!==round)throw new Error("wrong bulletin");
  $("question").textContent=inspected.question;$("authorize").disabled=false;say("Common signed review verified using this deployment's configured publication key. Independent split-view detection is not provided.");
})();
