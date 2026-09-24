/*******************************************************************************
 * @file         workspace.js
 * @brief        Part of the TopoTrace static module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

"use strict";
window.TopoTraceWorkspace = function ({api,el,app,downloadWithToken}) {
  const field=(text,node)=>el("label",{class:"work-field"},el("span",{text}),node);
  const card=(title,...nodes)=>el("section",{class:"fact-card"},el("h2",{text:title}),...nodes);
  function downloadJSON(value,name){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:"application/json"}));const a=el("a",{href:url,download:name});document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);}
  function setPresentation(on){document.body.classList.toggle("presentation-mode",on);try{sessionStorage.setItem("topotrace-presentation",String(on));}catch{};exit.hidden=!on;}
  const exit=el("button",{type:"button",class:"presentation-exit",text:"Exit presentation · Esc",hidden:true});exit.addEventListener("click",()=>setPresentation(false));document.body.appendChild(exit);
  window.addEventListener("keydown",e=>{if(e.key==="Escape")setPresentation(false);});try{setPresentation(sessionStorage.getItem("topotrace-presentation")==="true");}catch{}
  function presentationButton(){const b=el("button",{type:"button",class:"ghost",text:"Presentation mode"});b.addEventListener("click",()=>setPresentation(!document.body.classList.contains("presentation-mode")));return b;}
  function reportButton(demo=false){const message=el("span",{role:"status"});const b=el("button",{type:"button",text:demo?"Branded demo report":"Branded executive report"});b.addEventListener("click",async()=>{b.disabled=true;try{await downloadWithToken(`/api/reports/executive${demo?"?demo=1":""}`,"",true);message.textContent="Report opened. Use Print / Save as PDF.";}catch(err){message.textContent=err.message;}finally{b.disabled=false;}});return el("div",{class:"visibility-toolbar"},b,message);}
  function savedControls(page,getState,applyState){
    const slot=el("details",{class:"saved-view-controls setup-control"},el("summary",{text:"Saved views & layout"}));
    const list=el("select",{"aria-label":"Saved view"},el("option",{value:"",text:"Choose a saved view"})),name=el("input",{placeholder:"View name",maxlength:"100","aria-label":"New view name"});
    const shared=el("input",{type:"checkbox"}),layout=el("select",{"aria-label":"View layout"},el("option",{value:"comfortable",text:"Comfortable spacing"}),el("option",{value:"compact",text:"Compact spacing"}));
    const save=el("button",{type:"button",text:"Save current view"}),remove=el("button",{type:"button",text:"Delete my selected view"}),message=el("span",{role:"status"});let views=[];
    const setLayout=()=>app.classList.toggle("compact-view",layout.value==="compact");layout.value=app.classList.contains("compact-view")?"compact":"comfortable";layout.addEventListener("change",setLayout);
    const load=async()=>{try{views=(await api("/api/saved-views")).filter(v=>v.page===page);list.replaceChildren(el("option",{value:"",text:"Choose a saved view"}),...views.map(v=>el("option",{value:v.id,text:`${v.name}${v.shared?" (team)":""}`})));}catch(err){message.textContent=err.message;}};
    list.addEventListener("change",()=>{const v=views.find(v=>v.id===list.value);if(!v)return;layout.value=v.layout;setLayout();applyState(v);message.textContent=`Loaded ${v.name}`;});
    save.addEventListener("click",async()=>{save.disabled=true;try{await api("/api/saved-views",{method:"POST",body:{...getState(),name:name.value,page,shared:shared.checked,layout:layout.value}});name.value="";await load();message.textContent="View saved.";}catch(err){message.textContent=err.message;}finally{save.disabled=false;}});
    remove.addEventListener("click",async()=>{if(!list.value){message.textContent="Choose a view first.";return;}try{await api(`/api/saved-views/${encodeURIComponent(list.value)}`,{method:"DELETE"});await load();message.textContent="View deleted.";}catch(err){message.textContent=err.message;}});
    slot.appendChild(el("div",{class:"visibility-toolbar"},list,layout,name,field("Share with my group (remediate role)",shared),save,remove,message));load();return slot;
  }
  async function about(){const root=el("div",{class:"workspace-page"});app.replaceChildren(root);root.appendChild(el("h1",{text:"About TopoTrace"}));try{const info=await api("/api/about");root.appendChild(card("Turn Infrastructure Into Insight",el("img",{src:"img/topotrace-mark.svg",alt:"TopoTrace",class:"about-logo"}),el("p",{text:"TopoTrace brings device inventory, evidence, risk prioritization, and governed changes together. Its demo tools illustrate workflows using clearly labeled sample data."}),el("p",{text:`Version ${info.version} · Build ${info.revision}`}),el("p",{text:info.company}),el("p",{text:info.copyright})));root.appendChild(card("Support",el("p",{text:info.support}),el("a",{href:"#/docs",text:"Read the documentation"}),el("p",{},el("a",{href:"/legal.html",text:"Disclaimer & Responsible Use"}))));}catch(err){root.appendChild(el("p",{text:err.message}));}}
  async function show(){
    const root=el("div",{class:"workspace-page manage-page"});app.replaceChildren(root);root.appendChild(el("div",{class:"manage-hero"},el("p",{class:"eyebrow",text:"Protect your workspace"}),el("h1",{text:"Data & recovery"}),el("p",{class:"page-intro",text:"Download a portable copy of workspace preferences, or safely restore missing configuration from an earlier export."})));
    const backup=card("Workspace backup",el("p",{text:"This backup includes saved views, dynamic groups, and notification preferences. Device inventory and credentials remain protected in your full server backup."}),el("div",{class:"callout-note"},el("strong",{text:"Safe restore"}),el("span",{text:" TopoTrace previews every change and keeps existing records."})));
    const exportBtn=el("button",{type:"button",text:"Download backup"}),file=el("input",{type:"file",accept:".json,application/json","aria-label":"Choose a TopoTrace backup file"}),preview=el("button",{type:"button",class:"ghost",text:"Review backup"}),restore=el("button",{type:"button",text:"Restore missing items",disabled:true}),message=el("p",{role:"status",class:"save-msg"}),details=el("div",{class:"restore-preview"});let imported=null,previewHash="";
    exportBtn.addEventListener("click",async()=>{try{const b=await api("/api/config-backup");downloadJSON(b,`topotrace-config-${new Date().toISOString().slice(0,10)}.json`);message.textContent="Configuration exported.";}catch(err){message.textContent=err.message;}});
    file.addEventListener("change",async()=>{restore.disabled=true;imported=null;previewHash="";details.replaceChildren();try{if(!file.files[0])return;if(file.files[0].size>4*1024*1024)throw new Error("Backup exceeds 4 MB.");imported=JSON.parse(await file.files[0].text());message.textContent="File loaded. Preview before restoring.";}catch(err){message.textContent=err.message;}});
    preview.addEventListener("click",async()=>{restore.disabled=true;try{if(!imported)throw new Error("Select a backup file first.");const result=await api("/api/config-backup/preview",{method:"POST",body:{backup:imported}});previewHash=result.preview_hash;details.replaceChildren(el("p",{text:`Create ${result.create.length} missing records; preserve ${result.skip_existing.length} existing records.`}),el("ul",{},...result.create.map(text=>el("li",{text}))));restore.disabled=result.create.length===0;message.textContent=result.note;}catch(err){message.textContent=err.message;}});
    restore.addEventListener("click",async()=>{restore.disabled=true;try{const result=await api("/api/config-backup/restore",{method:"POST",body:{backup:imported,preview_hash:previewHash}});message.textContent=`Restored ${result.create.length} records. Existing configuration preserved.`;previewHash="";}catch(err){message.textContent=err.message+" Preview again before retrying.";}});
    backup.append(el("div",{class:"recovery-actions"},el("div",{class:"recovery-step"},el("span",{text:"01"}),el("div",{},el("strong",{text:"Create a backup"}),el("p",{text:"Download a dated JSON file and store it with your normal backups."}),exportBtn)),el("div",{class:"recovery-step"},el("span",{text:"02"}),el("div",{},el("strong",{text:"Review a backup"}),el("p",{text:"Choose a file to see exactly what would be added before anything changes."}),file,preview)),el("div",{class:"recovery-step"},el("span",{text:"03"}),el("div",{},el("strong",{text:"Restore safely"}),el("p",{text:"Existing configuration is preserved. Only missing items are restored."}),restore))),message,details);root.appendChild(backup);
  }
  async function notificationPreferencesCard(){
    const notify=card("Delivery schedule",el("p",{text:"Choose when notifications arrive and when overdue work should be escalated. Destinations are managed separately under Integrations."}));
    try{const p=await api("/api/notification-preferences");const quiet=el("input",{type:"checkbox"});quiet.checked=p.quiet_enabled;
      const number=(value,min,max)=>el("input",{type:"number",value:String(value),min:String(min),max:String(max),required:true});
      const start=number(p.quiet_start,0,23),end=number(p.quiet_end,0,23),zone=el("input",{value:p.timezone,required:true}),digest=number(p.digest_minutes,0,1440),delay=number(p.escalation_delay_hours,0,720),repeat=number(p.escalation_repeat_hours,0,720),save=el("button",{type:"submit",text:"Save notification controls"}),status=el("span",{role:"status"});
      const form=el("form",{class:"work-form setup-control"},field("Enable quiet hours",quiet),field("Quiet start (hour 0–23)",start),field("Quiet end (hour 0–23)",end),field("Timezone, e.g. America/Chicago",zone),field("Digest minutes (0 = immediate; otherwise 15–1440)",digest),field("Escalate hours after due date",delay),field("Repeat escalation hours (0 = once)",repeat),save,status);
      form.addEventListener("submit",async e=>{e.preventDefault();save.disabled=true;try{await api("/api/notification-preferences",{method:"PUT",body:{quiet_enabled:quiet.checked,quiet_start:Number(start.value),quiet_end:Number(end.value),timezone:zone.value.trim(),digest_minutes:Number(digest.value),escalation_delay_hours:Number(delay.value),escalation_repeat_hours:Number(repeat.value)}});status.textContent="Saved. New events use these settings; queued deliveries also respect quiet hours.";}catch(err){status.textContent=err.message;}finally{save.disabled=false;}});notify.appendChild(form);
    }catch(err){notify.appendChild(el("p",{text:err.message}));}
    return notify;
  }
  return {show,about,presentationButton,savedControls,reportButton,notificationPreferencesCard};
};
