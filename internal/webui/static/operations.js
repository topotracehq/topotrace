/* Operator workflows: evidence, ownership, exceptions, dynamic groups and staged changes. */
"use strict";
window.MusterWork = function ({ api, el, app, timeAgo, workspaceUI }) {
  const field = (label, input) => el("label", { class: "work-field" }, el("span", { text: label }), input);
  const input = (placeholder, value = "", type = "text") => el("input", { type, placeholder, value });
  const dateText = value => value ? new Date(value).toLocaleString() : "Not recorded";
  const localValue = value => { if (!value) return ""; const d = new Date(value); return new Date(d.getTime() - d.getTimezoneOffset()*60000).toISOString().slice(0,16); };
  const iso = value => value ? new Date(value).toISOString() : null;
  const badge = (text, state = "unknown") => el("span", { class: `evidence-badge evidence-${state}`, text });
  function formAction(form, button, message, action) {
    form.addEventListener("submit", async e => {
      e.preventDefault(); button.disabled = true; message.textContent = "Saving…";
      try { await action(); message.textContent = "Saved."; } catch (err) { message.textContent = err.message; }
      finally { button.disabled = false; }
    });
  }
  function evidence(coverage) {
    if (!coverage) return el("p", { text: "Evidence coverage is unavailable." });
    const details = el("details", { class: "evidence-details" }, el("summary", { text: `Evidence coverage: ${coverage.percent}% · ${coverage.verified}/${coverage.expected} checks have current evidence` }));
    details.appendChild(el("p", { class: "meta", text: "Verified means usable evidence collected within 24 hours. It does not mean the device passed its security checks." }));
    for (const e of coverage.evidence || []) details.appendChild(el("div", { class: "evidence-row" },
      el("strong", { text: e.label }), badge(e.state, e.state), el("span", { text: e.detail }),
      el("small", { text: e.collected_at ? `Collected ${dateText(e.collected_at)}` : "No collection timestamp" })));
    return details;
  }
  function answerNode(turn) {
    const body = el("div", { class: "evidence-answer" }, el("p", { text: turn.answer }));
    for (const warning of turn.warnings || []) body.appendChild(el("p", { class: "save-msg", text: warning }));
    if ((turn.sources || []).length) {
      const list = el("details", {}, el("summary", { text: "Inspect cited evidence" }));
      for (const source of turn.sources) list.appendChild(el("div", { class: "evidence-row" },
        el("a", { href: source.url, text: `[${source.id}] ${source.host} · ${source.category}` }),
        badge(source.state, source.state), el("small", { text: `Collected: ${dateText(source.collected_at)}` }),
        el("pre", { text: source.detail })));
      body.appendChild(list);
    }
    return body;
  }
  function assignmentForm(host, id, current, refresh) {
    const owner=input("Person",current.owner), team=input("Team",current.team), due=input("",localValue(current.due_at),"datetime-local"), escalate=input("Escalation contact or team",current.escalate_to);
    const button=el("button",{type:"submit",text:"Save ownership"}), msg=el("span",{class:"save-msg",role:"status"});
    const form=el("form",{class:"work-form"},field("Owner",owner),field("Team",team),field("Due date (your local time)",due),field("Escalate to",escalate),button,msg,
      el("p",{class:"meta",text:"Overdue open work is recorded in the audit log and sent to configured notification sinks, with this contact in the message. It does not send email directly."}));
    formAction(form,button,msg,async()=>{await api("/api/work/assignment",{method:"PUT",body:{id,host,owner:owner.value,team:team.value,due_at:iso(due.value),escalate_to:escalate.value}});await refresh();});
    return form;
  }
  function exceptionForm(item,refresh) {
    const reason=input("Why is this risk temporarily accepted?",item.exception?.reason), until=input("",localValue(item.exception?.expires_at),"datetime-local");
    reason.required=true; until.required=true;
    const button=el("button",{type:"submit",text:"Accept temporarily"}), msg=el("span",{class:"save-msg",role:"status"});
    const form=el("form",{class:"work-form"},field("Reason",reason),field("Expires (within 90 days)",until),button,msg);
    formAction(form,button,msg,async()=>{await api("/api/work/exception",{method:"PUT",body:{id:item.id,host:item.host,reason:reason.value,expires_at:iso(until.value)}});await refresh();});
    if(item.exception){const clear=el("button",{type:"button",class:"ghost",text:"Revoke exception"});clear.addEventListener("click",async()=>{try{await api("/api/work/exception",{method:"DELETE",body:{id:item.id,host:item.host}});await refresh();}catch(err){msg.textContent=err.message;}});form.appendChild(clear);}
    return form;
  }
  let activeSection="Findings";
  async function show() {
    const container=el("div",{class:"work-page"}); app.replaceChildren(container);
    container.appendChild(el("h1",{text:"Work queue"}));container.appendChild(el("p",{class:"page-intro",text:"Prioritize findings, assign ownership, and plan changes with evidence."}));
    const refreshButton=el("button",{type:"button",class:"ghost",text:"Refresh"}); refreshButton.addEventListener("click",show);container.appendChild(refreshButton);
    let data; try{data=await api("/api/work");}catch(err){container.appendChild(el("p",{text:err.message}));return;}
    const findingsPanel=el("section",{class:"work-panel"});container.appendChild(findingsPanel);
    const filter=input("Filter by host, owner, team, or finding"), onlyMine=el("input",{type:"checkbox"});
    findingsPanel.appendChild(el("div",{class:"editor-row"},field("Search work",filter),field("Overdue only",onlyMine)));
    const list=el("div",{class:"work-list"});findingsPanel.appendChild(list);
    findingsPanel.insertBefore(workspaceUI.savedControls("work",()=>({query:filter.value,filter:onlyMine.checked?"overdue":"all"}),v=>{filter.value=v.query;onlyMine.checked=v.filter==="overdue";render();}),list);
    function render(){list.replaceChildren();const rows=data.items.filter(i=>(!onlyMine.checked||i.overdue)&&`${i.host} ${i.title} ${i.assignment.owner} ${i.assignment.team}`.toLowerCase().includes(filter.value.toLowerCase()));
      list.appendChild(el("p",{class:"meta",text:`${rows.length} findings · updated ${dateText(data.generated_at)}`}));
      for(const item of rows){const a=item.assignment;const card=el("article",{class:"fact-card work-item"},
        el("div",{class:"work-item-head"},el("h2",{text:item.title}),badge(`Risk ${item.risk}/100`),badge(item.status.replaceAll("_"," "),item.exception?"unknown":"outdated")),
        el("a",{href:`#/host/${encodeURIComponent(item.host)}`,text:item.host}),el("p",{text:item.evidence}),el("p",{},el("strong",{text:"Recommended next step: "}),item.recommendation),
        el("p",{class:"meta",text:`Owner: ${a.owner||"Unassigned"} · Team: ${a.team||"Unassigned"} · Due: ${a.due_at?dateText(a.due_at):"Not set"}${item.overdue?" · OVERDUE":""}`}));
        if(item.exception)card.appendChild(el("p",{text:`Accepted until ${dateText(item.exception.expires_at)}: ${item.exception.reason}`}));
        card.appendChild(evidence(item.coverage));
        card.appendChild(el("details",{},el("summary",{text:"Assign this finding"}),assignmentForm(item.host,item.id,a,show)));
        card.appendChild(el("details",{},el("summary",{text:"Temporary exception (admin)"}),exceptionForm(item,show)));
        if(item.approval_id){const link=el("a",{href:"#/fleet",text:"Review pending approval in Fleet"});card.appendChild(link);}
        list.appendChild(card);
      }
      if(!rows.length)list.appendChild(el("p",{text:"No matching open work."}));
    }
    filter.addEventListener("input",render);onlyMine.addEventListener("change",render);render();
    const ownerSection=el("section",{class:"fact-card"},el("h2",{text:"Default device ownership"}));
    const hostSelect=el("select",{},...data.hosts.map(h=>el("option",{value:h,text:h}))), slot=el("div",{});
    const loadOwner=()=>{const host=hostSelect.value;slot.replaceChildren(...(host?[assignmentForm(host,"host:"+host,data.assignments.find(a=>a.id==="host:"+host)||{},show)]:[]));};hostSelect.addEventListener("change",loadOwner);ownerSection.append(field("Device",hostSelect),slot);loadOwner();container.appendChild(ownerSection);
    const groupSlot=el("section",{class:"fact-card"}), planSlot=el("section",{class:"fact-card"});container.append(groupSlot,planSlot);
    const panels={Findings:findingsPanel,Ownership:ownerSection,"Dynamic groups":groupSlot,"Change plans":planSlot};
    const tabs=el("div",{class:"visibility-toolbar work-sections",role:"group","aria-label":"Work queue sections"});
    const select=()=>{for(const [name,panel] of Object.entries(panels))panel.hidden=name!==activeSection;for(const b of tabs.querySelectorAll("button"))b.setAttribute("aria-pressed",String(b.textContent===activeSection));};
    for(const name of Object.keys(panels)){const b=el("button",{type:"button",text:name});b.addEventListener("click",()=>{activeSection=name;select();});tabs.appendChild(b);}container.insertBefore(tabs,refreshButton);select();
    await Promise.all([groups(groupSlot),plans(planSlot,data.hosts)]);
  }
  async function groups(container){
    container.replaceChildren(el("h2",{text:"Dynamic groups"}),el("p",{class:"meta",text:"Membership updates from current device facts. All selected conditions must match. Software matching requires a report from the last 24 hours."}));
    try{const groups=await api("/api/dynamic-groups");for(const g of groups){const remove=el("button",{type:"button",class:"ghost",text:"Delete"}),msg=el("span",{role:"status"});remove.addEventListener("click",async()=>{try{await api(`/api/dynamic-groups/${encodeURIComponent(g.id)}`,{method:"DELETE"});await window.dispatchEvent(new Event("muster-groups-changed"));await show();}catch(err){msg.textContent=err.message;}});
      container.appendChild(el("div",{class:"work-group"},el("strong",{text:g.name}),el("p",{text:`${g.members.length} devices: ${g.members.join(", ")||"None"}`}),el("p",{class:"meta",text:"Available as a target in Fleet → New policy rule."}),remove,msg));}
    }catch(err){container.appendChild(el("p",{text:err.message}));}
    const name=input("Group name"),platform=input("linux, windows, darwin…"),software=input("Package name contains…"),tag=input("Exact tag"),risk=input("0",0,"number"),exposure=el("select",{},el("option",{value:"",text:"Any"}),el("option",{value:"internet",text:"Internet-facing"}),el("option",{value:"internal",text:"Internal"}));risk.min="0";risk.max="100";name.required=true;
    const button=el("button",{type:"submit",text:"Create dynamic group"}),msg=el("span",{class:"save-msg",role:"status"});const form=el("form",{class:"work-form"},field("Name",name),field("Platform",platform),field("Installed software",software),field("Tag",tag),field("Exposure",exposure),field("Minimum risk",risk),button,msg);
    formAction(form,button,msg,async()=>{await api("/api/dynamic-groups",{method:"POST",body:{name:name.value,selector:{platform:platform.value.trim(),software:software.value.trim(),tag:tag.value.trim(),exposure:exposure.value,min_risk:Number(risk.value)}}});await show();});container.appendChild(el("details",{},el("summary",{text:"Create group (admin)"}),form));
  }
  async function plans(container,hosts){
    container.replaceChildren(el("h2",{text:"Scheduled changes"}),el("p",{class:"meta",text:"Service restarts only. Dispatch occurs during the selected window on an evaluator cycle. Pilot devices must be verified before you explicitly promote the remaining devices. These windows apply to scheduled changes, not actions queued elsewhere."}));
    try{const rows=await api("/api/change-plans");for(const {plan:p,checks} of rows){const msg=el("span",{role:"status"});const card=el("div",{class:"work-group"},el("h3",{text:p.name}),badge(p.status.replaceAll("_"," ")),el("p",{text:`${p.verb} ${p.arg} · ${dateText(p.window_start)} – ${dateText(p.window_end)} · Pilot: ${p.pilot_count}/${p.hosts.length}`}),el("p",{text:p.hosts.join(", ")}));
      for(const c of checks)card.appendChild(el("p",{},el("strong",{text:`${c.host}: ${c.state} `}),c.detail));
      card.appendChild(el("details",{},el("summary",{text:"Recovery instructions & safeguards"}),el("p",{text:p.rollback_instructions||"No recovery instructions recorded on this legacy plan."}),el("p",{text:p.require_preflight?"Readiness is checked before scheduling and again before each dispatch. Cancellation cannot recall actions already delivered.":"Legacy plan: created before mandatory preflight checks."})));
      for(const [decision,label]of [["promote","Promote remaining devices"],["cancel","Cancel undelivered work"]]){const b=el("button",{type:"button",class:"ghost",text:label});b.disabled=p.cancelled||(decision==="promote"&&(p.promoted||checks.length<p.pilot_count||checks.slice(0,p.pilot_count).some(c=>c.state!=="verified")||Date.now()>=new Date(p.window_end).getTime()));b.addEventListener("click",async()=>{b.disabled=true;try{await api(`/api/change-plans/${encodeURIComponent(p.id)}/${decision}`,{method:"POST"});await show();}catch(err){msg.textContent=err.message;b.disabled=false;}});card.appendChild(b);}card.appendChild(msg);container.appendChild(card);
    }}catch(err){container.appendChild(el("p",{text:err.message}));}
    const name=input("Change description"),service=input("Service name, e.g. nginx"),pilot=input("1",1,"number"),start=input("","","datetime-local"),end=input("","","datetime-local");name.required=service.required=start.required=end.required=true;pilot.min="1";
    const devices=el("fieldset",{},el("legend",{text:"Devices (pilots are taken from selected devices in the order shown)"}));const boxes=hosts.map(h=>{const box=el("input",{type:"checkbox",value:h});devices.appendChild(field(h,box));return box;});
    const backup=el("input",{type:"checkbox",required:true}),rollback=el("textarea",{rows:"4",required:true,minlength:"10",maxlength:"4000",placeholder:"Recovery owner, backup location, steps to restore service, and how to verify recovery."});
    const button=el("button",{type:"submit",text:"Schedule pilot restarts",disabled:true}),preview=el("button",{type:"button",text:"Check impact & readiness"}),checksOut=el("div",{class:"preflight-results",role:"status"}),msg=el("span",{class:"save-msg",role:"status"});const form=el("form",{class:"work-form setup-control"},field("Name",name),field("Service",service),field("Pilot device count",pilot),field("Window starts (local time)",start),field("Window ends (local time, maximum 24 hours)",end),devices,field("Backups and recovery path checked",backup),field("Recovery / rollback instructions",rollback),preview,checksOut,button,msg);
    const payload=()=>({name:name.value,hosts:boxes.filter(b=>b.checked).map(b=>b.value),verb:"restart-service",arg:service.value.trim(),pilot_count:Number(pilot.value),window_start:iso(start.value),window_end:iso(end.value),backup_confirmed:backup.checked,rollback_instructions:rollback.value.trim()});
    form.addEventListener("input",()=>{button.disabled=true;});
    preview.addEventListener("click",async()=>{button.disabled=true;if(!form.reportValidity())return;preview.disabled=true;try{const result=await api("/api/change-plans/preflight",{method:"POST",body:payload()});checksOut.replaceChildren(el("p",{text:result.impact}),...result.hosts.map(h=>el("p",{text:`${h.host}: ${h.ready?"Ready":"Blocked"}. ${[...h.blockers,...h.warnings].join("; ")}`})),el("p",{text:"Recovery instructions: "+result.rollback}));button.disabled=!result.ready;}catch(err){checksOut.textContent=err.message;}finally{preview.disabled=false;}});
    formAction(form,button,msg,async()=>{await api("/api/change-plans",{method:"POST",body:payload()});await show();});container.appendChild(el("details",{},el("summary",{text:"Schedule a staged service restart"}),form));
  }
  async function verification(host,container){try{const rows=await api(`/api/hosts/${encodeURIComponent(host)}/verification`);container.replaceChildren(el("h2",{text:"Remediation verification"}),el("p",{class:"meta",text:"Verified restarts require a newer report confirming that the service is running; this does not prove an unrelated policy issue was fixed."}));for(const row of rows)container.appendChild(el("p",{},badge(row.state,row.state==="verified"?"verified":"unknown"),` ${row.detail}`,row.evidence_at?` · Evidence ${dateText(row.evidence_at)}`:""));if(!rows.length)container.appendChild(el("p",{text:"No remediation actions yet."}));}catch(err){container.replaceChildren(el("p",{text:`Verification unavailable: ${err.message}`}));}}
  return { show, evidence, answerNode, verification };
};
