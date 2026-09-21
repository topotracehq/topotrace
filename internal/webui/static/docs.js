/*******************************************************************************
 * @file         docs.js
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
// A deliberately small, text-safe renderer for the bundled documentation.
// It creates DOM nodes, never inserts document content as HTML.
window.MusterDocs = function ({api, el, app}) {
  function inline(text) {
    const frag=document.createDocumentFragment();
    const re=/`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^\s)]+)\)/g;let start=0,m;
    while((m=re.exec(text))){
      frag.append(document.createTextNode(text.slice(start,m.index)));
      if(m[1])frag.append(el("code",{text:m[1]}));
      else if(m[2])frag.append(el("strong",{text:m[2]}));
      else{
        let href=m[4];
        if(/^[\w-]+\.md$/.test(href))href="#/docs/"+href.slice(0,-3);
        if(/^(https?:\/\/|#\/|\/(?!\/))/.test(href))frag.append(el("a",{href,text:m[3],...(href.startsWith("http")?{target:"_blank",rel:"noopener noreferrer"}:{})}));
        else frag.append(document.createTextNode(m[3]));
      }
      start=re.lastIndex;
    }
    frag.append(document.createTextNode(text.slice(start)));return frag;
  }
  const marked=(tag,text,attrs={})=>{const node=el(tag,attrs);node.append(inline(text));return node;};
  const special=line=>!line.trim()||/^\s*(```|#{1,6}\s|[-*]\s|\d+\.\s|\|)/.test(line);
  function render(md){
    const lines=md.replace(/\r\n/g,"\n").split("\n"),out=[];let i=0;
    while(i<lines.length){
      const line=lines[i];if(!line.trim()){i++;continue;}
      if(/^```/.test(line)){const code=[];i++;while(i<lines.length&&!/^```/.test(lines[i]))code.push(lines[i++]);i++;out.push(el("pre",{},el("code",{text:code.join("\n")})));continue;}
      const heading=line.match(/^(#{1,6})\s+(.*)$/);
      if(heading){out.push(marked("h"+Math.min(heading[1].length+1,6),heading[2]));i++;continue;}
      const list=line.match(/^\s*([-*]|\d+\.)\s+(.*)$/);
      if(list){
        const ordered=/\d/.test(list[1]),node=el(ordered?"ol":"ul",{class:"docs-list",...(ordered?{start:String(parseInt(list[1]))}:{})});
        while(i<lines.length){const item=lines[i].match(/^\s*([-*]|\d+\.)\s+(.*)$/);if(!item||/\d/.test(item[1])!==ordered)break;
          let text=item[2];i++;while(i<lines.length&&/^\s{2,}\S/.test(lines[i])&&!special(lines[i]))text+=" "+lines[i++].trim();node.append(marked("li",text));
        }out.push(node);continue;
      }
      if(/^\s*\|/.test(line)&&/^\s*\|[\s:|-]+\|\s*$/.test(lines[i+1]||"")){
        const cells=s=>s.trim().split("|").slice(1,-1).map(v=>v.trim());
        const table=el("table",{class:"docs-table"},el("thead",{},el("tr",{},...cells(line).map(t=>marked("th",t,{scope:"col"}))))),body=el("tbody",{});i+=2;
        while(i<lines.length&&/^\s*\|.*\|\s*$/.test(lines[i]))body.append(el("tr",{},...cells(lines[i++]).map(t=>marked("td",t))));
        table.append(body);out.push(el("div",{class:"docs-table-wrap",tabindex:"0","aria-label":"Scrollable reference table"},table));continue;
      }
      let text=lines[i++].trim();while(i<lines.length&&!special(lines[i]))text+=" "+lines[i++].trim();out.push(marked("p",text));
    }return out;
  }
  async function show(requested){
    const nav=el("ul",{class:"docs-nav"}),search=el("input",{class:"docs-search",type:"search",placeholder:"Find a guide…","aria-label":"Find a documentation guide"});
    const body=el("article",{class:"docs-body","aria-label":"Documentation article"},el("p",{text:"Loading documentation…",role:"status"}));
    const library=el("nav",{class:"docs-library","aria-label":"Documentation library"},search,nav);
    const root=el("div",{class:"docs-page"},el("h1",{text:"Documentation"}),el("p",{class:"page-intro",text:"Practical guides, operator workflows, and technical references. Start with a task or find the details you need."}),el("div",{class:"docs-layout"},library,body));app.replaceChildren(root);
    let pages;try{pages=await api("/api/docs");}catch(e){body.replaceChildren(el("p",{text:e.message,role:"alert"}));return;}
    if(!root.isConnected)return;
    const groups=[['Start here',['getting-started','visibility','workspace-tools','interface']],['Operate',['workflows','agents','compliance','recovery']],['Reference',['api-reference','security-model','scanner-import','entity-graph','data-model','ask-muster','siem-integration','legal']]];
    const selected=pages.find(p=>p.name===requested)||(!requested?pages[0]:null);
    function draw(){nav.replaceChildren();let count=0;
      for(const [title,names] of groups){const matches=pages.filter(p=>names.includes(p.name)&&(p.title+" "+p.name).toLowerCase().includes(search.value.toLowerCase()));if(!matches.length)continue;nav.append(el("li",{class:"docs-category",text:title}));for(const page of matches){count++;nav.append(el("li",{},el("a",{href:`#/docs/${page.name}`,text:page.title,...(page.name===selected?.name?{class:"active","aria-current":"page"}:{})})));}}
      // New guides remain reachable even before being assigned a library category.
      for(const page of pages.filter(p=>!groups.some(g=>g[1].includes(p.name))&&(p.title+" "+p.name).toLowerCase().includes(search.value.toLowerCase()))){count++;nav.append(el("li",{},el("a",{href:`#/docs/${page.name}`,text:page.title})));}
      if(!count)nav.append(el("li",{class:"docs-empty",text:"No matching guides. Try a broader search."}));
    }draw();search.addEventListener("input",draw);
    if(!selected){body.replaceChildren(el("h2",{text:"Guide not found"}),el("p",{text:"Choose a guide from the library to continue."}));return;}
    try{
      const res=await fetch(`/api/docs/${encodeURIComponent(selected.name)}`);if(!res.ok)throw new Error(`Could not load guide (HTTP ${res.status}).`);
      const md=await res.text();if(!root.isConnected)return;
      const print=el("button",{type:"button",text:"Print guide"}),copy=el("button",{type:"button",text:"Copy link"}),status=el("span",{role:"status"});
      print.addEventListener("click",()=>window.print());copy.addEventListener("click",async()=>{const url=new URL(location.href);url.hash=`/docs/${selected.name}`;try{await navigator.clipboard.writeText(url.href);status.textContent="Link copied.";}catch{status.textContent=url.href;}});
      body.replaceChildren(el("div",{class:"docs-tools"},el("span",{text:`GUIDE / ${Math.max(1,Math.ceil(md.split(/\s+/).length/220))} MIN READ`}),el("div",{},copy,document.createTextNode(" "),print),status),...render(md));
      const headings=[...body.querySelectorAll("h3")];
      if(headings.length){const links=headings.map((h,i)=>{h.id=`doc-section-${i}`;const link=el("a",{href:`#${h.id}`,text:h.textContent});link.addEventListener("click",e=>{e.preventDefault();h.scrollIntoView({block:"start"});h.tabIndex=-1;h.focus({preventScroll:true});});return el("li",{},link);});const toc=el("details",{class:"docs-toc"},el("summary",{text:"On this page"}),el("ul",{},...links));body.querySelector("h2")?.after(toc);}
      if(selected.name==="getting-started"){
        const flow=el("div",{class:"docs-flow","aria-label":"TopoTrace workflow"},...[['01','Collect evidence','Agents and imports report device facts.'],['02','Prioritize work','Review changes, coverage, and findings.'],['03','Verify outcomes','Assign work and check newer evidence.']].map(([step,title,description])=>el("div",{},el("span",{text:step}),el("strong",{text:title}),el("p",{text:description}))));body.querySelector(".docs-toc")?.after(flow);
      }
    }catch(e){if(root.isConnected)body.replaceChildren(el("p",{text:e.message,role:"alert"}));}
  }
  return {show,render};
};
