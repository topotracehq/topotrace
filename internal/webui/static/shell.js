/*******************************************************************************
 * @file         shell.js
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
window.MusterShell = (() => {
  const menu = document.querySelector(".mobile-menu"), sidebar = document.querySelector(".sidebar"), scrim = document.querySelector(".nav-scrim");
  function close(returnFocus = false) {
    document.body.classList.remove("nav-open"); menu.setAttribute("aria-expanded", "false"); scrim.hidden = true;
    if (returnFocus) menu.focus();
  }
  menu.addEventListener("click", () => {
    if (document.body.classList.contains("nav-open")) { close(true); return; }
    sidebar.inert=false; document.body.classList.add("nav-open"); menu.setAttribute("aria-expanded", "true"); scrim.hidden = false;
    sidebar.querySelector(".sidebar-close").focus();
  });
  scrim.addEventListener("click", () => close(true));
  sidebar.querySelector(".sidebar-close").addEventListener("click", () => close(true));
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") { close(document.body.classList.contains("nav-open")); const form=document.getElementById("auth-form"); if(!form.hidden){form.hidden=true;document.getElementById("auth-toggle").setAttribute("aria-expanded","false");document.getElementById("auth-toggle").focus();} }
    if(e.key === "Tab" && document.body.classList.contains("nav-open")){
      const nodes=[...sidebar.querySelectorAll("a,button")];const first=nodes[0],last=nodes[nodes.length-1];
      if(e.shiftKey && document.activeElement===first){e.preventDefault();last.focus();}
      if(!e.shiftKey && document.activeElement===last){e.preventDefault();first.focus();}
    }
  });
  const mq=matchMedia("(max-width: 900px)");
  function responsive(){close();sidebar.inert=mq.matches;}
  mq.addEventListener("change",responsive);responsive();
  new MutationObserver(()=>{sidebar.inert=mq.matches&&!document.body.classList.contains("nav-open");}).observe(document.body,{attributes:true,attributeFilter:["class"]});
  document.querySelector(".skip-link").addEventListener("click",e=>{e.preventDefault();document.getElementById("app").focus();});
  return {update(hash){
    const key=hash.startsWith("#/host/")?"hosts":hash.split("/")[1]||"hosts";
    let selected=null;
    document.querySelectorAll(".view-tabs a").forEach(a=>{const active=a.dataset.view===key;a.classList.toggle("active",active);if(active){a.setAttribute("aria-current","page");selected=a;}else a.removeAttribute("aria-current");});
    const extra={collections:"Collections",compare:"Compare",integrations:"Integration health",onboarding:"Getting started"};
    const title=key==="about"?"About TopoTrace":extra[key]||selected?.textContent.trim()||"Hosts";
    document.getElementById("nav-current").textContent=title;
    document.getElementById("nav-section").textContent=selected?.closest(".nav-section").querySelector(".nav-label").textContent||"Workspace";
    document.title=`${title} · TopoTrace`;close();
  }};
})();
