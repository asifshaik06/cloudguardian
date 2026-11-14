/* Page views that need more than a template: overview, findings, events, audit and the investigation drawer.
   Uses the globals defined in index.html (S, ML, AU, DS, BOOT, esc, tg, none, ring, stepper, evalTable, get, route). */
const Views=(()=>{
const _get=async p=>{if(typeof window.get==="function")return await window.get(p);try{return await(await fetch(p)).json()}catch(e){return null}};
let M={posture:[],anomaly:[],threshold:null,buckets:[],events_total:0,rem:{items:[],fixed:0,verified:0,rolled_back:0}},EVR=[],ES=new Set(),EBOOT=false,Q="",FSEV="",FST="",EK="",DR=null;
const ctx=()=>({S,ML,M}),mid=x=>(x.ref.match(/T\d{4}(\.\d{3})?/)||["n/a"])[0],$$=id=>document.getElementById(id);
const stat=s=>({pending:tg("Awaiting approval","wr"),fixed:tg("Remediated","ok"),rejected:tg("Rejected","gr")}[s]||tg(s,"gr"));
const noData=k=>k=="detectors"?!Object.values(ML.results||{}).some(r=>r.controlled):k=="calib"?!Object.values(ML.results||{}).some(r=>r.old_real_unlabelled):false,
 slot=(key,h)=>noData(key)?none(key=="calib"?"No flaws.cloud results yet. Run scripts\\train_eval.py with the flaws.cloud logs.":"No results yet. Run scripts\\train_eval.py."):`<div class="cslot" data-key="${key}" style="height:${h}px"></div>`,
 card=(t,sub,key,h)=>`<section class="panel"><div class="ph"><span class="pt">${t}</span><span class="mu">${sub}</span></div>${noData(key)?slot(key,h):`<div class="pb">${slot(key,h)}</div>`}</section>`;
function pipe(){const f=S.findings,fx=f.filter(x=>x.status=="fixed"),p=f.filter(x=>x.status=="pending").length;
 return [["Events",M.events_total],["Detections",f.length],["Awaiting approval",p,p>0],["Remediated",fx.length],["Verified",fx.filter(x=>x.verified).length]].map(s=>`<div class="stg${s[2]?" on":""}"><span>${s[0]}</span><b>${s[1]}</b></div>`).join("")}
function overview(){
 if(!BOOT)return`<div class="g3">${[1,2,3,4,5,6].map(()=>'<div class="panel sk" style="height:250px"></div>').join("")}</div>`;
 const f=S.findings,fx=f.filter(x=>x.status=="fixed"),td=f.filter(x=>x.tdetect!=null),avg=td.length?td.reduce((a,x)=>a+x.tdetect,0)/td.length:0,tr=M.rem.items.filter(i=>i.ttr!=null),ttr=tr.length?tr.reduce((a,i)=>a+i.ttr,0)/tr.length:0,live=S.mode=="Live AWS",vr=fx.length?Math.round(100*fx.filter(x=>x.verified).length/fx.length):null,
 kpi=(l,k,x,d,suf,h)=>`<div class="panel kp"><div class="lb">${l}</div><div class="kv" data-count="${x}" data-k="${k}" data-dec="${d||0}" data-suf="${suf||""}">${(+x).toFixed(d||0)}${suf||""}</div>${h?`<div class="mu">${h}</div>`:""}</div>`,
 acts=live?"":S.resources.map(r=>`<button class="btn sm" data-p="/api/attack/${r.id}" title="${esc(r.attack)}">${esc(r.name)}</button>`).join("");
 return`<div class="pipe" id="pipe">${pipe()}</div>
 <div class="kpis"><div class="panel kp rg"><div>${ring(S.score)}</div><div><div class="lb">Posture score</div><div class="kv" data-count="${S.score}" data-k="score" data-suf="%">${S.score}%</div></div></div>${kpi("Avg time to detect","ttd",avg,1,"s")}${kpi("Avg time to remediate","ttr",ttr,1,"s","includes approval wait")}${vr==null?`<div class="panel kp"><div class="lb">Verified fix rate</div><div class="kv mu">n/a</div><div class="mu">no fixes yet</div></div>`:kpi("Verified fix rate","vr",vr,0,"%")}${kpi("Rollbacks","rb",M.rem.rolled_back)}</div>
 <div class="g3">${card("Security posture","score over time","posture",240)}${card("Anomaly score","scored events and threshold","anomaly",240)}${card("Event activity","events per minute","activity",240)}${card("Detector comparison","controlled synthetic benchmark","detectors",240)}${f.length?card("Threat severity","findings by status","severity",240)+card("Remediation","seconds per finding","remediation",240):`<section class="panel span2"><div class="ph"><span class="pt">Findings</span><span class="mu">severity and remediation</span></div><div class="es"><div><b>No findings yet.</b><div class="mu">The severity breakdown and remediation timings appear after the first detection.</div></div>${acts?`<div class="mu">Simulate an attack to create one:</div><div class="ac">${acts}</div>`:""}</div></section>`}</div>
 <div class="g2 mt"><section class="panel"><div class="ph"><span class="pt">Recent findings</span><a class="lk" href="#findings">View all</a></div><div class="wrap"><table class="tbl">${f.length?f.slice(0,5).map(x=>`<tr class="clk" data-open="${x.id}"><td>${tg(x.sev,"bad")}</td><td>${esc(x.title)}</td><td>${stat(x.status)}</td></tr>`).join(""):`<tr><td>${none("No findings yet.")}</td></tr>`}</table></div></section>
 <section class="panel"><div class="ph"><span class="pt">Connection and resource health</span>${tg(live?"AWS live mode":"Simulation mode",live?"ok":"in")}</div>
 <div class="rw"><div class="gr1"><div>${live?"Live AWS account":"Local AWS emulator (moto)"}</div><div class="mu">Account ${esc(S.account)}, region ${esc(S.region)}, ${S.polls} checks at about ${S.latency} ms</div></div></div>
 ${S.resources.map(r=>`<div class="rw"><span class="dot ${r.ok?"ok":"bad"}"></span><div class="gr1"><div>${esc(r.name)}</div><div class="mu">${esc(r.ok?r.good:r.badtxt)}</div></div>${live?"":`<button class="btn sm" data-p="/api/attack/${r.id}" title="${esc(r.attack)}">Simulate attack</button>`}</div>`).join("")}</section></div>`}
function findings(){return`<div class="tools"><select id="fsev" aria-label="Severity"><option value="">All severities</option>${["Critical","High","Medium","Low"].map(x=>`<option>${x}</option>`).join("")}</select><select id="fst" aria-label="Status"><option value="">All statuses</option><option value="pending">Awaiting approval</option><option value="fixed">Remediated</option><option value="rejected">Rejected</option></select><span class="mu" id="fcount"></span></div><section class="panel"><div class="wrap"><table class="tbl" id="ftbl"></table></div></section>`}
function paintFindings(){const t=$$("ftbl");if(!t)return;const q=Q.toLowerCase(),L=S.findings.filter(x=>(!FSEV||x.sev==FSEV)&&(!FST||x.status==FST)&&(!q||(x.title+x.ref+x.id).toLowerCase().includes(q)));
 $$("fcount").textContent=`${L.length} of ${S.findings.length} findings`;
 t.innerHTML=L.length?`<tr><th>Severity</th><th>Finding</th><th>Technique</th><th>Source</th><th>Status</th><th>Detected in</th></tr>`+L.map(x=>`<tr class="clk" data-open="${x.id}"><td>${tg(x.sev,"bad")}</td><td>${esc(x.title)}</td><td class="mono">${mid(x)}</td><td>${x.id=="key"?"ML anomaly":"Rule"}</td><td>${stat(x.status)}</td><td>${x.tdetect}s</td></tr>`).join(""):`<tr><td colspan="6">${none(S.findings.length?"No findings match these filters.":"No findings yet. Use Simulate attack on the Overview page.")}</td></tr>`}
function events(){return`<div class="tools"><select id="ek" aria-label="Kind"><option value="">All events</option><option value="attack">Attack actions</option><option value="baseline">Baseline traffic</option></select><span class="mu" id="ecount"></span></div><section class="panel"><div class="wrap"><table class="tbl mono" id="etbl"></table></div></section><p class="mu" style="margin-top:12px">${S.mode=="Live AWS"?"Live CloudTrail ingestion is not built yet, so no live events appear here.":"Events are CloudTrail-style records written by the simulator, because moto does not produce CloudTrail. Baseline traffic is simulated normal activity."}</p>`}
function paintEvents(){const t=$$("etbl");if(!t)return;$$("ecount").textContent=`${EVR.length} shown`;
 t.innerHTML=EVR.length?`<tr><th>Time</th><th>Event</th><th>Service</th><th>Principal</th><th>Country</th><th>Kind</th><th>Mode</th></tr>`+EVR.map(e=>`<tr class="${EBOOT&&!ES.has(e.id)?"fresh":""}"><td>${esc(e.t)}</td><td>${esc(e.name)}</td><td>${esc(e.src)}</td><td>${esc(e.user)}</td><td>${esc(e.country)}</td><td>${tg(e.kind=="attack"?"Attack":"Baseline",e.kind=="attack"?"bad":"")}</td><td>${esc(e.mode)}</td></tr>`).join(""):`<tr><td colspan="7">${none("No events match.")}</td></tr>`;
 EVR.forEach(e=>ES.add(e.id));EBOOT=true}
async function loadEvents(){const r=await _get("/api/events?kind="+encodeURIComponent(EK)+"&q="+encodeURIComponent(Q));if(r){EVR=r.rows;if(route()=="events")paintEvents()}}
function audit(){return`<section class="panel"><div class="ph"><span class="pt">Audit trail</span><span>${tg(AU.chain_ok?"Hash chain verified":"Chain broken at entry "+AU.first_bad,AU.chain_ok?"ok":"bad")}${tg((AU.matched!=null&&AU.matched!=AU.count?AU.matched+" of ":"")+AU.count+" entries")}</span></div><div class="wrap"><table class="tbl mono">${AU.rows.map(r=>`<tr><td class="mu">#${r.i}</td><td class="mu">${esc(r.hash)}</td><td>${esc(r.text)}</td></tr>`).join("")||`<tr><td>${none("No entries match.")}</td></tr>`}</table></div></section>
 <section class="panel mt"><div class="ph"><span class="pt">Model evaluation</span></div>${evalTable()}${ML.multi?`<div class="pb"><div class="lb">Seed results (synthetic benchmark)</div><pre>${esc(ML.multi)}</pre></div>`:""}</section>
 <h2 class="sec">Dataset provenance</h2>${DS.length?DS.map(d=>`<details class="panel mt"><summary class="ph">${esc(d.name)}</summary><div class="pb"><pre>${esc(d.text)}</pre></div></details>`).join(""):'<div class="panel">'+none("No dataset metadata files found in datasets\\metadata. Add one per dataset with its source, licence, hash and record count.")+'</div>'}`}
const cfg=v=>v===undefined?"not recorded":v==="__na"?"not applied yet":v===null?"none configured":JSON.stringify(v,null,1),same=(a,b)=>JSON.stringify(a)==JSON.stringify(b);
function drawerHTML(x){const lab={pending:["Awaiting approval","wr"],fixed:["Fixed and verified","ok"],rejected:["Rejected","gr"]}[x.status]||[x.status,"gr"],m=x.mitre,
 acts=x.status=="pending"?`<button class="btn primary" data-p="/api/decide/${x.id}/ok">Approve fix</button><button class="btn danger" data-p="/api/decide/${x.id}/no">Reject</button>`:x.status=="fixed"?`<button class="btn" data-p="/api/rollback/${x.id}">Roll back this fix</button>`:"",
 hist=x.timeline.filter(t=>/APPROVED|REJECTED|STALE|ROLL/.test(t)),
 bars=x.explain&&x.explain.length>1?x.explain.map((e,i)=>`<div class="br"><span>${esc(e[0])}</span><b>${Math.round(e[1]*100)}%</b></div><div class="bt"><i class="gx" style="width:${e[1]*100}%;--i:${i}"></i></div>`).join(""):`<p class="mu">Rule trace: ${esc(x.ref)} was violated.</p>`;
 return`<div class="dh"><div><div class="pt">${esc(x.title)}</div><div class="mu">${esc(x.id)} · ${esc(x.asset)}</div></div><button class="btn sm" id="dclose">Close</button></div><div class="db">
 <div style="margin-top:12px">${tg(x.sev,"bad")}${tg(lab[0],lab[1])}</div>
 <div class="lb">Summary</div><p>${esc(x.what)}</p><p class="mu">${esc(x.why)}</p><p><span class="mu">Proposed fix:</span> ${esc(x.fix)}</p>
 <div class="lb">MITRE ATT&amp;CK</div><p><span class="chip">${esc(m.id||"n/a")}</span> ${esc(m.name||"No mapping recorded")}</p><p class="mu">Tactics: ${esc(m.tactics||"n/a")}</p>
 <div class="lb">Risk score</div><div class="rk"><b>${x.risk.score}</b> <span class="mu">/ 100</span></div>${x.risk.rows.map((r,i)=>`<div class="br"><span>${esc(r.name)} <span class="mu">weight ${Math.round(r.weight*100)}%, value ${r.value}</span></span><b>${r.points}</b></div><div class="bt"><i class="gx" style="width:${r.points}%;--i:${i}"></i></div>`).join("")}<p class="mu">${esc(x.risk.note)} ${esc(x.risk.excluded||"")}</p>
 ${x.blast_radius?`<div class="lb">IAM Capability &amp; Blast Radius</div>
 <div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:10px;margin-top:6px">
   <div style="display:flex;justify-content:space-between;align-items:center">
     <span><b>Target Identity:</b> ${esc(x.blast_radius.target_id)}</span>
     ${tg("Blast Risk: "+x.blast_radius.score+" / 100",x.blast_radius.severity=="Critical"?"bad":"wr")}
   </div>
   <p class="mu" style="margin-top:4px;font-size:12px">${esc(x.blast_radius.summary)}</p>
   ${x.blast_radius.admin_reachable?`<div style="margin-top:4px"><span class="chip" style="background:rgba(255,107,107,0.15);color:var(--bad);border:1px solid var(--bad)">★ Escalation Path to AdministratorAccess Detected</span></div>`:""}
   ${x.blast_radius.recommendations&&x.blast_radius.recommendations.length?`<div class="mu" style="margin-top:6px;font-size:11px"><b>Mitigation:</b> ${esc(x.blast_radius.recommendations[0])}</div>`:""}
 </div>`:""}
 <div class="lb">Evidence</div>${bars}${x.events.length?`<div class="lb">CloudTrail-style events</div><pre>${esc(JSON.stringify(x.events,null,1))}</pre>`:""}
 <div class="lb">Configuration before and after</div><div class="cmp">${[["At detection",x.detected],["Current",x.current],["After fix",x.status=="fixed"?x.after:"__na"]].map((c,i)=>`<div><div class="mu">${c[0]}</div><pre class="${i&&c[1]!=="__na"&&!same(c[1],x.detected)?"chg":""}">${esc(cfg(c[1]))}</pre></div>`).join("")}</div>
 <div class="lb">Remediation workflow</div>${stepper({status:x.status})}<div class="tl">${x.timeline.map(t=>`<div>${esc(t)}</div>`).join("")||'<span class="mu">No activity recorded.</span>'}</div>
 <div class="lb">Approval history and rollback</div><div class="tl">${hist.map(t=>`<div>${esc(t)}</div>`).join("")||'<span class="mu">No approvals yet.</span>'}</div><div class="ac">${acts}</div></div>`}
async function openDrawer(id){DR=id;const d=$$("drawer");d.className="drawer open";d.innerHTML='<div class="dh"><b>Loading…</b></div><div class="db"><div class="sk" style="height:200px;margin-top:12px"></div></div>';const x=await _get("/api/finding/"+id);if(DR!=id)return;d.innerHTML=x&&!x.error?drawerHTML(x):'<div class="dh"><b>Finding not available</b><button class="btn sm" id="dclose">Close</button></div>'}
function closeDrawer(){DR=null;$$("drawer").className="drawer"}
let KS="";async function loadMetrics(){const m=await _get("/api/metrics");if(!m)return;M=m;CG.update(ctx());const p=$$("pipe");if(p)p.innerHTML=pipe();const k=JSON.stringify([m.rem.rolled_back,m.rem.items.map(i=>i.ttr)]);if(k!==KS){KS=k;if(route()=="overview"&&BOOT)render()}}
function graph(){
 const g=window.GRAPH||{nodes:[],links:[],categories:[],stats:{}},
       st=g.stats||{},
       paths=window.ATTACK_PATHS||{},
       totPaths=Object.values(paths).reduce((a,b)=>a+b.length,0),
       selTarget=window.SEL_PRINCIPAL||"user/intern-dev",
       br=window.BLAST_REPORT;

 return `<div class="kpis">
   <div class="panel kp"><div class="lb">IAM Principals</div><div class="kv">${(st.users||0)+(st.roles||0)}</div><div class="mu">${st.users||0} users, ${st.roles||0} roles</div></div>
   <div class="panel kp"><div class="lb">Escalation Paths</div><div class="kv bad">${totPaths}</div><div class="mu">Multi-hop attack vectors</div></div>
   <div class="panel kp"><div class="lb">Admin Entities</div><div class="kv">${st.admin_roles||0}</div><div class="mu">Full AdministratorAccess</div></div>
   <div class="panel kp"><div class="lb">Cloud Resources</div><div class="kv">${st.resources||0}</div><div class="mu">S3 &amp; EC2 assets</div></div>
 </div>
 <div class="g3 mt">
   <section class="panel span2">
     <div class="ph">
       <span class="pt">IAM Capability &amp; Attack-Path Graph</span>
       <div class="ac">
         <button class="btn sm primary" id="btn-trace-admin" title="Highlight multi-hop attack path from intern-dev to admin-role">Trace intern-dev → admin</button>
         <button class="btn sm" id="btn-reset-graph" title="Reset view">Reset Graph</button>
       </div>
     </div>
     <div class="pb">
       <div class="cslot" data-key="iam_graph" style="height:460px"></div>
     </div>
   </section>
   <section class="panel">
     <div class="ph"><span class="pt">Blast Radius Investigator</span></div>
     <div class="pb">
       <div class="lb">Target Identity / Resource</div>
       <div style="display:flex;gap:6px;margin-bottom:12px">
         <select id="sel-blast-principal" style="flex:1;padding:6px;background:var(--sf2);color:var(--tx);border:1px solid var(--ln);border-radius:4px">
           ${(g.nodes||[]).filter(n=>n.category==0||n.category==1).map(n=>`<option value="${n.id}" ${n.id==selTarget?"selected":""}>${esc(n.name)} (${n.value})</option>`).join("")||'<option value="user/intern-dev">user/intern-dev</option>'}
         </select>
         <button class="btn sm" id="btn-investigate-blast">Check</button>
       </div>
       ${br?`<div class="rk"><b>${br.score}</b> <span class="mu">/ 100</span> ${tg(br.severity,br.severity=="Critical"?"bad":"wr")}</div>
         <p class="mu" style="font-size:12px;margin:8px 0">${esc(br.summary)}</p>
         <div class="lb">Reachable Identities (${(br.reachable_principals||[]).length})</div>
         <div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px">${(br.reachable_principals||[]).map(p=>`<span class="chip">${esc(p)}</span>`).join("")||'<span class="mu">None</span>'}</div>
         <div class="lb">Exposed Resources (${(br.reachable_resources||[]).length})</div>
         <div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px">${(br.reachable_resources||[]).map(r=>`<span class="chip ${(br.sensitive_resources_exposed||[]).includes(r)?"bad":""}">${esc(r)}</span>`).join("")||'<span class="mu">None</span>'}</div>
         <div class="lb">Remediation Guidance</div>
         <ul style="padding-left:16px;margin:4px 0;font-size:12px" class="mu">${(br.recommendations||[]).map(rec=>`<li>${esc(rec)}</li>`).join("")}</ul>`
       :`<div class="empty">Select an identity and click Check.</div>`}
     </div>
   </section>
 </div>
 <section class="panel mt">
   <div class="ph"><span class="pt">Discovered Privilege Escalation Vectors</span><span class="mu">${totPaths} active vectors</span></div>
   <div class="wrap">
     <table class="tbl">
       <tr><th>Source Principal</th><th>Target Capability</th><th>Hops</th><th>Risk</th><th>Severity</th><th>MITRE ATT&amp;CK</th><th>Action</th></tr>
       ${Object.entries(paths).flatMap(([p,list])=>list.map(pt=>`<tr>
         <td class="mono"><b>${esc(pt.source)}</b></td>
         <td class="mono">${esc(pt.target)}</td>
         <td>${pt.hops}</td>
         <td><b>${pt.risk_score}</b>/100</td>
         <td>${tg(pt.severity,pt.severity=="Critical"?"bad":"wr")}</td>
         <td><span class="chip">${esc((pt.steps[0]&&pt.steps[0].mitre&&pt.steps[0].mitre.id)||"T1078.004")}</span> ${esc((pt.steps[0]&&pt.steps[0].mitre&&pt.steps[0].mitre.name)||"Privilege Escalation")}</td>
         <td><button class="btn sm" data-trace="${esc(pt.nodes.join(","))}">Trace in Graph</button></td>
       </tr>`)).join("")||'<tr><td colspan="7"><div class="empty">No privilege escalation vectors detected.</div></td></tr>'}
     </table>
   </div>
 </section>`;
}
function refresh(){const r=route();if(r=="findings")paintFindings();if(r=="events")loadEvents();if(r=="audit")loadAudit();if(r=="graph"&&window.loadGraph)loadGraph()}
function bind(){const r=route();
 if(r=="findings"){$$("fsev").value=FSEV;$$("fst").value=FST;$$("fsev").onchange=e=>{FSEV=e.target.value;paintFindings()};$$("fst").onchange=e=>{FST=e.target.value;paintFindings()};paintFindings()}
 if(r=="events"){$$("ek").value=EK;$$("ek").onchange=e=>{EK=e.target.value;loadEvents()};loadEvents()}
 if(r=="graph"){
   const bTr=$$("btn-trace-admin");if(bTr)bTr.onclick=()=>window.loadGraph&&loadGraph("user/intern-dev,role/dev-role,role/cicd-deployer,role/admin-role,s3/student-records-demo");
   const bRs=$$("btn-reset-graph");if(bRs)bRs.onclick=()=>window.loadGraph&&loadGraph("");
   const bInv=$$("btn-investigate-blast");if(bInv)bInv.onclick=async()=>{
     const sel=$$("sel-blast-principal");if(sel&&window.investigateBlast)await investigateBlast(sel.value);
   };
   document.querySelectorAll("[data-trace]").forEach(btn=>{
     btn.onclick=()=>window.loadGraph&&loadGraph(btn.dataset.trace);
   });
 }
 CG.mount(ctx())}
let tm;$$("gq").addEventListener("input",e=>{clearTimeout(tm);tm=setTimeout(()=>{Q=e.target.value.trim();if(!["findings","events","audit"].includes(route()))location.hash="#findings";else refresh()},180)});
document.addEventListener("click",e=>{const o=e.target.closest("[data-open]");if(o)openDrawer(o.dataset.open);if(e.target.id=="dclose")closeDrawer();if(e.target.closest("[data-p]")&&DR)setTimeout(()=>DR&&openDrawer(DR),900)});
document.addEventListener("keydown",e=>{if(e.key=="Escape")closeDrawer();if(e.key=="/"&&!/INPUT|SELECT/.test(document.activeElement.tagName)){e.preventDefault();$$("gq").focus()}});
new MutationObserver(()=>CG.update(ctx())).observe(document.documentElement,{attributes:true,attributeFilter:["data-theme"]});
$$("menu").onclick=()=>document.body.classList.toggle("navopen");$$("scrim").onclick=()=>document.body.classList.remove("navopen");window.addEventListener("hashchange",()=>document.body.classList.remove("navopen"));
setTimeout(loadMetrics,0);setInterval(loadMetrics,3000);setInterval(()=>{if(route()=="events")loadEvents()},2000);
return{overview,findings,events,audit,graph,bind,slot,q:()=>Q,open:openDrawer}})();
