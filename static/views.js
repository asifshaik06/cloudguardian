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
   ${x.blast_radius.admin_reachable?`<div style="margin-top:4px"><span class="chip" style="background:rgba(255,107,107,0.15);color:var(--bad);border:1px solid var(--bad)">[CRITICAL] Escalation Path to AdministratorAccess Detected</span></div>`:""}
   ${x.blast_radius.recommendations&&x.blast_radius.recommendations.length?`<div class="mu" style="margin-top:6px;font-size:11px"><b>Mitigation:</b> ${esc(x.blast_radius.recommendations[0])}</div>`:""}
 </div>`:""}
 <div class="lb">Evidence</div>${bars}${x.events.length?`<div class="lb">CloudTrail-style events</div><pre>${esc(JSON.stringify(x.events,null,1))}</pre>`:""}
 <div class="lb">Configuration before and after</div><div class="cmp">${[["At detection",x.detected],["Current",x.current],["After fix",x.status=="fixed"?x.after:"__na"]].map((c,i)=>`<div><div class="mu">${c[0]}</div><pre class="${i&&c[1]!=="__na"&&!same(c[1],x.detected)?"chg":""}">${esc(cfg(c[1]))}</pre></div>`).join("")}</div>
 <div class="lb">Remediation workflow</div>${stepper({status:x.status})}<div class="tl">${x.timeline.map(t=>`<div>${esc(t)}</div>`).join("")||'<span class="mu">No activity recorded.</span>'}</div>
 <div class="lb">Approval history and rollback</div><div class="tl">${hist.map(t=>`<div>${esc(t)}</div>`).join("")||'<span class="mu">No approvals yet.</span>'}</div><div class="ac">${acts}</div></div>`}
async function openDrawer(id){DR=id;const d=$$("drawer");d.className="drawer open";d.innerHTML='<div class="dh"><b>Loading…</b></div><div class="db"><div class="sk" style="height:200px;margin-top:12px"></div></div>';const x=await _get("/api/finding/"+id);if(DR!=id)return;d.innerHTML=x&&!x.error?drawerHTML(x):'<div class="dh"><b>Finding not available</b><button class="btn sm" id="dclose">Close</button></div>'}
function closeDrawer(){DR=null;$$("drawer").className="drawer"}
let KS="";async function loadMetrics(){const m=await _get("/api/metrics");if(!m)return;M=m;CG.update(ctx());const p=$$("pipe");if(p)p.innerHTML=pipe();const k=JSON.stringify([m.rem.rolled_back,m.rem.items.map(i=>i.ttr)]);if(k!==KS){KS=k;if(route()=="overview"&&BOOT)render()}}
function renderInspectorHTML(){
 const edge = window.SELECTED_EDGE;
 const node = window.SELECTED_NODE;
 const path = window.ACTIVE_ATTACK_PATH;
 const br = window.BLAST_REPORT;
 const g = window.GRAPH || { nodes: [], links: [] };

 if(path){
  return `<div class="ph">
    <span class="pt">Attack Path Narrative</span>
    <button class="btn sm" id="btn-clear-path">Clear Trace</button>
  </div>
  <div class="pb">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <span class="mono" style="font-size:12px"><b>${esc(path.source)}</b> → <b>${esc(path.target)}</b></span>
      ${tg(path.severity, path.severity=="Critical"?"bad":"wr")}
    </div>
    <div class="rk" style="margin-bottom:8px"><b>${path.risk_score}</b> <span class="mu">/ 100 Risk</span> · <span class="mu">${path.hops} hops</span></div>
    <div class="lb">Execution Steps</div>
    <div style="display:flex;flex-direction:column;gap:6px;margin:8px 0">
      ${(path.steps||[]).map(s=>`
        <div style="background:var(--sf2);border:1px solid var(--ln);border-left:3px solid var(--bad);border-radius:4px;padding:8px">
          <div style="display:flex;justify-content:space-between;font-size:11px">
            <b>Step ${s.step}: ${esc(s.relationship)}</b>
            <span class="chip">${esc(s.mitre&&s.mitre.id||"T1078")}</span>
          </div>
          <div class="mono" style="font-size:11px;margin:3px 0">${esc(s.source)} → ${esc(s.target)}</div>
          ${s.actions&&s.actions.length?`<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:3px">${s.actions.map(a=>`<span class="chip" style="font-size:10px">${esc(a)}</span>`).join("")}</div>`:""}
        </div>
      `).join("")}
    </div>
    <div class="lb">Plain-English Summary</div>
    <p class="mu" style="font-size:12px;white-space:pre-line;line-height:1.4">${esc(path.narrative)}</p>
  </div>`;
 }

 if(edge){
  const ev = edge.evidence || {};
  return `<div class="ph">
    <span class="pt">Edge Relationship Inspector</span>
    <button class="btn sm" id="btn-clear-inspector">Close</button>
  </div>
  <div class="pb">
    <div style="margin-bottom:10px">
      ${tg(edge.relationship, edge.relationship=="AssumesRole"?"in":(edge.relationship=="PassRole"?"wr":(edge.relationship=="CanAccessResource"?"ok":"bad")))}
      ${edge.in_attack_path?tg("On Active Attack Path","bad"):""}
    </div>
    <div class="lb">Transition</div>
    <div style="background:var(--sf2);padding:8px;border-radius:4px;border:1px solid var(--ln);margin-bottom:10px">
      <div style="font-size:12px"><b>Source:</b> <span class="mono">${esc(edge.source)}</span></div>
      <div style="font-size:12px;margin-top:4px"><b>Target:</b> <span class="mono">${esc(edge.target)}</span></div>
    </div>
    <div class="lb">Permitted Actions</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
      ${edge.actions&&edge.actions.length?edge.actions.map(a=>`<span class="chip">${esc(a)}</span>`).join(""):`<span class="mu">Implicit trust transition</span>`}
    </div>
    ${ev.policy_arn?`<div class="lb">Policy ARN</div><code style="font-size:11px;display:block;margin-bottom:10px;word-break:break-all">${esc(ev.policy_arn)}</code>`:""}
    ${ev.vulnerability?`<div class="lb">Vulnerability Note</div><p class="mu" style="font-size:12px;margin-bottom:10px">${esc(ev.vulnerability)}</p>`:""}
    ${ev.impact?`<div class="lb">Potential Impact</div><p class="mu" style="font-size:12px;color:var(--bad);margin-bottom:10px">${esc(ev.impact)}</p>`:""}
    ${ev.trust_relationship?`<div class="lb">Trust Relationship</div><p class="mu" style="font-size:12px;margin-bottom:10px">${esc(ev.trust_relationship)}</p>`:""}
    <div class="lb">Evidence Provenance</div>
    <pre style="max-height:140px;overflow:auto;font-size:11px">${esc(JSON.stringify(ev,null,2))}</pre>
  </div>`;
 }

 if(node){
  const ev = node.evidence || {};
  return `<div class="ph">
    <span class="pt">Node Entity Inspector</span>
    <button class="btn sm" id="btn-clear-inspector">Close</button>
  </div>
  <div class="pb">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <span class="pt" style="font-size:14px">${esc(node.name)}</span>
      <div>
        ${node.is_admin?tg("AdministratorAccess","bad"):""}
        ${node.is_sensitive?tg("Sensitive Resource","wr"):""}
        ${tg(node.value||"Entity","in")}
      </div>
    </div>
    <div class="lb">Resource ARN / Identifier</div>
    <code style="font-size:11px;display:block;margin-bottom:10px;word-break:break-all">${esc(node.arn||node.id)}</code>
    <div class="lb">Entity Attributes</div>
    <pre style="max-height:140px;overflow:auto;font-size:11px;margin-bottom:10px">${esc(JSON.stringify(ev,null,2))}</pre>
    <button class="btn sm primary" style="width:100%" id="btn-inspect-node-blast" data-id="${esc(node.id)}">Calculate Blast Radius for this Node</button>
  </div>`;
 }

 // Default: Blast Radius Investigator
 return `<div class="ph"><span class="pt">Blast Radius Investigator</span></div>
 <div class="pb">
   <div class="lb">Target Identity / Resource</div>
   <div style="display:flex;gap:6px;margin-bottom:12px">
     <select id="sel-blast-principal" style="flex:1;padding:6px;background:var(--sf2);color:var(--tx);border:1px solid var(--ln);border-radius:4px">
       ${(g.nodes||[]).filter(n=>n.category==0||n.category==1).map(n=>`<option value="${n.id}" ${n.id==window.SEL_PRINCIPAL?"selected":""}>${esc(n.name)} (${n.value})</option>`).join("")||'<option value="user/intern-dev">user/intern-dev</option>'}
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
 </div>`;
}

function updateGraphInspector(){
 const el = $$("graph-inspector-panel");
 if(el){
  el.innerHTML = renderInspectorHTML();
  bindInspectorEvents();
 }
}
window.updateGraphInspector = updateGraphInspector;

window.onGraphElementClick = function(params){
 if(params.dataType === "edge"){
  window.SELECTED_EDGE = params.data;
  window.SELECTED_NODE = null;
  window.ACTIVE_ATTACK_PATH = null;
  updateGraphInspector();
 } else if(params.dataType === "node"){
  window.SELECTED_NODE = params.data;
  window.SELECTED_EDGE = null;
  window.ACTIVE_ATTACK_PATH = null;
  updateGraphInspector();
 }
};

function bindInspectorEvents(){
 const bClear = $$("btn-clear-path");
 if(bClear) bClear.onclick = () => {
  window.ACTIVE_ATTACK_PATH = null;
  window.loadGraph && loadGraph("");
  updateGraphInspector();
 };
 const bClose = $$("btn-clear-inspector");
 if(bClose) bClose.onclick = () => {
  window.SELECTED_EDGE = null;
  window.SELECTED_NODE = null;
  updateGraphInspector();
 };
 const bNodeBlast = $$("btn-inspect-node-blast");
 if(bNodeBlast) bNodeBlast.onclick = async () => {
  if(window.investigateBlast) await investigateBlast(bNodeBlast.dataset.id);
  window.SELECTED_NODE = null;
  updateGraphInspector();
 };
 const bInv = $$("btn-investigate-blast");
 if(bInv) bInv.onclick = async () => {
  const sel = $$("sel-blast-principal");
  if(sel && window.investigateBlast) await investigateBlast(sel.value);
  updateGraphInspector();
 };
}

function graph(){
 const g=window.GRAPH||{nodes:[],links:[],categories:[],stats:{}},
       st=g.stats||{},
       paths=window.ATTACK_PATHS||{},
       allPathsList=Object.values(paths).flat(),
       totPaths=allPathsList.length;

 return `<div class="kpis">
   <div class="panel kp"><div class="lb">IAM Principals</div><div class="kv">${(st.users||0)+(st.roles||0)}</div><div class="mu">${st.users||0} users, ${st.roles||0} roles</div></div>
   <div class="panel kp"><div class="lb">Escalation Paths</div><div class="kv bad">${totPaths}</div><div class="mu">Multi-hop attack vectors</div></div>
   <div class="panel kp"><div class="lb">Admin Entities</div><div class="kv">${st.admin_roles||0}</div><div class="mu">Full AdministratorAccess</div></div>
   <div class="panel kp"><div class="lb">Cloud Resources</div><div class="kv">${st.resources||0}</div><div class="mu">S3 &amp; EC2 assets</div></div>
 </div>

 <div class="tools" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
   <input id="graph-search" type="search" placeholder="Search node name or ARN..." value="${esc(window.GRAPH_SEARCH_QUERY||"")}" style="padding:6px 10px;background:var(--sf2);border:1px solid var(--ln);border-radius:4px;color:var(--tx);font-size:12px;min-width:180px" />
   
   <select id="filter-node-type" aria-label="Filter by Node Type" style="padding:6px;background:var(--sf2);border:1px solid var(--ln);border-radius:4px;color:var(--tx);font-size:12px">
     <option value="all" ${window.GRAPH_FILTER_NODE_TYPE=="all"?"selected":""}>All Node Types</option>
     <option value="user" ${window.GRAPH_FILTER_NODE_TYPE=="user"?"selected":""}>IAM Users</option>
     <option value="role" ${window.GRAPH_FILTER_NODE_TYPE=="role"?"selected":""}>IAM Roles</option>
     <option value="policy" ${window.GRAPH_FILTER_NODE_TYPE=="policy"?"selected":""}>Policies</option>
     <option value="s3" ${window.GRAPH_FILTER_NODE_TYPE=="s3"?"selected":""}>S3 Buckets</option>
     <option value="ec2" ${window.GRAPH_FILTER_NODE_TYPE=="ec2"?"selected":""}>EC2 Instances</option>
   </select>

   <select id="filter-rel-type" aria-label="Filter by Relationship Type" style="padding:6px;background:var(--sf2);border:1px solid var(--ln);border-radius:4px;color:var(--tx);font-size:12px">
     <option value="all" ${window.GRAPH_FILTER_REL_TYPE=="all"?"selected":""}>All Relationships</option>
     <option value="assumesrole" ${window.GRAPH_FILTER_REL_TYPE=="assumesrole"?"selected":""}>AssumesRole</option>
     <option value="passrole" ${window.GRAPH_FILTER_REL_TYPE=="passrole"?"selected":""}>PassRole</option>
     <option value="canaccessresource" ${window.GRAPH_FILTER_REL_TYPE=="canaccessresource"?"selected":""}>CanAccessResource</option>
     <option value="canescalateto" ${window.GRAPH_FILTER_REL_TYPE=="canescalateto"?"selected":""}>CanEscalateTo</option>
     <option value="haspolicy" ${window.GRAPH_FILTER_REL_TYPE=="haspolicy"?"selected":""}>HasPolicy</option>
   </select>

   <div style="display:flex;gap:4px;margin-left:auto">
     <button class="btn sm" id="btn-zoom-in" title="Zoom In">＋</button>
     <button class="btn sm" id="btn-zoom-out" title="Zoom Out">－</button>
     <button class="btn sm" id="btn-fit-screen" title="Fit to Screen">Fit</button>
     <button class="btn sm" id="btn-reset-layout" title="Reset Filters &amp; View">Reset</button>
   </div>
 </div>

 <div class="g3 mt" id="graph-section">
   <section class="panel span2">
     <div class="ph">
       <div>
         <span class="pt">IAM Capability &amp; Attack-Path Graph</span>
         <span class="mu" style="margin-left:8px;font-size:11px">Click nodes or edges to inspect details</span>
       </div>
       <div class="ac">
         <button class="btn sm primary" id="btn-trace-admin" title="Highlight multi-hop attack path from intern-dev to admin-role">Trace intern-dev → admin</button>
         <button class="btn sm" id="btn-trace-s3" title="Highlight path to sensitive student records">Trace to Sensitive S3</button>
         <button class="btn sm" id="btn-clear-path-top" title="Clear path highlight">Clear Highlight</button>
       </div>
     </div>
     <div class="pb">
       <div class="cslot" data-key="iam_graph" style="height:530px"></div>
     </div>
   </section>
   <section class="panel" id="graph-inspector-panel">
     ${renderInspectorHTML()}
   </section>
 </div>

 <section class="panel mt">
   <div class="ph"><span class="pt">Discovered Privilege Escalation Vectors</span><span class="mu">${totPaths} active vectors</span></div>
   <div class="wrap">
     <table class="tbl">
       <tr><th>Source Principal</th><th>Target Capability</th><th>Hops</th><th>Risk</th><th>Severity</th><th>MITRE ATT&amp;CK</th><th>Action</th></tr>
       ${allPathsList.map((pt,idx)=>`<tr>
         <td class="mono"><b>${esc(pt.source)}</b></td>
         <td class="mono">${esc(pt.target)}</td>
         <td>${pt.hops}</td>
         <td><b>${pt.risk_score}</b>/100</td>
         <td>${tg(pt.severity,pt.severity=="Critical"?"bad":"wr")}</td>
         <td><span class="chip">${esc((pt.steps[0]&&pt.steps[0].mitre&&pt.steps[0].mitre.id)||"T1078.004")}</span> ${esc((pt.steps[0]&&pt.steps[0].mitre&&pt.steps[0].mitre.name)||"Privilege Escalation")}</td>
         <td><button class="btn sm" data-trace-idx="${idx}">Trace in Graph</button></td>
       </tr>`).join("")||'<tr><td colspan="7"><div class="empty">No privilege escalation vectors detected.</div></td></tr>'}
     </table>
   </div>
 </section>`;
}
// ============================================================================
// IAM Attack Simulation Lab View (Part A, B, C, D, E)
// ============================================================================
let SCENARIOS_CATALOG = [];
let LAB_MODE = "catalog"; // "catalog" | "workbench" | "builder"
let LAB_CAT_FILTER = "";
let LAB_DIFF_FILTER = "";
let LAB_SEARCH_QUERY = "";
let ACTIVE_RUN = null;
let WORKBENCH_TAB = "paths"; // "paths" | "findings" | "inspector" | "remediation"
let SELECTED_SCENARIO_NODE = null;
let SELECTED_SCENARIO_EDGE = null;
let ACTIVE_SCENARIO_PATH = null;
let BUILDER_STATE = {
  name: "Custom Cloud Attack Scenario",
  description: "User-defined IAM access topology and escalation paths.",
  category: "Custom Scenario",
  learning_objective: "Evaluate custom authorization policies and path reachability.",
  identities: [
    { id: "user/custom-analyst", name: "custom-analyst", type: "user", is_admin: false, arn: "arn:aws:iam::123456789012:user/custom-analyst" },
    { id: "role/custom-admin", name: "custom-admin", type: "role", is_admin: true, arn: "arn:aws:iam::123456789012:role/custom-admin" }
  ],
  resources: [
    { id: "s3/confidential-archive", name: "confidential-archive", type: "s3", is_sensitive: true, arn: "arn:aws:s3:::confidential-archive" }
  ],
  relationships: [
    { source_id: "user/custom-analyst", target_id: "role/custom-admin", relationship: "AssumesRole", actions: ["sts:AssumeRole"] },
    { source_id: "role/custom-admin", target_id: "s3/confidential-archive", relationship: "CanAccessResource", actions: ["s3:*"] }
  ],
  statements: [
    { sid: "PermitAssume", effect: "Allow", actions: ["sts:AssumeRole"], resources: ["*"] }
  ]
};

async function loadScenarioCatalog() {
  const r = await _get("/api/scenarios");
  if (r && r.scenarios) {
    SCENARIOS_CATALOG = r.scenarios;
  }
}

async function launchScenarioRun(scenarioId) {
  const res = await fetch(`/api/scenarios/${encodeURIComponent(scenarioId)}/launch`, { method: "POST" });
  if (res.ok) {
    const data = await res.json();
    await loadRunDetails(data.run_id);
    LAB_MODE = "workbench";
    WORKBENCH_TAB = "paths";
    if (route() === "lab") render();
  } else {
    showToast("Failed to launch scenario.", "bad");
  }
}

async function loadRunDetails(runId, highlight) {
  const url = `/api/scenarios/runs/${encodeURIComponent(runId)}` + (highlight ? `?highlight=${encodeURIComponent(highlight)}` : "");
  const r = await _get(url);
  if (r && !r.error) {
    ACTIVE_RUN = r;
    window.SCENARIO_GRAPH = r.graph || { nodes: [], links: [], categories: [] };
    CG.update(ctx());
  }
}

window.onScenarioGraphClick = function(params) {
  if (params.dataType === "node") {
    SELECTED_SCENARIO_NODE = params.data;
    SELECTED_SCENARIO_EDGE = null;
    WORKBENCH_TAB = "inspector";
    updateWorkbenchInspector();
  } else if (params.dataType === "edge") {
    SELECTED_SCENARIO_EDGE = params.data;
    SELECTED_SCENARIO_NODE = null;
    WORKBENCH_TAB = "inspector";
    updateWorkbenchInspector();
  }
};

function renderWorkbenchInspector() {
  const edge = SELECTED_SCENARIO_EDGE;
  const node = SELECTED_SCENARIO_NODE;
  const run = ACTIVE_RUN;
  if (!run) return `<div class="pb"><p class="mu">No active scenario run.</p></div>`;

  if (WORKBENCH_TAB === "paths") {
    const paths = run.paths || [];
    if (!paths.length) {
      return `<div class="pb">
        <p class="mu">No active attack or privilege escalation paths discovered.</p>
        <p class="mu" style="font-size:11px;margin-top:6px">The current IAM configuration contains zero reachable paths to administrative control or sensitive resources.</p>
      </div>`;
    }

    return `<div class="pb" style="display:flex;flex-direction:column;gap:10px">
      ${paths.map((p, idx) => {
        const clsBadge = p.classification === "Confirmed" ? tg("Confirmed", "bad") :
                         p.classification === "Potential" ? tg("Potential", "wr") : tg("Theoretical", "");
        return `<div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:10px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span class="mono" style="font-size:12px"><b>${esc(p.source || p.source_id)}</b> → <b>${esc(p.target || p.target_id)}</b></span>
            ${clsBadge}
          </div>
          <div style="display:flex;gap:8px;font-size:11px;margin-bottom:8px" class="mu">
            <span>Risk Score: <b>${p.risk_score}</b></span>
            <span>·</span>
            <span>Hops: <b>${p.hops || p.hop_count}</b></span>
            <span>·</span>
            <span>${esc(p.severity || "High")} Severity</span>
          </div>
          <div style="font-size:11px;margin-bottom:8px;line-height:1.4">${esc(p.narrative || p.classification_reason || "")}</div>
          <div style="display:flex;gap:6px">
            <button class="btn sm primary" data-lab-trace="${idx}">Trace in Graph</button>
          </div>
        </div>`;
      }).join("")}
    </div>`;
  }

  if (WORKBENCH_TAB === "findings") {
    const findings = run.findings || [];
    if (!findings.length) {
      return `<div class="pb"><p class="mu">No security findings active for this scenario.</p></div>`;
    }

    return `<div class="pb" style="display:flex;flex-direction:column;gap:10px">
      ${findings.map(f => `
        <div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:10px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <b>${esc(f.title)}</b>
            ${tg(f.severity, f.severity === "Critical" ? "bad" : "wr")}
          </div>
          <div style="font-size:11px;color:var(--mu);margin-bottom:6px">${esc(f.category)} · MITRE ${esc(f.mitre_attack || "T1078")}</div>
          <p style="font-size:12px;margin-bottom:8px">${esc(f.description)}</p>
          <div style="background:var(--sf);border-left:3px solid var(--ac);padding:6px 8px;border-radius:3px;font-size:11px">
            <b>Remediation:</b> ${esc(f.remediation_advice)}
          </div>
        </div>
      `).join("")}
    </div>`;
  }

  if (WORKBENCH_TAB === "inspector") {
    if (edge) {
      return `<div class="pb">
        <div class="lb">Capability Transition Edge</div>
        <div style="display:flex;justify-content:space-between;margin-bottom:8px">
          <span class="mono"><b>${esc(edge.source)}</b> → <b>${esc(edge.target)}</b></span>
          ${tg(edge.relationship, "in")}
        </div>
        <div class="lb">Effect &amp; Permitted Actions</div>
        <p>${tg(edge.effect || "Allow", edge.effect === "Deny" ? "bad" : "ok")}</p>
        <div style="display:flex;flex-wrap:wrap;gap:4px;margin:6px 0">
          ${(edge.actions || []).map(a => `<span class="chip">${esc(a)}</span>`).join("") || '<span class="mu">No specific actions specified</span>'}
        </div>
        <div class="lb">Evidence &amp; Provenance</div>
        <pre>${esc(JSON.stringify(edge.evidence || {}, null, 2))}</pre>
        <button class="btn sm mt" id="btn-clear-lab-inspector">Clear Selection</button>
      </div>`;
    }

    if (node) {
      return `<div class="pb">
        <div class="lb">IAM / Resource Node</div>
        <div style="display:flex;justify-content:space-between;margin-bottom:8px">
          <b>${esc(node.name)}</b>
          ${tg(node.value || "Entity", "in")}
        </div>
        <div style="font-size:11px" class="mu mono">ARN: ${esc(node.arn || node.id)}</div>
        <div style="margin:8px 0">
          ${node.is_admin ? '<span class="tg bad">[ADMIN] AdministratorAccess</span>' : ''}
          ${node.is_sensitive ? '<span class="tg wr">[SENSITIVE] Sensitive Cloud Resource</span>' : ''}
        </div>
        <div class="lb">Evidence &amp; Policies</div>
        <pre>${esc(JSON.stringify(node.evidence || {}, null, 2))}</pre>
        <button class="btn sm mt" id="btn-clear-lab-inspector">Clear Selection</button>
      </div>`;
    }

    return `<div class="pb">
      <p class="mu">Click any node or relationship edge in the graph canvas to inspect IAM permissions, trust policies, and condition keys.</p>
    </div>`;
  }

  if (WORKBENCH_TAB === "remediation") {
    const vr = run.verification_result;
    const def = run.definition || {};
    const expRem = def.expected_remediation || {};

    return `<div class="pb">
      <div class="lb">Expected Remediation Strategy</div>
      <p style="font-size:12px;margin-bottom:10px">${esc(def.verification_criteria || "Eliminate privilege escalation vectors and enforce least privilege.")}</p>

      <div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:10px;margin-bottom:12px">
        <div class="lb" style="margin-top:0">Recommended Fix Action</div>
        <div class="mono" style="font-size:12px;margin-bottom:6px">Type: <b>${esc(expRem.type || "generic_remediation")}</b></div>
        ${expRem.target ? `<div class="mono" style="font-size:11px" class="mu">Target: ${esc(expRem.target)}</div>` : ""}
        <button class="btn primary sm" style="margin-top:10px" id="btn-apply-recommended-fix">Apply Recommended Fix</button>
      </div>

      ${vr ? `
        <div class="lb">Independent Verification Result</div>
        <div style="background:var(--sf2);border:1px solid ${vr.verified ? "var(--ok)" : "var(--bad)"};border-radius:6px;padding:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="font-size:14px;font-weight:600">${vr.verified ? "[PASS] Verification PASSED" : "[FAIL] Verification FAILED"}</span>
            ${tg(vr.status, vr.verified ? "ok" : "bad")}
          </div>
          <p style="font-size:12px;margin-bottom:8px">${esc(vr.summary)}</p>
          <div style="font-size:11px;color:var(--mu)">Verified at: ${esc(vr.timestamp)} · Action: ${esc(vr.action_taken)}</div>

          <div class="lb">Pre vs Post Metrics Comparison</div>
          <table class="tbl" style="font-size:11px;margin-top:4px">
            <tr><th>Metric</th><th>Pre-Fix</th><th>Post-Fix</th><th>Delta</th></tr>
            <tr><td>Attack Paths</td><td>${vr.metrics.pre_remediation.paths}</td><td>${vr.metrics.post_remediation.paths}</td><td>-${vr.metrics.delta.paths_eliminated}</td></tr>
            <tr><td>Blast Risk Score</td><td>${vr.metrics.pre_remediation.blast_radius_score}</td><td>${vr.metrics.post_remediation.blast_radius_score}</td><td>-${vr.metrics.delta.score_reduction}</td></tr>
            <tr><td>Confirmed Paths</td><td>${vr.metrics.pre_remediation.confirmed_paths}</td><td>${vr.metrics.post_remediation.confirmed_paths}</td><td>-</td></tr>
          </table>

          ${vr.remaining_paths && vr.remaining_paths.length ? `
            <div style="margin-top:8px;padding:6px;background:rgba(217,160,47,0.1);border:1px solid var(--wr);border-radius:4px;font-size:11px">
              <b>Alternative Vectors Remain:</b> ${vr.remaining_paths.length} path(s) still active in the topology.
            </div>
          ` : `
            <div style="margin-top:8px;padding:6px;background:rgba(63,178,127,0.1);border:1px solid var(--ok);border-radius:4px;font-size:11px;color:var(--ok)">
              [PASS] All discovered attack vectors completely mitigated.
            </div>
          `}
        </div>
      ` : `
        <div class="mu" style="font-size:11px">Click "Apply Recommended Fix" or choose a custom remediation to evaluate verification.</div>
      `}
    </div>`;
  }

  return "";
}

function updateWorkbenchInspector() {
  const el = $$("workbench-inspector-body");
  if (el) el.innerHTML = renderWorkbenchInspector();
  const tabs = document.querySelectorAll("[data-wb-tab]");
  tabs.forEach(t => {
    if (t.dataset.wbTab === WORKBENCH_TAB) {
      t.className = "btn sm primary";
    } else {
      t.className = "btn sm";
    }
  });
}

function renderCatalogView() {
  const q = LAB_SEARCH_QUERY.toLowerCase();
  const filtered = SCENARIOS_CATALOG.filter(s => {
    if (LAB_CAT_FILTER && s.category.toLowerCase() !== LAB_CAT_FILTER.toLowerCase()) return false;
    if (LAB_DIFF_FILTER && s.difficulty.toLowerCase() !== LAB_DIFF_FILTER.toLowerCase()) return false;
    if (q) {
      const txt = (s.name + s.description + s.learning_objective + (s.mitre_attack || []).join(" ")).toLowerCase();
      if (!txt.includes(q)) return false;
    }
    return true;
  });

  return `
    <div class="tools" style="margin-bottom:16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <input id="lab-search" type="search" placeholder="Search scenarios, MITRE techniques..." value="${esc(LAB_SEARCH_QUERY)}" style="min-width:260px" />
      <select id="lab-cat-filter">
        <option value="">All Categories (12)</option>
        <option value="Privilege Escalation" ${LAB_CAT_FILTER === "Privilege Escalation" ? "selected" : ""}>Privilege Escalation (4)</option>
        <option value="Resource Exposure" ${LAB_CAT_FILTER === "Resource Exposure" ? "selected" : ""}>Resource Exposure (4)</option>
        <option value="Identity & Lateral Movement" ${LAB_CAT_FILTER === "Identity & Lateral Movement" ? "selected" : ""}>Identity & Lateral Movement (4)</option>
      </select>
      <select id="lab-diff-filter">
        <option value="">All Difficulties</option>
        <option value="Beginner" ${LAB_DIFF_FILTER === "Beginner" ? "selected" : ""}>Beginner</option>
        <option value="Intermediate" ${LAB_DIFF_FILTER === "Intermediate" ? "selected" : ""}>Intermediate</option>
        <option value="Advanced" ${LAB_DIFF_FILTER === "Advanced" ? "selected" : ""}>Advanced</option>
      </select>
      <button class="btn sm" id="btn-lab-reset-filters">Reset Filters</button>
      <span class="mu" style="margin-left:auto">${filtered.length} of ${SCENARIOS_CATALOG.length} scenarios shown</span>
    </div>

    <div class="g3">
      ${filtered.map(s => `
        <article class="panel fc" style="display:flex;flex-direction:column;justify-content:space-between">
          <div>
            <div class="ph">
              <span class="pt">${esc(s.name)}</span>
              <div>
                ${tg(s.difficulty, s.difficulty === "Advanced" ? "bad" : s.difficulty === "Intermediate" ? "wr" : "ok")}
              </div>
            </div>
            <div class="pb">
              <div style="margin-bottom:8px">
                <span class="tg in" style="margin-left:0">${esc(s.category)}</span>
                ${(s.mitre_attack || []).map(m => `<span class="chip">${esc(m)}</span>`).join("")}
              </div>
              <p style="font-size:12px;margin-bottom:10px;line-height:1.4">${esc(s.description)}</p>
              <div style="background:var(--sf2);border-left:3px solid var(--ac);padding:6px 8px;border-radius:4px;font-size:11px;margin-bottom:12px">
                <b>Learning Objective:</b> ${esc(s.learning_objective)}
              </div>
              <div class="mu" style="font-size:11px">
                ${s.identity_count} Identities · ${s.resource_count} Resources · ${s.expected_findings_count} Expected Vectors
              </div>
            </div>
          </div>
          <div class="pb" style="border-top:1px solid var(--ln);padding-top:10px">
            <button class="btn primary sm" style="width:100%" data-launch-scenario="${esc(s.id)}">Launch in Workbench</button>
          </div>
        </article>
      `).join("")}
    </div>
  `;
}

function renderWorkbenchView() {
  if (!ACTIVE_RUN) {
    return `<div class="panel pb es" style="text-align:center;padding:48px 24px">
      <h3>No Active Scenario Simulation</h3>
      <p class="mu">Choose a predefined scenario from the Library or construct a custom scenario in the Builder to enter the active workbench.</p>
      <div style="display:flex;gap:12px;margin-top:16px">
        <button class="btn primary" id="btn-goto-catalog">Open Scenario Library</button>
        <button class="btn" id="btn-goto-builder">Open Custom Builder</button>
      </div>
    </div>`;
  }

  const run = ACTIVE_RUN;
  const def = run.definition || {};
  const statusColor = run.status === "verified" ? "ok" : run.status === "remediated" ? "wr" : "in";
  const br = run.blast_radius || {};
  const paths = run.paths || [];
  const findings = run.findings || [];

  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;background:var(--sf);border:1px solid var(--ln);padding:10px 16px;border-radius:8px;flex-wrap:wrap;gap:10px">
      <div>
        <div style="display:flex;align-items:center;gap:8px">
          <b style="font-size:15px">${esc(run.scenario_name)}</b>
          ${tg(run.status.toUpperCase(), statusColor)}
          <span class="chip" style="font-size:10px">${esc(run.run_id)}</span>
        </div>
        <div class="mu" style="font-size:11px;margin-top:3px">${esc(def.category || "")} · ${esc(def.difficulty || "")} · Isolated Moto Simulation</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn sm" id="btn-wb-reanalyze">Re-Analyze</button>
        <button class="btn sm" id="btn-wb-verify">Verify State</button>
        <button class="btn sm danger" id="btn-wb-reset">Reset Scenario</button>
        <button class="btn sm" id="btn-wb-switch">Switch Scenario</button>
      </div>
    </div>

    <div class="kpis">
      <div class="panel kp">
        <div class="lb">Blast Risk Score</div>
        <div class="kv ${br.score >= 70 ? "bad" : br.score >= 40 ? "wr" : "ok"}">${br.score || 0} <span class="mu" style="font-size:14px">/ 100</span></div>
        <div class="mu">${br.admin_reachable ? "[ADMIN] Admin Reachable" : "Admin Contained"}</div>
      </div>
      <div class="panel kp">
        <div class="lb">Attack Paths</div>
        <div class="kv">${paths.length}</div>
        <div class="mu">${paths.filter(p => p.classification === "Confirmed").length} Confirmed · ${paths.filter(p => p.classification === "Potential").length} Potential</div>
      </div>
      <div class="panel kp">
        <div class="lb">Security Findings</div>
        <div class="kv">${findings.length}</div>
        <div class="mu">${findings.filter(f => f.severity === "Critical").length} Critical · ${findings.filter(f => f.severity === "High").length} High</div>
      </div>
      <div class="panel kp">
        <div class="lb">Verification Status</div>
        <div class="kv ${run.status === "verified" ? "ok" : "mu"}">${run.status === "verified" ? "PASS" : "UNREMEDIATED"}</div>
        <div class="mu">${run.remediation_applied ? "Fix Applied" : "Awaiting Remediation"}</div>
      </div>
    </div>

    <div class="cols2" style="grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: 16px; margin-top: 16px">
      <!-- Left Column: Force-Directed Graph Canvas -->
      <section class="panel" style="display:flex;flex-direction:column">
        <div class="ph">
          <span class="pt">Simulated Capability Graph</span>
          <div style="display:flex;gap:6px">
            <button class="btn sm" id="btn-sg-zin" title="Zoom In">+</button>
            <button class="btn sm" id="btn-sg-zout" title="Zoom Out">-</button>
            <button class="btn sm" id="btn-sg-fit">Fit</button>
            <button class="btn sm" id="btn-sg-reset">Reset</button>
          </div>
        </div>
        <div class="pb" style="flex:1;min-height:540px;position:relative">
          <div class="cslot" data-key="scenario_graph" style="height:540px;width:100%"></div>
        </div>
      </section>

      <!-- Right Column: Inspector & Investigator -->
      <section class="panel" style="display:flex;flex-direction:column">
        <div class="ph" style="padding:6px 12px;gap:6px">
          <button class="btn sm ${WORKBENCH_TAB === "paths" ? "primary" : ""}" data-wb-tab="paths">Paths (${paths.length})</button>
          <button class="btn sm ${WORKBENCH_TAB === "findings" ? "primary" : ""}" data-wb-tab="findings">Findings (${findings.length})</button>
          <button class="btn sm ${WORKBENCH_TAB === "inspector" ? "primary" : ""}" data-wb-tab="inspector">Inspector</button>
          <button class="btn sm ${WORKBENCH_TAB === "remediation" ? "primary" : ""}" data-wb-tab="remediation">Playground</button>
        </div>
        <div id="workbench-inspector-body" style="overflow-y:auto;max-height:540px">
          ${renderWorkbenchInspector()}
        </div>
      </section>
    </div>
  `;
}

function renderBuilderView() {
  const b = BUILDER_STATE;

  return `
    <div class="cols2" style="grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); gap: 16px">
      <!-- Left Column: Builder Form -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <section class="panel">
          <div class="ph"><span class="pt">1. Scenario Metadata</span></div>
          <div class="pb" style="display:flex;flex-direction:column;gap:10px">
            <div>
              <div class="lb" style="margin-top:0">Scenario Name</div>
              <input id="b-meta-name" type="text" value="${esc(b.name)}" style="width:100%" />
            </div>
            <div>
              <div class="lb">Description</div>
              <input id="b-meta-desc" type="text" value="${esc(b.description)}" style="width:100%" />
            </div>
            <div>
              <div class="lb">Learning Objective</div>
              <input id="b-meta-obj" type="text" value="${esc(b.learning_objective)}" style="width:100%" />
            </div>
          </div>
        </section>

        <!-- Entity Creation -->
        <section class="panel">
          <div class="ph"><span class="pt">2. Add IAM Identities &amp; Resources</span></div>
          <div class="pb" style="display:flex;flex-direction:column;gap:12px">
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <input id="b-ent-name" placeholder="Entity name (e.g. dev-user)" style="flex:1" />
              <select id="b-ent-type">
                <option value="user">IAM User</option>
                <option value="role">IAM Role</option>
                <option value="group">IAM Group</option>
                <option value="s3">S3 Bucket</option>
                <option value="ec2">EC2 Instance</option>
                <option value="kms">KMS Key</option>
              </select>
              <label style="display:flex;align-items:center;gap:4px;font-size:12px">
                <input type="checkbox" id="b-ent-flag"> Privileged / Sensitive
              </label>
              <button class="btn sm primary" id="btn-b-add-entity">Add Entity</button>
            </div>

            <div class="lb">Configured Topology Entities (${b.identities.length + b.resources.length})</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              ${b.identities.map(i => `<span class="chip">${esc(i.id)} ${i.is_admin ? "[ADMIN]" : ""}</span>`).join("")}
              ${b.resources.map(r => `<span class="chip" style="border-color:var(--wr)">${esc(r.id)} ${r.is_sensitive ? "[SENSITIVE]" : ""}</span>`).join("")}
            </div>
          </div>
        </section>

        <!-- Relationship Creation -->
        <section class="panel">
          <div class="ph"><span class="pt">3. Add Capability Relationships</span></div>
          <div class="pb" style="display:flex;flex-direction:column;gap:12px">
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <select id="b-rel-src" style="flex:1">
                ${b.identities.concat(b.resources).map(e => `<option value="${esc(e.id)}">${esc(e.id)}</option>`).join("")}
              </select>
              <select id="b-rel-type">
                <option value="AssumesRole">AssumesRole</option>
                <option value="PassRole">PassRole</option>
                <option value="CanAccessResource">CanAccessResource</option>
                <option value="CanEscalateTo">CanEscalateTo</option>
              </select>
              <select id="b-rel-tgt" style="flex:1">
                ${b.identities.concat(b.resources).map(e => `<option value="${esc(e.id)}">${esc(e.id)}</option>`).join("")}
              </select>
            </div>
            <div style="display:flex;gap:8px">
              <input id="b-rel-actions" placeholder="Actions (comma separated, e.g. sts:AssumeRole, s3:*)" style="flex:1" />
              <button class="btn sm primary" id="btn-b-add-rel">Add Edge</button>
            </div>

            <div class="lb">Configured Capability Edges (${b.relationships.length})</div>
            <div style="display:flex;flex-direction:column;gap:4px">
              ${b.relationships.map(r => `
                <div class="mono" style="font-size:11px;background:var(--sf2);padding:4px 8px;border-radius:4px">
                  ${esc(r.source_id)} ──[${esc(r.relationship)}: ${esc((r.actions||[]).join(","))}]──&gt; ${esc(r.target_id)}
                </div>
              `).join("")}
            </div>
          </div>
        </section>
      </div>

      <!-- Right Column: Policy Validator & Launch -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <section class="panel">
          <div class="ph">
            <span class="pt">4. IAM Policy Statement Validator</span>
            <button class="btn sm" id="btn-validate-policy-stmt">Validate Statement</button>
          </div>
          <div class="pb" style="display:flex;flex-direction:column;gap:10px">
            <div style="display:flex;gap:8px">
              <select id="b-stmt-effect">
                <option value="Allow">Effect: Allow</option>
                <option value="Deny">Effect: Deny</option>
              </select>
              <input id="b-stmt-actions" placeholder="Action (e.g. s3:*, iam:PassRole)" style="flex:1" value="sts:AssumeRole" />
            </div>
            <div>
              <div class="lb" style="margin-top:0">Resource Scope</div>
              <input id="b-stmt-resources" placeholder="Resource ARN (e.g. * or arn:aws:s3:::*)" style="width:100%" value="*" />
            </div>
            <div id="policy-validation-result" style="display:none;padding:10px;border-radius:6px;background:var(--sf2);border:1px solid var(--ln);font-size:12px"></div>
          </div>
        </section>

        <section class="panel">
          <div class="ph"><span class="pt">5. Build &amp; Simulate</span></div>
          <div class="pb">
            <p class="mu" style="font-size:12px;margin-bottom:12px">
              Compiles your custom cloud entities, capability edges, and policy statements into an isolated NetworkX capability graph, discovers all transitive escalation paths, and calculates attack blast radius.
            </p>
            <button class="btn primary" id="btn-build-and-launch-custom" style="width:100%;height:36px;font-size:13px">
              Build &amp; Launch in Workbench
            </button>
          </div>
        </section>
      </div>
    </div>
  `;
}

function lab() {
  if (!SCENARIOS_CATALOG.length) {
    loadScenarioCatalog().then(() => {
      if (route() === "lab") render();
    });
  }

  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;border-bottom:1px solid var(--ln);padding-bottom:12px;flex-wrap:wrap;gap:10px">
      <div>
        <h2 style="margin:0;font-size:18px;font-weight:600">IAM Attack Simulation Lab</h2>
        <div class="mu" style="font-size:12px;margin-top:2px">Isolated Moto AWS attack scenarios, deterministic IAM policy evaluation, and independent post-remediation verification.</div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn ${LAB_MODE === "catalog" ? "primary" : ""}" id="tab-lab-catalog">Scenario Library (12)</button>
        <button class="btn ${LAB_MODE === "workbench" ? "primary" : ""}" id="tab-lab-workbench">Workbench ${ACTIVE_RUN ? `(${esc(ACTIVE_RUN.scenario_name)})` : ""}</button>
        <button class="btn ${LAB_MODE === "builder" ? "primary" : ""}" id="tab-lab-builder">Custom Builder</button>
      </div>
    </div>

    ${LAB_MODE === "catalog" ? renderCatalogView() :
      LAB_MODE === "workbench" ? renderWorkbenchView() :
      renderBuilderView()}
  `;
}

// =========================================================================
// SOC LAYER: ALERTS, INCIDENTS, REMEDIATION, ARCHITECTURE, GUIDED DEMO
// =========================================================================

let ALERTS_DATA = { alerts: [], total: 0 }, ALERTS_STATS = { total: 0, by_severity: {}, by_status: {} },
    ALERTS_SEV = "", ALERTS_ST = "", ALERTS_SRC = "", ALERTS_Q = "", SELECTED_ALERT_ID = null, ALERTS_BOOT = false;

async function loadAlerts() {
  const query = new URLSearchParams();
  if (ALERTS_SEV) query.set("severity", ALERTS_SEV);
  if (ALERTS_ST) query.set("status", ALERTS_ST);
  if (ALERTS_SRC) query.set("source", ALERTS_SRC);
  if (ALERTS_Q) query.set("q", ALERTS_Q);
  const data = await _get(`/api/alerts?${query.toString()}`);
  if (data) ALERTS_DATA = data;
  const stats = await _get("/api/alerts/stats");
  if (stats) ALERTS_STATS = stats;
  ALERTS_BOOT = true;
  if (route() === "alerts") render();
}

function alerts() {
  if (!ALERTS_BOOT) {
    loadAlerts();
    return `<div class="panel sk" style="height:400px"></div>`;
  }
  const st = ALERTS_STATS || {};
  const items = ALERTS_DATA.alerts || [];
  const selected = items.find(a => a.id === SELECTED_ALERT_ID) || items[0] || null;

  return `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;border-bottom:1px solid var(--ln);padding-bottom:12px;flex-wrap:wrap;gap:12px">
      <div>
        <h2 style="margin:0;font-size:18px;font-weight:600">Security Alerts Management</h2>
        <div class="mu" style="font-size:12px;margin-top:2px">Real-time alerts correlated from CIS rule scanner, ML anomaly detector, and IAM attack graph intelligence.</div>
      </div>
      <button class="btn sm" id="btn-refresh-alerts">Refresh Alerts</button>
    </div>

    <div class="kpis">
      <div class="panel kp">
        <div class="lb">Total Alerts</div>
        <div class="kv">${st.total || 0}</div>
        <div class="mu">All recorded detections</div>
      </div>
      <div class="panel kp">
        <div class="lb">Unresolved</div>
        <div class="kv ${(st.unresolved_count||0)>0?'bad':'ok'}">${st.unresolved_count || 0}</div>
        <div class="mu">Active investigation queue</div>
      </div>
      <div class="panel kp">
        <div class="lb">Critical Severity</div>
        <div class="kv bad">${(st.by_severity && st.by_severity.Critical) || 0}</div>
        <div class="mu">Immediate threat response</div>
      </div>
      <div class="panel kp">
        <div class="lb">High Severity</div>
        <div class="kv wr">${(st.by_severity && st.by_severity.High) || 0}</div>
        <div class="mu">Elevated risk posture</div>
      </div>
      <div class="panel kp">
        <div class="lb">Investigating</div>
        <div class="kv">${(st.by_status && st.by_status.Investigating) || 0}</div>
        <div class="mu">Assigned to analysts</div>
      </div>
    </div>

    <div class="tools">
      <select id="sel-al-sev" aria-label="Severity filter">
        <option value="" ${ALERTS_SEV===""?"selected":""}>All Severities</option>
        <option value="Critical" ${ALERTS_SEV==="Critical"?"selected":""}>Critical</option>
        <option value="High" ${ALERTS_SEV==="High"?"selected":""}>High</option>
        <option value="Medium" ${ALERTS_SEV==="Medium"?"selected":""}>Medium</option>
        <option value="Low" ${ALERTS_SEV==="Low"?"selected":""}>Low</option>
      </select>
      <select id="sel-al-st" aria-label="Status filter">
        <option value="" ${ALERTS_ST===""?"selected":""}>All Statuses</option>
        <option value="New" ${ALERTS_ST==="New"?"selected":""}>New</option>
        <option value="Acknowledged" ${ALERTS_ST==="Acknowledged"?"selected":""}>Acknowledged</option>
        <option value="Investigating" ${ALERTS_ST==="Investigating"?"selected":""}>Investigating</option>
        <option value="Resolved" ${ALERTS_ST==="Resolved"?"selected":""}>Resolved</option>
        <option value="Suppressed" ${ALERTS_ST==="Suppressed"?"selected":""}>Suppressed</option>
      </select>
      <select id="sel-al-src" aria-label="Source filter">
        <option value="" ${ALERTS_SRC===""?"selected":""}>All Sources</option>
        <option value="Rule Engine" ${ALERTS_SRC==="Rule Engine"?"selected":""}>Rule Engine</option>
        <option value="ML Anomaly Detector" ${ALERTS_SRC==="ML Anomaly Detector"?"selected":""}>ML Anomaly Detector</option>
        <option value="IAM Graph" ${ALERTS_SRC==="IAM Graph"?"selected":""}>IAM Graph</option>
        <option value="Simulation Lab" ${ALERTS_SRC==="Simulation Lab"?"selected":""}>Simulation Lab</option>
      </select>
      <input type="search" id="inp-al-q" placeholder="Filter alerts by title or resource..." value="${esc(ALERTS_Q)}" style="min-width:240px">
      <span class="mu" style="margin-left:auto">${items.length} of ${st.total || 0} alerts</span>
    </div>

    <div class="cols2">
      <!-- Alerts Table -->
      <section class="panel">
        <div class="ph">
          <span class="pt">Alerts Queue</span>
          <span class="mu">Click row to investigate</span>
        </div>
        <div class="wrap">
          <table class="tbl">
            <tr>
              <th>ID</th><th>Severity</th><th>Title</th><th>Resource</th><th>Status</th>
            </tr>
            ${items.length ? items.map(a => `
              <tr class="clk ${selected && selected.id === a.id ? 'fresh' : ''}" data-select-alert="${esc(a.id)}">
                <td class="mono"><b>${esc(a.id)}</b></td>
                <td>${tg(a.severity, a.severity === 'Critical' ? 'crit' : a.severity === 'High' ? 'high' : 'med')}</td>
                <td><b>${esc(a.title)}</b><div class="mu" style="font-size:11px">${esc(a.detection_source)} · ${esc(a.timestamp)}</div></td>
                <td class="mono" style="font-size:11px">${esc(a.affected_resource)}</td>
                <td>${tg(a.status, a.status === 'Resolved' ? 'ok' : a.status === 'New' ? 'bad' : 'wr')}</td>
              </tr>
            `).join("") : `<tr><td colspan="5">${none("No alerts match active filters.")}</td></tr>`}
          </table>
        </div>
      </section>

      <!-- Alert Investigation Inspector -->
      <section class="panel">
        <div class="ph">
          <span class="pt">Alert Investigation &amp; Triage</span>
          ${selected ? tg(selected.status, selected.status === 'Resolved' ? 'ok' : 'wr') : ''}
        </div>
        ${selected ? `
          <div class="pb">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
              <div>
                <h3 style="margin:0 0 4px;font-size:15px;font-weight:600">${esc(selected.title)}</h3>
                <div class="mu mono" style="font-size:11px">Alert ID: ${esc(selected.id)} · Account: ${esc(selected.account_id)}</div>
              </div>
              ${tg(selected.severity, selected.severity === 'Critical' ? 'crit' : selected.severity === 'High' ? 'high' : 'med')}
            </div>

            <div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:10px;margin-bottom:12px">
              <div class="lb" style="margin-top:0">Trigger Explanation</div>
              <p style="font-size:12px;margin:0 0 4px">${esc(selected.trigger_reason || 'Condition violated baseline security threshold.')}</p>
              <div class="mu" style="font-size:11px">Detection Source: <b>${esc(selected.detection_source)}</b> · Reference: <code class="mono">${esc(selected.rule_ref || 'N/A')}</code></div>
            </div>

            ${selected.ml_anomaly_score ? `
              <div style="background:rgba(76,141,255,0.08);border:1px solid var(--ac);border-radius:6px;padding:10px;margin-bottom:12px">
                <div class="lb" style="margin-top:0">ML Anomaly Detector Score</div>
                <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                  <span>Isolation Forest Anomaly Score:</span>
                  <b>${selected.ml_anomaly_score.toFixed(3)} (Threshold: 0.650)</b>
                </div>
                ${selected.ml_explanation ? `
                  <div class="mu" style="font-size:11px;margin-top:4px">Feature Contributions:</div>
                  <pre style="margin-top:4px;font-size:11px">${esc(JSON.stringify(selected.ml_explanation, null, 2))}</pre>
                ` : ''}
              </div>
            ` : ''}

            <div class="lb">Raw Evidence &amp; Telemetry</div>
            <pre style="max-height:160px;font-size:11px">${esc(JSON.stringify(selected.evidence || selected.raw_event || {}, null, 2))}</pre>

            <div class="lb">Audit Timeline (${selected.timeline ? selected.timeline.length : 0})</div>
            <div class="tl" style="max-height:140px;overflow-y:auto;margin-bottom:14px">
              ${(selected.timeline || []).map(t => `<div><span class="mu">${esc(t.timestamp)}:</span> ${esc(t.event)} ${t.user ? `<b class="mono">(${esc(t.user)})</b>` : ''}</div>`).join('')}
            </div>

            <div class="lb">SOC Analyst Actions</div>
            <div class="ac" style="margin-top:8px">
              <button class="btn sm" id="btn-al-ack" data-id="${esc(selected.id)}">Acknowledge</button>
              <button class="btn sm" id="btn-al-inv" data-id="${esc(selected.id)}">Investigate</button>
              <button class="btn sm primary" id="btn-al-res" data-id="${esc(selected.id)}">Resolve Alert</button>
              <button class="btn sm danger" id="btn-al-sup" data-id="${esc(selected.id)}">Suppress</button>
              <button class="btn sm primary" id="btn-al-esc" data-id="${esc(selected.id)}" style="background:var(--bad);border-color:var(--bad)">Escalate to Incident</button>
            </div>

            ${selected.related_finding_id ? `
              <div style="margin-top:14px;border-top:1px solid var(--ln);padding-top:10px;display:flex;gap:12px;font-size:12px">
                <a class="lk" href="#findings" data-open="${esc(selected.related_finding_id)}">View Correlated Finding (${esc(selected.related_finding_id)})</a>
                <a class="lk" href="#remediation">View Remediation Workflow</a>
                <a class="lk" href="#graph">Inspect Target in Graph</a>
              </div>
            ` : ''}
          </div>
        ` : `<div class="pb">${none("Select an alert from the table to inspect details.")}</div>`}
      </section>
    </div>
  `;
}

let INCIDENTS_DATA = { incidents: [], total: 0 }, SELECTED_INCIDENT_ID = null, INCIDENTS_BOOT = false;

async function loadIncidents() {
  const data = await _get("/api/incidents");
  if (data) INCIDENTS_DATA = data;
  INCIDENTS_BOOT = true;
  if (route() === "incidents") render();
}

function incidents() {
  if (!INCIDENTS_BOOT) {
    loadIncidents();
    return `<div class="panel sk" style="height:400px"></div>`;
  }

  const items = INCIDENTS_DATA.incidents || [];
  const selected = items.find(i => i.id === SELECTED_INCIDENT_ID) || items[0] || null;
  const STAGES = ["Triage", "Investigation", "Containment", "Remediation", "Verification", "Closed"];

  return `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;border-bottom:1px solid var(--ln);padding-bottom:12px;flex-wrap:wrap;gap:12px">
      <div>
        <h2 style="margin:0;font-size:18px;font-weight:600">Security Incident Management</h2>
        <div class="mu" style="font-size:12px;margin-top:2px">Formal SOC incident coordination with phased response: Triage -> Investigation -> Containment -> Remediation -> Verification -> Closed.</div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn sm" id="btn-refresh-incidents">Refresh</button>
        <button class="btn sm primary" id="btn-create-incident-modal">+ Create Incident</button>
      </div>
    </div>

    <div class="cols2">
      <!-- Incidents List -->
      <section class="panel">
        <div class="ph">
          <span class="pt">Active Incidents (${items.length})</span>
          <span class="mu">Click to open workspace</span>
        </div>
        <div class="wrap">
          <table class="tbl">
            <tr>
              <th>ID</th><th>Severity</th><th>Title</th><th>Stage</th><th>Responder</th>
            </tr>
            ${items.length ? items.map(inc => `
              <tr class="clk ${selected && selected.id === inc.id ? 'fresh' : ''}" data-select-incident="${esc(inc.id)}">
                <td class="mono"><b>${esc(inc.id)}</b></td>
                <td>${tg(inc.severity, inc.severity === 'Critical' ? 'crit' : 'high')}</td>
                <td><b>${esc(inc.title)}</b><div class="mu" style="font-size:11px">${esc(inc.created_at)} · ${inc.linked_alert_ids ? inc.linked_alert_ids.length : 0} alerts</div></td>
                <td>${tg(inc.status, inc.status === 'Closed' ? 'ok' : inc.status === 'Containment' ? 'crit' : 'wr')}</td>
                <td style="font-size:11px" class="mu">${esc(inc.lead_responder)}</td>
              </tr>
            `).join("") : `<tr><td colspan="5">${none("No active incidents. Escalate an alert to create one.")}</td></tr>`}
          </table>
        </div>
      </section>

      <!-- Incident Workspace -->
      <section class="panel">
        <div class="ph">
          <span class="pt">Incident Response Workspace</span>
          ${selected ? tg(selected.status, selected.status === 'Closed' ? 'ok' : 'wr') : ''}
        </div>
        ${selected ? `
          <div class="pb">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
              <div>
                <h3 style="margin:0 0 4px;font-size:16px;font-weight:600">${esc(selected.title)}</h3>
                <div class="mu mono" style="font-size:11px">Incident ID: ${esc(selected.id)} · Lead: ${esc(selected.lead_responder)}</div>
              </div>
              ${tg(selected.severity, selected.severity === 'Critical' ? 'crit' : 'high')}
            </div>

            <!-- Phased Lifecycle Stepper -->
            <div class="lb">Incident Response Lifecycle</div>
            <div class="st" style="margin-bottom:16px">
              ${STAGES.map((stg, i) => {
                const curIdx = STAGES.indexOf(selected.status);
                const cls = i < curIdx || selected.status === 'Closed' ? 'd' : i === curIdx ? 'a' : '';
                return `<span class="s ${cls}">${stg}</span>`;
              }).join("")}
            </div>

            <div class="lb">Incident Summary</div>
            <p style="font-size:12px;margin-bottom:12px">${esc(selected.summary)}</p>

            <div class="lb">Affected Cloud Assets (${selected.affected_assets ? selected.affected_assets.length : 0})</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">
              ${(selected.affected_assets || []).map(a => `<span class="chip" style="border-color:var(--bad)">${esc(a)}</span>`).join("") || '<span class="mu">No assets registered.</span>'}
            </div>

            <div class="lb">Linked Alerts &amp; Findings</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">
              ${(selected.linked_alert_ids || []).map(aid => `<a class="chip lk" href="#alerts" style="text-decoration:none">${esc(aid)}</a>`).join("")}
              ${(selected.linked_finding_ids || []).map(fid => `<a class="chip lk" href="#findings" style="text-decoration:none">Finding: ${esc(fid)}</a>`).join("")}
            </div>

            ${selected.containment_evidence ? `
              <div class="lb">Containment Evidence</div>
              <pre style="font-size:11px;margin-bottom:12px">${esc(JSON.stringify(selected.containment_evidence, null, 2))}</pre>
            ` : ''}

            <div class="lb">Incident Timeline &amp; Notes (${selected.timeline ? selected.timeline.length : 0})</div>
            <div class="tl" style="max-height:140px;overflow-y:auto;margin-bottom:14px">
              ${(selected.timeline || []).map(t => `<div><span class="mu">${esc(t.timestamp)}:</span> ${esc(t.event)} ${t.user ? `<b>(${esc(t.user)})</b>` : ''}</div>`).join('')}
            </div>

            <!-- Add Note -->
            <div style="display:flex;gap:8px;margin-bottom:14px">
              <input type="text" id="inp-inc-note" placeholder="Add responder note to audit log..." style="flex:1">
              <button class="btn sm" id="btn-inc-add-note" data-id="${esc(selected.id)}">Add Note</button>
            </div>

            <!-- Incident Actions -->
            <div class="lb">Response Actions</div>
            <div class="ac" style="margin-top:8px">
              ${selected.status !== 'Closed' ? `
                <button class="btn sm primary" id="btn-inc-next-stage" data-id="${esc(selected.id)}">Advance Phase (${STAGES[Math.min(STAGES.length-1, STAGES.indexOf(selected.status)+1)]})</button>
                <button class="btn sm" id="btn-inc-record-contain" data-id="${esc(selected.id)}">Record Containment</button>
                <button class="btn sm danger" id="btn-inc-close" data-id="${esc(selected.id)}">Close Incident</button>
              ` : `<span class="mu" style="font-size:12px">Incident closed on ${esc(selected.updated_at)}. Reason: ${esc(selected.closure_reason || 'Resolved')}</span>`}
            </div>
          </div>
        ` : `<div class="pb">${none("Select an incident to view details.")}</div>`}
      </section>
    </div>
  `;
}

let REM_DATA = { remediations: [], total: 0, stats: {} }, SELECTED_REM_ID = null, REM_BOOT = false, REM_SEV = "", REM_ST = "";

async function loadRemediations() {
  const query = new URLSearchParams();
  if (REM_SEV) query.set("severity", REM_SEV);
  if (REM_ST) query.set("status", REM_ST);
  const data = await _get(`/api/remediations?${query.toString()}`);
  if (data) REM_DATA = data;
  REM_BOOT = true;
  if (route() === "remediation" || route() === "response") render();
}

function remediation() {
  if (!REM_BOOT) {
    loadRemediations();
    return `<div class="panel sk" style="height:400px"></div>`;
  }

  const st = REM_DATA.stats || {};
  const items = REM_DATA.remediations || [];
  const selected = items.find(r => r.id === SELECTED_REM_ID) || items[0] || null;

  return `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;border-bottom:1px solid var(--ln);padding-bottom:12px;flex-wrap:wrap;gap:12px">
      <div>
        <h2 style="margin:0;font-size:18px;font-weight:600">Remediation Management &amp; Independent Verification</h2>
        <div class="mu" style="font-size:12px;margin-top:2px">Human-in-the-loop approval workflow with before/after diffs and strict independent post-remediation verification (PASS/PARTIAL/FAIL).</div>
      </div>
      <button class="btn sm" id="btn-refresh-rem">Refresh Tasks</button>
    </div>

    <div class="kpis">
      <div class="panel kp">
        <div class="lb">Total Tasks</div>
        <div class="kv">${st.total || 0}</div>
        <div class="mu">Remediation actions</div>
      </div>
      <div class="panel kp">
        <div class="lb">Pending Approval</div>
        <div class="kv ${(st.pending_approval||0)>0?'wr':'ok'}">${st.pending_approval || 0}</div>
        <div class="mu">Requires human review</div>
      </div>
      <div class="panel kp">
        <div class="lb">Approved</div>
        <div class="kv">${st.approved || 0}</div>
        <div class="mu">Ready for deployment</div>
      </div>
      <div class="panel kp">
        <div class="lb">Independently Verified</div>
        <div class="kv ok">${st.independently_verified || 0}</div>
        <div class="mu">Cloud state confirmed PASS</div>
      </div>
      <div class="panel kp">
        <div class="lb">Pass Rate</div>
        <div class="kv ok">${st.verification_pass_rate != null ? st.verification_pass_rate : 100}%</div>
        <div class="mu">Post-fix verification score</div>
      </div>
    </div>

    <div class="cols2">
      <!-- Tasks List -->
      <section class="panel">
        <div class="ph">
          <span class="pt">Remediation Tasks Queue (${items.length})</span>
          <span class="mu">Click row to inspect diff</span>
        </div>
        <div class="wrap">
          <table class="tbl">
            <tr>
              <th>ID</th><th>Severity</th><th>Title</th><th>Status</th><th>Verification</th>
            </tr>
            ${items.length ? items.map(r => `
              <tr class="clk ${selected && selected.id === r.id ? 'fresh' : ''}" data-select-rem="${esc(r.id)}">
                <td class="mono"><b>${esc(r.id)}</b></td>
                <td>${tg(r.severity, r.severity === 'Critical' ? 'crit' : 'high')}</td>
                <td><b>${esc(r.title)}</b><div class="mu mono" style="font-size:11px">${esc(r.affected_resource)}</div></td>
                <td>${tg(r.status, r.status === 'Verified' ? 'ok' : r.status === 'Pending' ? 'wr' : 'in')}</td>
                <td>${tg(r.verification_state, r.verification_state === 'PASS' ? 'pass' : r.verification_state === 'FAIL' ? 'fail' : 'gr')}</td>
              </tr>
            `).join("") : `<tr><td colspan="5">${none("No remediation tasks.")}</td></tr>`}
          </table>
        </div>
      </section>

      <!-- Task Inspector -->
      <section class="panel">
        <div class="ph">
          <span class="pt">Remediation Inspection &amp; Verification Diff</span>
          ${selected ? tg(selected.status, selected.status === 'Verified' ? 'ok' : 'wr') : ''}
        </div>
        ${selected ? `
          <div class="pb">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
              <div>
                <h3 style="margin:0 0 4px;font-size:16px;font-weight:600">${esc(selected.title)}</h3>
                <div class="mu mono" style="font-size:11px">Target: ${esc(selected.affected_resource)} · Assigned: ${esc(selected.assigned_owner)}</div>
              </div>
              <div style="display:flex;gap:6px">
                ${tg(selected.severity, selected.severity === 'Critical' ? 'crit' : 'high')}
                ${tg(selected.verification_state, selected.verification_state === 'PASS' ? 'pass' : selected.verification_state === 'FAIL' ? 'fail' : 'gr')}
              </div>
            </div>

            <div class="lb">Technical Explanation</div>
            <p style="font-size:12px;margin-bottom:6px">${esc(selected.technical_explanation || 'Remediation eliminates security misconfiguration and closes attack paths.')}</p>

            <div class="lb">Why It Matters</div>
            <p style="font-size:12px;margin-bottom:12px">${esc(selected.why_it_matters || 'Prevents unauthorized privilege escalation and maintains compliance.')}</p>

            <!-- Before / After Diff Viewer -->
            <div class="lb">Configuration Before &amp; Proposed Change</div>
            <div class="diff-view" style="margin-bottom:12px">
              <div>
                <div class="mu" style="font-size:11px;margin-bottom:4px">Before (Current Cloud State)</div>
                <pre style="font-size:11px;max-height:120px">${esc(JSON.stringify(selected.before_config || {"status": "Vulnerable configuration"}, null, 2))}</pre>
              </div>
              <div>
                <div class="mu" style="font-size:11px;margin-bottom:4px">Proposed Secure State</div>
                <pre class="chg" style="font-size:11px;max-height:120px">${esc(JSON.stringify(selected.proposed_change || {"action": selected.recommended_action}, null, 2))}</pre>
              </div>
            </div>

            <!-- Independent Verification Status Box -->
            <div class="lb">Independent Post-Remediation Verification</div>
            <div style="background:var(--sf2);border:1px solid ${selected.verification_state === 'PASS' ? 'var(--ok)' : selected.verification_state === 'FAIL' ? 'var(--bad)' : 'var(--ln)'};border-radius:6px;padding:12px;margin-bottom:14px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <span style="font-weight:600;font-size:13px">
                  ${selected.verification_state === 'PASS' ? '[PASS] Confirmed by Independent Re-Inspection' :
                    selected.verification_state === 'FAIL' ? '[FAIL] Verification Failed - Risk Persists' :
                    selected.verification_state === 'PARTIAL' ? '[PARTIAL] Secondary Vectors Remain' :
                    'Awaiting Post-Remediation Execution'}
                </span>
                ${tg(selected.verification_state, selected.verification_state === 'PASS' ? 'pass' : 'fail')}
              </div>
              <div style="font-size:11px;color:var(--mu)">
                ${selected.verified_at ? `Verified at ${esc(selected.verified_at)} via live cloud re-inspection.` : 'Remediation must be applied and verified.'}
              </div>
              ${selected.verification_evidence && Object.keys(selected.verification_evidence).length ? `
                <pre style="margin-top:6px;font-size:11px">${esc(JSON.stringify(selected.verification_evidence, null, 2))}</pre>
              ` : ''}
            </div>

            <div class="lb">Remediation Workflow Actions</div>
            <div class="ac" style="margin-top:8px">
              ${selected.status === 'Pending' ? `
                <button class="btn primary sm" id="btn-rem-approve" data-id="${esc(selected.id)}">Approve Fix</button>
              ` : ''}
              ${selected.status === 'Approved' || selected.status === 'Pending' ? `
                <button class="btn primary sm" id="btn-rem-apply" data-id="${esc(selected.id)}">Apply &amp; Independently Verify</button>
              ` : ''}
              ${selected.status === 'Verified' || selected.status === 'Applied' || selected.status === 'Failed' ? `
                <button class="btn sm" id="btn-rem-reverify" data-id="${esc(selected.id)}">Re-Verify Cloud State</button>
                <button class="btn sm danger" id="btn-rem-rollback" data-id="${esc(selected.id)}">Roll Back Fix</button>
              ` : ''}
              ${selected.status === 'Rolled Back' ? `
                <span class="mu" style="font-size:12px">This task has been rolled back and recorded in the audit trail.</span>
              ` : ''}
            </div>
          </div>
        ` : `<div class="pb">${none("Select a remediation task to inspect.")}</div>`}
      </section>
    </div>
  `;
}

let ARCH_DATA = null, SELECTED_ARCH_STAGE = 1, ARCH_BOOT = false;

async function loadArchitecture() {
  const data = await _get("/api/architecture");
  if (data) ARCH_DATA = data;
  ARCH_BOOT = true;
  if (route() === "architecture") render();
}

function architecture() {
  if (!ARCH_BOOT) {
    loadArchitecture();
    return `<div class="panel sk" style="height:400px"></div>`;
  }

  const d = ARCH_DATA || {};
  const stages = d.pipeline || d.pipeline_stages || [];
  const curStage = stages.find(s => s.step === SELECTED_ARCH_STAGE) || stages[0] || {};
  const diffs = d.core_differentiators || [];
  const stack = d.tech_stack || {};

  return `
    <div style="margin-bottom:16px;border-bottom:1px solid var(--ln);padding-bottom:12px">
      <h2 style="margin:0 0 4px;font-size:18px;font-weight:600">Project Architecture &amp; Technical Reference</h2>
      <div class="mu" style="font-size:12px">
        <b>${esc(d.academic_context || "Final Year B.Tech CSE (AI & ML) Project")}</b> · Author: <b>${esc(d.author || "Asif Shaik")}</b> · <a class="lk" href="${esc(d.repository || 'https://github.com/asifshaik06/cloudguardian')}" target="_blank">GitHub Repository</a>
      </div>
    </div>

    <!-- Problem Statement & Core Differentiators -->
    <div class="cols2">
      <section class="panel">
        <div class="ph"><span class="pt">Problem Statement &amp; Research Motivation</span></div>
        <div class="pb">
          <p style="font-size:12.5px;line-height:1.6;margin-bottom:10px">${esc(d.problem_statement)}</p>
          <div class="lb">Proposed Solution</div>
          <p style="font-size:12.5px;line-height:1.6">${esc(d.solution_overview)}</p>
        </div>
      </section>

      <section class="panel">
        <div class="ph"><span class="pt">Core Differentiators vs Traditional CSPMs</span></div>
        <div class="pb">
          <ul style="margin:0;padding-left:18px;font-size:12.5px;line-height:1.7">
            ${diffs.map(df => `<li>${esc(df)}</li>`).join("")}
          </ul>
        </div>
      </section>
    </div>

    <!-- 10-Stage Interactive Pipeline Flowchart -->
    <section class="panel mt">
      <div class="ph">
        <span class="pt">End-to-End Security Pipeline Flowchart (10 Stages)</span>
        <span class="mu">Click any stage to inspect underlying mechanics</span>
      </div>
      <div class="pb">
        <div class="flow-grid">
          ${stages.map(stg => `
            <div class="flow-card ${stg.step === SELECTED_ARCH_STAGE ? 'active' : ''}" data-select-stage="${stg.step}">
              <div style="font-size:11px;font-weight:600;color:var(--ac);margin-bottom:4px">STAGE ${stg.step}</div>
              <div style="font-weight:600;font-size:13px;margin-bottom:4px">${esc(stg.name)}</div>
              <div class="mu" style="font-size:11px">${esc(stg.tech)}</div>
            </div>
          `).join("")}
        </div>

        <!-- Stage Inspector Box -->
        <div style="background:var(--sf);border:1px solid var(--ac);border-radius:6px;padding:14px;margin-top:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <h4 style="margin:0;font-size:15px;color:var(--ac)">Stage ${curStage.step}: ${esc(curStage.name)}</h4>
            <span class="chip mono">${esc(curStage.tech)}</span>
          </div>
          <p style="font-size:13px;line-height:1.6;margin-bottom:8px">${esc(curStage.description)}</p>
          <div class="cols2" style="font-size:12px;margin-top:10px">
            <div>
              <div class="lb" style="margin-top:0">Operational Role</div>
              <div class="mu">Processes security telemetry continuously within isolated Moto sandbox or live AWS.</div>
            </div>
            <div>
              <div class="lb" style="margin-top:0">Verifiable Output</div>
              <div class="mu">Produces structured evidence, deterministic reachability graphs, and cryptographically chained audit hashes.</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Technology Stack Breakdown -->
    <section class="panel mt">
      <div class="ph"><span class="pt">Complete Technology Stack</span></div>
      <div class="pb">
        <div class="g3">
          ${Object.entries(stack).map(([k, v]) => `
            <div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:10px">
              <div class="lb" style="margin-top:0">${esc(k)}</div>
              <div class="mono" style="font-size:12px;font-weight:600">${esc(v)}</div>
            </div>
          `).join("")}
        </div>
      </div>
    </section>
  `;
}

let DEMO_DATA = null, CURRENT_DEMO_STEP = 1, DEMO_BOOT = false;

async function loadDemo() {
  const data = await _get("/api/demo");
  if (data) DEMO_DATA = data;
  DEMO_BOOT = true;
  if (route() === "demo") render();
}

function demo() {
  if (!DEMO_BOOT) {
    loadDemo();
    return `<div class="panel sk" style="height:400px"></div>`;
  }

  const d = DEMO_DATA || {};
  const steps = d.steps || [];
  const curStep = steps.find(s => s.step === CURRENT_DEMO_STEP) || steps[0] || {};
  const total = steps.length || 17;

  return `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;border-bottom:1px solid var(--ln);padding-bottom:12px;flex-wrap:wrap;gap:12px">
      <div>
        <h2 style="margin:0;font-size:18px;font-weight:600">Guided Viva Demonstration Mode</h2>
        <div class="mu" style="font-size:12px;margin-top:2px">17-Step interactive walkthrough designed for external university examiners, technical evaluators, and project presentation.</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="chip">Step ${curStep.step || 1} of ${total}</span>
        <button class="btn sm primary" id="btn-demo-jump-dash" data-target="${esc(curStep.target_page || 'overview')}">Launch in Dashboard</button>
      </div>
    </div>

    <!-- Step Navigation Bar -->
    <div class="step-nav">
      <button class="btn sm" id="btn-demo-prev" ${curStep.step <= 1 ? 'disabled' : ''}>&larr; Previous Step</button>
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-weight:600;font-size:13px">Jump to Step:</span>
        <select id="sel-demo-step" style="height:28px;font-size:12px">
          ${steps.map(s => `
            <option value="${s.step}" ${s.step === CURRENT_DEMO_STEP ? 'selected' : ''}>
              ${s.step}. ${esc(s.title)} (${esc(s.target_page)})
            </option>
          `).join("")}
        </select>
      </div>
      <button class="btn sm primary" id="btn-demo-next" ${curStep.step >= total ? 'disabled' : ''}>Next Step &rarr;</button>
    </div>

    <!-- Active Step Presentation Card -->
    <section class="panel">
      <div class="ph">
        <span class="pt">Step ${curStep.step}: ${esc(curStep.title)}</span>
        <span class="chip mono" style="color:var(--ac)">Target: #${esc(curStep.target_page)}</span>
      </div>
      <div class="pb">
        <div class="lb" style="margin-top:0">Evaluator Question / Viva Context</div>
        <div style="background:var(--sf2);border:1px solid var(--ln);border-radius:6px;padding:12px;margin-bottom:14px;font-size:13px;line-height:1.6">
          <b>Faculty / Examiner Question:</b> "${esc(curStep.evaluator_question || 'Explain the technical architecture and verifiable guarantees of this stage.')}"
        </div>

        <div class="cols2" style="margin-bottom:14px">
          <div style="background:rgba(76,141,255,0.06);border:1px solid var(--ac);border-radius:6px;padding:12px">
            <div class="lb" style="margin-top:0;color:var(--ac)">Demonstration Action to Perform</div>
            <p style="font-size:12.5px;line-height:1.6;margin:0">${esc(curStep.demonstration_action || 'Demonstrate live UI feature.')}</p>
          </div>

          <div style="background:rgba(63,178,127,0.06);border:1px solid var(--ok);border-radius:6px;padding:12px">
            <div class="lb" style="margin-top:0;color:var(--ok)">Technical Architecture Evidence to Cite</div>
            <p style="font-size:12.5px;line-height:1.6;margin:0">${esc(curStep.architecture_evidence || 'Refer to algorithms and data structures.')}</p>
          </div>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--ln);padding-top:12px;flex-wrap:wrap;gap:8px">
          <div class="mu" style="font-size:12px">
            Pressing <b>"Launch in Dashboard"</b> will automatically switch the page view to <code>#${esc(curStep.target_page)}</code>.
          </div>
          <button class="btn primary" id="btn-demo-action-launch" data-target="${esc(curStep.target_page || 'overview')}">
            Switch to #${esc(curStep.target_page)} &rarr;
          </button>
        </div>
      </div>
    </section>
  `;
}

function refresh(){const r=route();if(r=="findings")paintFindings();if(r=="events")loadEvents();if(r=="audit")loadAudit();if(r=="graph"&&window.loadGraph)loadGraph();if(r=="alerts")loadAlerts();if(r=="incidents")loadIncidents();if(r=="remediation"||r=="response")loadRemediations();if(r=="architecture")loadArchitecture();if(r=="demo")loadDemo()}
function bind(){const r=route();
 if(r=="findings"){$$("fsev").value=FSEV;$$("fst").value=FST;$$("fsev").onchange=e=>{FSEV=e.target.value;paintFindings()};$$("fst").onchange=e=>{FST=e.target.value;paintFindings()};paintFindings()}
 if(r=="events"){$$("ek").value=EK;$$("ek").onchange=e=>{EK=e.target.value;loadEvents()};loadEvents()}
 if(r=="graph"){
   bindInspectorEvents();
   const bSearch=$$("graph-search");
   if(bSearch){
     bSearch.oninput=(e)=>{
       window.GRAPH_SEARCH_QUERY=e.target.value.trim();
       CG.update(ctx());
     };
   }
   const fNode=$$("filter-node-type");
   if(fNode){
     fNode.onchange=(e)=>{
       window.GRAPH_FILTER_NODE_TYPE=e.target.value;
       CG.update(ctx());
     };
   }
   const fRel=$$("filter-rel-type");
   if(fRel){
     fRel.onchange=(e)=>{
       window.GRAPH_FILTER_REL_TYPE=e.target.value;
       CG.update(ctx());
     };
   }
   const bZIn=$$("btn-zoom-in");
   if(bZIn)bZIn.onclick=()=>window.graphZoom&&window.graphZoom(1.25);
   const bZOut=$$("btn-zoom-out");
   if(bZOut)bZOut.onclick=()=>window.graphZoom&&window.graphZoom(0.8);
   const bFit=$$("btn-fit-screen");
   if(bFit)bFit.onclick=()=>window.graphFit&&window.graphFit();
   const bResetL=$$("btn-reset-layout");
   if(bResetL)bResetL.onclick=()=>{
     window.GRAPH_SEARCH_QUERY="";
     window.GRAPH_FILTER_NODE_TYPE="all";
     window.GRAPH_FILTER_REL_TYPE="all";
     window.ACTIVE_ATTACK_PATH=null;
     window.SELECTED_EDGE=null;
     window.SELECTED_NODE=null;
     if(bSearch)bSearch.value="";
     if(fNode)fNode.value="all";
     if(fRel)fRel.value="all";
     window.loadGraph&&loadGraph("");
     updateGraphInspector();
   };
   const bTr=$$("btn-trace-admin");
   if(bTr)bTr.onclick=()=>{
     const allPathsList=Object.values(window.ATTACK_PATHS||{}).flat();
     const adminPath=allPathsList.find(p=>p.source==="user/intern-dev"&&p.target==="role/admin-role")||allPathsList[0];
     if(adminPath){
       window.ACTIVE_ATTACK_PATH=adminPath;
       window.SELECTED_EDGE=null;
       window.SELECTED_NODE=null;
       window.loadGraph&&loadGraph(adminPath.nodes.join(","));
       updateGraphInspector();
     } else {
       window.loadGraph&&loadGraph("user/intern-dev,role/dev-role,role/cicd-deployer,role/admin-role");
     }
   };
   const bTrS3=$$("btn-trace-s3");
   if(bTrS3)bTrS3.onclick=()=>{
     const allPathsList=Object.values(window.ATTACK_PATHS||{}).flat();
     const s3Path=allPathsList.find(p=>p.reaches_sensitive_data)||allPathsList[0];
     if(s3Path){
       window.ACTIVE_ATTACK_PATH=s3Path;
       window.SELECTED_EDGE=null;
       window.SELECTED_NODE=null;
       window.loadGraph&&loadGraph(s3Path.nodes.join(","));
       updateGraphInspector();
     }
   };
   const bClearTop=$$("btn-clear-path-top");
   if(bClearTop)bClearTop.onclick=()=>{
     window.ACTIVE_ATTACK_PATH=null;
     window.SELECTED_EDGE=null;
     window.SELECTED_NODE=null;
     window.loadGraph&&loadGraph("");
     updateGraphInspector();
   };
   document.querySelectorAll("[data-trace-idx]").forEach(btn=>{
     btn.onclick=()=>{
       const idx=+btn.dataset.traceIdx;
       const allPathsList=Object.values(window.ATTACK_PATHS||{}).flat();
       const pt=allPathsList[idx];
       if(pt){
         window.ACTIVE_ATTACK_PATH=pt;
         window.SELECTED_EDGE=null;
         window.SELECTED_NODE=null;
         window.loadGraph&&loadGraph(pt.nodes.join(","));
         updateGraphInspector();
         const gSec=$$("graph-section");
         if(gSec)gSec.scrollIntoView({behavior:"smooth"});
       }
     };
   });
 }
 // Bind Simulation Lab handlers
    if(r=="lab"){
      const bCat=$$("tab-lab-catalog");
      if(bCat)bCat.onclick=()=>{LAB_MODE="catalog";render()};
      const bWb=$$("tab-lab-workbench");
      if(bWb)bWb.onclick=()=>{LAB_MODE="workbench";render()};
      const bBld=$$("tab-lab-builder");
      if(bBld)bBld.onclick=()=>{LAB_MODE="builder";render()};

      const bGotoCat=$$("btn-goto-catalog");
      if(bGotoCat)bGotoCat.onclick=()=>{LAB_MODE="catalog";render()};
      const bGotoBld=$$("btn-goto-builder");
      if(bGotoBld)bGotoBld.onclick=()=>{LAB_MODE="builder";render()};

      const bResetFilt=$$("btn-lab-reset-filters");
      if(bResetFilt)bResetFilt.onclick=()=>{
        LAB_CAT_FILTER="";LAB_DIFF_FILTER="";LAB_SEARCH_QUERY="";
        render();
      };

      const inSearch=$$("lab-search");
      if(inSearch)inSearch.oninput=(e)=>{
        LAB_SEARCH_QUERY=e.target.value.trim();
        render();
      };

      const selCat=$$("lab-cat-filter");
      if(selCat)selCat.onchange=(e)=>{
        LAB_CAT_FILTER=e.target.value;
        render();
      };

      const selDiff=$$("lab-diff-filter");
      if(selDiff)selDiff.onchange=(e)=>{
        LAB_DIFF_FILTER=e.target.value;
        render();
      };

      document.querySelectorAll("[data-launch-scenario]").forEach(b=>{
        b.onclick=()=>launchScenarioRun(b.dataset.launchScenario);
      });

      document.querySelectorAll("[data-wb-tab]").forEach(b=>{
        b.onclick=()=>{
          WORKBENCH_TAB=b.dataset.wbTab;
          updateWorkbenchInspector();
        };
      });

      const bWbRe=$$("btn-wb-reanalyze");
      if(bWbRe&&ACTIVE_RUN)bWbRe.onclick=()=>reanalyzeRun(ACTIVE_RUN.run_id);
      const bWbVer=$$("btn-wb-verify");
      if(bWbVer&&ACTIVE_RUN)bWbVer.onclick=()=>verifyRun(ACTIVE_RUN.run_id);
      const bWbRes=$$("btn-wb-reset");
      if(bWbRes&&ACTIVE_RUN)bWbRes.onclick=()=>resetRun(ACTIVE_RUN.run_id);
      const bWbSw=$$("btn-wb-switch");
      if(bWbSw)bWbSw.onclick=()=>{LAB_MODE="catalog";render()};

      const bRecFix=$$("btn-apply-recommended-fix");
      if(bRecFix&&ACTIVE_RUN){
        bRecFix.onclick=()=>remediateRun(ACTIVE_RUN.run_id,ACTIVE_RUN.definition.expected_remediation||{type:"generic_remediation"});
      }

      document.querySelectorAll("[data-lab-trace]").forEach(b=>{
        b.onclick=()=>{
          if(!ACTIVE_RUN)return;
          const p=ACTIVE_RUN.paths[+b.dataset.labTrace];
          if(p&&p.nodes){
            ACTIVE_SCENARIO_PATH=p;
            loadRunDetails(ACTIVE_RUN.run_id,p.nodes.join(","));
          }
        };
      });

      const bClearLabInsp=$$("btn-clear-lab-inspector");
      if(bClearLabInsp)bClearLabInsp.onclick=()=>{
        SELECTED_SCENARIO_NODE=null;
        SELECTED_SCENARIO_EDGE=null;
        updateWorkbenchInspector();
      };

      const bZIn=$$("btn-sg-zin");
      if(bZIn)bZIn.onclick=()=>window.scenarioGraphZoom&&window.scenarioGraphZoom(1.25);
      const bZOut=$$("btn-sg-zout");
      if(bZOut)bZOut.onclick=()=>window.scenarioGraphZoom&&window.scenarioGraphZoom(0.8);
      const bFit=$$("btn-sg-fit");
      if(bFit)bFit.onclick=()=>window.scenarioGraphFit&&window.scenarioGraphFit();
      const bReset=$$("btn-sg-reset");
      if(bReset&&ACTIVE_RUN)bReset.onclick=()=>loadRunDetails(ACTIVE_RUN.run_id,"");

      const bAddEnt=$$("btn-b-add-entity");
      if(bAddEnt)bAddEnt.onclick=()=>{
        const name=($$("b-ent-name")||{}).value||"";
        const type=($$("b-ent-type")||{}).value||"user";
        const flag=($$("b-ent-flag")||{}).checked||false;
        if(!name)return showToast("Please enter entity name", "wr");
        const id=`${type}/${name.toLowerCase().replace(/[^a-z0-9-_]/g,"")}`;
        if(["user","role","group"].includes(type)){
          BUILDER_STATE.identities.push({
            id,name,type,is_admin:flag,arn:`arn:aws:iam::123456789012:${id}`
          });
        } else {
          BUILDER_STATE.resources.push({
            id,name,type,is_sensitive:flag,arn:`arn:aws:${type}:::${name}`
          });
        }
        render();
      };

      const bAddRel=$$("btn-b-add-rel");
      if(bAddRel)bAddRel.onclick=()=>{
        const src=($$("b-rel-src")||{}).value;
        const tgt=($$("b-rel-tgt")||{}).value;
        const rel=($$("b-rel-type")||{}).value;
        const acts=(($$("b-rel-actions")||{}).value||"").split(",").map(x=>x.trim()).filter(Boolean);
        if(!src||!tgt)return showToast("Select source and target entities", "wr");
        BUILDER_STATE.relationships.push({
          source_id:src,target_id:tgt,relationship:rel,actions:acts.length?acts:["*"]
        });
        render();
      };

      const bValPol=$$("btn-validate-policy-stmt");
      if(bValPol)bValPol.onclick=async()=>{
        const eff=($$("b-stmt-effect")||{}).value||"Allow";
        const acts=(($$("b-stmt-actions")||{}).value||"").split(",").map(x=>x.trim()).filter(Boolean);
        const res=(($$("b-stmt-resources")||{}).value||"").split(",").map(x=>x.trim()).filter(Boolean);
        const resp=await fetch("/api/scenarios/validate-policy",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({statements:[{effect:eff,actions:acts,resources:res}]})
        });
        const data=await resp.json();
        const el=$$("policy-validation-result");
        if(el){
          el.style.display="block";
          el.innerHTML=`
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <b>${data.valid?"[PASS] Statement Validated":"[FAIL] Invalid Statement"}</b>
              ${tg("Risk: "+(data.risk_level||"Low"),data.risk_level=="Critical"?"bad":data.risk_level=="High"?"wr":"ok")}
            </div>
            ${data.has_explicit_deny?'<div class="tg bad" style="margin-bottom:4px">Explicit Deny Rule Active</div>':''}
            ${(data.warnings||[]).map(w=>`<div class="mu" style="color:var(--wr);font-size:11px">[WARN] ${esc(w)}</div>`).join("")||'<div style="color:var(--ok);font-size:11px">Zero security warnings detected.</div>'}
          `;
        }
      };

      const bLaunchCustom=$$("btn-build-and-launch-custom");
      if(bLaunchCustom)bLaunchCustom.onclick=async()=>{
        const name=($$("b-meta-name")||{}).value||BUILDER_STATE.name;
        const desc=($$("b-meta-desc")||{}).value||BUILDER_STATE.description;
        const obj=($$("b-meta-obj")||{}).value||BUILDER_STATE.learning_objective;
        const payload={
          name,description:desc,learning_objective:obj,
          identities:BUILDER_STATE.identities,
          resources:BUILDER_STATE.resources,
          relationships:BUILDER_STATE.relationships,
          policies:[]
        };
        const res=await fetch("/api/scenarios/custom",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify(payload)
        });
        if(res.ok){
          const data=await res.json();
          await loadRunDetails(data.run_id);
          LAB_MODE="workbench";
          WORKBENCH_TAB="paths";
          render();
        } else {
          const err=await res.json().catch(()=>({}));
          showToast("Failed to build scenario: "+(err.error||"Validation error"), "bad");
        }
      };
    }

    if (r === "alerts") {
      const sSev = $$("sel-al-sev");
      if (sSev) sSev.onchange = e => { ALERTS_SEV = e.target.value; loadAlerts(); };
      const sSt = $$("sel-al-st");
      if (sSt) sSt.onchange = e => { ALERTS_ST = e.target.value; loadAlerts(); };
      const sSrc = $$("sel-al-src");
      if (sSrc) sSrc.onchange = e => { ALERTS_SRC = e.target.value; loadAlerts(); };
      const inQ = $$("inp-al-q");
      if (inQ) inQ.oninput = e => { ALERTS_Q = e.target.value.trim(); loadAlerts(); };

      const bRef = $$("btn-refresh-alerts");
      if (bRef) bRef.onclick = () => loadAlerts();

      document.querySelectorAll("[data-select-alert]").forEach(tr => {
        tr.onclick = () => {
          SELECTED_ALERT_ID = tr.dataset.selectAlert;
          render();
        };
      });

      const bAck = $$("btn-al-ack");
      if (bAck) bAck.onclick = async () => {
        await fetch(`/api/alerts/${bAck.dataset.id}/action`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "acknowledge" })
        });
        loadAlerts();
      };

      const bInv = $$("btn-al-inv");
      if (bInv) bInv.onclick = async () => {
        await fetch(`/api/alerts/${bInv.dataset.id}/action`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "investigate" })
        });
        loadAlerts();
      };

      const bRes = $$("btn-al-res");
      if (bRes) bRes.onclick = async () => {
        await fetch(`/api/alerts/${bRes.dataset.id}/action`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "resolve" })
        });
        loadAlerts();
      };

      const bSup = $$("btn-al-sup");
      if (bSup) bSup.onclick = async () => {
        await fetch(`/api/alerts/${bSup.dataset.id}/action`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "suppress" })
        });
        loadAlerts();
      };

      const bEsc = $$("btn-al-esc");
      if (bEsc) bEsc.onclick = () => {
        const alertId = bEsc.dataset.id;
        promptModal({
          title: "Escalate Alert to Security Incident",
          label: "Incident Title",
          defaultValue: "Escalated: Alert " + alertId,
          confirmText: "Escalate Incident",
          onConfirm: async (title) => {
            await fetch(`/api/alerts/${alertId}/escalate`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ title, severity: "Critical", summary: "Formal escalation from Alert " + alertId })
            });
            showToast("Alert successfully escalated to incident!", "ok");
            loadAlerts();
            location.hash = "#incidents";
          }
        });
      };
    }

    if (r === "incidents") {
      const bRef = $$("btn-refresh-incidents");
      if (bRef) bRef.onclick = () => loadIncidents();

      document.querySelectorAll("[data-select-incident]").forEach(tr => {
        tr.onclick = () => {
          SELECTED_INCIDENT_ID = tr.dataset.selectIncident;
          render();
        };
      });

      const bNote = $$("btn-inc-add-note");
      if (bNote) bNote.onclick = async () => {
        const val = ($$("inp-inc-note") || {}).value;
        if (val) {
          await fetch(`/api/incidents/${bNote.dataset.id}/action`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ notes: val })
          });
          loadIncidents();
        }
      };

      const bNext = $$("btn-inc-next-stage");
      if (bNext) bNext.onclick = async () => {
        const STAGES = ["Triage", "Investigation", "Containment", "Remediation", "Verification", "Closed"];
        const inc = (INCIDENTS_DATA.incidents || []).find(i => i.id === bNext.dataset.id);
        if (inc) {
          const curIdx = STAGES.indexOf(inc.status);
          const next = STAGES[Math.min(STAGES.length - 1, curIdx + 1)];
          await fetch(`/api/incidents/${bNext.dataset.id}/action`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: next })
          });
          loadIncidents();
        }
      };

      const bContain = $$("btn-inc-record-contain");
      if (bContain) bContain.onclick = async () => {
        await fetch(`/api/incidents/${bContain.dataset.id}/action`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            containment_evidence: {
              quarantine_enacted: true,
              sessions_terminated: true,
              ingress_restricted: true,
              timestamp: new Date().toISOString()
            }
          })
        });
        loadIncidents();
      };

      const bClose = $$("btn-inc-close");
      if (bClose) bClose.onclick = () => {
        const incId = bClose.dataset.id;
        promptModal({
          title: "Close Security Incident",
          label: "Closure Reason",
          defaultValue: "Threat contained and posture verified.",
          confirmText: "Close Incident",
          onConfirm: async (reason) => {
            await fetch(`/api/incidents/${incId}/action`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ status: "Closed", closure_reason: reason })
            });
            showToast("Incident successfully closed", "ok");
            loadIncidents();
          }
        });
      };

      const bNew = $$("btn-create-incident-modal");
      if (bNew) bNew.onclick = () => {
        promptModal({
          title: "Create Security Incident",
          label: "Incident Title",
          defaultValue: "New Security Incident",
          placeholder: "e.g. Unauthorized S3 Bucket Exfiltration",
          confirmText: "Create Incident",
          onConfirm: async (title) => {
            await fetch("/api/incidents", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                title,
                severity: "High",
                summary: "Manually initiated incident response."
              })
            });
            showToast("Security incident created successfully", "ok");
            loadIncidents();
          }
        });
      };
    }

    if (r === "remediation" || r === "response") {
      const bRef = $$("btn-refresh-rem");
      if (bRef) bRef.onclick = () => loadRemediations();

      document.querySelectorAll("[data-select-rem]").forEach(tr => {
        tr.onclick = () => {
          SELECTED_REM_ID = tr.dataset.selectRem;
          render();
        };
      });

      const bAppr = $$("btn-rem-approve");
      if (bAppr) bAppr.onclick = async () => {
        await fetch(`/api/remediations/${bAppr.dataset.id}/approve`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user: "Security Operator" })
        });
        loadRemediations();
      };

      const bApply = $$("btn-rem-apply");
      if (bApply) bApply.onclick = async () => {
        await fetch(`/api/remediations/${bApply.dataset.id}/apply`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user: "Security Operator" })
        });
        loadRemediations();
        poll();
      };

      const bRever = $$("btn-rem-reverify");
      if (bRever) bRever.onclick = async () => {
        await fetch(`/api/remediations/${bRever.dataset.id}/verify`, { method: "POST" });
        loadRemediations();
      };

      const bRoll = $$("btn-rem-rollback");
      if (bRoll) bRoll.onclick = () => {
        const remId = bRoll.dataset.id;
        confirmModal({
          title: "Confirm Remediation Rollback",
          message: "Are you sure you want to roll back this remediation fix? Previous resource configuration will be restored.",
          confirmText: "Roll Back Fix",
          danger: true,
          onConfirm: async () => {
            await fetch(`/api/remediations/${remId}/rollback`, { method: "POST" });
            showToast("Remediation successfully rolled back", "ok");
            loadRemediations();
            poll();
          }
        });
      };
    }

    if (r === "architecture") {
      document.querySelectorAll("[data-select-stage]").forEach(card => {
        card.onclick = () => {
          SELECTED_ARCH_STAGE = +card.dataset.selectStage;
          render();
        };
      });
    }

    if (r === "demo") {
      const bPrev = $$("btn-demo-prev");
      if (bPrev) bPrev.onclick = () => {
        CURRENT_DEMO_STEP = Math.max(1, CURRENT_DEMO_STEP - 1);
        render();
      };

      const bNext = $$("btn-demo-next");
      if (bNext) bNext.onclick = () => {
        const total = (DEMO_DATA && DEMO_DATA.steps) ? DEMO_DATA.steps.length : 17;
        CURRENT_DEMO_STEP = Math.min(total, CURRENT_DEMO_STEP + 1);
        render();
      };

      const selStep = $$("sel-demo-step");
      if (selStep) selStep.onchange = e => {
        CURRENT_DEMO_STEP = +e.target.value;
        render();
      };

      const bJump = $$("btn-demo-jump-dash");
      if (bJump) bJump.onclick = () => {
        location.hash = "#" + bJump.dataset.target;
      };

      const bActLaunch = $$("btn-demo-action-launch");
      if (bActLaunch) bActLaunch.onclick = () => {
        location.hash = "#" + bActLaunch.dataset.target;
      };
    }

  CG.mount(ctx())}
let tm;$$("gq").addEventListener("input",e=>{clearTimeout(tm);tm=setTimeout(()=>{Q=e.target.value.trim();if(!["findings","events","audit"].includes(route()))location.hash="#findings";else refresh()},180)});
document.addEventListener("click",e=>{const o=e.target.closest("[data-open]");if(o)openDrawer(o.dataset.open);if(e.target.id=="dclose")closeDrawer();if(e.target.closest("[data-p]")&&DR)setTimeout(()=>DR&&openDrawer(DR),900)});
document.addEventListener("keydown",e=>{if(e.key=="Escape"){if(window.closeModal)closeModal();closeDrawer()}if(e.key=="/"&&!/INPUT|SELECT/.test(document.activeElement.tagName)){e.preventDefault();$$("gq")?.focus()}});
new MutationObserver(()=>CG.update(ctx())).observe(document.documentElement,{attributes:true,attributeFilter:["data-theme"]});
$$("menu").onclick=()=>document.body.classList.toggle("navopen");$$("scrim").onclick=()=>document.body.classList.remove("navopen");window.addEventListener("hashchange",()=>document.body.classList.remove("navopen"));
setTimeout(loadMetrics,0);setInterval(loadMetrics,3000);setInterval(()=>{if(route()=="events")loadEvents()},2000);
return{overview,findings,events,audit,graph,lab,alerts,incidents,remediation,architecture,demo,bind,slot,q:()=>Q,open:openDrawer}})();
