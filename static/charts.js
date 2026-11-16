/* ECharts wrappers. Chart elements persist across page re-renders, so data updates animate smoothly. */
const CG=(()=>{
const RM=matchMedia("(prefers-reduced-motion: reduce)").matches,CH={};
const cv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const empty=m=>({animation:false,xAxis:{show:false},yAxis:{show:false},series:[],graphic:{type:"text",left:"center",top:"middle",style:{text:m,fill:cv("--sub")||"#78879A",fontSize:12}}});

function base(){
  const mu=cv("--mu")||"#9BAABD",ln=cv("--ln")||"#303B49",sf2=cv("--sf2")||"#202936",tx=cv("--tx")||"#DCE5EF",sub=cv("--sub")||"#78879A";
  return{
    mu,ln,sf2,tx,sub,
    o:{
      animation:!RM,
      animationDuration:800,
      animationDurationUpdate:400,
      animationEasing:"cubicOut",
      animationEasingUpdate:"cubicInOut",
      textStyle:{color:mu,fontFamily:'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'},
      grid:{left:48,right:16,top:28,bottom:28},
      tooltip:{
        trigger:"axis",
        backgroundColor:sf2,
        borderColor:ln,
        borderWidth:1,
        padding:[8,12],
        textStyle:{color:tx,fontSize:12},
        extraCssText:"box-shadow: 0 4px 12px rgba(0,0,0,0.3); border-radius: 6px; backdrop-filter: blur(4px);"
      }
    },
    ax:o=>Object.assign({
      axisLine:{lineStyle:{color:ln}},
      axisTick:{show:false},
      axisLabel:{color:mu,fontSize:11,hideOverlap:true},
      splitLine:{lineStyle:{color:ln,opacity:0.3}}
    },o),
    lg:{
      show:true,
      top:0,
      right:0,
      textStyle:{color:mu,fontSize:11},
      itemWidth:10,
      itemHeight:10
    }
  };
}

const hm=t=>new Date(t*1000).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",hour12:false});
const NM={zscore:"Z-score",isolation_forest:"Isolation Forest",lof:"LocalOutlierFactor",ocsvm:"OneClassSVM"};
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

const B={
  posture(D){
    const{o,ax,tx}=base(),p=D.M.posture;
    if(!p||!p.length)return empty("Collecting samples...");
    const cyan=cv("--cyan")||"#55BFCB";
    return{
      ...o,
      tooltip:{
        ...o.tooltip,
        valueFormatter:v=>v+" / 100",
        axisPointer:{type:"cross",lineStyle:{color:cyan,type:"dashed",width:1}}
      },
      xAxis:ax({type:"time",splitNumber:4,splitLine:{show:false}}),
      yAxis:ax({type:"value",min:0,max:100,interval:25,name:"Score",nameTextStyle:{color:cv("--mu"),fontSize:11,align:"left"}}),
      series:[{
        type:"line",
        step:"end",
        showSymbol:false,
        data:p.map(x=>[x.t*1000,x.score]),
        lineStyle:{color:cyan,width:2,shadowBlur:0},
        areaStyle:{
          color:new echarts.graphic.LinearGradient(0,0,0,1,[
            {offset:0,color:"rgba(85,191,203,0.18)"},
            {offset:1,color:"rgba(85,191,203,0.01)"}
          ])
        },
        emphasis:{
          scale:1.4,
          itemStyle:{
            color:cyan,
            borderColor:tx,
            borderWidth:1.5,
            shadowBlur:0
          }
        }
      }]
    };
  },

  anomaly(D){
    const{o,ax,mu,tx,ln,sf2,sub}=base(),a=D.M.anomaly,thr=D.M.threshold;
    if(!a||!a.length)return empty("Waiting for scored events...");
    const baselineCol = "#22D3EE"; // Cyan for normal observations
    const anomalyCol = "#FB7185";  // Coral for anomalous observations
    const thresholdCol = "#FBBF24"; // Amber for threshold line

    const dataPoints = a.map((x, idx) => {
      const origT = x.t * 1000;
      const origScore = x.score;
      const isAtk = x.kind === "attack";
      const isAnomaly = origScore > thr || isAtk;
      const color = isAnomaly ? anomalyCol : baselineCol;
      const obsId = x.obs_id || `OBS-${String(idx + 1).padStart(4, "0")}`;

      return {
        value: [origT, origScore],
        rawScore: origScore,
        rawT: origT,
        obsId: obsId,
        kind: x.kind,
        isAnomaly: isAnomaly,
        symbol: "circle",
        symbolSize: 3.5, // Crisp 3.5px diameter marker for clean point separation without crowding
        itemStyle: {
          color: color,
          opacity: 0.82, // Balanced opacity: reveals density when overlapping without vanishing
          borderWidth: 0,
          shadowBlur: 0 // Strict 0 shadowBlur: removes all halos and fuzzy glow
        }
      };
    });

    return {
      ...o,
      grid: {
        left: 44,
        right: 86, // Dedicated margin on the right for edge threshold badge outside data points
        top: 22,
        bottom: 26
      },
      dataZoom: [
        {
          type: "inside",
          xAxisIndex: 0,
          filterMode: "none",
          zoomOnMouseWheel: true,
          moveOnMouseMove: true,
          moveOnMouseWheel: false
        }
      ],
      tooltip: {
        trigger: "item",
        backgroundColor: sf2,
        borderColor: ln,
        borderWidth: 1,
        padding: [8, 12],
        textStyle: { color: tx, fontSize: 12 },
        extraCssText: "box-shadow: 0 4px 14px rgba(0,0,0,0.35); border-radius: 6px;",
        formatter: p => {
          const d = p.data;
          const isAtk = d.kind === "attack";
          const col = d.isAnomaly ? anomalyCol : baselineCol;
          const obsId = d.obsId || `OBS-${String(p.dataIndex + 1).padStart(4, "0")}`;
          const tag = isAtk 
            ? `<span style="color:${anomalyCol};font-weight:700">&bull; ANOMALOUS ATTACK OBSERVATION</span>` 
            : `<span style="color:${baselineCol};font-weight:600">&bull; NORMAL TELEMETRY BASELINE</span>`;
          const scoreStatus = d.rawScore > thr 
            ? `<span style="color:${anomalyCol};font-weight:700">ANOMALY (&gt; ${thr.toFixed(3)})</span>` 
            : `<span style="color:${baselineCol};font-weight:600">NORMAL (&le; ${thr.toFixed(3)})</span>`;
          const timeStr = new Date(d.rawT).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

          return `<div style="font-weight:700;font-size:12px;margin-bottom:4px;color:${tx}">Observation ${obsId} &middot; ${timeStr}</div>` +
            `<div style="font-size:11px;margin-bottom:2px">${tag}</div>` +
            `<div style="font-size:11px;margin-bottom:2px">Target: <b style="color:${tx}">${isAtk ? "iam/user/intern-dev (Compromised Key)" : "CloudTrail Telemetry Ingestion"}</b></div>` +
            `<div style="font-size:11px;margin-bottom:2px">Classification: ${scoreStatus}</div>` +
            `<div style="font-size:11px;margin-bottom:2px">Calculated Anomaly Score: <b style="color:${col};font-family:monospace">${d.rawScore.toFixed(4)}</b></div>` +
            `<div style="font-size:11px;margin-bottom:2px;color:${mu}">Detection Threshold: <b style="color:${thresholdCol};font-family:monospace">${thr.toFixed(4)}</b></div>` +
            `<div style="font-size:10px;color:${sub};border-top:1px solid ${ln};margin-top:4px;padding-top:3px">Detector: Isolation Forest (200 Trees, 12-dim runtime window)</div>`;
        }
      },
      xAxis: ax({
        type: "time",
        splitNumber: 5,
        splitLine: { show: false },
        axisLabel: {
          color: mu,
          fontSize: 10,
          hideOverlap: true
        }
      }),
      yAxis: ax({
        type: "value",
        scale: true,
        name: "Score",
        nameLocation: "end",
        nameTextStyle: { color: mu, fontSize: 10, align: "left" },
        splitLine: {
          show: true,
          lineStyle: { color: ln, opacity: 0.15, type: "dashed" }
        },
        axisLabel: {
          color: mu,
          fontSize: 10,
          formatter: v => v.toFixed(2)
        },
        boundaryGap: ["10%", "10%"]
      }),
      series: [{
        type: "scatter",
        data: dataPoints,
        emphasis: {
          scale: 2.2, // Clean enlargement from 3.5px to ~7.7px on hover with crisp border
          itemStyle: {
            borderColor: tx,
            borderWidth: 1.5,
            opacity: 1.0,
            shadowBlur: 0
          }
        },
        markLine: {
          silent: true,
          symbol: "none",
          lineStyle: { color: thresholdCol, type: "dashed", width: 1.2, opacity: 0.85 },
          label: {
            formatter: "Threshold " + thr.toFixed(3),
            color: thresholdCol,
            position: "end",
            distance: 6,
            fontSize: 10,
            fontWeight: 600,
            padding: [2, 5],
            backgroundColor: sf2,
            borderRadius: 3,
            borderColor: ln,
            borderWidth: 1
          },
          data: [{ yAxis: thr }]
        }
      }]
    };
  },

  activity(D){
    const{o,ax,lg}=base(),b=D.M.buckets;
    if(!b||!b.length)return empty("No events yet");
    const bad=cv("--bad")||"#D66C79",sub=cv("--sub")||"#78879A";
    return{
      ...o,
      legend:lg,
      tooltip:{
        ...o.tooltip,
        axisPointer:{type:"shadow"}
      },
      xAxis:ax({type:"category",data:b.map(v=>hm(v.t)),splitLine:{show:false}}),
      yAxis:ax({type:"value",minInterval:1,name:"Events",nameTextStyle:{color:cv("--mu"),fontSize:11,align:"left"}}),
      series:[
        {
          name:"Baseline (simulated)",
          type:"bar",
          stack:"e",
          barMaxWidth:16,
          data:b.map(v=>v.baseline),
          itemStyle:{
            color:"rgba(120,135,154,0.45)",
            borderRadius:[0,0,0,0],
            shadowBlur:0
          },
          emphasis:{focus:"series",itemStyle:{color:sub,shadowBlur:0}}
        },
        {
          name:"Attack actions",
          type:"bar",
          stack:"e",
          barMaxWidth:16,
          data:b.map(v=>v.attack),
          itemStyle:{
            color:bad,
            borderRadius:[2,2,0,0],
            shadowBlur:0
          },
          emphasis:{focus:"series",itemStyle:{color:bad,shadowBlur:0}}
        }
      ]
    };
  },

  severity(D){
    const{o,ax,lg}=base(),f=D.S.findings;
    if(!f||!f.length)return empty("No findings yet");
    const sv=["Critical","High","Medium","Low"],ST=[["pending","Awaiting approval","--amber","#D5A64B"],["fixed","Remediated","--emerald","#48A98B"],["rejected","Rejected","--sub","#78879A"]];
    return{
      ...o,
      legend:lg,
      grid:{...o.grid,left:68},
      tooltip:{
        ...o.tooltip,
        axisPointer:{type:"shadow"}
      },
      xAxis:ax({type:"value",minInterval:1}),
      yAxis:ax({type:"category",data:sv,inverse:true,splitLine:{show:false}}),
      series:ST.map(s=>({
        name:s[1],
        type:"bar",
        stack:"s",
        barWidth:14,
        data:sv.map(v=>f.filter(x=>x.sev==v&&x.status==s[0]).length),
        itemStyle:{
          color:cv(s[2])||s[3],
          borderRadius:[0,2,2,0],
          shadowBlur:0
        },
        emphasis:{focus:"series",itemStyle:{shadowBlur:0}}
      }))
    };
  },

  remediation(D){
    const{o,ax,lg}=base(),it=D.M.rem.items;
    if(!it||!it.length)return empty("No findings yet");
    const cyan=cv("--cyan")||"#55BFCB",emerald=cv("--emerald")||"#48A98B";
    return{
      ...o,
      legend:lg,
      tooltip:{
        ...o.tooltip,
        axisPointer:{type:"shadow"},
        valueFormatter:v=>v==null?"n/a":v+" s"
      },
      xAxis:ax({type:"category",data:it.map(i=>i.id),splitLine:{show:false}}),
      yAxis:ax({type:"value",name:"Seconds",nameTextStyle:{color:cv("--mu"),fontSize:11,align:"left"}}),
      series:[
        {
          name:"Time to detect",
          type:"bar",
          barMaxWidth:18,
          data:it.map(i=>i.ttd),
          itemStyle:{
            color:cyan,
            borderRadius:[2,2,0,0],
            shadowBlur:0
          },
          emphasis:{focus:"series",itemStyle:{shadowBlur:0}}
        },
        {
          name:"Time to remediate",
          type:"bar",
          barMaxWidth:18,
          data:it.map(i=>i.ttr),
          itemStyle:{
            color:emerald,
            borderRadius:[2,2,0,0],
            shadowBlur:0
          },
          emphasis:{focus:"series",itemStyle:{shadowBlur:0}}
        }
      ]
    };
  },

  detectors(D){
    const{o,ax,lg}=base(),r=(D.ML&&D.ML.results)||{},ks=Object.keys(NM).filter(k=>r[k]);
    if(!ks.length)return empty("Run scripts\\train_eval.py to generate results");
    return{
      ...o,
      legend:lg,
      tooltip:{
        ...o.tooltip,
        axisPointer:{type:"shadow"},
        valueFormatter:v=>Number(v).toFixed(3)
      },
      xAxis:ax({
        type:"category",
        data:ks.map(k=>NM[k]),
        splitLine:{show:false},
        axisLabel:{color:cv("--mu"),fontSize:11,interval:0,formatter:n=>({"Isolation Forest":"Iso. Forest",LocalOutlierFactor:"LOF",OneClassSVM:"OC-SVM"}[n]||n)}
      }),
      yAxis:ax({type:"value",min:0,max:1,interval:0.25}),
      series:[
        ["precision","Precision","--cyan","#55BFCB"],
        ["recall","Recall","--violet","#9A87D5"],
        ["f1","F1","--amber","#D5A64B"]
      ].map(m=>({
        name:m[1],
        type:"bar",
        barMaxWidth:16,
        data:ks.map(k=>r[k].controlled[m[0]]),
        itemStyle:{
          color:cv(m[2])||m[3],
          borderRadius:[2,2,0,0],
          shadowBlur:0
        },
        emphasis:{focus:"series",itemStyle:{shadowBlur:0}}
      }))
    };
  }
};

B.calib=function(D){
  const{o,ax}=base(),r=(D.ML&&D.ML.results)||{},ks=Object.keys(NM).filter(k=>r[k]&&r[k].old_real_unlabelled);
  if(!ks.length)return empty("Run train_eval.py with the flaws.cloud logs");
  const hit=k=>{const nr=r[k].new_real_recall||{},t=Object.values(nr).reduce((a,q)=>a+q.windows,0);return Math.round(Object.values(nr).reduce((a,q)=>a+q.windows*q.recall,0))+" of "+t+" real attack windows flagged"};
  return{
    ...o,
    grid:{...o.grid,left:130,right:36},
    tooltip:{
      ...o.tooltip,
      trigger:"item",
      formatter:p=>`${p.name}<br>${p.value}% of flaws.cloud windows flagged<br>${hit(ks[p.dataIndex])}`
    },
    xAxis:ax({type:"value",min:0,max:100,axisLabel:{color:cv("--mu"),fontSize:11,formatter:"{value}%"}}),
    yAxis:ax({type:"category",data:ks.map(k=>NM[k]),inverse:true,splitLine:{show:false}}),
    series:[{
      type:"bar",
      barWidth:14,
      data:ks.map(k=>({value:+(r[k].old_real_unlabelled.alert_rate*100).toFixed(1),itemStyle:{color:r[k].old_real_unlabelled.alert_rate>.3?(cv("--wr")||"#D5A64B"):(cv("--cyan")||"#55BFCB"),borderRadius:[0,2,2,0]}})),
      label:{show:true,position:"right",color:cv("--mu"),fontSize:11,formatter:"{c}%"},
      markLine:{silent:true,symbol:"none",lineStyle:{color:cv("--bad")||"#D66C79",type:"dashed"},label:{formatter:"1% target",color:cv("--mu"),position:"end",rotate:0,align:"left",padding:[0,0,0,6]},data:[{xAxis:1}]}
    }]
  };
};

B.iam_graph=function(D){
  const g=(D&&D.GRAPH)||window.GRAPH||{nodes:[],links:[],categories:[]};
  if(!g.nodes||!g.nodes.length)return empty("Loading IAM capability graph...");
  const mu=cv("--mu")||"#9BAABD",ln=cv("--ln")||"#303B49",tx=cv("--tx")||"#DCE5EF",sf=cv("--sf")||"#171D27",sf2=cv("--sf2")||"#202936",sub=cv("--sub")||"#78879A";
  const bad=cv("--bad")||"#D66C79",amber=cv("--amber")||"#D5A64B",emerald=cv("--emerald")||"#48A98B";

  let displayNodes = g.nodes;
  let displayLinks = g.links;

  if(window.GRAPH_FILTER_NODE_TYPE && window.GRAPH_FILTER_NODE_TYPE !== "all"){
    const filterType = window.GRAPH_FILTER_NODE_TYPE.toLowerCase();
    const matchedNodeIds = new Set();
    displayNodes = g.nodes.filter(n=>{
      const match = (n.value||"").toLowerCase().includes(filterType) || (n.name||"").toLowerCase().includes(filterType);
      if(match) matchedNodeIds.add(n.id);
      return match;
    });
    displayLinks = g.links.filter(l=>matchedNodeIds.has(l.source) && matchedNodeIds.has(l.target));
  }

  if(window.GRAPH_FILTER_REL_TYPE && window.GRAPH_FILTER_REL_TYPE !== "all"){
    const filterRel = window.GRAPH_FILTER_REL_TYPE.toLowerCase();
    displayLinks = displayLinks.filter(l=>(l.relationship||"").toLowerCase() === filterRel);
  }

  if(window.GRAPH_SEARCH_QUERY){
    const q = window.GRAPH_SEARCH_QUERY.toLowerCase();
    displayNodes = displayNodes.map(n=>{
      const match = n.name.toLowerCase().includes(q) || n.id.toLowerCase().includes(q);
      if(match){
        return{
          ...n,
          symbolSize: (n.symbolSize || 26) + 4,
          itemStyle:{...(n.itemStyle||{}), borderColor:amber, borderWidth:2.5, shadowBlur:4, shadowColor:"rgba(0,0,0,0.4)"}
        };
      }
      return n;
    });
  }

  return{
    animation:!RM,
    animationDuration:800,
    animationDurationUpdate:400,
    animationEasing:"cubicOut",
    animationEasingUpdate:"cubicInOut",
    tooltip:{
      trigger:"item",
      backgroundColor:sf2,
      borderColor:ln,
      borderWidth:1,
      padding:[8,12],
      textStyle:{color:tx,fontSize:12},
      extraCssText:"box-shadow: 0 4px 14px rgba(0,0,0,0.35); border-radius: 6px; max-width: 380px;",
      formatter:p=>{
        if(p.dataType=="node"){
          const d=p.data;
          const adm=d.is_admin?`<div style="color:${bad};font-weight:600;margin-top:2px">[ADMIN] AdministratorAccess</div>`:'';
          const sens=d.is_sensitive?`<div style="color:${amber};font-weight:600;margin-top:2px">[SENSITIVE] High-Value Target Asset</div>`:'';
          const path=d.in_attack_path?`<div style="color:${bad};font-weight:600;margin-top:2px">[ESCALATION] Active Escalation Node</div>`:'';
          const normal=(!d.is_admin&&!d.is_sensitive&&!d.in_attack_path)?`<div style="color:${emerald};font-size:11px;margin-top:2px">[STANDARD] Authorized Identity</div>`:'';
          return`<div style="font-weight:600;font-size:12.5px;color:${tx}">${esc(d.name)}</div>`+
            `<div style="font-size:11px;color:${mu}">Type: <b style="color:${tx}">${esc(d.value)}</b></div>`+
            `<div style="font-size:10.5px;color:${mu}">ARN: <code style="font-size:10px">${esc(d.arn||d.id)}</code></div>`+
            adm+sens+path+normal+
            `<div style="margin-top:6px;border-top:1px solid ${ln};padding-top:4px;color:${sub};font-size:10px">Click node to inspect capabilities &amp; blast radius</div>`;
        }
        if(p.dataType=="edge"){
          const l=p.data;
          const step=l.step_number?`<span style="color:${bad};font-weight:600">Step ${l.step_number}: </span>`:'';
          const acts=l.actions&&l.actions.length?`<div style="font-size:11px;color:${mu}">Actions: <span style="color:${emerald}">${esc(l.actions.slice(0,5).join(", "))}${l.actions.length>5?'...':''}</span></div>`:"";
          const path=l.in_attack_path?`<div style="color:${bad};font-weight:600;font-size:11px">[ESCALATION] Active Escalation Edge</div>`:'';
          return`<div style="font-weight:600;font-size:12.5px;color:${tx}">${step}${esc(l.relationship)}</div>`+
            `<div style="font-size:11px;color:${mu}">Path: <b style="color:${tx}">${esc(l.source)}</b> &rarr; <b style="color:${tx}">${esc(l.target)}</b></div>`+
            acts+path+
            `<div style="margin-top:6px;border-top:1px solid ${ln};padding-top:4px;color:${sub};font-size:10px">Click edge to inspect policy evidence</div>`;
        }
        return"";
      }
    },
    legend:{
      data:(g.categories||[]).map(c=>c.name),
      top:8,
      left:12,
      textStyle:{color:mu,fontSize:11},
      itemWidth:10,
      itemHeight:10
    },
    series:[{
      type:"graph",
      layout:"force",
      data:displayNodes,
      links:displayLinks,
      categories:g.categories,
      roam:true,
      draggable:true,
      label:{
        show:true,
        position:"bottom",
        distance:5,
        formatter:"{b}",
        fontSize:11,
        fontWeight:500,
        color:tx,
        textBorderColor:sf,
        textBorderWidth:2
      },
      edgeSymbol:["none","arrow"],
      edgeSymbolSize:[4,10],
      edgeLabel:{show:false},
      emphasis:{
        focus:"adjacency",
        scale:1.2,
        itemStyle:{
          borderWidth:2,
          borderColor:tx,
          shadowBlur:4,
          shadowColor:"rgba(0,0,0,0.4)"
        },
        lineStyle:{
          width:3.5,
          opacity:1.0,
          shadowBlur:0
        }
      },
      blur:{
        itemStyle:{opacity:0.22},
        lineStyle:{opacity:0.12},
        label:{opacity:0.15}
      },
      force:{repulsion:950,gravity:0.035,edgeLength:[140,250],friction:0.6}
    }]
  };
};

B.scenario_graph=function(D){
  const g=(D&&D.SCENARIO_GRAPH)||window.SCENARIO_GRAPH||{nodes:[],links:[],categories:[]};
  if(!g.nodes||!g.nodes.length)return empty("Launch or build a scenario to explore its isolated capability graph...");
  const mu=cv("--mu")||"#9BAABD",ln=cv("--ln")||"#303B49",tx=cv("--tx")||"#DCE5EF",sf=cv("--sf")||"#171D27",sf2=cv("--sf2")||"#202936",sub=cv("--sub")||"#78879A";
  const bad=cv("--bad")||"#D66C79",amber=cv("--amber")||"#D5A64B",emerald=cv("--emerald")||"#48A98B";

  return{
    animation:!RM,
    animationDuration:800,
    animationDurationUpdate:400,
    animationEasing:"cubicOut",
    animationEasingUpdate:"cubicInOut",
    tooltip:{
      trigger:"item",
      backgroundColor:sf2,
      borderColor:ln,
      borderWidth:1,
      padding:[8,12],
      textStyle:{color:tx,fontSize:12},
      extraCssText:"box-shadow: 0 4px 14px rgba(0,0,0,0.35); border-radius: 6px; max-width: 380px;",
      formatter:p=>{
        if(p.dataType=="node"){
          const d=p.data;
          const adm=d.is_admin?`<div style="color:${bad};font-weight:600;margin-top:2px">[ADMIN] AdministratorAccess</div>`:'';
          const sens=d.is_sensitive?`<div style="color:${amber};font-weight:600;margin-top:2px">[SENSITIVE] High-Value Target Asset</div>`:'';
          const path=d.in_attack_path?`<div style="color:${bad};font-weight:600;margin-top:2px">[ESCALATION] Active Escalation Node</div>`:'';
          const normal=(!d.is_admin&&!d.is_sensitive&&!d.in_attack_path)?`<div style="color:${emerald};font-size:11px;margin-top:2px">[STANDARD] Authorized Identity</div>`:'';
          return`<div style="font-weight:600;font-size:12.5px;color:${tx}">${esc(d.name)}</div>`+
            `<div style="font-size:11px;color:${mu}">Type: <b style="color:${tx}">${esc(d.value)}</b></div>`+
            `<div style="font-size:10.5px;color:${mu}">ARN: <code style="font-size:10px">${esc(d.arn||d.id)}</code></div>`+
            adm+sens+path+normal+
            `<div style="margin-top:6px;border-top:1px solid ${ln};padding-top:4px;color:${sub};font-size:10px">Click node to inspect capabilities &amp; blast radius</div>`;
        }
        if(p.dataType=="edge"){
          const l=p.data;
          const step=l.step_number?`<span style="color:${bad};font-weight:600">Step ${l.step_number}: </span>`:'';
          const acts=l.actions&&l.actions.length?`<div style="font-size:11px;color:${mu}">Actions: <span style="color:${emerald}">${esc(l.actions.slice(0,5).join(", "))}${l.actions.length>5?'...':''}</span></div>`:"";
          const path=l.in_attack_path?`<div style="color:${bad};font-weight:600;font-size:11px">[ESCALATION] Active Escalation Edge</div>`:'';
          return`<div style="font-weight:600;font-size:12.5px;color:${tx}">${step}${esc(l.relationship)}</div>`+
            `<div style="font-size:11px;color:${mu}">Path: <b style="color:${tx}">${esc(l.source)}</b> &rarr; <b style="color:${tx}">${esc(l.target)}</b></div>`+
            acts+path+
            `<div style="margin-top:6px;border-top:1px solid ${ln};padding-top:4px;color:${sub};font-size:10px">Click edge to inspect policy evidence</div>`;
        }
        return"";
      }
    },
    legend:{
      data:(g.categories||[]).map(c=>c.name),
      top:8,
      left:12,
      textStyle:{color:mu,fontSize:11},
      itemWidth:10,
      itemHeight:10
    },
    series:[{
      type:"graph",
      layout:"force",
      data:g.nodes,
      links:g.links,
      categories:g.categories,
      roam:true,
      draggable:true,
      label:{
        show:true,
        position:"bottom",
        distance:5,
        formatter:"{b}",
        fontSize:11,
        fontWeight:500,
        color:tx,
        textBorderColor:sf,
        textBorderWidth:2
      },
      edgeSymbol:["none","arrow"],
      edgeSymbolSize:[4,10],
      edgeLabel:{show:false},
      emphasis:{
        focus:"adjacency",
        scale:1.2,
        itemStyle:{
          borderWidth:2,
          borderColor:tx,
          shadowBlur:4,
          shadowColor:"rgba(0,0,0,0.4)"
        },
        lineStyle:{
          width:3.5,
          opacity:1.0,
          shadowBlur:0
        }
      },
      blur:{
        itemStyle:{opacity:0.22},
        lineStyle:{opacity:0.12},
        label:{opacity:0.15}
      },
      force:{repulsion:950,gravity:0.035,edgeLength:[140,250],friction:0.6}
    }]
  };
};

function paint(k,D){
  const c=CH[k];
  if(!c||!c.inst||!c.el.isConnected||!B[k])return;
  // Guard force-directed graph setOption so periodic 3s polling does NOT reset user nodes, zoom, or hover states!
  if(k==="iam_graph"||k==="scenario_graph"){
    const g=k==="iam_graph"?((D&&D.GRAPH)||window.GRAPH):((D&&D.SCENARIO_GRAPH)||window.SCENARIO_GRAPH);
    const filterKey=`${k}:${window.GRAPH_FILTER_NODE_TYPE||""}:${window.GRAPH_FILTER_REL_TYPE||""}:${window.GRAPH_SEARCH_QUERY||""}:${(g&&g.nodes&&g.nodes.length)||0}:${(g&&g.links&&g.links.length)||0}:${window._GRAPH_VER||0}`;
    if(c._lastKey===filterKey&&c._hasRendered){
      return;
    }
    c._lastKey=filterKey;
    c._hasRendered=true;
  }
  const o=B[k](D),e=!!o.graphic;
  c.inst.setOption(o,{notMerge:c.empty!==e||e,lazyUpdate:true});
  c.empty=e;
}

function mount(D){
  document.querySelectorAll(".cslot").forEach(s=>{
    const k=s.dataset.key;
    if(!window.echarts){
      s.textContent="Chart library not found. Download ECharts into static/vendor (see the setup steps).";
      return;
    }
    let c=CH[k];
    if(!c){
      const el=document.createElement("div");
      el.style.cssText="width:100%;height:100%";
      c=CH[k]={el,inst:null,empty:null,_lastKey:null,_hasRendered:false,_renderer:null};
      if(window.ResizeObserver){
        new ResizeObserver(()=>{if(c.inst&&c.el.isConnected)c.inst.resize()}).observe(el);
      }
    }
    s.replaceChildren(c.el);
    const targetRenderer = (k === "anomaly") ? "svg" : "canvas";
    if(c && c.inst && c._renderer && c._renderer !== targetRenderer){
      c.inst.dispose();
      c.inst = null;
    }
    if(!c.inst){
      // Anomaly chart uses native vector SVG rendering for mathematically crisp 3.5px markers and native font text.
      // Other five charts use Canvas with high-DPI supersampling (2.0 minimum DPR).
      const dpr = Math.max(2, window.devicePixelRatio || 1);
      c.inst=echarts.init(c.el,null,{
        renderer:targetRenderer,
        devicePixelRatio:dpr
      });
      c._renderer=targetRenderer;
      if(k==="iam_graph"||k==="scenario_graph"){
        c.inst.on("click",params=>{
          if(k==="scenario_graph"&&window.onScenarioGraphClick)window.onScenarioGraphClick(params);
          else if(window.onGraphElementClick)window.onGraphElementClick(params);
        });
      }
    }
    c.inst.resize();
    paint(k,D);
    requestAnimationFrame(()=>{
      if(c.inst&&c.el.isConnected)c.inst.resize();
    });
  });
}

window.graphZoom=function(factor){
  const c=CH["iam_graph"];if(!c||!c.inst)return;
  const opt=c.inst.getOption();if(!opt||!opt.series||!opt.series[0])return;
  const currentZoom=opt.series[0].zoom||1;
  const newZoom=Math.max(0.3,Math.min(4.0,currentZoom*factor));
  c.inst.setOption({series:[{zoom:newZoom}]});
};

window.graphFit=function(){
  const c=CH["iam_graph"];if(!c||!c.inst)return;
  c.inst.setOption({series:[{zoom:1.0,center:null}]});
};

window.scenarioGraphZoom=function(factor){
  const c=CH["scenario_graph"];if(!c||!c.inst)return;
  const opt=c.inst.getOption();if(!opt||!opt.series||!opt.series[0])return;
  const currentZoom=opt.series[0].zoom||1;
  const newZoom=Math.max(0.3,Math.min(4.0,currentZoom*factor));
  c.inst.setOption({series:[{zoom:newZoom}]});
};

window.scenarioGraphFit=function(){
  const c=CH["scenario_graph"];if(!c||!c.inst)return;
  c.inst.setOption({series:[{zoom:1.0,center:null}]});
};

function update(D){Object.keys(CH).forEach(k=>paint(k,D))}
window.addEventListener("resize",()=>Object.values(CH).forEach(c=>c.inst&&c.el.isConnected&&c.inst.resize()));

return{mount,update,count:()=>Object.keys(CH).length};
})();
