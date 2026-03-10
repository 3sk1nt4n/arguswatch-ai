// ═══════════════════════════════════════════════════════
// ArgusWatch AI v16.4.6 - Production Dashboard Engine
// Wires ALL 108 API endpoints
// ═══════════════════════════════════════════════════════

let _stats={},_findings=[],_detections=[],_customers=[],_actors=[],_campaigns=[],_darkweb=[];
let _aiProvider='ollama';

let _refreshTimer=null;
const REFRESH_MS=30000; // 30s auto-refresh
let _authToken=sessionStorage.getItem('aw_token')||'';
let _authUser=sessionStorage.getItem('aw_user')||'';
let _authRole=sessionStorage.getItem('aw_role')||'';

// ═══ AUTH - Login / Logout / Token ═══
async function checkAuth(){
  // AUTH_DISABLED=true (default) -> skip login, let normal init continue
  try{
    const h={};if(_authToken)h['Authorization']='Bearer '+_authToken;
    const ctrl=new AbortController();setTimeout(()=>ctrl.abort(),3000);
    const r=await fetch('/api/auth/me',{headers:h,signal:ctrl.signal});
    if(r.ok){const d=await r.json();
      if(d.auth_disabled){document.getElementById('login-overlay')?.classList.add('hidden');return;}
      _authUser=d.username;_authRole=d.role;
      document.getElementById('login-overlay')?.classList.add('hidden');updateUserBadge();return;}
    if(r.status===401){
      document.getElementById('login-overlay')?.classList.remove('hidden');
      document.getElementById('login-skip').style.display='block';return;}
  }catch(e){}
  // Backend not ready -  skip login (AUTH_DISABLED is default)
  document.getElementById('login-overlay')?.classList.add('hidden');
}
async function doLogin(){
  const u=document.getElementById('login-user')?.value;const p=document.getElementById('login-pass')?.value;
  const err=document.getElementById('login-err');err.textContent='';
  try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
    if(!r.ok){const d=await r.json();err.textContent=d.detail||'Login failed';return;}
    const d=await r.json();_authToken=d.access_token;_authUser=d.username;_authRole=d.role;
    sessionStorage.setItem('aw_token',_authToken);sessionStorage.setItem('aw_user',_authUser);sessionStorage.setItem('aw_role',_authRole);
    document.getElementById('login-overlay')?.classList.add('hidden');updateUserBadge();loadOv();
  }catch(e){err.textContent='Connection failed';}
}
function skipLogin(){document.getElementById('login-overlay')?.classList.add('hidden');loadOv();}
function logout(){_authToken='';_authUser='';_authRole='';sessionStorage.clear();location.reload();}
function updateUserBadge(){const el=document.getElementById('user-badge');if(el)el.textContent=(_authUser||'dev')+'·'+(_authRole||'admin');}

// ═══ API HELPER (auth-aware) ═══
async function api(path,opts={}){
  try{
    const headers={'Content-Type':'application/json',...(opts.headers||{})};
    if(_authToken)headers['Authorization']='Bearer '+_authToken;
    const r=await fetch(path,{...opts,headers});
    if(r.status===401){document.getElementById('login-overlay')?.classList.remove('hidden');return null;}
    if(!r.ok){try{return await r.json();}catch(e2){return null;}}
    return await r.json();
  }catch(e){console.warn('API:',path,e.message);return null;}
}
async function apiPost(path,body={}){return api(path,{method:'POST',body:JSON.stringify(body)});}
async function apiPatch(path,body={}){return api(path,{method:'PATCH',body:JSON.stringify(body)});}
async function apiDel(path){return api(path,{method:'DELETE'});}

// ═══ NAVIGATION ═══
function toggleSB(){document.querySelector('.sb')?.classList.toggle('open');document.getElementById('sb-overlay')?.classList.toggle('open');}
function closeSBMobile(){if(window.innerWidth<=768){document.querySelector('.sb')?.classList.remove('open');document.getElementById('sb-overlay')?.classList.remove('open');}}
function go(view){
  closeSBMobile();
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(s=>s.classList.remove('active'));
  const el=document.getElementById('view-'+view);
  if(el){el.classList.add('active');el.offsetHeight;}
  document.querySelectorAll('.sb-item').forEach(s=>{
    const txt=s.textContent.trim().toLowerCase();
    const match={'overview':'overview','findings':'findings','campaigns':'campaigns','detections':'detections',
      'actors':'actors','dark web':'darkweb','exposure':'exposure','threat universe':'threatgraph',
      'customers':'customers','reports':'reports','settings':'settings','sla':'sla',
      'fp memory':'fppatterns','advisories':'advisories','unattributed':'unattributed',
      'remediation':'remediations'}; 
    if(Object.entries(match).find(([k,v])=>v===view&&txt.includes(k.substring(0,4))))s.classList.add('active');
  });
  const loaders={overview:loadOv,findings:loadF,campaigns:loadCa,detections:loadD,actors:loadAct,
    darkweb:()=>loadDW(''),exposure:loadExp,threatgraph:()=>{const f=document.getElementById('tg-iframe');f.src='about:blank';setTimeout(()=>{f.src='/threat-universe';},100);},customers:loadCust,reports:loadRep,
    settings:loadSet,sla:loadSLA,fppatterns:loadFP,advisories:loadAdvisories,unattributed:loadUnattr,remediations:loadRemPage,iocregistry:loadIocRegistry};
  if(loaders[view])loaders[view]();
}

// ═══ MODALS / TOAST / UTILITIES ═══
function openM(id){document.getElementById(id)?.classList.add('open');}
function closeM(id){document.getElementById(id)?.classList.remove('open');}
function _sanitizeHtml(h){if(!h)return'';return h.replace(/<script[\s\S]*?<\/script>/gi,'').replace(/on\w+\s*=/gi,'data-removed=');}
function showDrilldown(title,body){document.getElementById('dd-title').textContent=title.replace(/<[^>]*>/g,'');document.getElementById('dd-body').innerHTML=_sanitizeHtml(body);openM('m-drilldown');}
function showOnboard(){openM('m-onboard');}
function toast(msg,type='success'){
  const t=document.getElementById('toast');
  t.textContent=(type==='success'?'✓ ':'✕ ')+msg;
  t.className='toast show '+type;
  setTimeout(()=>t.classList.remove('show'),3500);
}
function animNum(el,target,dur=800){
  if(!el)return;const start=parseInt(el.textContent)||0;const diff=target-start;
  if(diff===0){el.textContent=target.toLocaleString();return;}
  const t0=performance.now();
  (function tick(now){const p=Math.min((now-t0)/dur,1);el.textContent=Math.round(start+diff*(1-Math.pow(1-p,3))).toLocaleString();if(p<1)requestAnimationFrame(tick);})(t0);
}
function ago(ts){
  if(!ts)return'-';const s=Math.floor((Date.now()-new Date(ts).getTime())/1000);
  if(s<0)return'just now';
  if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';
}
function sevTag(s){const m={critical:'crit',high:'high',medium:'med',low:'low'};return`<span class="tag ${m[s]||'info'}">${(s||'-').toUpperCase()}</span>`;}
function escHtml(s){if(!s)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML;}
function sevDot(s){const m={critical:'crit',high:'high',medium:'med',low:'low'};return`<span class="sev ${m[s]||''}"></span>`;}
function statTag(s){const v=(s||'NEW').toUpperCase();const active=['NEW','ENRICHED','ALERTED','ESCALATION'];const resolved=['REMEDIATED','VERIFIED_CLOSED','CLOSED'];const cls=active.includes(v)?'high':resolved.includes(v)?'green':v==='FALSE_POSITIVE'?'med':'info';return`<span class="tag ${cls}">${v}</span>`;}
const _sevColors={CRITICAL:'#c62828',HIGH:'#ef6c00',MEDIUM:'#f9a825',LOW:'#2e7d32'};
const _sevEmoji={CRITICAL:'🔴',HIGH:'🟠',MEDIUM:'🟡',LOW:'🟢'};
const _sevCls={CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low'};
const _sevExplain={CRITICAL:'Actively exploited CVEs, confirmed credential breaches, C2 infrastructure matches. 4-hour SLA.',HIGH:'Known threat indicators with high confidence. Weaponized exploits, phishing domains, malware hashes. 24-hour SLA.',MEDIUM:'Moderate confidence matches. Suspicious domains, IP reputation hits, non-critical CVEs. 72-hour SLA.',LOW:'Informational indicators. Monitoring signals, low-confidence patterns, expired IOCs. 168-hour SLA.'};

// ═══════════════════════════════════════════════════════
// VIEW LOADERS - Each wires to real API endpoints
// ═══════════════════════════════════════════════════════

// ═══ OVERVIEW - /api/stats, /api/stats/timeline, /api/stats/ioc-types, /api/stats/sources, /api/findings, /api/threat-pressure, /api/metrics ═══
async function loadOv(){
  const [stats,timeline,iocTypes,findings,sources,tp,metrics]=await Promise.all([
    api('/api/stats'),api('/api/stats/timeline'),api('/api/stats/ioc-types'),
    api('/api/findings?limit=12'),api('/api/stats/sources'),api('/api/threat-pressure'),api('/api/metrics')
  ]);
  if(stats){
    _stats=stats;
    // Hero stats: formula-relevant only
    animNum(document.getElementById('ov-detections'),stats.total_detections||0);
    animNum(document.getElementById('ov-customers'),stats.total_customers||0);
    animNum(document.getElementById('ov-actors'),stats.total_actors||0);
    animNum(document.getElementById('ov-darkweb'),stats.darkweb_mentions||0);
    animNum(document.getElementById('ov-assets'),stats.total_assets||0);
    const maxExp=stats.max_exposure_score||0;
    const expEl=document.getElementById('ov-exposure');
    if(expEl){expEl.textContent=maxExp>0?maxExp.toFixed(1):'--';}
    // Sidebar badges for non-formula stats
    const badge=document.getElementById('badge-findings');
    if(badge){const v=stats.open_findings||stats.total_findings||0;badge.textContent=v||'';badge.style.display=v?'':'none';}
    const badgeCamp=document.getElementById('badge-campaigns');
    if(badgeCamp){const v=stats.active_campaigns||0;badgeCamp.textContent=v||'';badgeCamp.style.display=v?'':'none';}
    // Severity distribution bar
    // Severity distribution: DETECTION severity (formula input D1/D2), not findings
    const sev=stats.severity||{};
    const crit=sev.CRITICAL||sev.critical||0,hi=sev.HIGH||sev.high||0,med=sev.MEDIUM||sev.medium||0,lo=sev.LOW||sev.low||0;
    const total=crit+hi+med+lo||1;
    document.getElementById('ov-seg-crit').style.width=(crit/total*100)+'%';
    document.getElementById('ov-seg-high').style.width=(hi/total*100)+'%';
    document.getElementById('ov-seg-med').style.width=(med/total*100)+'%';
    document.getElementById('ov-seg-low').style.width=(lo/total*100)+'%';
    document.getElementById('ov-ct-crit').textContent=crit;
    document.getElementById('ov-ct-high').textContent=hi;
    document.getElementById('ov-ct-med').textContent=med;
    document.getElementById('ov-ct-low').textContent=lo;
    document.getElementById('ov-sev-summary').textContent=`${total} detections by severity`;
  }
  // Threat pressure gauge
  if(tp){
    const pval=tp.pressure_index||tp.level||0;
    animNum(document.getElementById('threat-pressure-num'),pval);
    document.getElementById('threat-pressure-text').textContent=tp.summary||`${tp.active_threats||0} active threats across monitored landscape`;
    // Animate SVG gauge arc (circumference=327)
    const arc=document.getElementById('ov-gauge-arc');
    if(arc){
      const offset=327-(327*(Math.min(pval,100)/100));
      arc.style.strokeDashoffset=offset;
      arc.style.stroke=pval>=70?'var(--red)':pval>=40?'var(--amber)':'var(--green)';
    }
    // Pressure detail badges
    const pd=document.getElementById('ov-pressure-detail');
    if(pd){
      let badges='';
      if(tp.active_threats)badges+=`<span class="tag info" style="font-size:11px;">🎯 ${tp.active_threats} active threats</span>`;
      if(tp.active_campaigns)badges+=`<span class="tag info" style="font-size:11px;">⚔️ ${tp.active_campaigns} campaigns</span>`;
      if(tp.new_last_24h)badges+=`<span class="tag crit" style="font-size:11px;">🔥 ${tp.new_last_24h} new (24h)</span>`;
      pd.innerHTML=badges;
    }
  }
  // Charts (unchanged logic)
  if(timeline?.length){
    const ctx=document.getElementById('chart-timeline');
    if(ctx?.getContext){
      if(window._cT)window._cT.destroy();
      window._cT=new Chart(ctx,{type:'line',data:{labels:timeline.map(t=>t.date||t.day||''),
        datasets:[{label:'Detections',data:timeline.map(t=>t.count||t.detections||0),borderColor:'#e65c00',backgroundColor:'rgba(230,92,0,.08)',fill:true,tension:.4,pointRadius:2,borderWidth:2}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8c7a65',font:{size:10}},grid:{color:'rgba(180,160,130,.08)'}},y:{ticks:{color:'#8c7a65',font:{size:10}},grid:{color:'rgba(180,160,130,.08)'}}}}});
    }
  }
  if(iocTypes){
    const entries=Array.isArray(iocTypes)?iocTypes:Object.entries(iocTypes).map(([k,v])=>({type:k,count:v}));
    // Sort by count descending, show top 12 + "Other" bucket
    const sorted=entries.sort((a,b)=>(b.count||b[1]||0)-(a.count||a[1]||0));
    const top=sorted.slice(0,12);
    const otherCount=sorted.slice(12).reduce((s,e)=>s+(e.count||e[1]||0),0);
    if(otherCount>0)top.push({type:`Other (${sorted.length-12} types)`,count:otherCount});
    const labels=top.map(e=>e.type||e[0]);
    const values=top.map(e=>e.count||e[1]);
    const ctx2=document.getElementById('chart-ioc-types');
    if(ctx2?.getContext){
      if(window._cI)window._cI.destroy();
      // Severity-aware coloring: credential/key types = red/orange, network = blue/teal, intel = purple
      const _typeColors={
        email_password_combo:'#c62828',aws_access_key:'#c62828',private_key:'#c62828',
        cve_id:'#e65c00',url:'#00897b',domain:'#e65100',ipv4:'#1565c0',
        sha256:'#2e7d32',md5:'#2e7d32',ransomware_group:'#7b1fa2',
        apt_group:'#7b1fa2',config_file:'#ef6c00',jwt_token:'#c62828',
      };
      const defaultColors=['#e65c00','#00897b','#c62828','#7b1fa2','#e65100','#2e7d32','#1565c0','#ec4899','#f59e0b','#6366f1','#14b8a6','#8b5cf6','#9e9e9e'];
      const colors=labels.map((l,i)=>_typeColors[l]||defaultColors[i%defaultColors.length]);
      window._cI=new Chart(ctx2,{type:'doughnut',data:{labels,datasets:[{data:values,backgroundColor:colors.map(c=>c+'25'),borderColor:colors,borderWidth:2}]},
        options:{responsive:true,maintainAspectRatio:false,cutout:'60%',
          onClick:(evt,elements)=>{if(elements.length>0){const idx=elements[0].index;const typeName=labels[idx];if(!typeName.startsWith('Other'))document.getElementById('ai-bar-q').value='show '+typeName+' findings';sendBarAI?.();}},
          plugins:{legend:{position:'right',labels:{color:'#8c7a65',font:{size:10},padding:6}}}}});
    }
  }
  // Activity feed (card-based, clickable)
  const items=Array.isArray(findings?.findings)?findings.findings:Array.isArray(findings)?findings:[];
  const feed=document.getElementById('ov-feed');
  if(feed){
    feed.innerHTML=items.slice(0,8).map(f=>{
      const sl=(f.severity||'').toLowerCase();
      const sevCls=sl==='critical'?'crit':sl==='high'?'high':sl==='medium'?'med':'low';
      return`<div class="ov-feed-item" onclick="openFi(${f.id})">
        <div class="ov-feed-sev ${sevCls}"></div>
        <div class="ov-feed-body">
          <div class="ov-feed-top">
            <span class="fi-pill sev-${sevCls}" style="font-size:10px;padding:2px 7px;">${(f.severity||'?').toUpperCase()}</span>
            <span class="ov-feed-ioc">${f.ioc_value||'-'}</span>
            <span class="fi-pill type" style="font-size:10px;padding:2px 7px;">${f.ioc_type||'-'}</span>
          </div>
          <div class="ov-feed-meta">👤 ${f.customer_name||'-'} · 📡 ${f.source||'-'} · ${ago(f.created_at)}</div>
        </div>
      </div>`;
    }).join('')||'<div style="padding:24px;text-align:center;color:var(--text4);">Awaiting first collection cycle</div>';
  }
  // Source health (card-based, clickable)
  const srcItems=Array.isArray(sources)?sources:sources?Object.entries(sources).map(([k,v])=>({source:k,...(typeof v==='object'?v:{count:v})})):[];
  const srcEl=document.getElementById('ov-sources');
  if(srcEl){
    srcEl.innerHTML=srcItems.slice(0,12).map(s=>{
      const ct=s.count||s.ioc_count||0;
      const lr=s.last_run;
      let health='dead';
      if(lr){const h=(Date.now()-new Date(lr).getTime())/3600000;if(h<6)health='active';else if(h<24)health='stale';}
      return`<div class="ov-src-item" onclick="drillCollector('${(s.source||s.name||'').replace(/'/g,"\\'")}')">
        <div class="ov-src-dot ${health}"></div>
        <div class="ov-src-name">${s.source||s.name||'-'}</div>
        <div class="ov-src-ct">${ct.toLocaleString()} IOCs</div>
        <div class="ov-src-time">${lr?ago(lr):'never'}</div>
      </div>`;
    }).join('')||'<div style="padding:24px;text-align:center;color:var(--text4);">No collector runs yet</div>';
  }
}

// ═══ FINDINGS - /api/findings, /api/findings/{id}, PATCH /api/findings/{id}/status ═══
async function loadF(){
  const sev=document.getElementById('fi-sev')?.value||'';
  const st=document.getElementById('fi-status')?.value||'';
  let u='/api/findings?limit=60';if(sev)u+='&severity='+sev;if(st)u+='&status='+st;
  const data=await api(u);const items=Array.isArray(data?.findings)?data.findings:Array.isArray(data)?data:[];_findings=items;
  document.getElementById('fi-count').textContent=items.length+' findings'+(sev?' · '+sev:'')+(st?' · '+st:'');
  document.getElementById('fi-list').innerHTML=items.map(f=>{
    const sl=(f.severity||'').toLowerCase();const sevCls=sl==='critical'?'crit':sl==='high'?'high':sl==='medium'?'med':'low';
    const stl=(f.status||'open').toLowerCase();
    return`<div class="fi-card" onclick="openFi(${f.id})">
      <div class="fi-sev-bar ${sevCls}"></div>
      <div class="fi-inner">
        <div class="fi-top">
          <span class="fi-pill sev-${sevCls}">${(f.severity||'?').toUpperCase()}</span>
          <span class="fi-ioc" title="${f.ioc_value||''}">${f.ioc_value||'-'}</span>
          <span class="fi-pill type">${f.ioc_type||'-'}</span>
          <span class="fi-pill st-${stl}">${(f.status||'open').replace('_',' ')}</span>
          <span class="fi-time">${ago(f.created_at)}</span>
        </div>
        <div class="fi-meta">
          <span class="fi-cust">👤 ${f.customer_name||'-'}</span>
          <span class="fi-pill src">📡 ${f.source||'-'}</span>
          ${f.match_strategy?`<span class="fi-strat">${f.match_strategy}</span>`:''}
          ${f.actor_name?`<span class="fi-pill sev-high">🎭 ${f.actor_name}</span>`:''}
          ${f.campaign_id?`<span class="fi-pill type">⚔️ Campaign #${f.campaign_id}</span>`:''}
        </div>
        <div class="fi-actions">
          <button class="btn green" style="padding:3px 10px;font-size:11px;" onclick="event.stopPropagation();patchFinding(${f.id},'resolved')">✓ Resolve</button>
          <button class="btn" style="padding:3px 10px;font-size:11px;" onclick="event.stopPropagation();patchFinding(${f.id},'investigating')">🔍</button>
          <button class="btn cyan" style="padding:3px 10px;font-size:11px;" onclick="event.stopPropagation();enrichIOC('${(f.ioc_value||'').replace(/'/g,"\\'")}','${f.ioc_type||''}')">🔬 Enrich</button>
        </div>
      </div>
    </div>`;
  }).join('')||'<div class="empty">No findings match filters</div>';
}

// ═══ FINDING DETAIL - /api/findings/{id}, /api/playbooks/{ioc_type}, /api/enrich/{detection_id}, PATCH status ═══
async function openFi(id){
  const [f,remStats]=await Promise.all([api('/api/findings/'+id),api('/api/finding-remediations/stats')]);
  if(!f)return;
  const pb=f.ioc_type?await api('/api/playbooks/'+encodeURIComponent(f.ioc_type)):null;
  document.getElementById('mf-title').innerHTML=`Finding #${f.id} <span class="text-muted text-sm">· ${f.ioc_type||''}</span>`;
  const sl=(f.severity||'').toLowerCase();
  const sevCls=sl==='critical'?'crit':sl==='high'?'high':sl==='medium'?'med':'low';
  const sevColor=sl==='critical'?'var(--red)':sl==='high'?'#e65100':sl==='medium'?'var(--cyan)':'var(--green)';
  let h='';
  // ═══ FINDING IDENTITY HEADER ═══
  h+=`<div class="fi-detail-hdr">
    <div class="fi-detail-sev-stripe" style="background:${sevColor};"></div>
    <div class="fi-detail-main">
      <div class="fi-detail-top">
        <span class="fi-pill sev-${sevCls}">${(f.severity||'?').toUpperCase()}</span>
        ${statTag(f.status)}
        ${f.confirmed_exposure?'<span class="tag crit">🚨 CONFIRMED EXPOSURE: '+(f.exposure_type||'')+'</span>':''}
        ${f.campaign_id?'<span class="tag info">⚔️ Campaign #'+f.campaign_id+'</span>':''}
        ${f.actor_name?'<span class="tag high">🎭 '+f.actor_name+'</span>':''}
      </div>
      <div class="fi-detail-ioc-wrap">
        <div class="fi-detail-ioc mono">${f.ioc_value||'-'}</div>
        <div class="fi-detail-ioc-copy" onclick="navigator.clipboard.writeText('${(f.ioc_value||'').replace(/'/g,"\\'")}');toast('Copied!')">📋 Copy</div>
      </div>
      <div class="fi-detail-meta">
        <span>👤 ${f.customer_name||'ID:'+f.customer_id}</span>
        <span>📡 ${f.source||'-'}</span>
        <span>🎯 ${f.match_strategy||'-'}</span>
        <span>🕐 ${f.created_at||'-'}</span>
        ${f.detection_id?'<span>🔗 Det #'+f.detection_id+'</span>':''}
      </div>
      ${f.confidence?`<div class="fi-conf-meter"><span class="text-xs text-muted">Confidence</span><div class="fi-conf-track"><div class="fi-conf-fill" style="width:${(f.confidence>1?f.confidence:f.confidence*100)}%;background:${(f.confidence>1?f.confidence:f.confidence*100)>=80?'var(--green)':(f.confidence>1?f.confidence:f.confidence*100)>=50?'var(--amber)':'var(--red)'};"></div></div><div class="fi-conf-val" style="color:${(f.confidence>1?f.confidence:f.confidence*100)>=80?'var(--green)':(f.confidence>1?f.confidence:f.confidence*100)>=50?'var(--amber)':'var(--red)'};">${f.confidence>1?f.confidence:(f.confidence*100).toFixed(0)}%</div></div>`:''}
    </div>
  </div>`;
  // ═══ AI NARRATIVE ═══
  if(f.ai_narrative)h+=`<div class="fi-section"><div class="fi-section-head"><span class="ico">🤖</span><span class="title">AI Investigation Narrative</span></div><div class="fi-section-body"><div class="text-sm" style="line-height:1.5;">${f.ai_narrative}</div>
    ${f.ai_severity_decision?`<div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);display:flex;gap:12px;flex-wrap:wrap;">
      <span class="text-xs"><b>AI Severity:</b> ${f.ai_severity_decision}</span>
      ${f.ai_severity_confidence?`<span class="text-xs"><b>Confidence:</b> ${(f.ai_severity_confidence*100).toFixed(0)}%</span>`:''}
      ${f.ai_false_positive_flag?`<span class="tag" style="font-size:10px;background:var(--amber-g);border-color:var(--amber);color:var(--amber);">⚠️ Possible FP: ${f.ai_false_positive_reason||'-'}</span>`:''}</div>`:''}</div></div>`;
  // ═══ MATCH EVIDENCE ═══
  if(f.match_proof)h+=`<div class="fi-section"><div class="fi-section-head"><span class="ico">🔍</span><span class="title">Match Evidence</span></div><div class="fi-section-body"><pre class="mono text-xs" style="white-space:pre-wrap;max-height:150px;overflow-y:auto;color:var(--text2);padding:10px;background:var(--surface);border-radius:var(--rs);">${f.match_proof}</pre></div></div>`;
  // ═══ PLAYBOOK ═══
  if(pb){
    const pbSteps=pb.steps||pb.steps_technical||[];
    const pbTitle=pb.title||('Playbook: '+f.ioc_type);
    const pbSev=pb.severity||'';
    const pbSla=pb.sla_hours||'';
    const pbRole=pb.assignee_role||'';
    const pbImpact=pb.business_impact||'';
    const pbConf=pb.confidence_note||'';
    const pbSevCol=pbSev==='CRITICAL'?'#c62828':pbSev==='HIGH'?'#e65100':'var(--amber)';
    h+=`<div class="fi-section"><div class="fi-section-head"><span class="ico">📋</span><span class="title">${pbTitle}</span></div><div class="fi-section-body">`;
    // Meta badges
    h+=`<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">`;
    if(pbSev)h+=`<span style="padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;background:${pbSevCol}10;color:${pbSevCol};border:1px solid ${pbSevCol}25;">⚡ ${pbSev}</span>`;
    if(pbSla)h+=`<span style="padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;background:var(--amber-g);color:var(--amber);border:1px solid var(--amber-b);">⏱️ SLA: ${pbSla}h</span>`;
    if(pbRole)h+=`<span style="padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;background:var(--cyan-g);color:var(--cyan);border:1px solid var(--cyan-b);">👤 ${pbRole}</span>`;
    h+=`</div>`;
    if(pbImpact)h+=`<div style="font-size:13px;color:var(--text2);margin-bottom:10px;padding:8px 12px;border-radius:8px;background:var(--surface);border-left:3px solid var(--amber);"><b>Business Impact:</b> ${pbImpact}</div>`;
    if(pbConf)h+=`<div style="font-size:12px;color:var(--text3);margin-bottom:10px;font-style:italic;">${pbConf}</div>`;
    // Steps
    if(pbSteps.length){
      h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">Response Steps</div>`;
      pbSteps.forEach((s,i)=>{
        const stepText=typeof s==='string'?s:(s.text||s.description||JSON.stringify(s));
        h+=`<div style="display:flex;gap:10px;margin-bottom:8px;padding:8px 12px;border-radius:8px;border:1px solid var(--border);transition:all .2s;" onmouseover="this.style.borderColor='var(--orange-b)'" onmouseout="this.style.borderColor='var(--border)'">
          <div style="width:26px;height:26px;border-radius:50%;background:var(--orange-g);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:var(--orange);flex-shrink:0;">${i+1}</div>
          <div style="font-size:13px;color:var(--text);line-height:1.5;flex:1;">${stepText}</div>
        </div>`;
      });
    }else{
      // No structured steps -  show what we have in a readable way
      const keys=['key','ioc_type','detection_sources'];
      const otherFields=Object.entries(pb).filter(([k])=>!['steps','steps_technical','title','severity','sla_hours','assignee_role','business_impact','confidence_note'].includes(k)&&pb[k]);
      if(otherFields.length){
        h+=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px;">`;
        otherFields.forEach(([k,v])=>{
          h+=`<div style="padding:8px 10px;border-radius:8px;background:var(--surface);"><div style="font-size:10px;color:var(--text4);text-transform:uppercase;font-weight:700;margin-bottom:3px;">${k.replace(/_/g,' ')}</div><div style="font-size:12px;color:var(--text);">${Array.isArray(v)?v.join(', ')||' - ':typeof v==='object'?JSON.stringify(v):v||' - '}</div></div>`;
        });
        h+=`</div>`;
      }
    }
    // Customer relevance
    // Customer relevance - rich evidence cards
    if(f.customer_name){
      const iocVal=f.ioc_value||'';
      const iocType=f.ioc_type||'';
      const matchedAsset=f.matched_asset||'';
      const corrType=f.correlation_type||f.match_strategy||'pattern_match';
      const allSources=f.all_sources||[];
      // Build source reference links
      const srcLinks=[];
      if(allSources.includes('cisa_kev')||iocType==='cve_id')srcLinks.push({name:'CISA KEV',url:iocType==='cve_id'?'https://www.cisa.gov/known-exploited-vulnerabilities-catalog':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',color:'#c62828',emoji:'🛡️',desc:'CISA Known Exploited Vulnerabilities -  U.S. government mandated patching catalog'});
      if(iocType==='cve_id')srcLinks.push({name:'NVD (NIST)',url:'https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(iocVal),color:'#1565c0',emoji:'📋',desc:'National Vulnerability Database -  official CVSS scoring and affected products'});
      if(iocType==='cve_id')srcLinks.push({name:'MITRE CVE',url:'https://cve.mitre.org/cgi-bin/cvename.cgi?name='+encodeURIComponent(iocVal),color:'#7b1fa2',emoji:'🎯',desc:'MITRE CVE record -  vulnerability identifier authority'});
      if(allSources.includes('otx'))srcLinks.push({name:'AlienVault OTX',url:'https://otx.alienvault.com/indicator/'+iocType+'/'+encodeURIComponent(iocVal),color:'#e65100',emoji:'🔍',desc:'Open Threat Exchange -  community threat intelligence'});
      if(allSources.includes('threatfox'))srcLinks.push({name:'ThreatFox',url:'https://threatfox.abuse.ch/browse/',color:'#00897b',emoji:'🦊',desc:'abuse.ch threat IOC sharing platform'});
      if(allSources.includes('urlhaus'))srcLinks.push({name:'URLhaus',url:'https://urlhaus.abuse.ch/browse/',color:'#e65c00',emoji:'🔗',desc:'Malicious URL database by abuse.ch'});
      if(allSources.includes('openphish'))srcLinks.push({name:'OpenPhish',url:'https://openphish.com/',color:'#c62828',emoji:'🎣',desc:'Phishing intelligence feed'});
      if(allSources.includes('circl_misp'))srcLinks.push({name:'CIRCL MISP',url:'https://www.circl.lu/',color:'#1565c0',emoji:'🌐',desc:'CIRCL MISP threat sharing community'});
      // Correlation type explanations
      const corrExplain={'exact_domain':'Exact domain match against registered customer domains','subdomain':'Subdomain of a registered customer domain','ip_range':'IP within customer\'s registered CIDR ranges','email_pattern':'Email pattern matches customer email domain','tech_stack':'Technology stack keyword match (e.g. vendor name, product)','typosquat':'Typosquatting variant of customer domain detected','keyword':'Keyword match against customer brand/exec names','exec_name':'Executive name mentioned in threat context','brand_name':'Brand name found in phishing or dark web context','cloud_asset':'Cloud resource identifier matches customer infrastructure','cidr':'IP falls within registered network range','pattern_match':'IOC pattern matched against customer asset registry'};
      h+=`<div style="margin-top:12px;border-radius:14px;border:1px solid var(--orange-b);background:linear-gradient(135deg,rgba(230,92,0,.03),rgba(0,137,123,.02));overflow:hidden;">
        <div style="padding:14px 16px;border-bottom:1px solid var(--border);">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <span style="font-size:18px;">🏢</span>
            <div style="flex:1;">
              <div style="font-size:14px;font-weight:800;color:var(--text);">Applies to: ${f.customer_name}</div>
              <div style="font-size:11px;color:var(--text4);">Customer ID: ${f.customer_id} · Correlated via ${corrType.replace(/_/g,' ')}</div>
            </div>
            <button class="btn" style="font-size:11px;padding:4px 12px;" onclick="closeM('m-finding');openCu(${f.customer_id})">View Customer -></button>
          </div>
          ${matchedAsset?`<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
            <span style="font-size:14px;">🖥️</span>
            <div>
              <div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;">Matched Asset</div>
              <div style="font-size:14px;font-weight:700;font-family:'JetBrains Mono';color:var(--orange);">${matchedAsset}</div>
            </div>
            <div style="margin-left:auto;padding:3px 10px;border-radius:8px;background:var(--green-g);border:1px solid var(--green-b);font-size:10px;font-weight:700;color:var(--green);">REGISTERED ASSET</div>
          </div>`:''}
          <div style="margin-top:8px;padding:8px 12px;border-radius:8px;background:rgba(0,137,123,.04);border-left:3px solid var(--cyan);font-size:12px;color:var(--text2);line-height:1.5;">
            <b>How was this matched?</b> ${corrExplain[corrType]||corrExplain['pattern_match']}. The IOC <code style="font-size:11px;background:var(--surface);padding:1px 6px;border-radius:4px;">${iocVal.substring(0,50)}${iocVal.length>50?'...':''}</code> was found in ${f.source_count||1} threat intelligence source${(f.source_count||1)>1?'s':''} and correlated to ${f.customer_name}'s registered assets.
            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
              ${(f.sources||f.sources_detail||[]).filter(s=>s.detection_id).slice(0,5).map(s=>`<button class="btn" style="font-size:11px;padding:4px 12px;" onclick="closeM('m-finding');openDetDetail(${s.detection_id})">📡 ${s.source||'source'} #${s.detection_id} -></button>`).join('')||`<span style="font-size:11px;color:var(--text4);">Source detection linked at correlation</span>`}
            </div>
          </div>
        </div>`;
      // ═══ PROOF CHAIN -  Evidence Trail ═══
      const ap=f.affected_products||[];
      const assetP=f.asset_proof;
      if(ap.length||assetP){
        h+=`<div style="padding:12px 16px;border-top:1px solid var(--border);">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--orange);margin-bottom:10px;">🔗 Proof Chain -  Evidence Trail</div>`;
        // LINK 1: CVE -> What products
        if(ap.length){
          h+=`<div style="margin-bottom:10px;padding:10px 14px;border-radius:10px;border:1px solid rgba(21,101,192,.15);background:rgba(21,101,192,.03);">
            <div style="font-size:11px;font-weight:700;color:#1565c0;margin-bottom:6px;">LINK 1: What does this IOC affect? (NVD CPE data)</div>`;
          ap.forEach(p=>{
            h+=`<div style="display:flex;align-items:center;gap:8px;padding:6px 10px;margin:3px 0;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
              <span style="font-size:14px;">${p.actively_exploited?'🔴':'📦'}</span>
              <div style="flex:1;"><div style="font-size:13px;font-weight:700;font-family:'JetBrains Mono';color:var(--text);">${escHtml(p.vendor||'')}${p.vendor?' / ':''}${escHtml(p.product)}</div>
              ${p.version_range?`<div style="font-size:11px;color:var(--text4);">Versions: ${escHtml(p.version_range)}</div>`:''}</div>
              ${p.cvss_score?`<div style="text-align:right;"><div style="font-size:14px;font-weight:900;font-family:'JetBrains Mono';color:${p.cvss_score>=9?'#c62828':p.cvss_score>=7?'#e65100':'#f9a825'};">${p.cvss_score}</div><div style="font-size:9px;color:var(--text4);">CVSS</div></div>`:''}
              ${p.actively_exploited?`<span style="padding:2px 6px;border-radius:6px;font-size:9px;font-weight:700;background:rgba(198,40,40,.08);color:#c62828;border:1px solid rgba(198,40,40,.12);">CISA KEV</span>`:''}
            </div>`;
          });
          h+=`</div>`;
        }
        // LINK 2: Asset source with verification links
        if(assetP){
          const _srcE={'onboarding':'📋','onboarding_auto':'📋','auto_from_email':'📧','auto_from_name':'🏷️','industry_default':'🏭','subfinder':'🔍','censys':'🌐','manual':'✏️','manual_entry':'✏️','csv_import':'📊','ct_log':'📜','analyst':'👤','recon':'🛰️','bulk_import':'📦','ai_onboarding':'🤖','auto_infer':'🔮','unknown':'📋'};
          const _srcL={'onboarding':'Added during customer onboarding -  domain extracted from registration email','onboarding_auto':'Auto-registered during customer onboarding from contact email domain','auto_from_email':'Automatically extracted from customer contact email address','auto_from_name':'Auto-generated from customer company name for brand monitoring','industry_default':'Auto-populated from industry-standard technology stack template for this sector','subfinder':'Discovered via passive subdomain enumeration using Certificate Transparency + DNS','censys':'Found via Censys internet-wide scan of exposed services and certificates','manual':'Manually registered and verified by security analyst','manual_entry':'Manually added by analyst with direct knowledge of customer infrastructure','csv_import':'Imported from CSV bulk asset upload file','ct_log':'Discovered in Certificate Transparency logs via crt.sh','analyst':'Registered by security analyst based on customer communication','recon':'Discovered by automated reconnaissance engine (subfinder + CT + DNS)','bulk_import':'Added via bulk asset import tool','ai_onboarding':'AI-identified asset during intelligent onboarding analysis','auto_infer':'Automatically inferred from collected threat intelligence patterns','unknown':'Registered during initial customer setup'};
          const ds=assetP.discovery_source||'onboarding';
          const dsDisplay={'onboarding':'Customer Onboarding','onboarding_auto':'Auto-Onboarding','auto_from_email':'Email Domain Extract','auto_from_name':'Brand Name Auto','industry_default':'Industry Template','subfinder':'Subdomain Discovery','censys':'Censys Scan','manual':'Analyst Registered','manual_entry':'Analyst Registered','csv_import':'CSV Import','ct_log':'CT Log Discovery','analyst':'Analyst Verified','recon':'Recon Engine','bulk_import':'Bulk Import','ai_onboarding':'AI Onboarding','auto_infer':'Auto-Inferred','unknown':'Customer Setup'}[ds]||ds.replace(/_/g,' ');
          const av=assetP.asset_value||'';
          const at=assetP.asset_type||'';
          const cn=f.customer_name||'';
          // Build verification links based on asset type
          const verifyLinks=[];
          if(at==='tech_stack'||at==='product'){
            verifyLinks.push({name:'Wappalyzer',url:`https://www.wappalyzer.com/lookup/${encodeURIComponent(cn.toLowerCase().replace(/\s+/g,''))}/`,emoji:'🔬',desc:'Technology profiler -  detects tech stacks from HTTP headers, JS libraries, meta tags'});
            verifyLinks.push({name:'BuiltWith',url:`https://builtwith.com/${encodeURIComponent(cn.toLowerCase().replace(/\s+/g,''))}.com`,emoji:'🏗️',desc:'Technology lookup -  shows what websites are built with'});
            verifyLinks.push({name:'Shodan',url:`https://www.shodan.io/search?query=org%3A%22${encodeURIComponent(cn)}%22+product%3A%22${encodeURIComponent(av)}%22`,emoji:'🔍',desc:'Internet-wide scan -  finds exposed instances of this product'});
          }
          if(at==='domain'||at==='subdomain'){
            verifyLinks.push({name:'crt.sh (CT Logs)',url:`https://crt.sh/?q=%25.${encodeURIComponent(av)}`,emoji:'📜',desc:'Certificate Transparency -  all SSL certificates ever issued for this domain'});
            verifyLinks.push({name:'Whois',url:`https://www.whois.com/whois/${encodeURIComponent(av)}`,emoji:'📋',desc:'Domain registration -  ownership, registrar, creation date'});
            verifyLinks.push({name:'SecurityTrails',url:`https://securitytrails.com/domain/${encodeURIComponent(av)}/dns`,emoji:'🛤️',desc:'Historical DNS records -  subdomains, IP history, NS changes'});
          }
          if(at==='ip'||at==='cidr'){
            verifyLinks.push({name:'Shodan',url:`https://www.shodan.io/host/${encodeURIComponent(av)}`,emoji:'🔍',desc:'Internet scanner -  open ports, services, vulnerabilities'});
            verifyLinks.push({name:'AbuseIPDB',url:`https://www.abuseipdb.com/check/${encodeURIComponent(av)}`,emoji:'🚫',desc:'IP reputation -  abuse reports and confidence score'});
            verifyLinks.push({name:'GreyNoise',url:`https://viz.greynoise.io/ip/${encodeURIComponent(av)}`,emoji:'📡',desc:'Internet noise classifier -  is this IP scanning the internet?'});
          }
          if(at==='email'||at==='email_domain'){
            verifyLinks.push({name:'HIBP',url:`https://haveibeenpwned.com/DomainSearch/${encodeURIComponent(av)}`,emoji:'🔓',desc:'Breach database -  check if this domain has been in data breaches'});
            verifyLinks.push({name:'Hunter.io',url:`https://hunter.io/domain-search/${encodeURIComponent(av)}`,emoji:'📧',desc:'Email finder -  shows publicly available email patterns'});
          }
          if(at==='github_org'){
            verifyLinks.push({name:'GitHub',url:`https://github.com/${encodeURIComponent(av)}`,emoji:'🐙',desc:'GitHub organization -  public repositories and members'});
          }
          // For industry defaults, link to the industry config
          if(ds==='industry_default'||ds==='seed'||ds==='seed v2'){
            const custIndustry=f.customer_industry||'technology';
            verifyLinks.push({name:'NIST Cybersecurity',url:'https://www.nist.gov/cyberframework',emoji:'🏛️',desc:'NIST framework -  industry-standard technology categorization'});
          }
          // Always add NVD link for CVE findings
          if(iocType==='cve_id'){
            verifyLinks.push({name:'NVD CPE Dictionary',url:`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(iocVal)}#vulnConfigurationsArea`,emoji:'📦',desc:'NVD CPE data -  official list of affected products for this CVE'});
          }
          h+=`<div style="margin-bottom:10px;padding:10px 14px;border-radius:10px;border:1px solid rgba(0,137,123,.15);background:rgba(0,137,123,.03);">
            <div style="font-size:11px;font-weight:700;color:var(--cyan);margin-bottom:6px;">LINK 2: How do we know ${escHtml(f.customer_name)} uses "${escHtml(assetP.asset_value)}"?</div>
            <div style="display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;background:var(--surface);border:1px solid var(--border);margin-bottom:6px;">
              <span style="font-size:18px;">${_srcE[ds]||'📍'}</span>
              <div style="flex:1;"><div style="font-size:13px;font-weight:700;color:var(--text);">Source: ${escHtml(dsDisplay)}</div>
              <div style="font-size:11px;color:var(--text3);">${_srcL[ds]||'Asset registered in customer profile during setup'}</div></div>
              <div style="text-align:right;"><div style="font-size:14px;font-weight:900;font-family:'JetBrains Mono';color:var(--cyan);">${Math.round((assetP.confidence||0)*100)}%</div><div style="font-size:9px;color:var(--text4);">confidence</div></div>
            </div>
            ${verifyLinks.length?`<div style="font-size:10px;font-weight:700;text-transform:uppercase;color:var(--text4);margin-bottom:4px;">🔗 Verify this asset externally:</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px;">
              ${verifyLinks.map(v=>`<a href="${v.url}" target="_blank" rel="noopener" style="text-decoration:none;display:flex;align-items:center;gap:6px;padding:6px 10px;border-radius:8px;border:1px solid rgba(0,137,123,.1);background:rgba(0,137,123,.02);transition:all .2s;" onmouseover="this.style.borderColor='rgba(0,137,123,.3)';this.style.boxShadow='0 2px 8px rgba(0,137,123,.08)'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
                <span style="font-size:14px;">${v.emoji}</span>
                <div><div style="font-size:11px;font-weight:700;color:var(--cyan);">${v.name} ↗</div>
                <div style="font-size:9px;color:var(--text4);line-height:1.2;">${v.desc}</div></div>
              </a>`).join('')}
            </div>`:''}
            <div style="margin-top:6px;font-size:11px;color:var(--text4);">Type: <b>${escHtml(assetP.asset_type)}</b> · Criticality: <b>${escHtml(assetP.criticality||'medium')}</b> · IOC hits: <b>${assetP.ioc_hit_count||0}</b>${assetP.manual_entry?' · <span style="color:var(--green);">✏️ Manually verified</span>':''}${assetP.created_at?' · Registered: '+new Date(assetP.created_at).toLocaleDateString():''}</div>
          </div>`;
        }
        // LINK 3: Match logic
        h+=`<div style="padding:10px 14px;border-radius:10px;border:1px solid rgba(230,92,0,.15);background:rgba(230,92,0,.03);">
          <div style="font-size:11px;font-weight:700;color:var(--orange);margin-bottom:4px;">LINK 3: Correlation engine match</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.5;">Strategy: <b>${escHtml((corrType||'').replace(/_/g,' '))}</b> · Confidence: <b>${f.confidence?Math.round(f.confidence*100)+'%':'N/A'}</b> · Sources: <b>${f.source_count||1}</b></div>
        </div>`;
        h+=`</div>`;
      }
      // Source reference links
      if(srcLinks.length){
        h+=`<div style="padding:12px 16px;">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">🔗 Intelligence Source References</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px;">`;
        srcLinks.forEach(s=>{
          h+=`<a href="${s.url}" target="_blank" rel="noopener" style="text-decoration:none;display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid ${s.color}20;background:${s.color}05;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='${s.color}50';this.style.boxShadow='0 2px 8px ${s.color}10'" onmouseout="this.style.borderColor='${s.color}20';this.style.boxShadow=''">
            <span style="font-size:16px;">${s.emoji}</span>
            <div>
              <div style="font-size:12px;font-weight:700;color:${s.color};">${s.name} ↗</div>
              <div style="font-size:10px;color:var(--text4);line-height:1.3;">${s.desc}</div>
            </div>
          </a>`;
        });
        h+=`</div></div>`;
      }
      // All contributing sources
      if(allSources.length>1){
        h+=`<div style="padding:8px 16px 12px;border-top:1px solid var(--border);">
          <div style="font-size:11px;font-weight:700;color:var(--text4);margin-bottom:4px;">Contributing Collectors (${allSources.length})</div>
          <div style="display:flex;gap:4px;flex-wrap:wrap;">${allSources.map(s=>`<span style="padding:3px 8px;border-radius:8px;font-size:10px;font-weight:600;background:var(--cyan-g);border:1px solid var(--cyan-b);color:var(--cyan);">${s}</span>`).join('')}</div>
        </div>`;
      }
      h+=`</div>`;
    }
    h+=`</div></div>`;
  }
  // ═══ ACTION BAR ═══
  h+=`<div class="fi-detail-actions">
    <div class="btn-group">
      <button class="btn green" onclick="patchFinding(${f.id},'resolved')">✓ Resolve</button>
      <button class="btn" onclick="patchFinding(${f.id},'investigating')">🔍 Investigate</button>
      <button class="btn red" onclick="patchFinding(${f.id},'false_positive')">✕ False Positive</button>
    </div>
    <button class="btn cyan" onclick="enrichIOC('${(f.ioc_value||'').replace(/'/g,"\\'")}','${f.ioc_type||''}')">🔬 Enrich</button>
    ${f.detection_id?`<button class="btn" onclick="exportSTIX(${f.detection_id})">📦 STIX</button>`:''}
    <button class="btn" onclick="loadRemediations()">🔧 Remediations</button>
    ${f.remediations?.length?f.remediations.map(r=>`<button class="btn" style="font-size:11px;" onclick="cuPatchFindingRem(${f.id},${r.id},{status:'completed'})">${r.status==='completed'?'↩ Reopen':'✓ Complete'} Rem #${r.id}</button>`).join(''):''}
    ${f.detection_id?`<button class="btn" onclick="apiPost('/api/export/cef/${f.detection_id}').then(r=>toast(r?'CEF exported':'Failed',r?'success':'error'))">📋 CEF</button>`:''}
    ${f.detection_id?`<button class="btn" onclick="enrichDetection(${f.detection_id})">🧠 Attrib</button>`:''}
  </div>`;
  // ═══ REMEDIATIONS ═══
  const remList=f.remediations||[];
  h+=`<div class="fi-section"><div class="fi-section-head"><span class="ico">🩹</span><span class="title">Remediation Actions (${remList.length})</span>
    <button class="btn" style="font-size:10px;padding:2px 10px;margin-left:auto;" onclick="createRemed(${f.id})">+ Add</button></div>
    <div class="fi-section-body">`;
  if(remList.length){
    remList.forEach(r=>{
      const statusColor=r.status==='completed'?'var(--green)':r.status==='in_progress'?'var(--cyan)':'var(--text4)';
      h+=`<div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);">
        <span style="width:8px;height:8px;border-radius:50%;background:${statusColor};flex-shrink:0;"></span>
        <div style="flex:1;"><div style="font-size:13px;font-weight:600;">${r.title||r.playbook_key||'-'}</div>
        <div style="font-size:11px;color:var(--text3);">${r.description||r.notes||''}</div></div>
        <select style="font-size:10px;padding:2px 6px;border-radius:6px;border:1px solid var(--border);background:var(--glass);color:var(--text);"
          onchange="patchRemedStatus(${r.id},this.value,${f.id})">
          <option value="pending" ${r.status==='pending'?'selected':''}>Pending</option>
          <option value="in_progress" ${r.status==='in_progress'?'selected':''}>In Progress</option>
          <option value="completed" ${r.status==='completed'?'selected':''}>Completed</option>
          <option value="skipped" ${r.status==='skipped'?'selected':''}>Skipped</option>
        </select>
        <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="patchRemed(${r.id},${f.id})">✏️</button>
      </div>`;
    });
  } else {
    h+=`<div class="text-sm text-muted" style="padding:8px 0;">No remediations yet. Click + Add to create one.</div>`;
  }
  h+=`</div></div>`;
  // ═══ ENRICHMENTS ═══
  if(f.enrichments?.length)h+=`<div class="fi-section"><div class="fi-section-head"><span class="ico">🔬</span><span class="title">Enrichment Results</span></div><div class="fi-section-body">${f.enrichments.map(e=>`<div class="fi-enrich-row"><div class="fi-enrich-provider">${e.provider||'-'}</div><div class="text-sm">${typeof e.result==='object'?JSON.stringify(e.result).substring(0,200):e.result||'-'}</div></div>`).join('')}</div></div>`;
  document.getElementById('mf-body').innerHTML=h;openM('m-finding');
}
async function patchFinding(id,status){await apiPatch('/api/findings/'+id+'/status',{status});toast('Finding -> '+status);closeM('m-finding');loadF();}
async function enrichIOC(value,type){
  toast('Enriching '+value.substring(0,30)+'...');
  if(type?.includes('ip'))await api('/api/enrich/ip/'+encodeURIComponent(value));
  else if(type?.includes('domain'))await api('/api/enrich/domain/'+encodeURIComponent(value));
  toast('Enrichment complete');
}
async function exportSTIX(detId){const r=await apiPost('/api/stix/export/'+detId);toast(r?'STIX bundle exported':'Export failed',r?'success':'error');}

// ═══ CAMPAIGNS - /api/campaigns ═══
async function loadCa(){
  const data=await api('/api/campaigns?status=');
  const items=Array.isArray(data)?data:(data?.campaigns||[]);
  // Sort: CRITICAL -> HIGH -> MEDIUM -> LOW (backup client-side sort)
  const sevOrd={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  items.sort((a,b)=>(sevOrd[(a.severity||'HIGH').toUpperCase()]??4)-(sevOrd[(b.severity||'HIGH').toUpperCase()]??4));
  _campaigns=items;
  const grid=document.getElementById('ca-grid');
  document.getElementById('ca-empty').style.display=items.length?'none':'block';
  grid.innerHTML=items.map(c=>{const sl=(c.severity||'high').toLowerCase();const sevCls=sl==='critical'?'crit':sl==='high'?'high':sl==='medium'?'med':'low';
    const kcEmoji={'recon':'🔍','delivery':'📧','exploitation':'💥','c2':'📡','exfiltration':'💧'};
    const kcStage=c.kill_chain_stage||c.kill_chain_phase||'';
    const sevColor=sl==='critical'?'var(--red)':sl==='high'?'#e65100':sl==='medium'?'var(--cyan)':'var(--green)';
    const custName=c.customer_name||'Unknown';
    return`<div class="ca-card" style="cursor:pointer;transition:all .25s;position:relative;" onclick="openCampaign(${c.id})" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 8px 28px rgba(0,0,0,.10)'" onmouseout="this.style.transform='';this.style.boxShadow=''">
    <div class="ca-sev-stripe ${sevCls}"></div>
    <div class="ca-body">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
        ${sevTag(c.severity||'high')}
        <span class="text-xs text-muted">#${c.id}</span>
        <span style="margin-left:auto;padding:2px 8px;border-radius:8px;font-size:10px;font-weight:600;background:rgba(0,137,123,.08);color:var(--cyan);border:1px solid rgba(0,137,123,.15);">🏢 ${escHtml(custName)}</span>
      </div>
      <div class="ca-title">${escHtml(c.name||c.title||'Campaign #'+c.id)}</div>
      <div class="ca-desc">${escHtml(c.ai_narrative||c.narrative||c.description||'AI-correlated attack pattern')}</div>
      <div class="ca-tags">
        ${c.finding_count?`<span class="tag info">🔍 ${c.finding_count} findings</span>`:''}
        ${kcStage?`<span class="tag low">${kcEmoji[kcStage]||'⚡'} ${kcStage}</span>`:''}
        ${c.actor_name?`<span class="tag high">🎭 ${escHtml(c.actor_name)}</span>`:''}
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:8px;font-size:11px;color:var(--text4);">
        ${c.first_seen?`<span>First: ${ago(c.first_seen)}</span>`:''}
        ${c.last_activity?`<span>· Last: ${ago(c.last_activity)}</span>`:''}
        <span style="margin-left:auto;color:${sevColor};font-weight:700;font-size:10px;">click for details -></span>
      </div>
    </div></div>`;}).join('');
}

// ═══ CAMPAIGN DETAIL DRILLDOWN ═══
async function openCampaign(id){
  showDrilldown('⚔️ Loading campaign...','<div style="text-align:center;padding:30px;"><span class="loading-spin" style="display:inline-block;width:24px;height:24px;border:3px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span></div>');
  const c=await api('/api/campaigns/'+id);
  if(!c){showDrilldown('⚔️ Campaign','<div class="empty">Campaign not found</div>');return;}
  const sevColor={'CRITICAL':'#c62828','HIGH':'#e65100','MEDIUM':'#e65c00','LOW':'#2e7d32'}[c.severity||'HIGH']||'#e65100';
  const kcEmoji={'recon':'🔍','delivery':'📧','exploitation':'💥','c2':'📡','exfiltration':'💧'};
  const kcStages=['recon','delivery','exploitation','c2','exfiltration'];
  const activeStage=c.kill_chain_stage||'exploitation';
  const kcDesc={
    recon:'Attacker reconnaissance -  domain lookups, OSINT gathering, certificate transparency',
    delivery:'Payload delivery -  spear-phishing emails, weaponized documents, malicious links',
    exploitation:'Active exploitation -  CVE exploitation, credential stuffing, vulnerability scanning',
    c2:'Command & Control -  C2 beacons, reverse shells, lateral movement',
    exfiltration:'Data exfiltration -  stolen credentials on dark web, data dumps, ransomware claims'
  };
  const findings=c.findings||[];
  let h='';

  // ═══ 1. CAMPAIGN IDENTITY HEADER ═══
  h+=`<div style="display:flex;align-items:center;gap:14px;margin-bottom:18px;">
    <div style="width:56px;height:56px;border-radius:14px;background:${sevColor}10;display:flex;align-items:center;justify-content:center;border:2px solid ${sevColor}30;">
      <span style="font-size:28px;">⚔️</span>
    </div>
    <div style="flex:1;">
      <div style="font-size:18px;font-weight:800;">${escHtml(c.name||'Campaign #'+c.id)}</div>
      <div style="font-size:13px;color:var(--text3);margin-top:2px;">🏢 ${escHtml(c.customer_name||'Unknown')} ${c.actor_name?'· 🎭 '+escHtml(c.actor_name):''}</div>
    </div>
    <div style="text-align:right;">
      <div style="padding:4px 12px;border-radius:10px;font-size:12px;font-weight:800;background:${sevColor}10;color:${sevColor};border:1px solid ${sevColor}30;">${c.severity||'HIGH'}</div>
      <div style="font-size:10px;color:var(--text4);margin-top:4px;">${c.status||'active'}</div>
    </div>
  </div>`;

  // ═══ 2. CUSTOMER RELATIONSHIP -  WHO IS AFFECTED ═══
  const cust=c.customer;
  if(cust){
    const tierColor={'enterprise':'#e65100','professional':'#1565c0','standard':'#00897b','trial':'#7b1fa2'}[(cust.tier||'').toLowerCase()]||'var(--text3)';
    const tierEmoji={'enterprise':'🏢','professional':'🏛️','standard':'📦','trial':'🧪'}[(cust.tier||'').toLowerCase()]||'🏢';
    // Count unique IOC types targeting this customer
    const iocTypes=[...new Set(findings.map(f=>f.ioc_type).filter(Boolean))];
    const critCount=findings.filter(f=>(f.severity||'').toUpperCase()==='CRITICAL').length;
    const exposedCount=findings.filter(f=>f.confirmed_exposure).length;
    h+=`<div style="margin-bottom:18px;padding:14px;border-radius:12px;border:1px solid rgba(0,137,123,.2);background:rgba(0,137,123,.03);">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:10px;">🎯 Affected Customer</div>
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;cursor:pointer;" onclick="closeM('m-drilldown');openCu(${cust.id})">
        <div style="width:42px;height:42px;border-radius:12px;background:${tierColor}10;display:flex;align-items:center;justify-content:center;border:1px solid ${tierColor}25;">
          <span style="font-size:22px;">${tierEmoji}</span>
        </div>
        <div style="flex:1;">
          <div style="font-size:15px;font-weight:800;color:var(--text);">${escHtml(cust.name)}</div>
          <div style="font-size:11px;color:var(--text4);">${cust.industry?escHtml(cust.industry)+' · ':''}${cust.tier?escHtml(cust.tier)+' tier':''}${cust.primary_domain?' · '+escHtml(cust.primary_domain):''}</div>
        </div>
        <span style="color:var(--cyan);font-weight:700;font-size:11px;">view customer -></span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;">
        <div style="text-align:center;padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
          <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--orange);">${findings.length}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">FINDINGS</div></div>
        <div style="text-align:center;padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
          <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:#c62828;">${critCount}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">CRITICAL</div></div>
        <div style="text-align:center;padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
          <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--text2);">${iocTypes.length}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">IOC TYPES</div></div>
        <div style="text-align:center;padding:8px;border-radius:8px;background:${exposedCount?'rgba(198,40,40,.06)':'var(--surface)'};border:1px solid ${exposedCount?'rgba(198,40,40,.15)':'var(--border)'};">
          <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:${exposedCount?'#c62828':'var(--text2)'};">${exposedCount}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">CONFIRMED</div></div>
      </div>
      ${findings.some(f=>f.matched_asset)?`<div style="margin-top:8px;padding:8px 10px;border-radius:8px;background:var(--surface);border-left:3px solid var(--cyan);">
        <div style="font-size:10px;font-weight:700;color:var(--text4);margin-bottom:4px;">MATCHED ASSETS</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap;">${[...new Set(findings.map(f=>f.matched_asset).filter(Boolean))].map(a=>`<span style="padding:2px 8px;border-radius:8px;font-size:10px;font-family:'JetBrains Mono';background:rgba(0,137,123,.06);color:var(--cyan);border:1px solid rgba(0,137,123,.12);">${escHtml(a)}</span>`).join('')}</div>
      </div>`:''}
    </div>`;
  }

  // ═══ 3. KILL CHAIN POSITION ═══
  h+=`<div style="margin-bottom:18px;padding:14px;border-radius:12px;background:var(--surface);border:1px solid var(--border);">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:10px;">Kill Chain Position</div>
    <div style="display:flex;gap:4px;margin-bottom:10px;">`;
  kcStages.forEach((s,i)=>{
    const isActive=s===activeStage;
    const isPast=kcStages.indexOf(activeStage)>=i;
    h+=`<div style="flex:1;text-align:center;cursor:pointer;" onclick="this.querySelector('.kc-exp').classList.toggle('hidden')">
      <div style="height:6px;border-radius:3px;background:${isPast?sevColor+'cc':'var(--bg3)'};margin-bottom:6px;${isActive?'box-shadow:0 0 8px '+sevColor+'40;':''}"></div>
      <div style="font-size:${isActive?'13':'11'}px;font-weight:${isActive?'800':'600'};color:${isActive?sevColor:'var(--text4)'};">${kcEmoji[s]||'⚡'} ${s}</div>
      <div class="kc-exp hidden" style="font-size:11px;color:var(--text3);line-height:1.4;margin-top:4px;text-align:left;padding:4px;">${kcDesc[s]||''}</div>
    </div>`;
  });
  h+=`</div>
    <div style="font-size:12px;color:var(--text2);line-height:1.5;padding:8px 10px;border-radius:8px;background:${sevColor}06;border-left:3px solid ${sevColor};">
      <b>Current: ${kcEmoji[activeStage]||''} ${activeStage.toUpperCase()}</b> -  ${kcDesc[activeStage]||'Active attack phase'}
    </div></div>`;

  // ═══ 4. STATS GRID ═══
  h+=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:18px;">
    <div style="text-align:center;padding:10px;border-radius:10px;border:1px solid var(--border);background:var(--glass);">
      <div style="font-size:20px;font-weight:900;font-family:'JetBrains Mono';color:var(--orange);">${c.finding_count||0}</div>
      <div style="font-size:10px;color:var(--text4);font-weight:700;">FINDINGS</div></div>
    <div style="text-align:center;padding:10px;border-radius:10px;border:1px solid var(--border);background:var(--glass);">
      <div style="font-size:20px;font-weight:900;font-family:'JetBrains Mono';color:${sevColor};">${c.severity||'-'}</div>
      <div style="font-size:10px;color:var(--text4);font-weight:700;">SEVERITY</div></div>
    <div style="text-align:center;padding:10px;border-radius:10px;border:1px solid var(--border);background:var(--glass);">
      <div style="font-size:14px;font-weight:900;font-family:'JetBrains Mono';color:var(--text2);">${ago(c.first_seen)}</div>
      <div style="font-size:10px;color:var(--text4);font-weight:700;">FIRST SEEN</div></div>
    <div style="text-align:center;padding:10px;border-radius:10px;border:1px solid var(--border);background:var(--glass);">
      <div style="font-size:14px;font-weight:900;font-family:'JetBrains Mono';color:var(--text2);">${ago(c.last_activity)}</div>
      <div style="font-size:10px;color:var(--text4);font-weight:700;">LAST ACTIVITY</div></div>
  </div>`;

  // ═══ 5. AI CAMPAIGN NARRATIVE ═══
  if(c.ai_narrative){
    h+=`<div style="margin-bottom:18px;padding:14px;border-radius:12px;background:linear-gradient(135deg,rgba(230,92,0,.03),rgba(0,137,123,.03));border:1px solid rgba(230,92,0,.15);">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">🤖 AI Campaign Narrative</div>
      <div style="font-size:14px;color:var(--text);line-height:1.7;">${c.ai_narrative}</div>
    </div>`;}

  // ═══ 6. ACTOR CARD ═══
  if(c.actor){const a=c.actor;
    const _flag={"Russia":"🇷🇺","China":"🇨🇳","Iran":"🇮🇷","North Korea":"🇰🇵","United Kingdom":"🇬🇧","United States":"🇺🇸","India":"🇮🇳","Israel":"🇮🇱","Pakistan":"🇵🇰","Vietnam":"🇻🇳","Turkey":"🇹🇷","Brazil":"🇧🇷","Nigeria":"🇳🇬"}[a.origin_country]||'🎭';
    h+=`<div style="margin-bottom:18px;padding:14px;border-radius:12px;border:1px solid rgba(123,31,162,.2);background:rgba(123,31,162,.03);cursor:pointer;" onclick="this.querySelector('.actor-exp').classList.toggle('hidden')">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
        <span style="font-size:28px;">${_flag}</span>
        <div style="flex:1;"><div style="font-size:15px;font-weight:800;">🎭 ${escHtml(a.name)}</div>
        <div style="font-size:11px;color:var(--text4);">${a.mitre_id||''} · ${a.motivation||''} · ${a.origin_country||''}</div></div>
        <span style="font-size:10px;color:var(--text4);">click ▸</span>
      </div>
      ${a.aliases?.length?`<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px;">${a.aliases.map(al=>`<span style="padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;background:rgba(123,31,162,.06);color:#7b1fa2;border:1px solid rgba(123,31,162,.15);">${escHtml(al)}</span>`).join('')}</div>`:''}
      <div class="actor-exp hidden" style="margin-top:8px;">
        <div style="font-size:13px;color:var(--text2);line-height:1.6;margin-bottom:8px;">${a.description||''}</div>
        ${a.techniques?.length?`<div style="font-size:11px;font-weight:700;color:var(--text3);margin-bottom:4px;">MITRE Techniques</div><div style="display:flex;gap:4px;flex-wrap:wrap;">${a.techniques.map(t=>`<span style="padding:2px 8px;border-radius:8px;font-size:10px;font-family:'JetBrains Mono';background:rgba(198,40,40,.06);color:#c62828;border:1px solid rgba(198,40,40,.12);">${escHtml(t)}</span>`).join('')}</div>`:''}
      </div></div>`;}

  // ═══ 7. LINKED FINDINGS -  ENRICHED IOC TIMELINE ═══
  if(findings.length){
    h+=`<div style="margin-bottom:18px;">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:10px;">🔍 Linked Findings -  IOC Timeline (${findings.length})</div>`;
    findings.forEach((f,idx)=>{
      const fSev=(f.severity||'HIGH').toUpperCase();
      const fSevColor={'CRITICAL':'#c62828','HIGH':'#e65100','MEDIUM':'#e65c00','LOW':'#2e7d32'}[fSev]||'#e65c00';
      const sources=f.all_sources||[];
      const srcDetail=f.sources_detail||[];
      const rems=f.remediations||[];
      const hasExpanded=f.ai_narrative||f.ai_severity_reasoning||srcDetail.length||rems.length||f.matched_asset||f.correlation_type;
      h+=`<div style="padding:12px 14px;border-radius:12px;border:1px solid var(--border);margin-bottom:8px;transition:all .2s;border-left:3px solid ${fSevColor};" onmouseover="this.style.boxShadow='0 3px 12px ${fSevColor}12'" onmouseout="this.style.boxShadow=''">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="padding:2px 8px;border-radius:8px;font-size:10px;font-weight:800;background:${fSevColor}10;color:${fSevColor};">${fSev}</span>
          <span style="font-family:'JetBrains Mono';font-size:13px;font-weight:700;color:var(--text);flex:1;word-break:break-all;cursor:pointer;" onclick="closeM('m-drilldown');openFi(${f.id})">${escHtml(f.ioc_value||'-')}</span>
          <span style="padding:2px 8px;border-radius:8px;font-size:10px;background:var(--surface);color:var(--text3);border:1px solid var(--border);">${escHtml(f.ioc_type||'')}</span>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:6px;font-size:11px;color:var(--text4);">
          ${f.confidence?`<span>📊 ${(f.confidence*100).toFixed(0)}% confidence</span>`:''}
          ${f.status?`<span>📋 ${escHtml(f.status)}</span>`:''}
          <span>🕐 ${f.created_at?new Date(f.created_at).toLocaleString():' - '}</span>
          ${f.confirmed_exposure?'<span style="color:#c62828;font-weight:700;">⚠️ CONFIRMED EXPOSURE</span>':''}
        </div>`;

      // Source attribution
      if(sources.length||srcDetail.length){
        h+=`<div style="margin-top:8px;padding:8px 10px;border-radius:8px;background:rgba(230,92,0,.03);border:1px solid rgba(230,92,0,.08);">
          <div style="font-size:10px;font-weight:700;color:var(--text4);margin-bottom:4px;">📡 SOURCE ATTRIBUTION</div>
          <div style="display:flex;gap:4px;flex-wrap:wrap;">`;
        if(srcDetail.length){
          srcDetail.forEach(s=>{
            h+=`<span style="padding:2px 8px;border-radius:8px;font-size:10px;font-family:'JetBrains Mono';background:rgba(230,92,0,.06);color:var(--orange);border:1px solid rgba(230,92,0,.12);" title="${s.contributed_at?'Found: '+new Date(s.contributed_at).toLocaleString():''}">${escHtml(s.source)}</span>`;
          });
        } else {
          sources.forEach(s=>{
            h+=`<span style="padding:2px 8px;border-radius:8px;font-size:10px;font-family:'JetBrains Mono';background:rgba(230,92,0,.06);color:var(--orange);border:1px solid rgba(230,92,0,.12);">${escHtml(s)}</span>`;
          });
        }
        h+=`</div></div>`;
      }

      // Customer relationship -  how this IOC maps to the customer
      if(f.matched_asset||f.correlation_type){
        h+=`<div style="margin-top:6px;padding:8px 10px;border-radius:8px;background:rgba(0,137,123,.03);border:1px solid rgba(0,137,123,.08);">
          <div style="font-size:10px;font-weight:700;color:var(--text4);margin-bottom:4px;">🎯 CUSTOMER RELATIONSHIP</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.5;">`;
        if(f.matched_asset) h+=`Matched asset: <span style="font-family:'JetBrains Mono';font-weight:700;color:var(--cyan);">${escHtml(f.matched_asset)}</span>`;
        if(f.correlation_type) h+=` via <span style="padding:2px 6px;border-radius:6px;font-size:10px;font-weight:600;background:rgba(0,137,123,.06);color:var(--cyan);">${escHtml(f.correlation_type)}</span>`;
        h+=`</div></div>`;
      }

      // AI analysis
      if(f.ai_narrative||f.ai_severity_reasoning){
        h+=`<div style="margin-top:6px;padding:8px 10px;border-radius:8px;background:rgba(123,31,162,.03);border:1px solid rgba(123,31,162,.08);">
          <div style="font-size:10px;font-weight:700;color:var(--text4);margin-bottom:3px;">🤖 AI ANALYSIS</div>
          <div style="font-size:12px;color:var(--text3);line-height:1.5;font-style:italic;">${escHtml(f.ai_narrative||f.ai_severity_reasoning||'')}</div>
        </div>`;
      }

      // Remediation steps for this finding
      if(rems.length){
        h+=`<div style="margin-top:6px;padding:8px 10px;border-radius:8px;background:rgba(46,125,50,.03);border:1px solid rgba(46,125,50,.08);">
          <div style="font-size:10px;font-weight:700;color:var(--text4);margin-bottom:4px;">🔧 REMEDIATION (${rems.length})</div>`;
        rems.forEach(r=>{
          const remStatus={'pending':'⏳','in_progress':'🔄','completed':'✅','overdue':'🚨'}[r.status]||'⏳';
          h+=`<div style="margin-bottom:4px;">
            <div style="display:flex;align-items:center;gap:6px;">
              <span>${remStatus}</span>
              <span style="font-size:12px;font-weight:700;color:var(--text);">${escHtml(r.title||r.action_type||'Action')}</span>
              <span style="margin-left:auto;font-size:10px;padding:2px 6px;border-radius:6px;background:var(--surface);color:var(--text4);border:1px solid var(--border);">${escHtml(r.status||'pending')}</span>
            </div>`;
          if(r.steps_technical?.length){
            h+=`<div style="margin-top:3px;padding-left:20px;font-size:11px;color:var(--text3);">`;
            r.steps_technical.slice(0,3).forEach((step,si)=>{
              h+=`<div style="margin-bottom:2px;">${si+1}. ${escHtml(step)}</div>`;
            });
            if(r.steps_technical.length>3) h+=`<div style="color:var(--text4);font-style:italic;">+${r.steps_technical.length-3} more steps</div>`;
            h+=`</div>`;
          }
          if(r.deadline) h+=`<div style="font-size:10px;color:var(--text4);padding-left:20px;margin-top:2px;">⏰ Deadline: ${new Date(r.deadline).toLocaleString()}</div>`;
          h+=`</div>`;
        });
        h+=`</div>`;
      }

      // Open finding link
      h+=`<div style="margin-top:6px;text-align:right;">
        <span style="font-size:11px;color:var(--orange);font-weight:700;cursor:pointer;" onclick="closeM('m-drilldown');openFi(${f.id})">open full finding -></span>
      </div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // ═══ 8. CAMPAIGN-WIDE REMEDIATION SUMMARY ═══
  const allRems=findings.flatMap(f=>f.remediations||[]);
  if(allRems.length){
    const pending=allRems.filter(r=>r.status==='pending').length;
    const inProg=allRems.filter(r=>r.status==='in_progress').length;
    const done=allRems.filter(r=>r.status==='completed').length;
    const overdue=allRems.filter(r=>r.status==='overdue').length;
    h+=`<div style="margin-bottom:18px;padding:14px;border-radius:12px;border:1px solid rgba(46,125,50,.2);background:rgba(46,125,50,.03);">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:10px;">🔧 Remediation Summary (${allRems.length} actions)</div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;">
        <div style="text-align:center;padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
          <div style="font-size:18px;font-weight:900;color:#e65c00;">${pending}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">⏳ PENDING</div></div>
        <div style="text-align:center;padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
          <div style="font-size:18px;font-weight:900;color:#1565c0;">${inProg}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">🔄 IN PROGRESS</div></div>
        <div style="text-align:center;padding:8px;border-radius:8px;background:var(--surface);border:1px solid var(--border);">
          <div style="font-size:18px;font-weight:900;color:#2e7d32;">${done}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">✅ DONE</div></div>
        <div style="text-align:center;padding:8px;border-radius:8px;background:${overdue?'rgba(198,40,40,.06)':'var(--surface)'};border:1px solid ${overdue?'rgba(198,40,40,.15)':'var(--border)'};">
          <div style="font-size:18px;font-weight:900;color:${overdue?'#c62828':'var(--text3)'};">${overdue}</div>
          <div style="font-size:9px;color:var(--text4);font-weight:700;">🚨 OVERDUE</div></div>
      </div>
    </div>`;
  }

  // ═══ 9. WHAT IS A CAMPAIGN ═══
  h+=`<div style="padding:12px 14px;border-radius:10px;background:var(--surface);border-left:3px solid var(--orange);font-size:12px;color:var(--text3);line-height:1.5;margin-bottom:14px;">
    <b>What is a Campaign?</b> The correlation engine groups findings into campaigns when <b>3+ findings from the same threat actor targeting the same customer within a 14-day window</b> are detected. Kill chain stage is determined by the IOC type mix: domain recon -> email delivery -> CVE exploitation -> IP C2 -> dark web exfiltration.
  </div>`;

  // ═══ 10. ACTIONS ═══
  h+=`<div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;">
    <button class="btn pri" onclick="closeM('m-drilldown');openCu(${c.customer_id})">🏢 View Customer</button>
    ${c.actor_id?`<button class="btn" onclick="closeM('m-drilldown');openActDetail(${c.actor_id})">🎭 Actor Profile</button>`:''}
    <button class="btn" style="background:rgba(46,125,50,.06);color:#2e7d32;border-color:rgba(46,125,50,.2);" onclick="closeM('m-drilldown');go('remediations')">🔧 Remediations</button>
    <button class="btn" style="background:rgba(198,40,40,.06);color:#c62828;border-color:rgba(198,40,40,.2);" onclick="toast('Incident Response activated for campaign #${c.id}')">🚨 Activate IR</button>
  </div>`;
  showDrilldown('⚔️ '+( c.name||'Campaign #'+c.id),h);
}

// ═══ DETECTIONS - /api/detections/, /api/detections/{did}, /api/collectors/status ═══
async function loadD(){
  const src=document.getElementById('det-src')?.value||'';
  let u='/api/detections/?limit=60&offset=0';if(src)u+='&source='+src;
  const [data,cols]=await Promise.all([api(u),api('/api/collectors/status')]);
  const items=data?.items||data?.detections||data||[];
  // Populate source filter
  if(cols){const sel=document.getElementById('det-src');const opts=Object.keys(cols);
    if(sel.options.length<=1)opts.forEach(o=>{const op=document.createElement('option');op.value=o;op.text=o;sel.add(op);});}
  document.getElementById('det-grid').innerHTML=items.map(d=>{
    const conf=d.confidence?d.confidence.toFixed(2):'?';
    const confColor=conf>=0.8?'var(--green)':conf>=0.5?'var(--amber)':'var(--text4)';
    return`<div class="det-card" onclick="openDetDetail(${d.id})">
      <div class="det-top"><span class="tag info">${d.ioc_type||'-'}</span><span class="text-xs text-muted">${ago(d.collected_at||d.created_at)}</span></div>
      <div class="mono text-sm font-bold" style="word-break:break-all;margin:6px 0;">${d.ioc_value||'-'}</div>
      <div class="det-meta"><span>📡 ${d.source||'-'}</span><span class="mono" style="color:${confColor};">📊 ${conf}</span>
      ${d.customer_id?`<span class="text-green">✓ Attributed</span>`:'<span class="text-muted">Global</span>'}</div>
      <div style="display:flex;gap:4px;margin-top:6px;">
        <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="event.stopPropagation();enrichDetection(${d.id})">🔬 Enrich</button>
        <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="event.stopPropagation();patchDetStatus(${d.id},'${d.status==='resolved'?'active':'resolved'}')">${d.status==='resolved'?'↩ Reopen':'✓ Resolve'}</button>
        <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="event.stopPropagation();apiPost('/api/export/cef/${d.id}').then(r=>toast(r?'CEF exported':'Failed',r?'success':'error'))">📋 CEF</button>
        <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="event.stopPropagation();cuExportSTIXDet(${d.id})">📦 STIX</button>
        ${d.ioc_type==='cve_id'?`<button class="btn" style="font-size:10px;padding:2px 8px;" onclick="event.stopPropagation();api('/api/attribution/cve/'+encodeURIComponent('${d.ioc_value}')).then(r=>{if(r)showDrilldown('🛡️ CVE Attribution','<pre style=\\'padding:16px;font-size:12px;white-space:pre-wrap;\\'>'+JSON.stringify(r,null,2)+'</pre>');})">🛡️ CVE</button>`:''}
      </div>
    </div>`;}).join('')||'<div class="empty">No detections yet. Run collection to start.</div>';
}

// ═══ ACTORS - /api/actors, /api/actors/{id}, /api/actor-iocs ═══
async function loadAct(){
  let data=await api('/api/actors?limit=300');
  let items=Array.isArray(data)?data:(data?.actors||[]);
  // Auto-seed MITRE actors if empty
  if(items.length===0){
    document.getElementById('act-count').textContent='Loading MITRE ATT&CK threat actors...';
    document.getElementById('act-grid').innerHTML=`<div style="text-align:center;padding:40px;grid-column:1/-1;"><div style="font-size:40px;margin-bottom:12px;animation:pulse-glow 2s infinite;">🎭</div><div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:6px;">Seeding Threat Actors...</div><div style="font-size:13px;color:var(--text3);">Loading 20 MITRE ATT&CK groups (APT28, APT29, Lazarus, Volt Typhoon...)</div><div style="margin-top:16px;"><span class="loading-spin" style="display:inline-block;width:24px;height:24px;border:3px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span></div></div>`;
    await apiPost('/api/seed/actors');
    data=await api('/api/actors?limit=300');
    items=Array.isArray(data)?data:(data?.actors||[]);
  }
  _actors=items;
  document.getElementById('act-count').textContent=items.length+' threat actors tracked';
  renderActors(items);
}
function renderActors(items){
  document.getElementById('act-grid').innerHTML=items.slice(0,60).map(a=>{
    const flag=a.country_flag||'🎭';
    const aliases=Array.isArray(a.aliases)?a.aliases.join(', '):a.aliases||'';
    const desc=(a.description||'').substring(0,150);
    const sectors=Array.isArray(a.target_sectors)?a.target_sectors.slice(0,3).join(', '):'';
    const _cc={'Russia':'#c62828','China':'#e65100','Iran':'#7b1fa2','North Korea':'#1565c0','United Kingdom':'#00897b','Unknown':'#9e9e9e','Vietnam':'#2e7d32','Pakistan':'#e65c00','India':'#ef6c00','Israel':'#1565c0'};
    const cc=_cc[a.origin_country||a.country||'']||'var(--text3)';
    const _se={'expert':'🔴','advanced':'🟠','intermediate':'🟡','basic':'🟢'};
    return`<div class="act-card" onclick="openActDetail(${a.id})" style="border-left:3px solid ${cc};">
      ${a.mitre_id?`<div class="act-mitre">${a.mitre_id}</div>`:''}
      <div class="act-head">
        <div class="act-flag" style="border:2px solid ${cc}30;box-shadow:0 0 8px ${cc}15;">${flag}</div>
        <div style="flex:1;min-width:0;">
          <div class="act-name" style="font-size:16px;">${a.name||'Unknown'}</div>
          ${aliases?`<div class="act-aliases" title="${escHtml(aliases)}">${escHtml(aliases.substring(0,60))}</div>`:''}
        </div>
        ${a.sophistication?`<span style="font-size:12px;">${_se[a.sophistication]||'⚪'}</span>`:''}
      </div>
      ${desc?`<div class="act-desc" style="font-size:12px;line-height:1.5;margin:8px 0;">${escHtml(desc)}${desc.length>=150?'...':''}</div>`:''}
      <div class="act-tags" style="margin-top:8px;">
        ${a.motivation?`<span class="act-tag motive">⚡ ${a.motivation}</span>`:''}
        ${a.technique_count>0?`<span class="act-tag ttp">🛡 ${a.technique_count} TTPs</span>`:''}
        ${a.origin_country?`<span class="act-tag country" style="background:${cc}08;color:${cc};border-color:${cc}20;">📍 ${a.origin_country}</span>`:''}
        ${sectors?`<span class="act-tag sectors">🎯 ${sectors}</span>`:''}
      </div>
      <div style="margin-top:8px;font-size:10px;color:var(--orange);font-weight:600;text-align:right;">click for details -></div>
    </div>`;
  }).join('')||'<div class="empty">No threat actors loaded yet</div>';
}
function filterActors(q){
  if(!q){renderActors(_actors);return;}
  const lq=q.toLowerCase();
  const filtered=_actors.filter(a=>(a.name||'').toLowerCase().includes(lq)||(a.origin_country||'').toLowerCase().includes(lq)||
    (Array.isArray(a.aliases)?a.aliases.join(' '):(a.aliases||'')).toLowerCase().includes(lq)||(a.motivation||'').toLowerCase().includes(lq));
  renderActors(filtered);
}
async function openActDetail(id){
  const [a,iocs]=await Promise.all([api('/api/actors/'+id),api('/api/actor-iocs?actor_id='+id)]);
  if(!a)return;
  document.getElementById('ma-title').textContent=a.name||'Actor';
  const aliases=Array.isArray(a.aliases)?a.aliases.join(', '):a.aliases||'-';
  const sectors=Array.isArray(a.target_sectors)?a.target_sectors.join(', '):'';
  const techs=a.techniques||[];
  const _cc={'Russia':'#c62828','China':'#e65100','Iran':'#7b1fa2','North Korea':'#1565c0','Unknown':'#9e9e9e'};
  const cc=_cc[a.origin_country||'']||'#e65c00';
  const _se={'expert':'🔴 Expert','advanced':'🟠 Advanced','intermediate':'🟡 Intermediate','basic':'🟢 Basic'};

  let h=`<div style="padding:18px;border-radius:16px;background:linear-gradient(135deg,${cc}08,${cc}03);border:1.5px solid ${cc}20;margin-bottom:16px;">
    <div style="display:flex;align-items:center;gap:16px;">
      <div class="act-flag" style="width:64px;height:64px;font-size:32px;border:2.5px solid ${cc}30;box-shadow:0 0 12px ${cc}15;">${a.country_flag||'🎭'}</div>
      <div style="flex:1;">
        <div style="font-size:22px;font-weight:900;color:var(--text);margin-bottom:4px;">${a.name}</div>
        <div style="font-size:13px;color:var(--text3);">${aliases}</div>
        ${a.mitre_id?`<div style="margin-top:4px;"><a href="https://attack.mitre.org/groups/${a.mitre_id}" target="_blank" style="font-size:12px;font-family:'JetBrains Mono';color:${cc};text-decoration:none;font-weight:700;">${a.mitre_id} ↗ MITRE ATT&CK</a></div>`:''}
      </div>
      <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end;">
        ${a.motivation?`<span style="padding:4px 12px;border-radius:10px;font-size:11px;font-weight:700;background:${cc}10;color:${cc};border:1px solid ${cc}20;">⚡ ${a.motivation}</span>`:''}
        ${a.origin_country?`<span style="padding:4px 12px;border-radius:10px;font-size:11px;font-weight:700;background:${cc}10;color:${cc};border:1px solid ${cc}20;">📍 ${a.origin_country}</span>`:''}
      </div>
    </div>
  </div>`;

  // Stats grid
  h+=`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px;">
    <div style="text-align:center;padding:10px;border-radius:10px;background:var(--surface);border:1px solid var(--border);"><div style="font-size:11px;color:var(--text4);font-weight:700;">SOPHISTICATION</div><div style="font-size:14px;font-weight:800;color:var(--text);">${_se[a.sophistication]||a.sophistication||'-'}</div></div>
    <div style="text-align:center;padding:10px;border-radius:10px;background:var(--surface);border:1px solid var(--border);"><div style="font-size:11px;color:var(--text4);font-weight:700;">ACTIVE SINCE</div><div style="font-size:14px;font-weight:800;color:var(--text);">${a.active_since||'-'}</div></div>
    <div style="text-align:center;padding:10px;border-radius:10px;background:var(--surface);border:1px solid var(--border);"><div style="font-size:11px;color:var(--text4);font-weight:700;">TTPs</div><div style="font-size:14px;font-weight:800;font-family:'JetBrains Mono';color:var(--orange);">${techs.length||a.technique_count||0}</div></div>
    <div style="text-align:center;padding:10px;border-radius:10px;background:var(--surface);border:1px solid var(--border);"><div style="font-size:11px;color:var(--text4);font-weight:700;">IOCs</div><div style="font-size:14px;font-weight:800;font-family:'JetBrains Mono';color:#c62828;">${(iocs?.iocs||iocs||[]).length}</div></div>
  </div>`;

  // Target sectors
  if(sectors){
    h+=`<div style="margin-bottom:14px;padding:12px 14px;border-radius:12px;background:rgba(198,40,40,.03);border:1px solid rgba(198,40,40,.1);">
      <div style="font-size:11px;font-weight:700;color:#c62828;text-transform:uppercase;margin-bottom:6px;">🎯 Target Sectors</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${sectors.split(',').map(s=>`<span style="padding:3px 10px;border-radius:8px;font-size:11px;font-weight:600;background:rgba(198,40,40,.06);color:#c62828;border:1px solid rgba(198,40,40,.1);">${s.trim()}</span>`).join('')}</div>
    </div>`;
  }

  // Description
  if(a.description){
    h+=`<div style="padding:14px;border-radius:12px;background:var(--surface);border:1px solid var(--border);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">📝 Intelligence Summary</div>
      <div style="font-size:13px;color:var(--text);line-height:1.7;">${a.description}</div>
    </div>`;
  }

  // MITRE Techniques
  if(techs.length){
    h+=`<div style="padding:14px;border-radius:12px;background:rgba(230,92,0,.03);border:1px solid rgba(230,92,0,.1);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;color:var(--orange);text-transform:uppercase;margin-bottom:8px;">🛡 MITRE ATT&CK Techniques (${techs.length})</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;max-height:150px;overflow-y:auto;">${techs.slice(0,40).map(t=>`<a href="https://attack.mitre.org/techniques/${t.replace('.','/').replace('T','T')}" target="_blank" style="text-decoration:none;padding:3px 10px;border-radius:8px;font-size:11px;font-weight:700;font-family:'JetBrains Mono';background:rgba(230,92,0,.06);color:var(--orange);border:1px solid rgba(230,92,0,.15);transition:all .2s;" onmouseover="this.style.background='rgba(230,92,0,.12)'" onmouseout="this.style.background='rgba(230,92,0,.06)'">${t} ↗</a>`).join('')}</div>
    </div>`;
  }

  // Associated IOCs
  const iocList=iocs?.iocs||iocs||[];
  if(iocList.length){
    h+=`<div style="padding:14px;border-radius:12px;background:rgba(0,137,123,.03);border:1px solid rgba(0,137,123,.1);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;color:var(--cyan);text-transform:uppercase;margin-bottom:8px;">🔬 Associated IOCs (${iocList.length})</div>
      <div style="max-height:200px;overflow-y:auto;">${iocList.slice(0,25).map(i=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;border-bottom:1px solid var(--border);"><span style="padding:2px 6px;border-radius:6px;font-size:10px;font-weight:700;background:rgba(0,137,123,.06);color:var(--cyan);border:1px solid rgba(0,137,123,.12);">${i.ioc_type||'-'}</span><span style="font-family:'JetBrains Mono';font-size:12px;color:var(--text);flex:1;word-break:break-all;">${escHtml(i.ioc_value||'-')}</span></div>`).join('')}</div>
    </div>`;
  }

  // External intelligence links
  h+=`<div style="padding:14px;border-radius:12px;border:1px solid rgba(230,92,0,.12);background:rgba(230,92,0,.03);margin-bottom:14px;">
    <div style="font-size:11px;font-weight:700;color:var(--orange);text-transform:uppercase;margin-bottom:8px;">🔗 External Intelligence</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px;">
      ${a.mitre_id?`<a href="https://attack.mitre.org/groups/${a.mitre_id}" target="_blank" style="text-decoration:none;display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid rgba(230,92,0,.1);transition:all .2s;" onmouseover="this.style.borderColor='rgba(230,92,0,.3)'" onmouseout="this.style.borderColor=''"><span style="font-size:16px;">⚔️</span><div><div style="font-size:12px;font-weight:700;color:var(--orange);">MITRE ATT&CK ↗</div><div style="font-size:10px;color:var(--text4);">Official group profile</div></div></a>`:''}
      <a href="https://www.google.com/search?q=%22${encodeURIComponent(a.name)}%22+threat+actor+APT" target="_blank" style="text-decoration:none;display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid rgba(230,92,0,.1);transition:all .2s;" onmouseover="this.style.borderColor='rgba(230,92,0,.3)'" onmouseout="this.style.borderColor=''"><span style="font-size:16px;">🔍</span><div><div style="font-size:12px;font-weight:700;color:var(--orange);">Google Research ↗</div><div style="font-size:10px;color:var(--text4);">Threat reports & analysis</div></div></a>
      <a href="https://malpedia.caad.fkie.fraunhofer.de/actor/${encodeURIComponent(a.name.toLowerCase().replace(/\s+/g,'_'))}" target="_blank" style="text-decoration:none;display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid rgba(230,92,0,.1);transition:all .2s;" onmouseover="this.style.borderColor='rgba(230,92,0,.3)'" onmouseout="this.style.borderColor=''"><span style="font-size:16px;">📚</span><div><div style="font-size:12px;font-weight:700;color:var(--orange);">Malpedia ↗</div><div style="font-size:10px;color:var(--text4);">Malware & actor database</div></div></a>
      <a href="https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(a.name)}" target="_blank" style="text-decoration:none;display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid rgba(230,92,0,.1);transition:all .2s;" onmouseover="this.style.borderColor='rgba(230,92,0,.3)'" onmouseout="this.style.borderColor=''"><span style="font-size:16px;">👽</span><div><div style="font-size:12px;font-weight:700;color:var(--orange);">AlienVault OTX ↗</div><div style="font-size:10px;color:var(--text4);">Community threat pulses</div></div></a>
    </div>
  </div>`;

  document.getElementById('ma-body').innerHTML=h;openM('m-actor');
}

// ═══ DARK WEB - /api/darkweb, /api/darkweb/stats, /api/darkweb/triage-stats, POST /api/darkweb/triage-now ═══
function dwBtnActive(el){el.parentElement.querySelectorAll('.btn').forEach(b=>b.classList.remove('pri'));el.classList.add('pri');}
async function triggerDWTriage(){toast('Running AI dark web triage...');await apiPost('/api/darkweb/triage-now');setTimeout(()=>{toast('Triage complete');loadDW('');},2000);}
let _dwItems=[];
async function loadDW(filter){
  const filterName=filter==='ransomwatch'?'Ransomware':filter==='paste'?'Paste dumps':'All sources';
  toast('🌑 Loading '+filterName+'...');
  const [items,stats,triageStats]=await Promise.all([
    api('/api/darkweb?limit=60'+(filter?'&source='+filter:'')),api('/api/darkweb/stats'),api('/api/darkweb/triage-stats')]);
  if(stats){document.getElementById('dw-stats').innerHTML=
    `<div class="stat red" style="border-radius:14px;border:1.5px solid rgba(220,38,38,.15);background:linear-gradient(135deg,rgba(220,38,38,.06),rgba(220,38,38,.02));cursor:pointer;transition:all .3s;" onclick="loadDW('ransomwatch');toast('Filtering ransomware claims...','info');setTimeout(()=>document.getElementById('dw-list')?.scrollIntoView({behavior:'smooth',block:'start'}),300)" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 6px 20px rgba(220,38,38,.15)'" onmouseout="this.style.transform='';this.style.boxShadow=''"><div class="stat-num red" style="font-size:32px;">${stats.ransomware_claims||0}</div><div class="stat-lbl">Ransomware Claims</div><div style="font-size:10px;color:#dc2626;font-weight:600;margin-top:4px;">click to filter ↓</div></div>
    <div class="stat orange" style="border-radius:14px;border:1.5px solid rgba(234,88,12,.15);background:linear-gradient(135deg,rgba(234,88,12,.06),rgba(234,88,12,.02));cursor:pointer;transition:all .3s;" onclick="loadDW('paste');toast('Filtering paste dumps...','info');setTimeout(()=>document.getElementById('dw-list')?.scrollIntoView({behavior:'smooth',block:'start'}),300)" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 6px 20px rgba(234,88,12,.15)'" onmouseout="this.style.transform='';this.style.boxShadow=''"><div class="stat-num orange" style="font-size:32px;">${stats.paste_dumps||stats.total_mentions||0}</div><div class="stat-lbl">Paste Dumps</div><div style="font-size:10px;color:#ea580c;font-weight:600;margin-top:4px;">click to filter ↓</div></div>
    <div class="stat purple" style="border-radius:14px;border:1.5px solid rgba(124,58,237,.15);background:linear-gradient(135deg,rgba(124,58,237,.06),rgba(124,58,237,.02));cursor:pointer;transition:all .3s;" onclick="loadDW('');toast('Loading all mentions...','info');setTimeout(()=>document.getElementById('dw-list')?.scrollIntoView({behavior:'smooth',block:'start'}),300)" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 6px 20px rgba(124,58,237,.15)'" onmouseout="this.style.transform='';this.style.boxShadow=''"><div class="stat-num purple" style="font-size:32px;">${stats.dark_web_mentions||0}</div><div class="stat-lbl">All DW Mentions</div><div style="font-size:10px;color:#7c3aed;font-weight:600;margin-top:4px;">click to show all ↓</div></div>
    <div class="stat amber" style="border-radius:14px;border:1.5px solid rgba(230,92,0,.15);background:linear-gradient(135deg,rgba(230,92,0,.06),rgba(230,92,0,.02));cursor:pointer;transition:all .3s;" onclick="triggerDWTriage();toast('🤖 Running AI triage on dark web mentions...','info')" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 6px 20px rgba(230,92,0,.15)'" onmouseout="this.style.transform='';this.style.boxShadow=''"><div class="stat-num amber" style="font-size:32px;">${triageStats?.triaged||stats.customer_attributed||0}</div><div class="stat-lbl">AI Triaged</div><div style="font-size:10px;color:var(--orange);font-weight:600;margin-top:4px;">click to run triage ⚡</div></div>`;}
  const list=items?.mentions||items||[];
  _dwItems=list;
  document.getElementById('dw-list').innerHTML=list.map(d=>{
    const isRansom=d.source==='ransomwatch'||d.source==='ransomfeed'||d.mention_type==='ransomware_claim';
    const isPaste=d.source==='paste'||(d.mention_type||'').includes('paste');
    const cardCls=isRansom?'ransom':isPaste?'paste':'mention';
    const srcCls=isRansom?'ransom':isPaste?'paste':'default';
    const hasSummary=d.ai_summary&&d.ai_summary!=='null';
    if(!d.id){console.warn('DW item missing id:',d);return'';}
    const typeIcon=isRansom?'🔴':isPaste?'📋':'🌑';
    const typeLabel=isRansom?'Ransomware Leak':isPaste?'Credential Dump':'Dark Web Mention';
    const sevColor=isRansom?'#dc2626':isPaste?'#ea580c':'#7c3aed';
    return`<div class="dw-card ${cardCls}" style="cursor:pointer;" onclick="openDWDetail(${d.id})" onmouseover="this.style.transform='translateY(-3px)'" onmouseout="this.style.transform=''">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <div style="width:36px;height:36px;border-radius:10px;background:${sevColor}10;display:flex;align-items:center;justify-content:center;font-size:18px;border:1px solid ${sevColor}20;flex-shrink:0;">${typeIcon}</div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <span class="dw-src ${srcCls}">${d.source||'-'}</span>
            <span class="dw-type">${d.mention_type||d.type||'-'}</span>
            ${d.triage_classification?`<span style="padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;background:rgba(230,92,0,.08);color:var(--orange);border:1px solid rgba(230,92,0,.12);">🤖 ${d.triage_classification.replace(/_/g,' ')}</span>`:''}
          </div>
          <div style="font-size:10px;color:var(--text4);margin-top:2px;">${typeLabel}</div>
        </div>
        <span style="font-size:10px;color:var(--orange);font-weight:700;">details -></span>
        <span class="dw-time">${ago(d.discovered_at||d.created_at)}</span>
      </div>
      <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:8px;line-height:1.4;word-break:break-word;">${escHtml((d.content||d.title||'Untitled').substring(0,200))}</div>
      ${hasSummary?`<div style="padding:8px 12px;border-radius:8px;background:rgba(230,92,0,.04);border-left:3px solid var(--orange);font-size:12px;color:var(--text2);line-height:1.5;margin-bottom:8px;">🤖 ${escHtml(d.ai_summary)}</div>`:`<div style="padding:6px 10px;border-radius:8px;background:var(--surface);font-size:11px;color:var(--text4);margin-bottom:8px;">⏳ Pending AI triage</div>`}
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        ${d.customer_name?`<span style="padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700;background:rgba(0,137,123,.06);color:var(--cyan);border:1px solid rgba(0,137,123,.12);cursor:pointer;" onclick="event.stopPropagation();openCu(${d.customer_id})">🏢 ${escHtml(d.customer_name)}</span>`:'<span style="font-size:11px;color:var(--text4);">Unattributed</span>'}
        ${d.threat_actor?`<span style="padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700;background:rgba(198,40,40,.06);color:#c62828;border:1px solid rgba(198,40,40,.12);">🎭 ${escHtml(d.threat_actor)}</span>`:''}
        ${d.url?`<span style="margin-left:auto;padding:3px 10px;border-radius:10px;font-size:10px;font-weight:600;background:rgba(230,92,0,.06);color:var(--orange);border:1px solid rgba(230,92,0,.12);cursor:pointer;" onclick="event.stopPropagation();window.open('${d.url}','_blank')">🔗 Source</span>`:''}
      </div>
    </div>`;
  }).join('');
  if(list.length){
    document.getElementById('dw-list').innerHTML=`<div style="font-size:12px;color:var(--text3);margin-bottom:8px;font-weight:600;">Showing ${list.length} dark web mentions -  click any card for details</div>`+document.getElementById('dw-list').innerHTML;
    toast('Loaded '+list.length+' dark web mentions','success');
  } else {
    document.getElementById('dw-list').innerHTML='<div class="empty" style="padding:40px;text-align:center;"><div style="font-size:40px;margin-bottom:12px;">🌑</div><div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:6px;">No dark web intelligence found</div><div style="font-size:13px;color:var(--text3);">Try "All Sources" or wait for the next collection cycle</div></div>';
  }
}

function openDWDetail(id){
  console.log('openDWDetail called with id:',id);
  const d=_dwItems.find(x=>x.id===id||x.id===String(id));
  if(!d){toast('Dark web mention not found (id: '+id+')','error');console.log('_dwItems:',_dwItems.map(x=>x.id));return;}
  const isRansom=d.source==='ransomwatch'||d.source==='ransomfeed'||d.mention_type==='ransomware_claim';
  const isPaste=d.source==='paste'||(d.mention_type||'').includes('paste');
  const sevColor={'CRITICAL':'#c62828','HIGH':'#e65100','MEDIUM':'#f9a825','LOW':'#2e7d32'}[(d.severity||'HIGH').toUpperCase()]||'#e65100';
  const typeEmoji=isRansom?'🔴':isPaste?'📋':'🌐';
  const typeLabel=isRansom?'Ransomware Leak Claim':isPaste?'Paste Dump / Credential Leak':'Dark Web Mention';
  let h='';

  // Header
  h+=`<div style="display:flex;align-items:center;gap:14px;margin-bottom:18px;">
    <div style="width:52px;height:52px;border-radius:14px;background:${sevColor}10;display:flex;align-items:center;justify-content:center;font-size:28px;border:2px solid ${sevColor}30;">${typeEmoji}</div>
    <div style="flex:1;">
      <div style="font-size:16px;font-weight:800;color:var(--text);">${typeLabel}</div>
      <div style="font-size:12px;color:var(--text3);margin-top:2px;">${escHtml(d.source||'-')} · ${d.mention_type||'-'} · ${d.discovered_at?new Date(d.discovered_at).toLocaleString():'-'}</div>
    </div>
    <div style="padding:4px 12px;border-radius:10px;font-size:12px;font-weight:800;background:${sevColor}10;color:${sevColor};border:1px solid ${sevColor}30;">${d.severity||'HIGH'}</div>
  </div>`;

  // Content
  h+=`<div style="padding:14px;border-radius:12px;background:var(--surface);border:1px solid var(--border);margin-bottom:14px;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text4);margin-bottom:6px;">Content</div>
    <div style="font-size:14px;color:var(--text);line-height:1.6;word-break:break-word;">${escHtml(d.content||d.title||'No content available')}</div>
  </div>`;

  // AI Triage
  if(d.ai_summary||d.triage_classification){
    h+=`<div style="padding:14px;border-radius:12px;background:linear-gradient(135deg,rgba(230,92,0,.03),rgba(0,137,123,.02));border:1px solid rgba(230,92,0,.12);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--orange);margin-bottom:6px;">🤖 AI Triage Analysis</div>
      ${d.triage_classification?`<div style="margin-bottom:6px;"><span style="padding:3px 10px;border-radius:8px;font-size:11px;font-weight:700;background:rgba(230,92,0,.08);color:var(--orange);border:1px solid rgba(230,92,0,.15);">${escHtml(d.triage_classification.replace(/_/g,' '))}</span></div>`:''}
      ${d.ai_summary?`<div style="font-size:13px;color:var(--text2);line-height:1.6;">${escHtml(d.ai_summary)}</div>`:'<div style="font-size:13px;color:var(--text4);font-style:italic;">⏳ Awaiting AI triage -  click "Triage Now" to process</div>'}
    </div>`;
  }

  // Customer Relationship
  h+=`<div style="padding:14px;border-radius:12px;border:1px solid rgba(0,137,123,.15);background:rgba(0,137,123,.03);margin-bottom:14px;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--cyan);margin-bottom:8px;">🎯 Customer Relationship</div>`;
  if(d.customer_name&&d.customer_id){
    h+=`<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;background:var(--surface);border:1px solid var(--border);cursor:pointer;" onclick="closeM('m-drilldown');openCu(${d.customer_id})">
      <div style="width:36px;height:36px;border-radius:10px;background:rgba(0,137,123,.08);display:flex;align-items:center;justify-content:center;font-size:18px;">🏢</div>
      <div style="flex:1;"><div style="font-size:14px;font-weight:700;color:var(--text);">${escHtml(d.customer_name)}</div>
      <div style="font-size:11px;color:var(--text3);">Customer ID: ${d.customer_id} · This mention was attributed to this customer</div></div>
      <span style="font-size:11px;color:var(--orange);font-weight:600;">view customer -></span>
    </div>
    <div style="margin-top:8px;padding:8px 12px;border-radius:8px;background:rgba(0,137,123,.04);border-left:3px solid var(--cyan);font-size:12px;color:var(--text2);line-height:1.5;">
      <b>How was this linked?</b> ${isRansom?'The ransomware group leak page mentioned this customer\'s name or domain. This is a CONFIRMED breach indicator -  the threat actor claims to have exfiltrated data.':isPaste?'Credentials or data matching this customer\'s domain/email patterns were found in a paste dump. This indicates potential credential compromise.':'This customer\'s brand name, domain, or executive name was found in dark web forums, marketplaces, or Telegram channels.'}
    </div>`;
  } else {
    h+=`<div style="padding:12px;border-radius:8px;background:rgba(198,40,40,.04);border-left:3px solid rgba(198,40,40,.2);font-size:13px;color:var(--text3);line-height:1.5;">
      <b>⚠️ Unattributed</b> -  This mention hasn't been linked to any customer yet. Possible reasons:<br>
      • No customer's domain/brand matches the mention content<br>
      • Customer not yet onboarded when this was collected<br>
      • Mention is generic threat intel (not customer-specific)<br>
      <div style="margin-top:6px;"><button class="btn" style="font-size:11px;padding:4px 12px;" onclick="closeM('m-drilldown');go('customers')">Review Customers -></button></div>
    </div>`;
  }
  h+=`</div>`;

  // Threat Actor
  if(d.threat_actor){
    h+=`<div style="padding:14px;border-radius:12px;border:1px solid rgba(123,31,162,.15);background:rgba(123,31,162,.03);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#7b1fa2;margin-bottom:6px;">🎭 Threat Actor</div>
      <div style="font-size:15px;font-weight:800;color:var(--text);">${escHtml(d.threat_actor)}</div>
      <div style="font-size:12px;color:var(--text3);margin-top:4px;">${isRansom?'This ransomware group claimed responsibility for the attack. They operate a leak site where stolen data is published to pressure victims into paying ransom.':'This threat actor was mentioned in connection with the dark web intelligence.'}</div>
    </div>`;
  }

  // Source & Evidence
  const srcLinks=[];
  if(d.url)srcLinks.push({name:'Original Source',url:d.url,emoji:'🔗',desc:'Direct link to the dark web mention (may require Tor)'});
  if(isRansom){
    srcLinks.push({name:'Ransom Watch',url:'https://ransomwatch.telemetry.ltd/',emoji:'👁️',desc:'Ransomware leak site monitoring -  tracks 150+ groups'});
    srcLinks.push({name:'RansomFeed',url:'https://ransomfeed.it/',emoji:'📰',desc:'Real-time ransomware leak announcements feed'});
  }
  if(isPaste){
    srcLinks.push({name:'Have I Been Pwned',url:'https://haveibeenpwned.com/',emoji:'🔓',desc:'Check if credentials from this dump appear in breach databases'});
  }
  srcLinks.push({name:'Ahmia (Tor Search)',url:'https://ahmia.fi/',emoji:'🌑',desc:'Search engine for .onion dark web sites'});
  if(d.content&&d.content.includes('.onion')){
    const onion=d.content.match(/https?:\/\/[a-z2-7]{16,56}\.onion[^\s]*/);
    if(onion)srcLinks.push({name:'.onion URL',url:onion[0],emoji:'🧅',desc:'Direct Tor hidden service link (requires Tor browser)'});
  }

  h+=`<div style="padding:14px;border-radius:12px;border:1px solid rgba(230,92,0,.12);background:rgba(230,92,0,.03);margin-bottom:14px;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--orange);margin-bottom:8px;">🔗 Source & Evidence</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px;">
      ${srcLinks.map(s=>`<a href="${s.url}" target="_blank" rel="noopener" style="text-decoration:none;display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid rgba(230,92,0,.1);background:rgba(230,92,0,.02);transition:all .2s;" onmouseover="this.style.borderColor='rgba(230,92,0,.3)'" onmouseout="this.style.borderColor=''">
        <span style="font-size:16px;">${s.emoji}</span>
        <div><div style="font-size:12px;font-weight:700;color:var(--orange);">${s.name} ↗</div>
        <div style="font-size:10px;color:var(--text4);line-height:1.2;">${s.desc}</div></div>
      </a>`).join('')}
    </div>
  </div>`;

  // Metadata
  const meta=d.metadata||{};
  if(Object.keys(meta).length){
    h+=`<div style="padding:12px;border-radius:10px;background:var(--surface);border:1px solid var(--border);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text4);margin-bottom:6px;">📋 Raw Metadata</div>
      <div style="font-family:'JetBrains Mono';font-size:11px;color:var(--text3);line-height:1.5;">
        ${Object.entries(meta).map(([k,v])=>`<span style="color:var(--text4);">${escHtml(k)}:</span> <span style="color:var(--text);">${escHtml(String(v).substring(0,100))}</span>`).join('<br>')}
      </div>
    </div>`;
  }

  // Actions
  h+=`<div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;">
    ${d.customer_id?`<button class="btn pri" onclick="closeM('m-drilldown');openCu(${d.customer_id})">🏢 View Customer</button>`:''}
    <button class="btn" onclick="closeM('m-drilldown');go('darkweb')">🌑 Back to Dark Web</button>
    <button class="btn" style="background:rgba(198,40,40,.06);color:#c62828;border-color:rgba(198,40,40,.2);" onclick="toast('Escalation triggered for mention #${d.id}')">🚨 Escalate</button>
  </div>`;

  showDrilldown('🌑 Dark Web -  '+(d.title||d.content||'Mention #'+d.id).substring(0,50),h);
}

// ═══ EXPOSURE - /api/exposure/leaderboard, /api/exposure/{cid}, POST /api/exposure/recalculate ═══
async function loadExp(){
  const data=await api('/api/exposure/leaderboard');
  const items=data?.leaderboard||data||[];
  document.getElementById('exp-grid').innerHTML=items.map(c=>{
    const s=c.max_exposure_score||c.exposure_score||c.score||0;const clr=s>70?'#c62828':s>40?'#e65c00':'#2e7d32';
    const cid=c.customer_id||c.id;
    const nm=c.customer_name||c.name||'-';
    return`<div class="card" style="cursor:pointer;position:relative;transition:all .3s;border:1.5px solid ${clr}15;overflow:hidden;" onclick="openCu(${cid})" onmouseover="this.style.transform='translateY(-3px)';this.style.boxShadow='0 8px 24px ${clr}12';this.style.borderColor='${clr}30';this.querySelector('.exp-del').style.opacity='1'" onmouseout="this.style.transform='';this.style.boxShadow='';this.style.borderColor='${clr}15';this.querySelector('.exp-del').style.opacity='0'">
    <button class="exp-del" style="position:absolute;top:8px;right:8px;padding:3px 8px;border-radius:8px;border:1px solid rgba(198,40,40,.15);background:rgba(198,40,40,.04);color:#c62828;font-size:10px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:3px;opacity:0;transition:all .2s;z-index:2;" onclick="event.stopPropagation();delCustomer(${cid},'${nm.replace(/'/g,"\\'")}')" onmouseover="this.style.background='rgba(198,40,40,.15)'" onmouseout="this.style.background='rgba(198,40,40,.04)'">🗑️</button>
    <div class="flex gap-8 mb-12">
      <div style="width:56px;height:56px;border-radius:50%;border:3.5px solid ${clr};display:flex;align-items:center;justify-content:center;font-weight:900;font-family:'JetBrains Mono';font-size:20px;color:${clr};box-shadow:0 0 12px ${clr}20;">${Math.round(s)}</div>
      <div><div class="font-bold" style="font-size:15px;">${nm}</div><div class="text-xs text-muted">${c.industry||c.sector||'-'}</div></div></div>
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:4px;">
      ${['D1·Actor','D2·Target','D3·Sector','D4·DarkWeb','D5·Surface'].map((d,i)=>{
        const v=c['d'+(i+1)]||c['d'+(i+1)+'_score']||0;
        return`<div style="text-align:center;padding:4px 2px;border-radius:8px;background:${v>7?'rgba(198,40,40,.04)':v>4?'rgba(230,92,0,.04)':'rgba(46,125,50,.04)'};"><div class="text-xs text-muted">${d.split('·')[0]}</div><div class="mono text-sm font-bold" style="color:${v>7?'#c62828':v>4?'#e65c00':'#2e7d32'};">${typeof v==='number'?v.toFixed(1):v}</div><div style="font-size:8px;color:var(--text4);">${d.split('·')[1]}</div></div>`;}).join('')}
    </div>
    <div style="margin-top:8px;text-align:right;font-size:10px;color:var(--orange);font-weight:600;">click for details -></div>
    </div>`;}).join('')||'<div class="empty">Onboard customers to start exposure scoring</div>';
}

// ═══ CUSTOMERS - /api/customers, /api/customers/{cid}, /api/customers/onboard, assets, breach, coverage, attribution, collection, exposure-trend, sla, threat-summary, threat-graph, narrative, risk ═══
async function loadCust(){
  const data=await api('/api/customers');
  _customers=Array.isArray(data)?data:(data?.customers||[]);
  document.getElementById('cu-grid').innerHTML=_customers.map(c=>{
    const fc=c.finding_count||0;const cc=c.critical_count||0;const es=c.exposure_score||0;const ac=c.asset_count||0;const dc=c.detection_count||0;
    const ss=c.score_source||'none';
    const tierMap={'premium':{color:'#e65c00',bg:'rgba(230,92,0,.08)',label:'PREMIUM'},'enterprise':{color:'#00897b',bg:'rgba(0,137,123,.08)',label:'ENTERPRISE'},'standard':{color:'#1565c0',bg:'rgba(21,101,192,.08)',label:'STANDARD'}}; 
    const tier=tierMap[(c.tier||'standard').toLowerCase()]||tierMap.standard;
    const riskColor=es>=70?'#c62828':es>=40?'#e65100':es>0?'#e65c00':'#2e7d32';
    const riskLabel=es>=70?'CRITICAL':es>=40?'HIGH':es>0?'MODERATE':'SAFE';
    const scoreTag=ss==='d1d5_scorer'?'D1-D5':ss==='actor_exposure'?'ACTOR':ss==='estimated_from_findings'?'EST.':' - ';
    const dashOff=151-(151*(Math.min(es,100)/100));
    const state=c.onboarding_state||'active';
    const stateEmoji={'created':'🆕','assets_added':'📋','monitoring':'👁️','tuning':'🔧','production':'✅'};
    return`<div class="cust-card" onclick="openCu(${c.id})" style="--tier-c:${tier.color};">
    <div class="cust-avatar" style="background:linear-gradient(135deg,${tier.bg},${tier.color}08);">
      <span style="color:${tier.color};">${(c.name||'?')[0].toUpperCase()}</span>
    </div>
    <div class="cust-info">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;">
        <div class="cust-name">${c.name||'-'}</div>
        <span style="font-size:10px;font-weight:800;padding:2px 8px;border-radius:10px;background:${tier.bg};color:${tier.color};border:1px solid ${tier.color}25;">${tier.label}</span>
        <span style="font-size:10px;color:var(--text4);">${stateEmoji[state]||'⚡'} ${state}</span>
      </div>
      <div class="cust-domain">${c.primary_domain||c.domain||'-'} · ${c.industry||'-'}</div>
      <div class="cust-metrics">
        <span title="Monitored assets"><span class="mono" style="color:var(--cyan);">${ac}</span> assets</span>
        <span title="Detections ingested"><span class="mono" style="color:var(--amber);">${dc}</span> detections</span>
        <span title="Attributed findings"><span class="mono" style="color:var(--orange);">${fc}</span> findings</span>
      </div>
      ${cc?`<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
        <span style="padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700;background:rgba(198,40,40,.06);color:#c62828;border:1px solid rgba(198,40,40,.12);animation:pulse-glow 2s infinite;">${cc} CRITICAL</span>
        ${fc-cc>0?`<span style="padding:3px 10px;border-radius:10px;font-size:11px;font-weight:600;background:rgba(230,92,0,.06);color:#e65100;border:1px solid rgba(230,92,0,.12);">${fc-cc} other findings</span>`:''}
      </div>`:''}
      <div style="display:flex;align-items:center;gap:8px;margin-top:10px;">
        <div style="flex:1;height:7px;background:var(--bg3);border-radius:4px;overflow:hidden;">
          <div style="width:${Math.min(es,100)}%;height:100%;background:linear-gradient(90deg,${riskColor},${riskColor}cc);border-radius:4px;box-shadow:0 0 8px ${riskColor}40;transition:width 1s;"></div>
        </div>
        <span class="mono" style="font-size:12px;font-weight:800;color:${riskColor};min-width:36px;text-align:right;">${es>0?es.toFixed(1):' - '}</span>
      </div>
    </div>
    <div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex-shrink:0;">
      <div style="position:relative;width:68px;height:68px;">
        <svg viewBox="0 0 72 72" width="68" height="68">
          <circle cx="36" cy="36" r="29" fill="none" stroke="var(--border)" stroke-width="6" opacity=".2"/>
          <circle cx="36" cy="36" r="29" fill="none" stroke="${riskColor}" stroke-width="6"
            stroke-dasharray="182" stroke-dashoffset="${182-(182*(Math.min(es,100)/100))}" stroke-linecap="round"
            transform="rotate(-90 36 36)" style="filter:drop-shadow(0 0 6px ${riskColor});transition:stroke-dashoffset 1s;"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;">
          <div class="mono" style="font-size:18px;font-weight:900;color:${riskColor};line-height:1;text-shadow:0 0 10px ${riskColor}30;">${es>0?es.toFixed(1):'--'}</div>
        </div>
      </div>
      <span style="font-size:10px;font-weight:800;color:${riskColor};text-transform:uppercase;letter-spacing:.5px;">${riskLabel}</span>
      <span style="font-size:9px;color:var(--text4);font-weight:600;">click details -></span>
    </div>
    <button class="cu-del-btn" onclick="event.stopPropagation();delCustomer(${c.id},'${(c.name||'').replace(/'/g,"\\'")}')" title="Delete ${c.name}">🗑️ Remove</button>
  </div>`;}).join('')||'<div class="empty">No customers yet. Click <b>+ Onboard</b> to start.</div>';
}
// Coverage category drilldown -  shows actual IOCs that matched this category
const _catIocTypes={
  1:['email_password_combo','username_password_combo','credential','stealer_log','password','combo','breachdirectory'],
  2:['aws_access_key','github_pat','api_key','private_key','secret_key','token','bearer','openai_api_key','stripe'],
  3:['ipv4','ipv6','ip','ip_address','c2_ip'],
  4:['url','domain','fqdn','malicious_url','phishing_url','dark_web_url','subdomain','hostname'],
  5:['email','email_address','executive_email'],
  6:['md5','sha1','sha256','hash','ssdeep','file_hash','malware_hash'],
  7:['config_file','db_config','internal_hostname','backup_file','exposed_service','misconfiguration','open_port'],
  8:['credit_card','ssn','financial','swift_bic','iban','bank'],
  9:['ransomware','apt_group','ransom_note','data_auction','advisory','ransomware_leak','actor'],
  10:['session_cookie','ntlm_hash','saml','jwt_token','cookie'],
  11:['jwt','azure_bearer','google_oauth','oauth_token','oauth'],
  12:['s3_bucket','elasticsearch','cloud_misconfig','exposed_bucket','open_database'],
  13:['privileged','breakglass','golden_ticket','admin_credential'],
  14:['personal_cloud','dev_tunnel','rogue_endpoint','shadow_it'],
  15:['data_transfer','exfiltration','archive_exfil','data_leak'],
  16:['cve_id','cve','vulnerability','exploit'],
  17:['bitcoin','ethereum','monero','crypto_address','btc','eth']
};
async function drillCoverageCategory(custId,catName,emoji,color,catNum){
  showDrilldown(`${emoji} Loading ${catName}...`,'<div style="text-align:center;padding:30px;">Fetching real IOCs...</div>');
  const findings=await api('/api/findings?limit=100&customer_id='+custId);
  const findArr=Array.isArray(findings)?findings:(findings?.items||findings?.findings||[]);
  const targetTypes=_catIocTypes[catNum]||[];
  // Filter findings whose ioc_type matches this category (bidirectional partial match)
  const matched=findArr.filter(f=>{
    if(!f.ioc_type)return false;
    const ft=f.ioc_type.toLowerCase();
    return targetTypes.some(t=>ft.includes(t)||t.includes(ft));
  });
  // Also get coverage data for debug_ioc_types
  const covData=await api('/api/customers/'+custId+'/coverage');
  const debugTypes=covData?.debug_ioc_types||{};
  // Build the modal
  let h='';
  // Get the original detection count from coverage API for this category
  const covCat=(covData?.categories||[]).find(c=>c.name===catName||c.cat===catNum);
  const detCount=covCat?.detections||0;
  // Header - show findings count (deduplicated), mention detection count
  h+=`<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px;">
    <div style="width:48px;height:48px;border-radius:14px;background:${color}10;display:flex;align-items:center;justify-content:center;font-size:28px;border:2px solid ${color}25;">${emoji}</div>
    <div style="flex:1;">
      <div style="font-size:17px;font-weight:800;color:var(--text);">${catName}</div>
      <div style="font-size:12px;color:var(--text3);">Category ${catNum} · ${detCount} IOC detections · ${matched.length} deduplicated findings · Customer ID: ${custId}</div>
    </div>
    <div style="text-align:right;padding:6px 14px;border-radius:10px;background:${color}10;border:1px solid ${color}25;">
      <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${color};">${matched.length}</div>
      <div style="font-size:9px;color:var(--text4);">FINDINGS</div>
    </div>
  </div>`;
  // Explanation
  const _catExp={'Stolen Credentials':'Usernames + passwords from stealer logs, combo lists, and dark web markets.','API Keys & Tokens':'Exposed API keys, AWS access keys, or tokens in public repos/paste sites.','Network IOCs':'Suspicious IPs, C2 server addresses, and scanning infrastructure.','Domain & URL IOCs':'Malicious URLs, phishing domains, and typosquatted domains.','Email IOCs':'Compromised email addresses from breach databases.','File & Hash IOCs':'Malware file hashes associated with campaigns targeting your industry.','Infrastructure Leaks':'Exposed internal infrastructure found on the open internet.','Financial & Identity':'Financial data linked to your organization on dark web markets.','Threat Actor Intel':'Direct mentions by APT groups or ransomware gangs.','Session & Auth Tokens':'Stolen session cookies or JWT tokens.','OAuth / SaaS Tokens':'Compromised OAuth tokens for SaaS platforms.','SaaS Misconfiguration':'Publicly accessible cloud instances with sensitive data.','Privileged Account Anomaly':'Admin account activity indicating possible compromise.','Shadow IT Discovery':'Unauthorized applications outside IT governance.','Data Exfiltration':'Evidence of data being moved to external destinations.','CVE':'Known vulnerabilities matched to your tech stack via NVD/CISA KEV.','Crypto Addresses':'Cryptocurrency wallet addresses linked to ransomware payments.'};
  h+=`<div style="padding:12px 16px;border-radius:10px;background:${color}05;border-left:3px solid ${color};margin-bottom:16px;font-size:13px;color:var(--text2);line-height:1.6;">
    <b>What is this category?</b> ${_catExp[catName]||'Threat intelligence coverage category.'}
  </div>`;
  // IOC type breakdown from debug data
  const relevantTypes={};
  for(const[dt,dc]of Object.entries(debugTypes)){
    if(!dt)continue;
    const dtl=dt.toLowerCase();
    if(targetTypes.some(t=>dtl.includes(t)||t.includes(dtl))){
      relevantTypes[dt]=dc;
    }
  }
  if(Object.keys(relevantTypes).length){
    h+=`<div style="font-size:11px;font-weight:700;text-transform:uppercase;color:${color};margin-bottom:8px;">📊 IOC Type Breakdown (from database)</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;">`;
    const rtTotal=Object.values(relevantTypes).reduce((a,b)=>a+b,0);
    Object.entries(relevantTypes).sort((a,b)=>b[1]-a[1]).forEach(([t,c])=>{
      const pct=Math.round(c/Math.max(rtTotal,1)*100);
      h+=`<div style="padding:6px 12px;border-radius:10px;background:${color}08;border:1px solid ${color}20;display:flex;align-items:center;gap:6px;">
        <span style="font-family:'JetBrains Mono';font-size:12px;font-weight:700;color:${color};">${c}</span>
        <span style="font-size:11px;color:var(--text);font-weight:600;">${t}</span>
        <span style="font-size:10px;color:var(--text4);">${pct}%</span>
      </div>`;
    });
    h+=`</div>`;
  }
  // Actual findings list with customer relationship proof
  if(detCount>0 && detCount!==matched.length){
    h+=`<div style="padding:8px 12px;border-radius:8px;background:rgba(230,92,0,.04);border-left:3px solid var(--orange);margin-bottom:10px;font-size:11px;color:var(--text3);line-height:1.5;">
      <b>Why ${detCount} IOCs but ${matched.length} finding${matched.length!==1?'s':''}?</b> The ${detCount} number counts raw IOC detections (including duplicates from multiple sources). Findings are deduplicated -  multiple detections of the same IOC merge into one finding.
    </div>`;
  }
  if(matched.length){
    h+=`<div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">🔍 Matched Findings (${matched.length}) -  click any to see full proof chain</div>`;
    matched.slice(0,20).forEach(f=>{
      const sv=(f.severity||'MEDIUM').toUpperCase();
      const svCol={'CRITICAL':'#c62828','HIGH':'#ef6c00','MEDIUM':'#f9a825','LOW':'#2e7d32'}[sv]||'#e65100';
      const corrType=(f.correlation_type||f.match_strategy||'').replace(/_/g,' ');
      const conf=f.confidence?Math.round(f.confidence*100)+'%':'';
      const asset=f.matched_asset||f.asset_value||'';
      const _srcE={'threatfox':'🦊','cisa_kev':'🏛️','nvd':'📦','openphish':'🎣','feodo':'🤖','ransomfeed':'📰','paste':'📋','hudsonrock':'🪨','github_gist':'🐙','abuse_ch':'🚫','circl_misp':'🔵','grep_app':'🔍','urlscan':'🔗','shodan':'🔎','otx':'👽'};
      const srcEmoji=_srcE[f.source||f.all_sources?.[0]||'']||'📡';
      h+=`<div style="padding:14px;margin:6px 0;border-radius:12px;border:1.5px solid ${svCol}20;background:linear-gradient(135deg,${svCol}04,transparent);cursor:pointer;transition:all .3s;" onclick="closeM('m-drilldown');openFi(${f.id})" onmouseover="this.style.borderColor='${svCol}40';this.style.boxShadow='0 4px 16px ${svCol}10';this.style.transform='translateY(-2px)'" onmouseout="this.style.borderColor='${svCol}20';this.style.boxShadow='';this.style.transform=''">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <div style="width:4px;height:36px;border-radius:2px;background:${svCol};flex-shrink:0;"></div>
          <div style="flex:1;min-width:0;">
            <div style="font-family:'JetBrains Mono';font-size:13px;font-weight:700;color:var(--text);word-break:break-all;">${escHtml(f.ioc_value||'-')}</div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px;">
              <span style="padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;background:${svCol}10;color:${svCol};border:1px solid ${svCol}20;">${sv}</span>
              <span style="padding:2px 8px;border-radius:8px;font-size:10px;font-weight:600;background:var(--surface);color:var(--text3);border:1px solid var(--border);">${escHtml(f.ioc_type||'-')}</span>
              <span style="padding:2px 8px;border-radius:8px;font-size:10px;font-weight:600;background:var(--surface);color:var(--text3);border:1px solid var(--border);">${srcEmoji} ${escHtml(f.source||f.all_sources?.[0]||'-')}</span>
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <span style="font-size:10px;color:var(--orange);font-weight:700;">open details -></span>
            <div style="font-size:10px;color:var(--text4);margin-top:2px;">${ago(f.first_seen||f.created_at)}</div>
          </div>
        </div>
        <div style="display:flex;gap:8px;margin-left:14px;">
          ${f.customer_name?`<div style="flex:1;padding:6px 10px;border-radius:8px;background:rgba(0,137,123,.04);border:1px solid rgba(0,137,123,.1);font-size:11px;color:var(--text2);line-height:1.4;">
            <b style="color:var(--cyan);">🏢 Customer:</b> ${escHtml(f.customer_name)}
            ${asset?` · <b>Asset:</b> <span style="font-family:'JetBrains Mono';color:var(--text);">${escHtml(asset)}</span>`:''}
            ${corrType?` · <b>Matched via:</b> <span style="color:var(--orange);">${corrType}</span>`:''}
            ${conf?` · <b>Confidence:</b> ${conf}`:''}
          </div>`:''}
        </div>
      </div>`;
    });
    if(matched.length>20)h+=`<div style="text-align:center;font-size:12px;color:var(--text4);margin-top:8px;">...and ${matched.length-20} more. View all in Findings page.</div>`;
  } else {
    h+=`<div style="text-align:center;padding:24px;color:var(--text4);">
      <div style="font-size:28px;margin-bottom:8px;">📭</div>
      <div style="font-size:14px;font-weight:600;">No findings matched this category</div>
      <div style="font-size:12px;margin-top:4px;">IOC types searched: ${targetTypes.slice(0,6).join(', ')}${targetTypes.length>6?'...':''}</div>
      <div style="font-size:11px;color:var(--text4);margin-top:8px;">This could mean: detections exist but haven't been promoted to findings yet, or the IOC types don't match. Check <code>/api/customers/${custId}/coverage</code> -> debug_ioc_types for raw data.</div>
    </div>`;
  }
  // Actions
  h+=`<div style="display:flex;gap:8px;justify-content:center;margin-top:16px;">
    <button class="btn pri" onclick="closeM('m-drilldown');openCu(${custId})">🏢 Back to Customer</button>
    <button class="btn" onclick="closeM('m-drilldown');go('findings')">🔍 All Findings</button>
  </div>`;
  showDrilldown(`${emoji} ${catName} -  ${matched.length} Finding${matched.length!==1?'s':''}`,h);
}

async function openCu(id){
  const [c,breach,cov,attr,colSt,slaSt,summary,risk,assets,trend,completeness,threatGraph,narrative]=await Promise.all([
    api('/api/customers/'+id),api('/api/customers/'+id+'/breach-status'),api('/api/customers/'+id+'/coverage'),
    api('/api/customers/'+id+'/attribution-breakdown'),api('/api/customers/'+id+'/collection-status'),
    api('/api/customers/'+id+'/sla-compliance'),api('/api/customers/'+id+'/threat-summary'),
    api('/api/customers/'+id+'/risk'),api('/api/customers/'+id+'/assets'),
    api('/api/customers/'+id+'/exposure-trend'),api('/api/customers/'+id+'/completeness'),api('/api/customers/'+id+'/threat-graph'),api('/api/customers/'+id+'/narrative')
  ]);
  if(!c)return;
  document.getElementById('mc-title').textContent=c.name||'Customer #'+id;
  const riskScore=risk?.overall_score||risk?.score||risk?.exposure_score||c.exposure_score||0;
  const riskColor=riskScore>=70?'var(--red)':riskScore>=40?'var(--amber)':'var(--green)';
  let h='';
  // ═══ CUSTOMER IDENTITY HEADER ═══
  h+=`<div class="cu-identity">
    <div class="cu-avatar" style="background:linear-gradient(135deg,${riskColor}22,${riskColor}08);">
      <span style="font-size:28px;font-weight:900;color:${riskColor};">${(c.name||'?')[0].toUpperCase()}</span>
    </div>
    <div class="cu-info">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <span style="font-size:18px;font-weight:800;">${c.name||'-'}</span>
        <span class="tag ${c.tier==='premium'?'crit':'green'}" style="font-size:11px;">${(c.tier||'standard').toUpperCase()}</span>
        <span class="tag info" style="font-size:11px;">${c.onboarding_state||'active'}</span>
      </div>
      <div class="text-sm text-muted" style="margin-top:3px;">${c.primary_domain||c.domain||'-'} · ${c.industry||'-'} · ${c.email||'-'}</div>
    </div>
    <div class="cu-risk-ring" style="cursor:pointer;" onclick="cuStatDrill('exposure',${id})" title="Click for D1-D5 formula breakdown">
      <svg viewBox="0 0 60 60" width="56" height="56">
        <circle cx="30" cy="30" r="24" fill="none" stroke="var(--border)" stroke-width="5" opacity=".3"/>
        <circle cx="30" cy="30" r="24" fill="none" stroke="${riskColor}" stroke-width="5"
          stroke-dasharray="151" stroke-dashoffset="${151-(151*(Math.min(riskScore,100)/100))}" stroke-linecap="round"
          transform="rotate(-90 30 30)" style="filter:drop-shadow(0 0 4px ${riskColor});"/>
      </svg>
      <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;">
        <div class="mono" style="font-size:16px;font-weight:900;color:${riskColor};line-height:1;">${riskScore}</div>
        <div style="font-size:8px;color:var(--text4);">RISK</div>
      </div>
    </div>
  </div>`;
  // ═══ CUSTOMER ACTION TOOLBAR -  fancy grouped layout ═══
  const _domain=c.primary_domain||c.domain||'';
  h+=`<div style="margin-bottom:12px;padding:14px;border-radius:14px;background:linear-gradient(135deg,rgba(230,92,0,.05),rgba(0,137,123,.03));border:1.5px solid rgba(230,92,0,.12);box-shadow:0 0 20px rgba(230,92,0,.04);">
    <div style="display:flex;gap:6px;flex-wrap:wrap;">
      <div style="display:flex;gap:4px;padding:4px;border-radius:10px;background:rgba(0,137,123,.06);border:1px solid rgba(0,137,123,.1);">
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuDiscover(${id},'${_domain}')" title="Passive subdomain & service discovery">🔍 Discover</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuDiscoverExt(${id})" title="External asset discovery via Censys/CT logs">🌐 External</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuMatchIntel(${id})" title="Match global intel against customer assets">🔗 Match Intel</button>
      </div>
      <div style="display:flex;gap:4px;padding:4px;border-radius:10px;background:rgba(230,92,0,.06);border:1px solid rgba(230,92,0,.1);">
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuRecalcExposure(${id})" title="Recalculate D1-D5 exposure score">♻️ Rescore</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuRunAttribution(${id})" title="Run AI attribution engine">🧠 Attribute</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuRecorrelate(${id})" title="Re-correlate unmatched detections">🔄 Correlate</button>
      </div>
      <div style="display:flex;gap:4px;padding:4px;border-radius:10px;background:rgba(123,31,162,.06);border:1px solid rgba(123,31,162,.1);">
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="openTechStackModal(${id})" title="Add/edit technology stack">🔧 Tech Stack</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="openBulkAssetsModal(${id})" title="Bulk add assets">📦 Assets</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuOnboarding(${id})" title="Onboarding pipeline">📋 Onboard</button>
      </div>
      <div style="display:flex;gap:4px;padding:4px;border-radius:10px;background:rgba(21,101,192,.06);border:1px solid rgba(21,101,192,.1);">
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuTopThreats(${id})" title="View top threats">📊 Threats</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuExportCEF(${id})" title="Export in CEF format">📋 CEF</button>
        <button class="btn" style="font-size:11px;border:none;background:transparent;color:var(--text2);" onclick="cuNarrative(${id})" title="Generate AI narrative">📖 AI Story</button>
      </div>
    </div>
  </div>`;
  // ═══ BREACH BANNER (clickable) ═══
  if(breach?.confirmed_exposed||breach?.risk_label?.includes('BREACH')||breach?.risk_label?.includes('COMPROMISED'))
    h+=`<div class="breach-red" style="cursor:pointer;" onclick="this.querySelector('.bb-exp').classList.toggle('hidden')"><div class="ico">🚨</div><div style="flex:1;"><div class="font-bold text-red">${breach.risk_label||'CONFIRMED BREACH'}</div><div class="text-sm text-muted">${breach.evidence_count||0} evidence events · <span style="color:var(--text4);">click for details</span></div>
      <div class="bb-exp hidden" style="margin-top:8px;padding:10px;border-radius:8px;background:rgba(198,40,40,.06);font-size:12px;color:var(--text2);line-height:1.5;"><b>What this means:</b> ArgusWatch detected confirmed evidence of compromise across dark web sources. This includes credential dumps, stealer logs, paste site mentions, or ransomware claims matching this customer's registered assets. <b>Immediate action recommended</b> -  review the Findings tab for IOCs linked to the breach evidence.</div></div></div>`;
  else h+=`<div class="breach-green" style="cursor:pointer;" onclick="this.querySelector('.bb-exp').classList.toggle('hidden')"><div class="ico" style="font-size:24px;">🛡️</div><div style="flex:1;"><div class="font-bold text-green">${breach?.risk_label||'No Confirmed Exposure'}</div><div class="text-sm text-muted">Continuously monitored across 6 evidence sources · <span style="color:var(--text4);">click for details</span></div>
      <div class="bb-exp hidden" style="margin-top:8px;padding:10px;border-radius:8px;background:rgba(46,125,50,.06);font-size:12px;color:var(--text2);line-height:1.5;"><b>Evidence sources monitored:</b> (1) Dark web forums & markets, (2) Stealer log databases (HudsonRock), (3) Paste sites (Pastebin, paste.ee), (4) Ransomware leak sites, (5) Credential breach databases, (6) Telegram channels. No confirmed exposure means none of these sources contain active breach evidence for this customer's assets.</div></div></div>`;
  // ═══ PROGRESS BAR ═══
  if(completeness){const pct=completeness.completeness_pct||completeness.pct||0;
    h+=`<div class="mb-12" style="cursor:pointer;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')">
      <div class="text-xs text-muted mb-12" style="display:flex;align-items:center;gap:6px;">
        <span>Onboarding: ${c.onboarding_state||'active'} · ${Math.round(pct)}% complete</span>
        <span style="font-size:10px;color:var(--text4);">ⓘ click for details</span>
      </div>
      <div class="rem-progress"><div class="rem-progress-bar" style="width:${pct}%;background:linear-gradient(90deg,#e65c00,#00897b);"></div></div>
      <div class="dd-exp hidden" style="margin-top:8px;padding:10px 14px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-size:12px;color:var(--text2);line-height:1.5;">
        <div style="font-weight:700;margin-bottom:6px;">📋 Onboarding Progress: ${(c.onboarding_state||'active').toUpperCase()}</div>
        <div style="margin-bottom:6px;">Customers move through 5 stages: <b>Created -> Assets Added -> Monitoring -> Tuning -> Production</b></div>
        <div>Current: <b>${c.onboarding_state||'active'}</b> (${Math.round(pct)}%) -  ${
          c.onboarding_state==='created'?'Customer registered, awaiting asset configuration':
          c.onboarding_state==='assets_added'?'Assets registered, correlation engine starting first scan':
          c.onboarding_state==='monitoring'?'Active monitoring in progress, detections being ingested and attributed':
          c.onboarding_state==='tuning'?'False positive tuning, SLA calibration, analyst review':
          'Full production monitoring with SLA enforcement'
        }</div>
        <div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap;">
          ${['created','assets_added','monitoring','tuning','production'].map((s,i)=>{
            const states=['created','assets_added','monitoring','tuning','production'];
            const idx=states.indexOf(c.onboarding_state||'created');
            const done=i<=idx;
            return`<span style="padding:3px 8px;border-radius:12px;font-size:10px;font-weight:700;${done?'background:var(--green-g);color:var(--green);border:1px solid var(--green-b);':'background:var(--surface);color:var(--text4);border:1px solid var(--border);'}">${done?'✓':''} ${s.replace(/_/g,' ')}</span>`;
          }).join('')}
        </div>
      </div>
    </div>`;}
  // ═══ STATS ROW (CLICKABLE) ═══
  const _esColor=riskScore>=70?'var(--red)':riskScore>=40?'var(--amber)':riskScore>0?'var(--orange)':'var(--green)';
  const _custId=c.id;
  h+=`<div class="cu-stats">
    <div class="cu-stat" style="cursor:pointer;" onclick="cuStatDrill('assets',${_custId})" title="Click for asset breakdown">
      <div class="cu-stat-val mono" style="color:var(--cyan);">${c.asset_count||assets?.length||0}</div><div class="cu-stat-lbl">Assets</div>
    </div>
    <div class="cu-stat" style="cursor:pointer;" onclick="cuStatDrill('detections',${_custId})" title="Detections = raw IOC matches from collectors. Multiple detections for the same IOC merge into one finding.">
      <div class="cu-stat-val mono" style="color:var(--amber);">${c.detection_count||0}</div><div class="cu-stat-lbl">Detections <span style="font-size:10px;cursor:help;opacity:.5;" title="Raw collector hits -  click for Detections vs Findings explanation">ⓘ</span></div>
    </div>
    <div class="cu-stat" style="cursor:pointer;" onclick="cuStatDrill('findings',${_custId})" title="Click for finding breakdown">
      <div class="cu-stat-val mono" style="color:var(--orange);">${c.finding_count||0}</div><div class="cu-stat-lbl">Findings</div>
    </div>
    <div class="cu-stat" style="cursor:pointer;" onclick="cuStatDrill('critical',${_custId})" title="Click for critical items">
      <div class="cu-stat-val mono" style="color:var(--red);">${c.critical_count||0}</div><div class="cu-stat-lbl">Critical</div>
    </div>
    <div class="cu-stat" style="cursor:pointer;" onclick="cuStatDrill('exposure',${_custId})" title="Click for exposure formula">
      <div class="cu-stat-val mono" style="color:${_esColor};">${riskScore>0?riskScore.toFixed(1):' - '}</div><div class="cu-stat-lbl">Exposure</div>
    </div>
    <div class="cu-stat" style="cursor:pointer;" onclick="cuStatDrill('sla',${_custId})" title="Click for SLA details">
      <div class="cu-stat-val mono" style="color:var(--green);">${slaSt?.compliance_pct||slaSt?.met||'-'}%</div><div class="cu-stat-lbl">SLA</div>
    </div>
  </div>`;
  // ═══ TABS ═══
  const tabs=['📊 Coverage','🎯 Attribution','📡 Collection','⏱️ SLA','📈 Trend','📋 Summary','🗂️ Assets','🔍 Findings'];
  h+=`<div class="tabs">${tabs.map((t,i)=>`<div class="tab${i===0?' active':''}" onclick="cuTab(this,'cu-t-${i}')">${t}</div>`).join('')}</div>`;
  // Tab 0: Coverage heatmap (clickable categories with explanations)
  h+=`<div id="cu-t-0">`;
  const cats=cov?.categories||cov||[];
  const catArr=Array.isArray(cats)?cats:Object.entries(cats).map(([k,v])=>({name:k,...(typeof v==='object'?v:{count:v})}));
  const _catExplain={
    'Stolen Credentials':'Usernames + passwords from stealer logs, combo lists, and dark web markets. If detected, immediate password reset required.',
    'API Keys & Tokens':'Exposed API keys, AWS access keys, or tokens found in public repos or paste sites. Enables unauthorized access to cloud services.',
    'Network IOCs':'Suspicious IPs, C2 server addresses, and scanning infrastructure targeting your network ranges.',
    'Domain & URL IOCs':'Malicious URLs, phishing domains, and typosquatted domains impersonating your brand.',
    'Email IOCs':'Compromised email addresses from breach databases. Often the entry point for spearphishing campaigns.',
    'File & Hash IOCs':'Malware file hashes (SHA256/MD5) associated with campaigns targeting your industry.',
    'Infrastructure Leaks':'Exposed internal infrastructure like VPNs, admin panels, or debug endpoints found on the open internet.',
    'Financial & Identity':'SSNs, credit card numbers, or financial data linked to your organization on dark web markets.',
    'Threat Actor Intel':'Direct mentions by APT groups or ransomware gangs in their target lists or communications.',
    'Session & Auth Tokens':'Stolen session cookies or JWT tokens that allow attackers to bypass authentication.',
    'OAuth / SaaS Tokens':'Compromised OAuth tokens for SaaS platforms (Slack, GitHub, Jira) enabling lateral movement.',
    'SaaS Misconfiguration':'Publicly accessible SaaS instances (S3 buckets, Firebase DBs) with sensitive data exposure.',
    'Privileged Account Anomaly':'Admin or root account activity patterns indicating possible compromise or insider threat.',
    'Shadow IT Discovery':'Unauthorized applications, domains, or cloud services operated outside IT governance.',
    'Data Exfiltration':'Evidence of data being moved to external destinations -  paste sites, file shares, or Telegram.',
    'CVE':'Known vulnerabilities matched to your tech stack via NVD/CISA KEV. Feeds D2 (Active Exploitation).',
    'Crypto Addresses':'Cryptocurrency wallet addresses linked to ransomware payments or illicit transactions involving your data.'
  };
  const _catEmoji={'Stolen Credentials':'🔑','API Keys & Tokens':'🔐','Network IOCs':'🌐','Domain & URL IOCs':'🔗','Email IOCs':'📧','File & Hash IOCs':'#️⃣','Infrastructure Leaks':'🏗️','Financial & Identity':'💳','Threat Actor Intel':'🎭','Session & Auth Tokens':'🍪','OAuth / SaaS Tokens':'🔓','SaaS Misconfiguration':'☁️','Privileged Account Anomaly':'👑','Shadow IT Discovery':'👻','Data Exfiltration':'📤','CVE':'🛡️','Crypto Addresses':'₿'};
  const _catColor={'Stolen Credentials':'#c62828','API Keys & Tokens':'#e65100','Network IOCs':'#1565c0','Domain & URL IOCs':'#e65c00','Email IOCs':'#7b1fa2','File & Hash IOCs':'#00897b','Infrastructure Leaks':'#ef6c00','Financial & Identity':'#ad1457','Threat Actor Intel':'#c62828','Session & Auth Tokens':'#e65100','OAuth / SaaS Tokens':'#1565c0','SaaS Misconfiguration':'#00897b','Privileged Account Anomaly':'#c62828','Shadow IT Discovery':'#7b1fa2','Data Exfiltration':'#e65100','CVE':'#e65c00','Crypto Addresses':'#ef6c00'};
  h+=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;">${catArr.map((cat,ci)=>{
    const cnt=cat.detections||cat.detection_count||cat.count||0;
    const nm=cat.name||cat.category||'-';
    const emoji=_catEmoji[nm]||'📦';
    const col=_catColor[nm]||'var(--text2)';
    const explain=_catExplain[nm]||'Threat intelligence coverage category';
    const hc=cnt===0?'background:var(--surface);border-color:var(--border);':'background:'+col+'08;border-color:'+col+'25;';
    const catNum=cat.cat||ci+1;
    return`<div class="card" style="padding:12px;cursor:pointer;transition:all .25s;${hc}" onclick="drillCoverageCategory(${c.id},'${escHtml(nm)}','${emoji}','${col}',${catNum})" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 16px ${col}15'" onmouseout="this.style.transform='';this.style.boxShadow=''">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-size:20px;">${emoji}</span>
        <span style="font-size:12px;font-weight:700;color:var(--text);flex:1;">${nm}</span>
        <div style="text-align:right;"><span class="mono" style="font-size:22px;font-weight:900;color:${cnt?col:'var(--text4)'};text-shadow:${cnt?'0 0 10px '+col+'30':'none'};">${cnt}</span>
        ${cnt?`<div style="font-size:8px;color:var(--text4);font-weight:600;">IOCs</div>`:''}</div>
      </div>
      <div style="font-size:10px;color:${cnt?col:'var(--text4)'};font-weight:600;">${cnt?'click for details ->':'click for details ->'}</div>
    </div>`;}).join('')}</div></div>`;
  // Tab 1: Attribution bars
  const attrArr=Array.isArray(attr)?attr:attr?Object.entries(attr.strategies||attr).map(([k,v])=>({strategy:k,count:typeof v==='number'?v:v?.count||0})):[];
  const maxA=Math.max(...attrArr.map(e=>e.count||0),1);
  h+=`<div id="cu-t-1" class="hidden">${attrArr.map(s=>`<div class="cu-bar-row"><div class="cu-bar-lbl">${s.strategy}</div><div class="cu-bar-track"><div class="cu-bar-fill" style="width:${(s.count/maxA*100)}%;"></div></div><div class="cu-bar-val mono">${s.count}</div></div>`).join('')||'<div class="empty">No attribution data yet</div>'}</div>`;
  // Tab 2: Collection status with styled cards
  const colArr=colSt?Object.entries(typeof colSt==='object'?colSt:{}).map(([k,v])=>({name:k,...(typeof v==='object'?v:{status:v})})):[];
  h+=`<div id="cu-t-2" class="hidden">${colArr.length?colArr.map(c=>{
    const lr=c.last_run||c.last_collected;let health='dead';
    if(lr){const hrs=(Date.now()-new Date(lr).getTime())/3600000;if(hrs<6)health='active';else if(hrs<24)health='stale';}
    else if(c.active||c.status==='active')health='stale';
    return`<div class="cu-col-item">
      <div class="cu-col-dot ${health}"></div>
      <div class="cu-col-name">${c.name}</div>
      <div class="cu-col-ct">${c.ioc_count||c.count||0}</div>
      <div class="cu-col-time">${lr?ago(lr):'never'}</div>
    </div>`;}).join(''):'<div class="empty">Collection status loading...</div>'}</div>`;
  // Tab 3: SLA
  h+=`<div id="cu-t-3" class="hidden">${slaSt?`<div class="grid-3 mb-12"><div class="card" style="text-align:center;"><div class="stat-num green">${slaSt.compliance_pct||slaSt.met||0}%</div><div class="text-xs text-muted">Compliance</div></div><div class="card" style="text-align:center;"><div class="stat-num orange">${slaSt.breached||0}</div><div class="text-xs text-muted">Breached</div></div><div class="card" style="text-align:center;"><div class="stat-num cyan">${slaSt.open||slaSt.pending||0}</div><div class="text-xs text-muted">Open</div></div></div>`:'<div class="empty">SLA tracking active from first finding</div>'}</div>`;
  // Tab 4: Trend
  h+=`<div id="cu-t-4" class="hidden"><canvas id="cu-trend-c" height="200"></canvas></div>`;
  // Tab 5: Summary (render structured, never raw JSON)
  h+=`<div id="cu-t-5" class="hidden">`;
  if(summary){
    const s=typeof summary==='string'?{headline:summary}:summary;
    const riskLvl=(s.risk_level||'LOW').toUpperCase();
    const rlCol=riskLvl==='CRITICAL'?'#c62828':riskLvl==='HIGH'?'#e65100':riskLvl==='MEDIUM'?'#e65c00':'#2e7d32';
    const rlEmoji=riskLvl==='CRITICAL'?'🔴':riskLvl==='HIGH'?'🟠':riskLvl==='MEDIUM'?'🟡':'🟢';
    h+=`<div style="background:linear-gradient(135deg,${rlCol}05,${rlCol}02);border:1px solid ${rlCol}20;border-radius:14px;padding:20px;">`;
    h+=`<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
      <span style="font-size:24px;">🤖</span>
      <div style="flex:1;">
        <div style="font-size:16px;font-weight:800;color:var(--text);">AI Threat Summary</div>
        <div style="font-size:12px;color:var(--text3);">${s.customer||c.name||'-'} · ${s.industry||c.industry||'-'}</div>
      </div>
      <div style="display:flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;background:${rlCol}10;border:1px solid ${rlCol}25;">
        <span>${rlEmoji}</span>
        <span style="font-size:13px;font-weight:800;color:${rlCol};">${riskLvl}</span>
      </div>
    </div>`;
    // Headline
    if(s.headline)h+=`<div style="font-size:14px;color:var(--text);line-height:1.6;margin-bottom:14px;padding:12px 16px;background:var(--surface);border-radius:10px;border-left:3px solid ${rlCol};">${s.headline}</div>`;
    if(s.summary||s.narrative)h+=`<div style="font-size:14px;color:var(--text);line-height:1.6;margin-bottom:14px;padding:12px 16px;background:var(--surface);border-radius:10px;border-left:3px solid ${rlCol};">${s.summary||s.narrative}</div>`;
    // Stats row
    h+=`<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">`;
    if(s.total_open_detections!==undefined)h+=`<div style="flex:1;min-width:100px;text-align:center;padding:10px;border-radius:10px;background:var(--surface);"><div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:var(--cyan);">${s.total_open_detections}</div><div style="font-size:11px;color:var(--text4);text-transform:uppercase;font-weight:700;">Open Detections</div></div>`;
    if(s.exposure!==null&&s.exposure!==undefined){let _ev=0;if(typeof s.exposure==='number'){_ev=s.exposure;}else if(typeof s.exposure==='object'&&s.exposure!==null){_ev=s.exposure.score||s.exposure.overall_score||s.exposure.exposure_score||s.exposure.value||0;}else{_ev=parseFloat(s.exposure)||0;}h+=`<div style="flex:1;min-width:100px;text-align:center;padding:10px;border-radius:10px;background:var(--surface);"><div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${rlCol};">${typeof _ev==='number'&&_ev>0?_ev.toFixed(1):' - '}</div><div style="font-size:11px;color:var(--text4);text-transform:uppercase;font-weight:700;">Exposure Score</div></div>`;}
    h+=`</div>`;
    // Severity breakdown
    const sevBk=s.severity_breakdown||{};
    if(Object.keys(sevBk).length){
      h+=`<div style="margin-bottom:14px;"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">Severity Breakdown</div><div style="display:flex;gap:8px;flex-wrap:wrap;">`;
      const sevColors2={CRITICAL:'#c62828',HIGH:'#e65100',MEDIUM:'#e65c00',LOW:'#2e7d32'};
      Object.entries(sevBk).forEach(([k,v])=>{h+=`<div style="padding:8px 14px;border-radius:10px;background:${sevColors2[k]||'var(--surface)'}08;border:1px solid ${sevColors2[k]||'var(--border)'}25;text-align:center;min-width:80px;"><div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:${sevColors2[k]||'var(--text)'};">${v}</div><div style="font-size:10px;color:var(--text4);font-weight:700;">${k}</div></div>`;});
      h+=`</div></div>`;
    }
    // Top IOC types
    const topTypes=s.top_ioc_types||[];
    if(topTypes.length){h+=`<div style="margin-bottom:14px;"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:6px;">Top IOC Types</div><div style="display:flex;gap:6px;flex-wrap:wrap;">${topTypes.map(t=>`<span style="padding:4px 10px;border-radius:16px;font-size:12px;font-weight:600;background:var(--orange-g);border:1px solid var(--orange-b);color:var(--orange);cursor:pointer;transition:all .2s;" onmouseover="this.style.transform='scale(1.05)';this.style.boxShadow='0 2px 8px rgba(230,92,0,.15)'" onmouseout="this.style.transform='';this.style.boxShadow=''" onclick="cuStatDrill('findings',${id})">${typeof t==='object'?(t.type||t.name)+' ('+t.count+')':t}</span>`).join('')}</div></div>`;}
    // Top sources
    const topSrc=s.top_sources||[];
    if(topSrc.length){h+=`<div style="margin-bottom:14px;"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:6px;">Top Sources</div><div style="display:flex;gap:6px;flex-wrap:wrap;">${topSrc.map(t=>`<span style="padding:4px 10px;border-radius:16px;font-size:12px;font-weight:600;background:var(--cyan-g);border:1px solid var(--cyan-b);color:var(--cyan);cursor:pointer;transition:all .2s;" onmouseover="this.style.transform='scale(1.05)';this.style.boxShadow='0 2px 8px rgba(0,188,212,.15)'" onmouseout="this.style.transform='';this.style.boxShadow=''" onclick="cuStatDrill('detections',${id})">${typeof t==='object'?(t.source||t.name)+' ('+t.count+')':t}</span>`).join('')}</div></div>`;}
    // Critical items
    const critItems=s.critical_items||[];
    if(critItems.length){h+=`<div style="margin-bottom:14px;"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--red);margin-bottom:6px;">🚨 Critical Items -  click to view findings</div>${critItems.map(ci=>{
      const val=typeof ci==='object'?(ci.ioc_value||ci.value||JSON.stringify(ci)):ci;
      return`<div style="padding:8px 12px;border-radius:8px;border:1px solid #c6282825;background:#c6282808;margin-bottom:4px;font-size:13px;cursor:pointer;transition:all .2s;" onmouseover="this.style.borderColor='#c6282850';this.style.boxShadow='0 2px 8px rgba(198,40,40,.1)'" onmouseout="this.style.borderColor='#c6282825';this.style.boxShadow=''" onclick="cuStatDrill('critical',${id})"><span style="font-family:'JetBrains Mono';color:#c62828;font-weight:700;">${val}</span> <span style="font-size:11px;color:var(--text4);margin-left:6px;">-> view</span></div>`;}).join('')}</div>`;}
    // No data state
    if(!s.headline&&!s.summary&&!s.narrative&&!Object.keys(sevBk).length&&!topTypes.length)
      h+=`<div style="text-align:center;padding:20px;color:var(--text4);"><div style="font-size:32px;margin-bottom:8px;">🛡️</div><div style="font-size:14px;font-weight:600;">No Active Threats Detected</div><div style="font-size:12px;margin-top:4px;">This customer is being continuously monitored across all collectors. Findings will appear here when IOCs match registered assets.</div></div>`;
    h+=`</div>`;
  }else{h+=`<div class="empty" style="padding:30px;text-align:center;"><div style="font-size:32px;margin-bottom:8px;">🤖</div><div style="font-size:14px;">AI summary generates after findings are attributed</div></div>`;}
  h+=`</div>`;
  // Tab 6: Assets (grouped by type)
  const assetList=assets?.assets||assets||[];
  const _aEmoji={'domain':'🏷️','ip':'🌐','cidr':'📡','email_domain':'📧','brand_name':'✨','keyword':'🔍','tech_stack':'⚙️','github_org':'💻','cloud_asset':'☁️','subdomain':'🔗','exec_name':'👤','org_name':'🏢','email':'📧'};
  const _aColor={'domain':'#e65c00','ip':'#c62828','cidr':'#1565c0','email_domain':'#7b1fa2','brand_name':'#e65100','keyword':'#00897b','tech_stack':'#ef6c00','github_org':'#2e7d32','cloud_asset':'#1565c0','subdomain':'#e65c00','exec_name':'#c62828','org_name':'#00897b'};
  const _aExplain={'domain':'Primary domains monitored for typosquatting & phishing','ip':'IP addresses matched against C2 and reputation feeds','cidr':'Network ranges for bulk IOC matching','email_domain':'Email domains for breach monitoring','brand_name':'Brand keywords for look-alike domain detection','keyword':'Dark web search terms','tech_stack':'Software for CVE->product matching (feeds D2)','github_org':'GitHub org for code leak detection','cloud_asset':'Cloud resources for exposure scanning','subdomain':'Discovered subdomains expanding attack surface','exec_name':'VIP names for targeted phishing detection','org_name':'Organization name for dark web mentions'};
  // Group assets by type
  const assetByType={};
  assetList.forEach(a=>{const t=a.asset_type||(a.type?a.type:'other');if(!assetByType[t])assetByType[t]=[];assetByType[t].push(a);});
  const typeKeys=Object.keys(assetByType).sort((a,b)=>{const order=['domain','email_domain','brand_name','keyword','ip','cidr','tech_stack','subdomain','github_org','cloud_asset','exec_name','org_name'];return(order.indexOf(a)===-1?99:order.indexOf(a))-(order.indexOf(b)===-1?99:order.indexOf(b));});
  h+=`<div id="cu-t-6" class="hidden"><div class="mb-12 flex gap-8"><input id="new-asset-val" class="btn" placeholder="Value (e.g. 10.0.0.0/24)" style="flex:1;text-align:left;"><select id="new-asset-type" class="btn"><option>domain</option><option>ip</option><option>cidr</option><option>email_domain</option><option>brand_name</option><option>keyword</option><option>tech_stack</option><option>github_org</option><option>cloud_asset</option></select><button class="btn pri" onclick="addAsset(${id})">+ Add</button></div>`;
  if(typeKeys.length){
    typeKeys.forEach(t=>{
      const items=assetByType[t];
      const emoji=_aEmoji[t]||'📦';
      const col=_aColor[t]||'var(--text2)';
      const explain=_aExplain[t]||'Asset type for threat correlation';
      const collapsed=items.length>6;
      h+=`<div style="margin-bottom:12px;border:1px solid var(--border);border-radius:12px;overflow:hidden;">
        <div style="display:flex;align-items:center;gap:10px;padding:12px 14px;background:${col}05;border-bottom:1px solid var(--border);cursor:pointer;" onclick="const b=this.nextElementSibling;b.style.display=b.style.display==='none'?'':'none';this.querySelector('.chevron').textContent=b.style.display==='none'?'▸':'▾'">
          <span style="font-size:18px;">${emoji}</span>
          <span style="font-size:14px;font-weight:800;color:var(--text);flex:1;text-transform:uppercase;letter-spacing:.5px;">${t.replace(/_/g,' ')}</span>
          <span style="font-size:13px;font-weight:900;font-family:'JetBrains Mono';color:${col};padding:2px 10px;border-radius:12px;background:${col}10;">${items.length}</span>
          <span class="chevron" style="color:var(--text4);font-size:12px;">▾</span>
        </div>
        <div style="padding:10px 14px;">
          <div style="font-size:11px;color:var(--text4);margin-bottom:8px;line-height:1.4;">${explain}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;${collapsed?'max-height:120px;overflow-y:auto;':''}">
            ${items.map(a=>{
              const val=a.asset_value||a.value||'-';
              const hits=a.ioc_hit_count||0;
              return`<div style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:8px;background:${col}06;border:1px solid ${col}15;font-size:12px;transition:all .2s;" onmouseover="this.style.borderColor='${col}40'" onmouseout="this.style.borderColor='${col}15'">
                <span style="font-family:'JetBrains Mono';font-weight:600;color:var(--text);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${val}">${val}</span>
                ${hits?`<span style="font-size:10px;font-weight:700;padding:1px 5px;border-radius:6px;background:${col}15;color:${col};">${hits} hits</span>`:''}
                <span style="cursor:pointer;color:var(--text4);font-size:11px;" onclick="event.stopPropagation();delAsset(${id},${a.id})" title="Remove">✕</span>
              </div>`;}).join('')}
          </div>
        </div>
      </div>`;
    });
  }else{h+=`<div class="empty">No assets. Add domains, IPs, keywords to start matching.</div>`;}
  h+=`</div>`;
  // Tab 7: Findings (lazy)
  h+=`<div id="cu-t-7" class="hidden"><div class="loading">Loading...</div></div>`;
  document.getElementById('mc-body').innerHTML=h;openM('m-customer');
  loadCuFindings(id);
  const trendItems=trend?.trend||trend||[];
  if(trendItems.length>1){setTimeout(()=>{const ctx=document.getElementById('cu-trend-c');
    if(ctx)new Chart(ctx,{type:'line',data:{labels:trendItems.map(t=>t.date||''),datasets:[{label:'Exposure',data:trendItems.map(t=>t.score||0),borderColor:'#e65c00',backgroundColor:'rgba(230,92,0,.08)',fill:true,tension:.4}]},options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{min:0,max:100,ticks:{color:'#8c7a65'}},x:{ticks:{color:'#8c7a65'}}}}});},100);}
}
function cuTab(el,tabId){el.parentElement.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');
  document.querySelectorAll('[id^="cu-t-"]').forEach(t=>t.classList.add('hidden'));document.getElementById(tabId)?.classList.remove('hidden');}
async function loadCuFindings(cid, filterSev){
  const data=await api('/api/findings?customer_id='+cid+'&limit=50');let items=data?.findings||data||[];
  // Sort by severity: CRITICAL -> HIGH -> MEDIUM -> LOW
  const sevOrder={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  items.sort((a,b)=>(sevOrder[(a.severity||'').toUpperCase()]??9)-(sevOrder[(b.severity||'').toUpperCase()]??9));
  // Optional severity filter
  if(filterSev){items=items.filter(f=>(f.severity||'').toUpperCase()===filterSev.toUpperCase());}
  document.getElementById('cu-t-7').innerHTML=items.length?`<div style="max-height:400px;overflow-y:auto;">${items.map(f=>{
    const sl=(f.severity||'').toLowerCase();const sevCls=sl==='critical'?'crit':sl==='high'?'high':sl==='medium'?'med':'low';
    return`<div class="cu-fi-item" onclick="closeM('m-customer');openFi(${f.id})">
      <div class="cu-fi-sev ${sevCls}"></div>
      <div class="cu-fi-body">
        <div class="cu-fi-top">
          <span class="fi-pill sev-${sevCls}">${(f.severity||'?').toUpperCase()}</span>
          <span class="cu-fi-ioc" title="${f.ioc_value||''}">${f.ioc_value||'-'}</span>
          <span class="fi-pill type">${f.ioc_type||'-'}</span>
          <span class="fi-pill st-${(f.status||'open').toLowerCase()}">${(f.status||'open').replace('_',' ')}</span>
        </div>
        <div class="cu-fi-meta"><span>📡 ${f.source||'-'}</span><span>🕐 ${ago(f.created_at)}</span></div>
      </div>
    </div>`;}).join('')}</div>`:'<div class="empty">No findings yet</div>';
}
async function addAsset(cid){
  const val=document.getElementById('new-asset-val')?.value;const type=document.getElementById('new-asset-type')?.value;
  if(!val){toast('Enter asset value','error');return;}
  await apiPost('/api/customers/'+cid+'/assets',{asset_type:type,value:val});toast('Asset added');openCu(cid);
}
async function delAsset(cid,aid){await apiDel('/api/customers/'+cid+'/assets/'+aid);toast('Asset removed');openCu(cid);}
async function delCustomer(cid,name){
  let h=`<div style="text-align:center;padding:10px;">
    <div style="font-size:48px;margin-bottom:12px;">⚠️</div>
    <div style="font-size:18px;font-weight:800;color:#c62828;margin-bottom:8px;">Delete ${escHtml(name)}?</div>
    <div style="font-size:13px;color:var(--text2);line-height:1.6;margin-bottom:16px;">This will <b>permanently remove</b> all data for this customer:</div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:20px;text-align:center;">
      <div style="padding:8px;border-radius:10px;background:rgba(198,40,40,.04);border:1px solid rgba(198,40,40,.1);"><div style="font-size:18px;">📡</div><div style="font-size:11px;color:#c62828;font-weight:700;">Detections</div></div>
      <div style="padding:8px;border-radius:10px;background:rgba(198,40,40,.04);border:1px solid rgba(198,40,40,.1);"><div style="font-size:18px;">🎯</div><div style="font-size:11px;color:#c62828;font-weight:700;">Findings</div></div>
      <div style="padding:8px;border-radius:10px;background:rgba(198,40,40,.04);border:1px solid rgba(198,40,40,.1);"><div style="font-size:18px;">🗂️</div><div style="font-size:11px;color:#c62828;font-weight:700;">Assets</div></div>
      <div style="padding:8px;border-radius:10px;background:rgba(198,40,40,.04);border:1px solid rgba(198,40,40,.1);"><div style="font-size:18px;">📈</div><div style="font-size:11px;color:#c62828;font-weight:700;">Exposure</div></div>
      <div style="padding:8px;border-radius:10px;background:rgba(198,40,40,.04);border:1px solid rgba(198,40,40,.1);"><div style="font-size:18px;">🌑</div><div style="font-size:11px;color:#c62828;font-weight:700;">Dark Web</div></div>
      <div style="padding:8px;border-radius:10px;background:rgba(198,40,40,.04);border:1px solid rgba(198,40,40,.1);"><div style="font-size:18px;">⚔️</div><div style="font-size:11px;color:#c62828;font-weight:700;">Campaigns</div></div>
    </div>
    <div style="padding:10px 14px;border-radius:10px;background:rgba(198,40,40,.06);border:1px solid rgba(198,40,40,.15);margin-bottom:16px;font-size:12px;color:#c62828;font-weight:600;">
      ⛔ This action cannot be undone. Type the customer name to confirm.
    </div>
    <input id="del-confirm-input" placeholder="Type '${escHtml(name)}' to confirm" style="width:100%;padding:10px 14px;border:2px solid rgba(198,40,40,.2);border-radius:10px;font-size:14px;text-align:center;outline:none;font-family:inherit;margin-bottom:12px;" oninput="document.getElementById('del-confirm-btn').disabled=this.value!=='${escHtml(name)}';document.getElementById('del-confirm-btn').style.opacity=this.value==='${escHtml(name)}'?'1':'.4'" onfocus="this.style.borderColor='#c62828'" onblur="this.style.borderColor='rgba(198,40,40,.2)'">
    <div style="display:flex;gap:10px;justify-content:center;">
      <button class="btn" style="padding:10px 24px;font-size:14px;" onclick="closeM('m-drilldown')">Cancel</button>
      <button id="del-confirm-btn" class="btn" style="padding:10px 24px;font-size:14px;background:rgba(198,40,40,.08);color:#c62828;border-color:rgba(198,40,40,.3);opacity:.4;font-weight:700;" disabled onclick="executeDeleteCustomer(${cid},'${escHtml(name)}')">🗑️ Delete Permanently</button>
    </div>
  </div>`;
  showDrilldown('⚠️ Delete Customer',h);
}
async function executeDeleteCustomer(cid,name){
  closeM('m-drilldown');
  toast('Deleting '+name+'...','info');
  try{
    const r=await fetch('/api/customers/'+cid,{method:'DELETE',headers:{'Content-Type':'application/json','Authorization':'Bearer '+(_authToken||'')}});
    console.log('Delete response status:',r.status);
    const text=await r.text();
    console.log('Delete response body:',text);
    let data=null;
    try{data=JSON.parse(text);}catch(e){}
    if(r.ok&&data&&data.deleted){
      toast(name+' deleted permanently','success');
      closeM('m-customer');
      // Force refresh both pages
      setTimeout(()=>{loadCust();loadExp();},500);
    } else {
      const err=data?.detail||data?.error||text||r.statusText||'Unknown error';
      toast('Delete failed: '+err,'error');
      console.error('Delete failed:',r.status,text);
    }
  }catch(e){
    toast('Delete network error: '+e.message,'error');
    console.error('Delete exception:',e);
  }
}

// ═══ ONBOARD - POST /api/customers/onboard (V16.4.6: validated) ═══
function obValidateLive(){
  const name=(document.getElementById('ob-name').value||'').trim();
  const domain=(document.getElementById('ob-domain').value||'').trim().toLowerCase();
  const btn=document.getElementById('ob-submit-btn');
  const hint=document.getElementById('ob-domain-hint');
  const warn=document.getElementById('ob-warnings');
  let warnings=[];
  
  // Basic checks
  const ok=name.length>=2 && domain.length>=4 && domain.includes('.');
  btn.disabled=!ok; btn.style.opacity=ok?'1':'.5';
  
  if(!domain){hint.innerHTML='';warn.style.display='none';return;}
  
  // Format check
  if(domain.includes(' ')){hint.innerHTML='<span style="color:var(--red);">⚠ Domain cannot contain spaces</span>';btn.disabled=true;btn.style.opacity='.5';return;}
  if(!domain.match(/^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$/)){hint.innerHTML='<span style="color:var(--orange);">⚠ Check format -  expected: company.com</span>';
  }else{hint.innerHTML='<span style="color:var(--green);">✓ Valid format</span>';}
  
  // Name-domain mismatch check (mirrors backend)
  if(name.length>=3 && domain.length>=4){
    const dRoot=domain.replace('www.','').split('.')[0];
    const nameWords=name.toLowerCase().match(/[a-z0-9]{3,}/g)||[];
    const nameConcat=nameWords.join('');
    const acronym=nameWords.length>=2?nameWords.map(w=>w[0]).join(''):'';
    const match=nameWords.some(w=>dRoot.includes(w)||w.includes(dRoot))
      ||dRoot.includes(nameConcat)||nameConcat.includes(dRoot)
      ||(acronym&&(acronym===dRoot||dRoot.startsWith(acronym)));
    if(!match){
      warnings.push('⚠️ <b>Domain mismatch:</b> "'+name+'" and "'+domain+'" don\'t appear related. Double-check the domain is correct.');
    }
  }
  
  if(warnings.length){warn.innerHTML=warnings.join('<br>');warn.style.display='block';}
  else{warn.style.display='none';}
}
function obBackToStep1(){
  document.getElementById('ob-step1').style.display='block';
  document.getElementById('ob-step2').style.display='none';
}
async function doOnboard(confirm=false){
  const name=document.getElementById('ob-name').value.trim();
  const domain=document.getElementById('ob-domain').value.trim().toLowerCase();
  const email=document.getElementById('ob-email').value.trim();
  const industry=document.getElementById('ob-industry').value;
  if(!name||!domain){toast('Name and domain required','error');return;}
  
  const status=document.getElementById('ob-status');
  status.innerHTML='<span style="color:var(--blue);">⏳ Onboarding... recon + correlation may take 30-90s for large domains</span>';
  document.getElementById('ob-submit-btn').disabled=true;
  
  const body={name,domain,email,industry};
  if(confirm)body.confirm=true;
  
  // Use longer timeout for onboard (recon can be slow for large domains)
  let r;
  try{
    const ctrl=new AbortController();const tid=setTimeout(()=>ctrl.abort(),120000); // 2 min timeout
    const resp=await fetch('/api/customers/onboard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:ctrl.signal});
    clearTimeout(tid);
    r=await resp.json();
  }catch(e){
    if(e.name==='AbortError'){
      status.innerHTML='<span style="color:var(--amber);">⏱️ Onboard is running in background (large domain). Check Customers page in 1-2 minutes.</span>';
      document.getElementById('ob-submit-btn').disabled=false;
      return;
    }
    r={error:'Connection failed',detail:e.message};
  }
  
  if(r&&r.error==='Domain mismatch'){
    // Show confirmation step
    document.getElementById('ob-step1').style.display='none';
    document.getElementById('ob-step2').style.display='block';
    document.getElementById('ob-confirm-msg').innerHTML=
      '<b>⚠️ Domain Mismatch Detected</b><br><br>'+
      (r.detail||'Company name and domain don\'t match.')+'<br><br>'+
      '<b>Common causes:</b> typo in domain, subsidiary with different name, acquired company.<br>'+
      'If this is correct, click "Proceed Anyway" to continue.';
    status.innerHTML='';
    document.getElementById('ob-submit-btn').disabled=false;
    return;
  }
  if(r&&r.error==='Domain does not resolve'){
    document.getElementById('ob-step1').style.display='none';
    document.getElementById('ob-step2').style.display='block';
    document.getElementById('ob-confirm-msg').innerHTML=
      '<b>⚠️ Domain Not Found</b><br><br>'+
      (r.detail||'This domain has no DNS records.')+'<br><br>'+
      '<b>Common causes:</b> typo, internal-only domain, domain expired.<br>'+
      'If this is an internal domain, click "Proceed Anyway."';
    status.innerHTML='';
    document.getElementById('ob-submit-btn').disabled=false;
    return;
  }
  if(r&&r.customer_id&&!r.error){
    const findings=r.intel_match?.total_matches||r.findings_promoted||r.finding_count||0;
    const assets=r.assets_auto_registered?.length||0;
    const tech=r.tech_stack_defaults?.length||0;
    const recon=r.recon?.assets_discovered||0;
    // Show success state in modal before closing
    status.innerHTML=`<div style="padding:16px;border-radius:12px;background:rgba(40,167,69,.08);border:2px solid rgba(40,167,69,.3);text-align:center;margin-top:12px;">
      <div style="font-size:32px;margin-bottom:8px;">✅</div>
      <div style="font-size:16px;font-weight:800;color:#28a745;margin-bottom:6px;">${name} Onboarded Successfully!</div>
      <div style="display:flex;gap:16px;justify-content:center;margin-top:10px;">
        <div style="text-align:center;"><div style="font-size:20px;font-weight:800;color:var(--text);">${findings}</div><div style="font-size:10px;color:var(--text3);">Findings</div></div>
        <div style="text-align:center;"><div style="font-size:20px;font-weight:800;color:var(--text);">${assets+recon}</div><div style="font-size:10px;color:var(--text3);">Assets</div></div>
        <div style="text-align:center;"><div style="font-size:20px;font-weight:800;color:var(--text);">${tech}</div><div style="font-size:10px;color:var(--text3);">Tech Stack</div></div>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:8px;">Redirecting to customer page...</div>
    </div>`;
    document.getElementById('ob-submit-btn').style.display='none';
    toast(name+' onboarded! '+findings+' findings, '+(assets+recon)+' assets','success');
    // Auto-close after 2.5s and navigate
    setTimeout(()=>{
      closeM('m-onboard');
      document.getElementById('ob-name').value='';document.getElementById('ob-domain').value='';
      document.getElementById('ob-email').value='';document.getElementById('ob-warnings').style.display='none';
      document.getElementById('ob-domain-hint').innerHTML='';document.getElementById('ob-submit-btn').style.display='';
      document.getElementById('ob-submit-btn').disabled=false;obBackToStep1();
      go('customers');
    },2500);
  }else if(r&&r.error){
    toast(r.error+': '+(r.detail||(r.details||[]).join(', ')),'error');
    status.innerHTML='<span style="color:var(--red);">'+r.error+'</span>';
    document.getElementById('ob-submit-btn').disabled=false;
  }else{
    const msg=r?.detail||r?.error||r?.message||'Unknown error -  check browser console (F12)';
    toast('Onboard failed: '+msg,'error');
    status.innerHTML='<span style="color:var(--red);">'+msg+'</span>';
    document.getElementById('ob-submit-btn').disabled=false;
  }
}

// ═══ CUSTOMER ACTIONS -  wiring unwired endpoints ═══
async function cuDiscover(cid,domain){
  if(!domain){toast('No domain registered','error');return;}
  toast('🔍 Running passive discovery on '+domain+'...');
  const [r1,r2]=await Promise.all([api('/api/discover/'+encodeURIComponent(domain)),apiPost('/api/customers/'+cid+'/discover')]);
  const r=r1||r2;
  if(r){toast('Discovery found '+(r.subdomains?.length||r.count||Object.keys(r).length)+' results','success');}
  else{toast('Discovery returned no data');}
}
async function cuMatchIntel(cid){
  toast('🔗 Matching threat intel for customer #'+cid+'...');
  const r=await apiPost('/api/match-intel/'+cid);
  if(r){toast('Matched '+(r.new_findings||r.matches||r.total_matches||0)+' findings','success');}
  else{toast('Intel match complete');}
}
async function cuRecalcExposure(cid){
  toast('♻️ Recalculating exposure scores...');
  const r=await apiPost('/api/exposure/recalculate',{customer_id:cid});
  if(r){toast('Exposure recalculated: '+(r.score?.toFixed(1)||r.status||'done'),'success');}
  else{toast('Recalculation sent');}
}
async function cuTopThreats(cid){
  toast('📊 Loading top threats...');
  const r=await api('/api/exposure/customer/'+cid);
  if(r&&r.top_threats){
    const threats=r.top_threats.slice(0,5).map(t=>`• ${t.actor_name||t.threat||'-'}: ${(t.score||t.exposure_score||0).toFixed(1)}`).join('\n');
    showDrilldown('📊 Top Threats -  Customer #'+cid,`<pre style="font-family:'JetBrains Mono';font-size:13px;color:var(--text);padding:16px;white-space:pre-wrap;">${threats||'No threat exposure data yet'}</pre>`);
  }else{toast('No threat data available');}
}
async function cuRunAttribution(cid){
  toast('🧠 Running attribution engine...');
  const r=await apiPost('/api/attribution/run',{customer_id:cid});
  if(r){toast('Attribution: '+(r.attributed||r.count||r.status||'complete'),'success');}
  else{toast('Attribution engine triggered');}
}
async function cuExportCEF(cid){
  toast('📋 Exporting CEF...');
  // Get first detection for this customer to export
  const dets=await api('/api/detections/?customer_id='+cid+'&limit=1');
  const items=dets?.items||dets||[];
  if(items.length>0){
    const r=await apiPost('/api/export/cef/'+items[0].id);
    if(r){toast('CEF export: '+(r.cef_line?'1 event':'done'),'success');}
  }else{toast('No detections to export','error');}
}
async function enrichDetection(detId){
  toast('🔬 Enriching detection #'+detId+'...');
  const r=await apiPost('/api/attribution/enrich-detection/'+detId);
  if(r){toast('Enrichment: '+(r.attribution||r.status||'done'),'success');}
  else{toast('Enrichment triggered');}
}
async function patchDetStatus(detId,newStatus){
  const r=await fetch('/api/detections/'+detId+'/status',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:newStatus})}).then(r=>r.json()).catch(()=>null);
  if(r&&!r.error){toast('Detection -> '+newStatus,'success');loadD();}else{toast('Update failed','error');}
}

// ═══ DETECTION DETAIL MODAL (V16.4.6) ═══
async function openDetDetail(detId){
  const d=await api('/api/detections/'+detId);
  if(!d||d.error){toast('Detection not found','error');return;}
  const sev=d.severity||'MEDIUM';
  const sevC={'CRITICAL':'#c62828','HIGH':'#e65100','MEDIUM':'#f9a825','LOW':'#2e7d32','INFO':'#9e9e9e'}[sev]||'#e65100';
  const meta=d.metadata||{};
  const extLinks=[];
  if(d.ioc_type==='cve_id'){
    extLinks.push({icon:'🏛️',label:'NVD',url:'https://nvd.nist.gov/vuln/detail/'+d.ioc_value});
    extLinks.push({icon:'🔴',label:'CISA KEV',url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'});
  }
  if(d.ioc_type==='domain'||d.ioc_type==='url'){
    extLinks.push({icon:'🔍',label:'VirusTotal',url:'https://www.virustotal.com/gui/domain/'+encodeURIComponent((d.ioc_value||'').replace(/https?:\/\//,'').split('/')[0])});
    extLinks.push({icon:'🌐',label:'URLScan',url:'https://urlscan.io/search/#'+encodeURIComponent(d.ioc_value)});
  }
  if(d.ioc_type==='ipv4'){
    extLinks.push({icon:'🔍',label:'VirusTotal',url:'https://www.virustotal.com/gui/ip-address/'+d.ioc_value});
    extLinks.push({icon:'🛡️',label:'AbuseIPDB',url:'https://www.abuseipdb.com/check/'+d.ioc_value});
    extLinks.push({icon:'📡',label:'Shodan',url:'https://internetdb.shodan.io/'+d.ioc_value});
  }
  if(d.ioc_type==='hash_sha256'){
    extLinks.push({icon:'🔍',label:'VirusTotal',url:'https://www.virustotal.com/gui/file/'+d.ioc_value});
    extLinks.push({icon:'🦠',label:'MalwareBazaar',url:'https://bazaar.abuse.ch/sample/'+d.ioc_value});
  }
  if(d.source==='grep_app') extLinks.push({icon:'🔎',label:'grep.app',url:'https://grep.app/search?q='+encodeURIComponent((d.ioc_value||'').substring(0,50))});
  if(d.source==='github_gist') extLinks.push({icon:'🐙',label:'GitHub Gists',url:'https://gist.github.com/search?q='+encodeURIComponent((d.ioc_value||'').substring(0,30))});
  if(d.source==='crtsh'){const dom=(d.ioc_value||'').split('.').slice(-2).join('.');extLinks.push({icon:'📜',label:'crt.sh',url:'https://crt.sh/?q=%25.'+dom});}
  if(d.source==='openphish') extLinks.push({icon:'🎣',label:'OpenPhish',url:'https://openphish.com/'});
  if(d.source==='urlhaus') extLinks.push({icon:'🔗',label:'URLhaus',url:'https://urlhaus.abuse.ch/browse.php?search='+encodeURIComponent(d.ioc_value)});
  if(d.source==='abuse_ch'||d.source==='feodo') extLinks.push({icon:'🛡️',label:'Abuse.ch',url:'https://feodotracker.abuse.ch/browse/host/'+d.ioc_value+'/'});
  if(d.source==='ransomwatch') extLinks.push({icon:'🔴',label:'Ransomwatch',url:'https://ransomwatch.telemetry.lt/'});
  if(!extLinks.find(l=>l.label==='VirusTotal')&&d.ioc_value) extLinks.push({icon:'🔍',label:'VirusTotal',url:'https://www.virustotal.com/gui/search/'+encodeURIComponent(d.ioc_value)});

  let h=`<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px;">
    <div style="padding:6px 14px;border-radius:10px;font-size:13px;font-weight:800;background:${sevC}15;color:${sevC};border:1px solid ${sevC}30;">${sev}</div>
    <div style="flex:1;">
      <div style="font-size:11px;color:var(--text4);text-transform:uppercase;font-weight:700;">Detection #${d.id} · ${d.ioc_type}</div>
      <div style="font-size:16px;font-weight:800;font-family:'JetBrains Mono';color:var(--text);word-break:break-all;">${escHtml(d.ioc_value||'-')}</div>
    </div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
    <div style="padding:6px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-size:12px;">📡 <b>${d.source||'-'}</b></div>
    <div style="padding:6px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-size:12px;">📊 Conf: <b>${d.confidence?.toFixed(2)||'?'}</b></div>
    <div style="padding:6px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-size:12px;">⏱️ SLA: <b>${d.sla_hours||'-'}h</b></div>
    ${d.customer_id?`<div style="padding:6px 12px;border-radius:8px;background:rgba(0,137,123,.06);border:1px solid rgba(0,137,123,.15);font-size:12px;color:var(--cyan);cursor:pointer;" onclick="closeM('m-drilldown');openCu(${d.customer_id})">🏢 Customer -></div>`:''}
    ${d.finding_id?`<div style="padding:6px 12px;border-radius:8px;background:rgba(230,92,0,.06);border:1px solid rgba(230,92,0,.15);font-size:12px;color:var(--orange);cursor:pointer;" onclick="closeM('m-drilldown');openFi(${d.finding_id})">🎯 Finding #${d.finding_id} -></div>`:''}
  </div>`;
  h+=`<div style="margin-bottom:14px;"><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--orange);margin-bottom:6px;letter-spacing:1px;">📋 Raw Intelligence (Source Evidence)</div>
    <div style="padding:14px;border-radius:10px;background:#1a1a2e;color:#e0e0e0;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;max-height:250px;overflow-y:auto;border:1px solid #333;">${escHtml(d.raw_text||'No raw text available')}</div></div>`;
  if(d.matched_asset||d.correlation_type){
    h+=`<div style="padding:12px;border-radius:10px;background:rgba(0,137,123,.04);border:1px solid rgba(0,137,123,.12);margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--cyan);margin-bottom:6px;">🔗 Correlation</div>
      <div style="font-size:13px;color:var(--text);">Matched via <b>${(d.correlation_type||'').replace(/_/g,' ')}</b> against <code style="background:var(--surface);padding:2px 6px;border-radius:4px;">${escHtml(d.matched_asset||'-')}</code></div>
      ${d.source_count>1?`<div style="margin-top:4px;font-size:12px;color:var(--green);font-weight:700;">✓ ${d.source_count} independent sources</div>`:''}
    </div>`;
  }
  if(meta&&Object.keys(meta).length){
    h+=`<div style="margin-bottom:14px;"><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:6px;">📦 Metadata</div>
      <div style="padding:10px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-family:'JetBrains Mono';font-size:11px;max-height:120px;overflow-y:auto;white-space:pre-wrap;">${escHtml(JSON.stringify(meta,null,2))}</div></div>`;
  }
  if(extLinks.length){
    h+=`<div style="margin-bottom:14px;"><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--orange);margin-bottom:8px;letter-spacing:1px;">🔗 Verify Externally</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${extLinks.map(l=>`<a href="${l.url}" target="_blank" rel="noopener" style="display:flex;align-items:center;gap:6px;padding:8px 14px;border-radius:10px;background:var(--surface);border:1px solid var(--border);text-decoration:none;color:var(--text);font-size:12px;font-weight:600;transition:all .2s;" onmouseover="this.style.borderColor='var(--cyan)'" onmouseout="this.style.borderColor='var(--border)'">${l.icon} ${l.label} ↗</a>`).join('')}
      </div></div>`;
  }
  h+=`<div style="display:flex;gap:8px;font-size:11px;color:var(--text4);border-top:1px solid var(--border);padding-top:10px;">
    <span>Created: ${d.created_at?new Date(d.created_at).toLocaleString():'-'}</span>
    ${d.first_seen?'<span>First: '+new Date(d.first_seen).toLocaleString()+'</span>':''}
    ${d.last_seen?'<span>Last: '+new Date(d.last_seen).toLocaleString()+'</span>':''}
  </div>
  <div style="display:flex;gap:8px;margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
    <button class="btn pri" style="font-size:12px;" onclick="enrichDetection(${d.id})">🔬 Enrich</button>
    <button class="btn" style="font-size:12px;" onclick="patchDetStatus(${d.id},'resolved');closeM('m-drilldown')">✓ Resolve</button>
    <button class="btn" style="font-size:12px;" onclick="apiPost('/api/export/cef/${d.id}').then(r=>toast(r?'CEF sent':'Failed',r?'success':'error'))">📋 CEF</button>
    <button class="btn" style="font-size:12px;" onclick="cuExportSTIXDet(${d.id})">📦 STIX</button>
  </div>`;
  showDrilldown('📡 Detection #'+d.id+' · '+d.ioc_type,h);
}
async function batchEnrich(){
  toast('🔬 Running batch enrichment...');
  const r=await apiPost('/api/enrich/batch');
  if(r){toast('Batch enriched '+(r.enriched||r.count||0)+' IOCs','success');}
  else{toast('Batch enrichment sent');}
}
async function loadDiscoveryInfo(){
  const [schema,providers]=await Promise.all([api('/api/discovery/agent-schema'),api('/api/discovery/providers')]);
  return {schema,providers};
}
async function triggerEnterprise(sourceId){
  toast('▶ Triggering '+sourceId+'...');
  const r=await apiPost('/api/enterprise/'+encodeURIComponent(sourceId)+'/trigger');
  if(r){toast(sourceId+' collection triggered','success');}
  else{toast(sourceId+' trigger sent');}
}
async function createRemed(findingId){
  const title=prompt('Remediation description (e.g. "Reset credentials", "Block IP"):');
  if(!title)return;
  // Get finding to get detection_id
  const f=await api('/api/findings/'+findingId);
  if(!f||!f.detection_id){toast('No detection linked to this finding','error');return;}
  toast('Creating remediation...');
  const r=await apiPost('/api/finding-remediations/create',{finding_id:findingId,action_type:'manual',title:title});
  if(r&&!r.error){toast('Remediation created','success');openFi(findingId);}
  else{toast('Failed: '+(r?.detail||r?.error||'unknown'),'error');}
}
async function patchRemedStatus(remId,status,findingId){
  if(findingId){
    const r=await apiPatch('/api/findings/'+findingId+'/remediations/'+remId+'?status='+status);
    if(r){toast('Remediation -> '+status,'success');return;}
  }
  toast('Update failed -  no finding linked','error');
}
async function patchRemed(remId,findingId){
  if(findingId) openRemDetail(remId);
  else toast('No finding linked','error');
}


// ═══ WIRING: 12 previously unwired endpoints ═══
async function cuTechStack(cid){
  const stack=prompt('Enter tech stack (comma-separated, e.g. nginx,wordpress,aws):');
  if(!stack)return;
  toast('Scanning tech stack...');
  const r=await apiPost('/api/customers/'+cid+'/tech-stack',{technologies:stack.split(',').map(s=>s.trim())});
  if(r){toast('Tech stack: '+(r.findings_created||r.count||r.status||'scanned'),'success');}
  else{toast('Tech stack scan sent');}
}
function openTechStackModal(cid){
  const commonTech=['nginx','apache','wordpress','java','python','nodejs','react','angular','docker','kubernetes','aws','azure','gcp','oracle','mysql','postgresql','mongodb','redis','elasticsearch','php','ruby','go','spring','django','flask','tomcat','iis','exchange','sharepoint','salesforce','sap','fortinet','paloalto','cisco','juniper','f5','citrix','vmware','jenkins','gitlab','jira','confluence','slack','okta','duo'];
  let h=`<div style="padding:4px;">
    <div style="font-size:13px;color:var(--text2);margin-bottom:12px;">Select technologies this customer uses. This enables CVE->product matching via NVD CPE data.</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;" id="ts-chips">
      ${commonTech.map(t=>`<button style="padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;transition:all .2s;" onclick="this.classList.toggle('ts-sel');this.style.background=this.classList.contains('ts-sel')?'rgba(0,137,123,.12)':'var(--surface)';this.style.borderColor=this.classList.contains('ts-sel')?'rgba(0,137,123,.3)':'';this.style.color=this.classList.contains('ts-sel')?'#00897b':'var(--text2)'">${t}</button>`).join('')}
    </div>
    <div style="margin-bottom:12px;">
      <div style="font-size:11px;font-weight:700;color:var(--text3);margin-bottom:4px;">Or type custom (comma-separated):</div>
      <input id="ts-custom" style="width:100%;padding:10px 14px;border:1.5px solid var(--border);border-radius:10px;font-size:13px;background:var(--surface);color:var(--text);outline:none;font-family:inherit;" placeholder="e.g. custom-app, internal-tool, proprietary-db" onfocus="this.style.borderColor='rgba(0,137,123,.4)'" onblur="this.style.borderColor='var(--border)'">
    </div>
    <button class="btn pri" style="width:100%;padding:10px;font-size:14px;" onclick="submitTechStack(${cid})">🔧 Scan & Match CVEs</button>
  </div>`;
  showDrilldown('🔧 Tech Stack -  CVE/CPE Matching',h);
}
async function submitTechStack(cid){
  const chips=[...document.querySelectorAll('.ts-sel')].map(b=>b.textContent.trim());
  const custom=(document.getElementById('ts-custom')?.value||'').split(',').map(s=>s.trim()).filter(Boolean);
  const all=[...new Set([...chips,...custom])];
  if(!all.length){toast('Select at least one technology','error');return;}
  closeM('m-drilldown');
  toast('Scanning '+all.length+' technologies...');
  const r=await apiPost('/api/customers/'+cid+'/tech-stack',{technologies:all});
  if(r){toast('Tech stack scanned: '+(r.findings_created||r.assets_added||r.status||'done'),'success');openCu(cid);}
  else{toast('Tech stack scan sent');}
}
function openBulkAssetsModal(cid){
  const assetTypes=['domain','subdomain','ip','cidr','email_domain','tech_stack','brand_name','exec_name','keyword','github_org','cloud_asset','internal_domain'];
  let h=`<div style="padding:4px;">
    <div style="font-size:13px;color:var(--text2);margin-bottom:12px;">Add multiple assets at once. One per line, format: <code style="background:var(--surface);padding:2px 6px;border-radius:4px;">type:value</code></div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px;">
      ${assetTypes.map(t=>`<span style="padding:2px 8px;border-radius:8px;font-size:10px;background:rgba(0,137,123,.06);color:var(--cyan);border:1px solid rgba(0,137,123,.12);cursor:pointer;" onclick="document.getElementById('ba-input').value+='${t}:\\n';document.getElementById('ba-input').focus()" title="Click to add">${t}</span>`).join('')}
    </div>
    <textarea id="ba-input" rows="8" style="width:100%;padding:12px 14px;border:1.5px solid var(--border);border-radius:10px;font-size:13px;font-family:'JetBrains Mono',monospace;background:var(--surface);color:var(--text);outline:none;resize:vertical;" placeholder="domain:example.com\nip:10.0.0.1\ntech_stack:nginx\nemail_domain:example.com\nbrand_name:Acme Corp\nexec_name:John Smith" onfocus="this.style.borderColor='rgba(0,137,123,.4)'" onblur="this.style.borderColor='var(--border)'"></textarea>
    <div style="margin-top:10px;display:flex;gap:8px;">
      <button class="btn pri" style="flex:1;padding:10px;font-size:14px;" onclick="submitBulkAssets(${cid})">📦 Add Assets</button>
      <button class="btn" style="padding:10px 16px;font-size:12px;" onclick="document.getElementById('ba-input').value='domain:\\nip:\\ntech_stack:\\nemail_domain:\\n'">📋 Template</button>
    </div>
  </div>`;
  showDrilldown('📦 Bulk Asset Import',h);
}
async function submitBulkAssets(cid){
  const input=document.getElementById('ba-input')?.value||'';
  const assets=input.split('\n').filter(l=>l.includes(':')).map(l=>{const [t,...v]=l.split(':');return{asset_type:t.trim(),value:v.join(':').trim()};}).filter(a=>a.value);
  if(!assets.length){toast('No valid assets -  use format type:value','error');return;}
  closeM('m-drilldown');
  toast('Adding '+assets.length+' assets...');
  const r=await apiPost('/api/customers/'+cid+'/assets/bulk',{assets});
  if(r){toast('Added '+(r.created||r.count||assets.length)+' assets','success');openCu(cid);}
  else{toast('Bulk add failed','error');}
}
async function cuRecorrelate(cid){
  toast('🔄 Re-correlating findings...');
  const r=await apiPost('/api/customers/'+cid+'/recorrelate');
  if(r){toast('Re-correlation: '+(r.correlated||r.new_findings||r.status||'done'),'success');}
  else{toast('Re-correlation triggered');}
}
async function cuOnboarding(cid){
  const ob=await api('/api/customers/'+cid+'/onboarding');
  if(!ob){toast('No onboarding data');return;}
  const states=['created','assets_added','monitoring','tuning','production'];
  const cur=ob.state||ob.onboarding_state||'created';
  const idx=states.indexOf(cur);
  const h=`<div style="padding:16px;">
    <div style="font-weight:800;margin-bottom:12px;">📋 Onboarding State: ${cur.toUpperCase()}</div>
    <div style="display:flex;gap:4px;margin-bottom:16px;">${states.map((s,i)=>
      `<div style="flex:1;padding:6px;text-align:center;border-radius:6px;font-size:11px;font-weight:700;background:${i<=idx?'rgba(0,137,123,.15)':'var(--surface)'};color:${i<=idx?'var(--green)':'var(--text4)'};">${s}</div>`
    ).join('')}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      ${states.map(s=>`<button class="btn" style="font-size:11px;" onclick="patchOnboarding(${cid},'${s}')">${s}</button>`).join('')}
    </div>
  </div>`;
  showDrilldown('📋 Customer Onboarding',h);
}
async function patchOnboarding(cid,state){
  const r=await fetch('/api/customers/'+cid+'/onboarding',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({state:state})}).then(r=>r.json()).catch(()=>null);
  if(r&&!r.error){toast('Onboarding -> '+state,'success');}else{toast('Update failed','error');}
}
async function cuDiscoverExt(cid){
  toast('🌐 Running external discovery...');
  const r=await apiPost('/api/customers/'+cid+'/discover/external');
  if(r){toast('External discovery: '+(r.discovered||r.count||r.status||'done'),'success');}
  else{toast('External discovery triggered');}
}
async function cuBulkAssets(cid){openBulkAssetsModal(cid);}
async function cuDeleteAsset(cid,assetId,name){
  if(!confirm('Delete asset '+name+'?'))return;
  const r=await fetch('/api/customers/'+cid+'/assets/'+assetId,{method:'DELETE'}).then(r=>({ok:true})).catch(()=>null);
  if(r){toast('Asset deleted','success');openCu(cid);}else{toast('Delete failed','error');}
}
async function cuNarrative(cid){
  toast('📖 Loading AI narrative...');
  const r=await api('/api/customers/'+cid+'/narrative');
  if(r&&(r.narrative||r.summary)){
    showDrilldown('📖 AI Threat Narrative',`<div style="padding:16px;font-size:14px;line-height:1.7;color:var(--text);">${r.narrative||r.summary||'No narrative generated yet'}</div>`);
  }else{toast('No narrative available');}
}
async function cuExportSTIXDet(detId){
  const r=await api('/api/export/stix/'+detId);
  if(r){showDrilldown('📦 STIX Bundle',`<pre style="padding:16px;font-size:12px;white-space:pre-wrap;max-height:500px;overflow:auto;">${JSON.stringify(r,null,2)}</pre>`);}
  else{toast('STIX export failed','error');}
}
async function cuPatchFindingRem(findingId,remId,data){
  const r=await fetch('/api/findings/'+findingId+'/remediations/'+remId,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(r=>r.json()).catch(()=>null);
  if(r&&!r.error){toast('Remediation updated','success');}else{toast('Update failed','error');}
}
async function deleteAIKey(provider){
  if(!confirm('Delete '+provider+' API key?'))return;
  const r=await fetch('/api/settings/ai-keys/'+provider,{method:'DELETE'}).then(r=>r.json()).catch(()=>null);
  if(r&&!r.error){toast(provider+' key deleted','success');loadSet();}else{toast('Delete failed','error');}
}

// ═══ REPORTS - POST /api/reports/generate/{cid}, GET /api/reports/download/{name} ═══
async function loadRep(){
  if(!_customers.length)_customers=await api('/api/customers')||[];
  const items=Array.isArray(_customers)?_customers:(_customers?.customers||[]);
  document.getElementById('rep-list').innerHTML=items.map(c=>{
    const fc=c.finding_count||0;const dc=c.detection_count||0;const es=c.exposure_score||0;
    const esCol=es>=70?'#c62828':es>=40?'#e65100':es>0?'#e65c00':'#2e7d32';
    return`<div class="rep-card" style="padding:16px;gap:14px;">
      <div class="rep-icon" style="font-size:28px;">📄</div>
      <div class="rep-info" style="flex:1;">
        <div class="rep-name" style="font-size:15px;font-weight:800;">${c.name||'-'}</div>
        <div class="rep-sub">${c.primary_domain||''} · ${c.industry||'-'}</div>
        <div style="display:flex;gap:8px;margin-top:6px;">
          <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(0,188,212,.08);color:var(--cyan);">${dc} detections</span>
          <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;background:rgba(230,92,0,.08);color:var(--orange);">${fc} findings</span>
          <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;background:${esCol}08;color:${esCol};">${es>0?es.toFixed(1):' - '} exposure</span>
        </div>
      </div>
      <div class="rep-actions" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
        <button class="btn" style="font-size:12px;" onclick="exportSIEM(${c.id},'${c.name}')">📤 SIEM</button>
        <button class="btn" style="font-size:12px;" onclick="exportSTIXCust(${c.id},'${c.name}')">📦 STIX</button>
        <button class="btn pri" style="font-size:12px;" onclick="genReport(${c.id},'${c.name}')">📄 PDF</button>
      </div>
      <div id="rep-status-${c.id}" style="display:none;width:100%;margin-top:6px;"></div>
    </div>`;}).join('')||'<div class="empty">Onboard customers first</div>';
}
async function genReport(cid,name){
  const el=document.getElementById('rep-status-'+cid);
  if(el){el.style.display='block';el.innerHTML=`<div style="display:flex;align-items:center;gap:6px;padding:8px 12px;border-radius:8px;background:rgba(230,92,0,.04);border:1px solid rgba(230,92,0,.15);"><span class="loading-spin" style="display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span><span style="font-size:12px;color:var(--text2);">Generating PDF report for ${name||'customer'}...</span></div>`;}
  toast('Generating PDF report...');
  const r=await apiPost('/api/reports/generate/'+cid);
  if(r&&!r.error&&r.file_name){
    if(el){el.innerHTML=`<div style="padding:8px 12px;border-radius:8px;background:rgba(46,125,50,.06);border:1px solid rgba(46,125,50,.2);display:flex;align-items:center;gap:8px;"><span style="color:var(--green);font-weight:700;">✓</span><span style="font-size:12px;color:var(--text2);flex:1;">Report ready</span><a href="/api/reports/download/${r.file_name}" target="_blank" style="font-size:12px;font-weight:700;color:#e65c00;text-decoration:none;padding:4px 12px;border-radius:8px;background:rgba(230,92,0,.08);border:1px solid rgba(230,92,0,.15);">⬇ Download PDF</a></div>`;}
    toast('PDF report generated!','success');
  }else{
    const err=r?.error||r?.detail||'PDF generation requires the reporting engine. Check that weasyprint/reportlab is installed.';
    if(el){el.innerHTML=`<div style="padding:8px 12px;border-radius:8px;background:rgba(198,40,40,.06);border:1px solid rgba(198,40,40,.2);font-size:12px;color:var(--text2);"><span style="color:#c62828;font-weight:700;">⚠</span> ${err}</div>`;}
    toast('Report generation: '+err,'error');
  }
}
async function exportSIEM(cid,name){
  toast('Exporting SIEM format for '+name+'...');
  const r=await apiPost('/api/export/siem',{customer_id:cid});
  const el=document.getElementById('rep-status-'+cid);
  if(r&&!r.error){
    toast('SIEM export complete','success');
    if(el){el.style.display='block';el.innerHTML=`<div style="padding:8px 12px;border-radius:8px;background:rgba(46,125,50,.06);border:1px solid rgba(46,125,50,.2);font-size:12px;color:var(--text2);"><span style="color:var(--green);font-weight:700;">✓</span> SIEM CEF export complete -  ${r.count||r.exported||'?'} events</div>`;}
  }else{toast('SIEM export failed','error');}
}
async function exportSTIXCust(cid,name){
  toast('Exporting STIX bundle for '+name+'...');
  const r=await apiPost('/api/export/stix',{customer_id:cid});
  const el=document.getElementById('rep-status-'+cid);
  if(r&&!r.error){
    toast('STIX export complete','success');
    if(el){el.style.display='block';el.innerHTML=`<div style="padding:8px 12px;border-radius:8px;background:rgba(46,125,50,.06);border:1px solid rgba(46,125,50,.2);font-size:12px;color:var(--text2);"><span style="color:var(--green);font-weight:700;">✓</span> STIX 2.1 bundle exported -  ${r.object_count||r.count||'?'} objects</div>`;}
  }else{toast('STIX export failed','error');}
}

// ═══ SETTINGS - /api/settings/ai, /api/settings/ai-keys, /api/settings/active-provider, /api/collectors/status, /api/enterprise/status, /api/fp-patterns/stats ═══
// ═══ OLD REMEDIATIONS - redirected to finding-remediations ═══
async function loadRemediations(){loadRemPage();}
async function createRemediation(){createRemediationGlobal();}
async function toggleRemStatus(id,newStatus){
  // Find the finding_id from _remData
  const rem=_remData.find(r=>r.id===id);
  if(rem)toggleFindingRemStatus(rem.finding_id,id,newStatus);
  else toast('Remediation not found','error');
}
async function updateRemediation(id){openRemDetail(id);}
async function deleteUser(username){if(!confirm('Delete user '+username+'?'))return;const r=await fetch('/api/auth/users/'+username,{method:'DELETE'}).then(r=>r.json()).catch(()=>null);toast(r?'Deleted':'Failed',r?'success':'error');}

// ═══ REMEDIATIONS PAGE (V16.4.6) ═══
let _remFilter='all';
let _remData=[];
// filterRem moved below -  enhanced version with no_playbook support
function renderRemGrid(){
  let items=_remData;
  const now=new Date();
  if(_remFilter==='overdue')items=items.filter(r=>r.status!=='completed'&&r.deadline&&new Date(r.deadline)<now);
  else if(_remFilter!=='all')items=items.filter(r=>r.status===_remFilter);
  
  const grid=document.getElementById('rem-grid');
  if(!items.length){grid.innerHTML='<div class="empty">No remediation actions match this filter</div>';return;}
  grid.innerHTML='<div class="grid-2">'+items.map(r=>{
    const st=r.status||'pending';
    const stCol=st==='completed'?'var(--green)':st==='in_progress'?'var(--cyan)':'var(--amber)';
    const overdue=r.deadline&&new Date(r.deadline)<now&&st!=='completed';
    const slaStr=r.sla_hours?r.sla_hours+'h SLA':'';
    const deadStr=r.deadline?new Date(r.deadline).toLocaleString():'';
    const custStr=r.customer_name?'<span class="tag" style="font-size:10px;">'+r.customer_name+'</span>':'';
    const sevStr=r.severity?'<span class="tag" style="font-size:10px;">'+r.severity+'</span>':'';
    const iocStr=r.ioc_value?'<div class="mono text-xs" style="margin:4px 0;word-break:break-all;opacity:.7;">'+r.ioc_value.substring(0,80)+'</div>':'';
    const sevC={'CRITICAL':'#c62828','HIGH':'#e65100','MEDIUM':'#f9a825','LOW':'#2e7d32'}[(r.severity||'').toUpperCase()]||'var(--amber)';
    return`<div class="card" style="padding:14px;cursor:pointer;transition:all .2s;${overdue?'border-left:3px solid var(--red);':'border-left:3px solid '+sevC+';'}" onclick="openRemDetail(${r.id})" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 16px rgba(0,0,0,.08)'" onmouseout="this.style.transform='';this.style.boxShadow=''">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span class="font-bold" style="font-size:14px;">${r.title||r.action_type||'Remediation #'+r.id}</span>
        <span class="tag" style="background:${stCol}22;color:${stCol};font-size:11px;">${overdue?'🚨 OVERDUE ':''}${st}</span>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:4px;">${custStr}${sevStr}<span class="text-xs text-muted">${r.playbook_key||''}</span><span class="text-xs text-muted">${r.assigned_role?'-> '+r.assigned_role:''}</span></div>
      ${iocStr}
      ${r.steps_technical&&r.steps_technical.length?'<div style="font-size:12px;margin:6px 0;padding:8px;background:rgba(100,160,255,.05);border-radius:6px;max-height:60px;overflow:hidden;">'+r.steps_technical.slice(0,2).map(s=>'• '+s).join('<br>')+(r.steps_technical.length>2?'<br><span class="text-muted">+'+(r.steps_technical.length-2)+' more...</span>':'')+'</div>':''}
      <div style="display:flex;gap:6px;align-items:center;margin-top:8px;">
        <span class="text-xs text-muted">${slaStr} ${deadStr?'· Due: '+deadStr:''}</span>
        <span style="margin-left:auto;font-size:10px;color:var(--orange);font-weight:700;">details -></span>
      </div>
    </div>`;
  }).join('')+'</div>';
}
async function loadRemPage(){
  const [r,stats]=await Promise.all([api('/api/finding-remediations/'),api('/api/finding-remediations/stats')]);
  _remData=r?.items||r||[];
  const now=new Date();
  const pending=_remData.filter(r=>r.status==='pending').length;
  const inprog=_remData.filter(r=>r.status==='in_progress').length;
  const done=_remData.filter(r=>r.status==='completed').length;
  const overdue=_remData.filter(r=>r.status!=='completed'&&r.deadline&&new Date(r.deadline)<now).length;
  document.getElementById('rem-stats').innerHTML=
    `<div class="stat orange"><div class="stat-num orange">${pending}</div><div class="stat-lbl">Pending</div></div>
    <div class="stat cyan"><div class="stat-num cyan">${inprog}</div><div class="stat-lbl">In Progress</div></div>
    <div class="stat green"><div class="stat-num green">${done}</div><div class="stat-lbl">Completed</div></div>
    <div class="stat red"><div class="stat-num red">${overdue}</div><div class="stat-lbl">Overdue</div></div>`;
  renderRemGrid();
}
function openRemDetail(remId){
  const r=_remData.find(x=>x.id===remId);
  if(!r){toast('Remediation not found','error');return;}
  const st=r.status||'pending';
  const stCol=st==='completed'?'#2e7d32':st==='in_progress'?'#0097a7':'#e65c00';
  const sevC={'CRITICAL':'#c62828','HIGH':'#e65100','MEDIUM':'#f9a825','LOW':'#2e7d32'}[(r.severity||'').toUpperCase()]||'#e65100';
  const now=new Date();
  const overdue=r.deadline&&new Date(r.deadline)<now&&st!=='completed';
  let h=`<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px;">
    <div style="width:48px;height:48px;border-radius:12px;background:${stCol}10;display:flex;align-items:center;justify-content:center;font-size:24px;border:2px solid ${stCol}30;">${st==='completed'?'✅':st==='in_progress'?'🔄':'⏳'}</div>
    <div style="flex:1;">
      <div style="font-size:16px;font-weight:800;color:var(--text);">${r.title||r.action_type||'Remediation #'+r.id}</div>
      <div style="font-size:12px;color:var(--text3);margin-top:2px;">${r.playbook_key||'manual'} · ${r.assigned_role||'unassigned'} · ${r.action_type||'-'}</div>
    </div>
    <div style="padding:6px 14px;border-radius:10px;font-size:12px;font-weight:800;background:${stCol}15;color:${stCol};border:1px solid ${stCol}30;">${overdue?'🚨 OVERDUE':''}${st.toUpperCase()}</div>
  </div>`;
  // Customer + severity + IOC
  h+=`<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
    ${r.customer_name?`<div style="padding:6px 12px;border-radius:8px;background:rgba(0,137,123,.06);border:1px solid rgba(0,137,123,.15);font-size:12px;color:var(--cyan);">🏢 ${r.customer_name}</div>`:''}
    ${r.severity?`<div style="padding:6px 12px;border-radius:8px;background:${sevC}10;border:1px solid ${sevC}30;font-size:12px;font-weight:700;color:${sevC};">${r.severity}</div>`:''}
    ${r.sla_hours?`<div style="padding:6px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-size:12px;">⏱️ ${r.sla_hours}h SLA</div>`:''}
    ${r.deadline?`<div style="padding:6px 12px;border-radius:8px;background:${overdue?'rgba(220,38,38,.06)':'var(--surface)'};border:1px solid ${overdue?'rgba(220,38,38,.2)':'var(--border)'};font-size:12px;${overdue?'color:#c62828;font-weight:700;':''}">📅 Due: ${new Date(r.deadline).toLocaleString()}</div>`:''}
    ${r.finding_id?`<div style="padding:6px 12px;border-radius:8px;background:rgba(230,92,0,.06);border:1px solid rgba(230,92,0,.15);font-size:12px;color:var(--orange);cursor:pointer;" onclick="closeM('m-drilldown');openFi(${r.finding_id})">🎯 Finding #${r.finding_id} -></div>`:''}
  </div>`;
  // IOC value
  if(r.ioc_value){
    h+=`<div style="margin-bottom:14px;padding:10px 14px;border-radius:10px;background:#1a1a2e;border:1px solid #333;">
      <div style="font-size:10px;color:#888;text-transform:uppercase;margin-bottom:4px;">IOC Value</div>
      <div style="font-family:'JetBrains Mono';font-size:13px;color:#e0e0e0;word-break:break-all;">${escHtml(r.ioc_value)}</div>
      ${r.ioc_type?`<div style="font-size:10px;color:#888;margin-top:4px;">Type: ${r.ioc_type}</div>`:''}
    </div>`;
  }
  // Technical steps
  if(r.steps_technical&&r.steps_technical.length){
    h+=`<div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--orange);margin-bottom:8px;letter-spacing:1px;">🔧 Technical Response Steps (${r.steps_technical.length})</div>`;
    r.steps_technical.forEach((s,i)=>{
      h+=`<div style="display:flex;gap:10px;padding:10px 12px;margin-bottom:4px;border-radius:8px;background:rgba(230,92,0,.03);border:1px solid rgba(230,92,0,.08);">
        <div style="width:24px;height:24px;border-radius:8px;background:var(--orange);color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;flex-shrink:0;">${i+1}</div>
        <div style="font-size:13px;color:var(--text);line-height:1.5;">${escHtml(s)}</div>
      </div>`;
    });
    h+=`</div>`;
  }
  // Governance steps
  if(r.steps_governance&&r.steps_governance.length){
    h+=`<div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#7b1fa2;margin-bottom:8px;letter-spacing:1px;">📋 Governance Steps</div>`;
    r.steps_governance.forEach((s,i)=>{
      h+=`<div style="padding:8px 12px;margin-bottom:3px;border-radius:8px;background:rgba(123,31,162,.03);border:1px solid rgba(123,31,162,.08);font-size:12px;color:var(--text);">${i+1}. ${escHtml(s)}</div>`;
    });
    h+=`</div>`;
  }
  // Evidence required
  if(r.evidence_required&&r.evidence_required.length){
    h+=`<div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#1565c0;margin-bottom:8px;letter-spacing:1px;">📎 Evidence Required</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${r.evidence_required.map(e=>`<span style="padding:4px 10px;border-radius:8px;background:rgba(21,101,192,.06);border:1px solid rgba(21,101,192,.12);font-size:12px;color:#1565c0;">${escHtml(e)}</span>`).join('')}
      </div></div>`;
  }
  // Action buttons
  h+=`<div style="display:flex;gap:8px;margin-top:16px;padding-top:16px;border-top:1px solid var(--border);flex-wrap:wrap;">
    ${st==='pending'?`<button class="btn pri" style="font-size:12px;" onclick="toggleFindingRemStatus(${r.finding_id},${r.id},'in_progress');closeM('m-drilldown');setTimeout(loadRemPage,500)">▶ Start Working</button>`:''}
    ${st==='in_progress'?`<button class="btn pri" style="font-size:12px;background:linear-gradient(135deg,#2e7d32,#43a047);" onclick="toggleFindingRemStatus(${r.finding_id},${r.id},'completed');closeM('m-drilldown');setTimeout(loadRemPage,500)">✅ Mark Complete</button>`:''}
    ${st==='completed'?`<button class="btn" style="font-size:12px;" onclick="toggleFindingRemStatus(${r.finding_id},${r.id},'pending');closeM('m-drilldown');setTimeout(loadRemPage,500)">↩ Reopen</button>`:''}
    ${r.finding_id?`<button class="btn" style="font-size:12px;" onclick="closeM('m-drilldown');openFi(${r.finding_id})">🎯 View Finding</button>`:''}
    <button class="btn" style="font-size:12px;" onclick="remAiRegen(${r.finding_id||0},${r.id})">🤖 AI Regenerate</button>
    <button class="btn" style="font-size:12px;" onclick="remVerifyFix(${r.id},'${escHtml(r.ioc_value||'')}','${r.ioc_type||''}')">✅ Verify Fix</button>
    <button class="btn" style="font-size:12px;" onclick="remShowCompliance('${r.ioc_type||''}','${r.playbook_key||''}')">📋 Compliance Map</button>
  </div>`;
  showDrilldown('🔧 Remediation #'+r.id,h);
}
async function createRemediationGlobal(){
  // Show inline form in drilldown instead of ugly browser prompt
  let h=`<div style="padding:8px 0;">
    <div style="margin-bottom:14px;">
      <label style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;display:block;margin-bottom:6px;">Title *</label>
      <input id="rem-new-title" style="width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-size:14px;box-sizing:border-box;" placeholder="e.g. Reset compromised credentials for Starbucks">
    </div>
    <div style="margin-bottom:14px;">
      <label style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;display:block;margin-bottom:6px;">Description</label>
      <textarea id="rem-new-desc" rows="3" style="width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-size:13px;box-sizing:border-box;resize:vertical;" placeholder="Optional details about what needs to be done"></textarea>
    </div>
    <div style="display:flex;gap:8px;">
      <button class="btn pri" style="flex:1;" onclick="submitNewRemediation()">🔧 Create Remediation</button>
      <button class="btn" onclick="closeM('m-drilldown')">Cancel</button>
    </div>
  </div>`;
  showDrilldown('🔧 Create New Remediation',h);
  setTimeout(()=>document.getElementById('rem-new-title')?.focus(),100);
}
async function submitNewRemediation(){
  const title=document.getElementById('rem-new-title')?.value?.trim();
  const desc=document.getElementById('rem-new-desc')?.value?.trim();
  if(!title){toast('Title is required','error');return;}
  const r=await apiPost('/api/finding-remediations/create',{title,description:desc||'',action_type:'manual',status:'pending'});
  if(r&&!r.error){toast('Remediation created','success');closeM('m-drilldown');loadRemPage();}
  else{toast('Failed: '+(r?.error||r?.detail||'unknown'),'error');}
}
async function toggleFindingRemStatus(findingId,remId,newStatus){
  await fetch('/api/findings/'+findingId+'/remediations/'+remId,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:newStatus})}).then(r=>r.json()).catch(()=>null);
  toast(newStatus==='completed'?'Remediation completed':'Status updated');
}

// ═══ AI-AGENTIC REMEDIATION FUNCTIONS ═══

// AI Regenerate -  asks LLM to write fresh remediation steps for a finding
async function remAiRegen(findingId,remId){
  if(!findingId){toast('No finding linked to this remediation','error');return;}
  showDrilldown('🤖 AI Regenerating Remediation...','<div style="text-align:center;padding:30px;"><span class="loading-spin" style="display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span> AI writing specific remediation steps...</div>');
  const r=await apiPost('/api/ai-remediation-regen',{finding_id:findingId,limit:1});
  if(r?.regenerated>0||r?.results?.length){
    toast('AI remediation regenerated');
    setTimeout(()=>{loadRemPage();closeM('m-drilldown');},500);
  }else{
    showDrilldown('🤖 AI Regeneration','<div style="padding:16px;color:var(--text2);">AI could not generate remediation. LLM may be offline or finding data insufficient.<br><br>Result: '+(r?.error||JSON.stringify(r))+'</div>');
  }
}

// Verify Fix -  re-runs enrichment on the IOC to check if it's still active/exposed
async function remVerifyFix(remId,iocValue,iocType){
  if(!iocValue){toast('No IOC value to verify','error');return;}
  showDrilldown('✅ Verifying Fix...','<div style="text-align:center;padding:30px;"><span class="loading-spin" style="display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:#2e7d32;border-radius:50%;animation:spin .6s linear infinite;"></span> Re-checking IOC against enrichment sources...</div>');
  // Use the AI Bar compromise check to verify
  try{
    const r=await fetch('/api/search/compromise/'+encodeURIComponent(iocValue)).then(r=>r.json());
    const stillActive=r?.compromised&&r?.total_hits>0;
    let h=`<div style="padding:16px;">
      <div style="padding:14px;border-radius:12px;margin-bottom:16px;${stillActive?'background:rgba(198,40,40,.06);border-left:4px solid #c62828;':'background:rgba(46,125,50,.06);border-left:4px solid #2e7d32;'}">
        <div style="font-size:16px;font-weight:800;margin-bottom:4px;">${stillActive?'⚠️ IOC STILL ACTIVE':'✅ IOC APPEARS REMEDIATED'}</div>
        <div style="font-size:13px;color:var(--text2);">${stillActive?`Still showing ${r.total_hits} hits across ${(r.sources_checked||[]).length} sources. Remediation may not be complete.`:'No active compromise indicators found. Fix appears successful.'}</div>
      </div>
      <div style="font-size:12px;color:var(--text3);">
        <div style="font-weight:700;margin-bottom:4px;">Sources Checked:</div>
        ${(r.sources_checked||[]).map(s=>`<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);">
          <span>${s.source||s.name||'?'}</span>
          <span style="font-weight:700;color:${s.hits>0?'#c62828':'#2e7d32'};">${s.hits||0} hits</span>
        </div>`).join('')}
      </div>
    </div>`;
    showDrilldown('✅ Fix Verification: '+iocValue.substring(0,40),h);
  }catch(e){
    showDrilldown('✅ Verification Failed','<div style="padding:16px;color:#c62828;">Could not verify: '+e.message+'</div>');
  }
}

// Compliance Map -  shows which frameworks this remediation satisfies
async function remShowCompliance(iocType,playbookKey){
  const COMPLIANCE_MAP={
    'leaked_api_key':{'NIST CSF':'PR.AC-1 Identity & Access','PCI DSS':'Req 8.2 Authentication','SOC 2':'CC6.1 Access Control','CIS':'CIS 16 Account Monitoring'},
    'credential_combo':{'NIST CSF':'PR.AC-7 Credential Management','PCI DSS':'Req 8.1 User ID Management','HIPAA':'§164.312(d) Authentication','SOC 2':'CC6.1 Access Control'},
    'malicious_ip':{'NIST CSF':'DE.CM-1 Network Monitoring','PCI DSS':'Req 11.4 IDS/IPS','SOC 2':'CC7.2 System Monitoring','CIS':'CIS 13 Network Monitoring'},
    'phishing_domain':{'NIST CSF':'PR.AT-1 Awareness Training','PCI DSS':'Req 12.6 Security Awareness','SOC 2':'CC2.2 Internal Communication','CIS':'CIS 14 Security Training'},
    'cve_tech_stack':{'NIST CSF':'ID.RA-1 Vulnerability ID','PCI DSS':'Req 6.1 Security Patches','SOC 2':'CC7.1 Vulnerability Management','CIS':'CIS 7 Continuous Vuln Management'},
    'ransomware_leak':{'NIST CSF':'RS.RP-1 Response Plan','PCI DSS':'Req 12.10 Incident Response','HIPAA':'§164.308(6) Security Incident','SOC 2':'CC7.4 Incident Response'},
    'data_exfiltration':{'NIST CSF':'PR.DS-5 Data Leak Prevention','PCI DSS':'Req 10.6 Log Review','HIPAA':'§164.312(e) Transmission Security','SOC 2':'CC6.7 Data Classification'},
    'exposed_infrastructure':{'NIST CSF':'PR.PT-3 Least Functionality','PCI DSS':'Req 2.2 System Hardening','SOC 2':'CC6.6 System Boundaries','CIS':'CIS 9 Port/Service Limitation'},
    'malware_hash':{'NIST CSF':'DE.CM-4 Malicious Code Detection','PCI DSS':'Req 5.1 Anti-Virus','SOC 2':'CC7.1 Monitoring','CIS':'CIS 10 Malware Defenses'},
  };
  const map=COMPLIANCE_MAP[playbookKey]||COMPLIANCE_MAP['credential_combo']||{};
  let h=`<div style="padding:16px;">
    <div style="font-size:13px;color:var(--text3);margin-bottom:12px;">Compliance frameworks satisfied by remediating <b>${iocType}</b> (playbook: ${playbookKey})</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
      ${Object.entries(map).map(([fw,ctrl])=>`<div style="padding:12px;border-radius:10px;background:rgba(21,101,192,.04);border:1px solid rgba(21,101,192,.1);">
        <div style="font-size:12px;font-weight:800;color:#1565c0;margin-bottom:4px;">${fw}</div>
        <div style="font-size:12px;color:var(--text2);">${ctrl}</div>
      </div>`).join('')}
    </div>
    ${!Object.keys(map).length?'<div style="color:var(--text3);padding:12px;">No specific compliance mapping for this playbook type.</div>':''}
  </div>`;
  showDrilldown('📋 Compliance Mapping: '+iocType,h);
}

// Bulk: AI regenerate for all findings missing playbooks
async function remAiRegenAll(){
  toast('AI regenerating remediations for findings without playbooks...');
  const r=await apiPost('/api/ai-remediation-regen',{limit:20});
  toast(`AI regenerated ${r?.regenerated||0} remediations`);
  setTimeout(loadRemPage,1000);
}

// Bulk: Verify all completed remediations are actually fixed
async function remVerifyAll(){
  const completed=_remData.filter(r=>r.status==='completed'&&r.ioc_value);
  if(!completed.length){toast('No completed remediations to verify');return;}
  toast(`Verifying ${completed.length} completed remediations...`);
  let stillActive=0;
  for(const r of completed.slice(0,5)){
    try{
      const check=await fetch('/api/search/compromise/'+encodeURIComponent(r.ioc_value)).then(r=>r.json());
      if(check?.compromised&&check?.total_hits>0)stillActive++;
    }catch(e){}
  }
  if(stillActive>0){
    toast(`⚠️ ${stillActive} "completed" remediations still show active IOCs!`,'error');
  }else{
    toast(`✅ All verified completed remediations appear clean`);
  }
}

// Enhanced filter: no_playbook
let _origFilterRem=filterRem;
function filterRem(f,btn){
  if(f==='no_playbook'){
    _remFilter='no_playbook';
    document.querySelectorAll('#rem-filters .btn').forEach(b=>b.classList.remove('active'));
    if(btn)btn.classList.add('active');
    const grid=document.getElementById('rem-grid');
    // Find findings WITHOUT remediations by querying
    apiPost('/api/ai/chat',{question:'List all findings that have no remediation actions. Show finding ID, IOC type, severity, and customer name.'}).then(r=>{
      const answer=r?.response||r?.answer||'Could not query findings without remediations.';
      grid.innerHTML=`<div style="padding:16px;border-radius:12px;background:rgba(230,92,0,.04);border:1px solid rgba(230,92,0,.1);font-size:14px;line-height:1.7;">${escHtml(answer).replace(/\n/g,'<br>')}<div style="margin-top:12px;"><button class="btn pri" style="font-size:12px;" onclick="remAiRegenAll()">🤖 Generate All Missing</button></div></div>`;
    });
    return;
  }
  _remFilter=f;
  document.querySelectorAll('#rem-filters .btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  renderRemGrid();
}

async function loadSet(){
  const [ai,cols,ent,fpStats]=await Promise.all([api('/api/settings/ai'),api('/api/collectors/status'),api('/api/enterprise/status'),api('/api/fp-patterns/stats')]);
  console.log('Enterprise status response:',JSON.stringify(ent).substring(0,500));
  const colItems=cols?Object.entries(cols).map(([k,v])=>({name:k,...(typeof v==='object'?v:{status:v})})):[];
  const eItems=ent?Object.entries(ent).map(([k,v])=>({name:k,...(typeof v==='object'?v:{active:v})})):[];
  // All API key categories
  const _aiProviders=[
    {id:'openai',name:'OpenAI',emoji:'🤖',color:'#10a37f',desc:'GPT-5.3 Codex for AI threat assessment, narrative generation, and severity analysis',placeholder:'sk-...',url:'https://platform.openai.com/api-keys'},
    {id:'anthropic',name:'Anthropic Claude',emoji:'🟣',color:'#7b1fa2',desc:'Claude for investigation narratives and false positive reasoning',placeholder:'sk-ant-...',url:'https://console.anthropic.com/settings/keys'},
    {id:'google',name:'Google Gemini',emoji:'💎',color:'#1565c0',desc:'Gemini for multi-modal analysis and structured data extraction',placeholder:'AIza...',url:'https://aistudio.google.com/app/apikey'},
    {id:'local',name:'🦙 Qwen (Ollama)',emoji:'🦙',color:'#e65c00',desc:'Self-hosted Qwen 3.5 9B -  no API key needed, runs locally in Docker',placeholder:'No key required',nokey:true,url:'https://ollama.com/'},
  ];
  const _collectors=[
    {cat:'🆓 Free (No API Key)',items:[
      {id:'nvd',name:'NVD',desc:'NIST National Vulnerability Database -  CVE data',status:true,url:'https://nvd.nist.gov/',price:'FREE'},
      {id:'mitre',name:'MITRE ATT&CK',desc:'Threat actor groups, TTPs, techniques',status:true,url:'https://attack.mitre.org/',price:'FREE'},
      {id:'openphish',name:'OpenPhish',desc:'Community phishing URL feed',status:true,url:'https://openphish.com/',price:'FREE'},
      {id:'urlhaus',name:'URLhaus',desc:'Abuse.ch malicious URL database',status:true,url:'https://urlhaus.abuse.ch/',price:'FREE'},
      {id:'phishtank',name:'PhishTank',desc:'Community-verified phishing URLs',status:true,url:'https://phishtank.org/',price:'FREE'},
      {id:'feodo',name:'Feodo Tracker',desc:'Botnet C2 server tracking',status:true,url:'https://feodotracker.abuse.ch/',price:'FREE'},
      {id:'threatfox',name:'ThreatFox',desc:'Abuse.ch IOC sharing platform',status:true,url:'https://threatfox.abuse.ch/',price:'FREE'},
      {id:'malwarebazaar',name:'MalwareBazaar',desc:'Malware sample hash repository',status:true,url:'https://bazaar.abuse.ch/',price:'FREE'},
      {id:'circl_misp',name:'CIRCL MISP',desc:'Luxembourg CERT threat sharing',status:true,url:'https://www.circl.lu/services/misp-malware-information-sharing-platform/',price:'FREE'},
      {id:'abuse_ch',name:'Abuse.ch',desc:'Combined abuse tracking feeds',status:true,url:'https://abuse.ch/',price:'FREE'},
      {id:'paste',name:'Paste Sites',desc:'Pastebin/paste.ee monitoring',status:true,url:'https://psbdmp.ws/',price:'FREE'},
      {id:'rss',name:'RSS Feeds',desc:'Security blog and advisory feeds',status:true,url:'https://www.cisa.gov/news-events/cybersecurity-advisories',price:'FREE'},
      {id:'darksearch',name:'DarkSearch',desc:'Dark web search engine',status:true,url:'https://darksearch.io/',price:'FREE'},
      {id:'pulsedive',name:'Pulsedive',desc:'Community threat intelligence',status:true,url:'https://pulsedive.com/',price:'FREE'},
      {id:'grep_app',name:'Grep.app',desc:'Public code search for leaks',status:true,url:'https://grep.app/',price:'FREE'},
      {id:'cisa_kev',name:'CISA KEV',desc:'Known Exploited Vulnerabilities catalog',status:true,url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',price:'FREE'},
      {id:'ransomfeed',name:'RansomFeed',desc:'Ransomware victim leak announcements from ransomwatch',status:true,url:'https://ransomfeed.it/',price:'FREE'},
      {id:'vxunderground',name:'VX-Underground',desc:'Malware samples, APT tracking, threat research',status:true,url:'https://vx-underground.org/',price:'FREE'},
      {id:'hudsonrock',name:'HudsonRock',desc:'Free stealer log OSINT search per customer domain',status:true,url:'https://cavalier.hudsonrock.com/',price:'FREE'},
      {id:'github_gist',name:'GitHub Gist Scanner',desc:'Scan public gists for leaked secrets via pattern_matcher',status:true,url:'https://gist.github.com/',price:'FREE'},
      {id:'sourcegraph',name:'Sourcegraph Search',desc:'Search 2M+ public repos for exposed secrets',status:true,url:'https://sourcegraph.com/',price:'FREE'},
      {id:'alt_paste',name:'Alt Paste Sites',desc:'dpaste, paste.ee, centos, ubuntu paste scanning',status:true,url:'https://dpaste.org/',price:'FREE'},
      {id:'telegram',name:'Telegram Channels',desc:'Public threat intel channels -  IOC + breach mention scanning',status:true,url:'https://t.me/',price:'FREE'},
    ]},
    {cat:'🔑 Requires API Key',items:[
      {id:'grayhatwarfare',name:'GrayHatWarfare',desc:'Open S3/Azure/GCS bucket search -  finds exposed cloud storage per customer',placeholder:'GHW API key',color:'#e65100',url:'https://grayhatwarfare.com/api',price:'Free tier'},
      {id:'leakix',name:'LeakIX',desc:'Exposed services + leaked data search per customer domain/IP',placeholder:'LeakIX API key',color:'#2e7d32',url:'https://leakix.net/api-documentation',price:'Free tier'},
      {id:'otx',name:'AlienVault OTX',desc:'Community threat intel pulses -  IPs, domains, hashes from 200K+ contributors',placeholder:'OTX API key',color:'#2e7d32',url:'https://otx.alienvault.com/',price:'Free'},
      {id:'urlscan',name:'URLScan.io',desc:'Phishing/malware URL scanning -  1000 lookups/day',placeholder:'URLScan API key',color:'#1565c0',url:'https://urlscan.io/user/signup/',price:'Free'},
      {id:'hibp',name:'HIBP + BreachDir',desc:'Has this email been breached? Powers compromise search bar',placeholder:'HIBP API key',color:'#c62828',url:'https://haveibeenpwned.com/API/Key',price:'$3.50/mo'},
      {id:'github',name:'GitHub Secrets',desc:'Search public repos for exposed credentials per customer org',placeholder:'GitHub classic token (no scopes)',color:'#1565c0',url:'https://github.com/settings/tokens',price:'Free'},
      {id:'socradar',name:'SocRadar',desc:'Brand monitoring -  your customer mentioned on dark web?',placeholder:'SocRadar API key',color:'#7b1fa2',url:'https://platform.socradar.com/',price:'Enterprise'},
      {id:'shodan',name:'Shodan',desc:'Internet-wide scanning & exposure detection',placeholder:'Shodan API key',color:'#c62828',url:'https://account.shodan.io/',price:'$69/mo'},
      {id:'virustotal',name:'VirusTotal',desc:'Multi-engine malware scanning & URL analysis',placeholder:'VT API key',color:'#e65100',url:'https://www.virustotal.com/gui/my-apikey',price:'Free tier'},
      {id:'abuseipdb',name:'AbuseIPDB',desc:'IP address abuse reporting & reputation checking -  1000 checks/day free',placeholder:'AbuseIPDB API key',color:'#c62828',url:'https://www.abuseipdb.com/account/api',price:'Free tier'},
      {id:'intelx',name:'IntelX',desc:'Intelligence X -  dark web & leak search',placeholder:'IntelX API key',color:'#7b1fa2',url:'https://intelx.io/account?tab=developer',price:'€3K/yr'},
      {id:'censys',name:'Censys',desc:'Internet asset discovery and monitoring',placeholder:'Censys API ID:Secret',color:'#1565c0',url:'https://search.censys.io/account/api',price:'Free tier'},
      {id:'greynoise',name:'GreyNoise',desc:'Internet background noise classification',placeholder:'GreyNoise API key',color:'#2e7d32',url:'https://viz.greynoise.io/account/api-key',price:'Free tier'},
      {id:'binaryedge',name:'BinaryEdge',desc:'Internet scanning and data analytics',placeholder:'BinaryEdge API key',color:'#e65100',url:'https://app.binaryedge.io/account/api',price:'Free tier'},
      {id:'leakcheck',name:'LeakCheck',desc:'Credential breach monitoring',placeholder:'LeakCheck API key',color:'#c62828',url:'https://leakcheck.io/api',price:'$30/mo'},
      {id:'spycloud',name:'SpyCloud',desc:'Enterprise credential exposure monitoring',placeholder:'SpyCloud API key',color:'#c62828',url:'https://portal.spycloud.com/',price:'Enterprise'},
      {id:'recordedfuture',name:'Recorded Future',desc:'Enterprise threat intelligence platform',placeholder:'RF API token',color:'#1565c0',url:'https://support.recordedfuture.com/hc/en-us/articles/115002793388',price:'Enterprise'},
      {id:'crowdstrike',name:'CrowdStrike',desc:'Falcon threat intelligence feed',placeholder:'CS Client ID:Secret',color:'#e65100',url:'https://falcon.crowdstrike.com/api-clients-and-keys/',price:'Enterprise'},
      {id:'mandiant',name:'Mandiant',desc:'Google Mandiant threat intelligence',placeholder:'Mandiant API key',color:'#c62828',url:'https://www.mandiant.com/advantage/threat-intelligence/api',price:'Enterprise'},
      {id:'flare',name:'Flare',desc:'Dark web monitoring and leaked credentials',placeholder:'Flare API key',color:'#7b1fa2',url:'https://app.flare.io/',price:'Enterprise'},
      {id:'cyberint',name:'CyberInt',desc:'External threat intelligence and brand protection',placeholder:'CyberInt API key',color:'#1565c0',url:'https://cyberint.com/',price:'Enterprise'},
    ]}
  ];
  let h='';
  // ═══ AI PROVIDERS -  orange glowy container ═══
  h+=`<div style="margin-bottom:24px;padding:20px;border-radius:18px;background:linear-gradient(135deg,rgba(230,92,0,.07),rgba(255,140,66,.04),rgba(0,137,123,.02));border:1.5px solid rgba(230,92,0,.20);box-shadow:0 0 30px rgba(230,92,0,.06),0 0 60px rgba(230,92,0,.03);animation:hero-glow-pulse 4s ease-in-out infinite;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
      <div style="width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,rgba(230,92,0,.12),rgba(255,140,66,.08));display:flex;align-items:center;justify-content:center;font-size:24px;border:1px solid rgba(230,92,0,.15);">🤖</div>
      <div style="flex:1;"><div style="font-size:18px;font-weight:800;color:var(--text);">AI Provider Configuration</div>
      <div style="font-size:12px;color:var(--text3);">Active: <span style="color:#e65c00;font-weight:700;">${ai?.active_provider||ai?.provider||'ollama'}</span> · Model: <span style="font-weight:700;">${ai?.model||'qwen3.5:9b'}</span> · FP Patterns: ${fpStats?.total_patterns||0}</div></div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;">`;
  _aiProviders.forEach(p=>{
    const activeProv=ai?.active_provider||ai?.provider||'ollama';
    const isActive=(activeProv==='ollama'&&p.id==='local')||activeProv===p.id;
    h+=`<div style="padding:16px;border-radius:14px;border:${isActive?'2px':'1px'} solid ${isActive?p.color+'50':'var(--border)'};background:${isActive?p.color+'06':'var(--glass)'};position:relative;transition:all .3s;${isActive?'box-shadow:0 0 20px '+p.color+'15;':''}">
      ${isActive?`<div style="position:absolute;top:10px;right:10px;width:10px;height:10px;border-radius:50%;background:${p.color};box-shadow:0 0 8px ${p.color};animation:pulse-glow 2s infinite;"></div>`:''}
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <span style="font-size:24px;">${p.emoji}</span>
        <div><div style="font-size:15px;font-weight:800;color:var(--text);cursor:pointer;" onclick="window.open('${p.url}','_blank')">${p.name} <span style="font-size:10px;opacity:.5;">↗</span></div>
        <div style="font-size:11px;color:${isActive?p.color:'var(--text4)'};font-weight:700;">${isActive?'✓ ACTIVE':'Inactive'}</div></div>
      </div>
      <div style="font-size:12px;color:var(--text3);line-height:1.4;margin-bottom:12px;">${p.desc}</div>
      ${p.nokey?`<button class="btn ${isActive?'':'pri'}" style="width:100%;font-size:12px;" onclick="switchAI('${p.id}')">${isActive?'Currently Active':'Activate 🦙 Qwen'}</button>`
      :`<div style="display:flex;gap:6px;">
        <input class="btn" style="flex:1;text-align:left;font-size:12px;padding:8px 12px;" placeholder="${p.placeholder}" id="key-${p.id}">
        <button class="btn pri" style="font-size:12px;padding:8px 14px;" onclick="saveProviderKey('${p.id}')">Save</button>
        <button class="btn" style="font-size:12px;padding:8px 10px;color:#c62828;" onclick="deleteAIKey('${p.id}')" title="Delete key">🗑️</button>
      </div>
      ${!isActive?`<button class="btn" style="width:100%;font-size:11px;margin-top:6px;" onclick="switchAI('${p.id}')">Activate ${p.name}</button>`:''}
      <div style="margin-top:6px;text-align:right;"><a href="${p.url}" target="_blank" style="font-size:10px;color:${p.color};text-decoration:none;font-weight:600;">📄 Get API Key -></a></div>`}
    </div>`;
  });
  h+=`</div></div>`;
  // ═══ FREE COLLECTORS ═══
  h+=`<div style="margin-bottom:24px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;cursor:pointer;" onclick="const b=document.getElementById('set-free-cols');b.style.display=b.style.display==='none'?'':'none';this.querySelector('.chv').textContent=b.style.display==='none'?'▸':'▾'">
      <span style="font-size:24px;">📡</span>
      <div style="flex:1;"><div style="font-size:18px;font-weight:800;color:var(--text);">${_collectors[0].cat} <span style="font-size:14px;color:var(--green);font-weight:900;">${_collectors[0].items.length} active</span></div>
      <div style="font-size:12px;color:var(--text3);">These collectors work out of the box -  no API keys needed</div></div>
      <button class="btn cyan" style="font-size:11px;padding:6px 14px;" onclick="event.stopPropagation();triggerCollect()">⚡ Collect All Now</button>
      <span class="chv" style="font-size:14px;color:var(--text4);">▾</span>
    </div>
    <div id="set-free-cols" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px;">`;
  _collectors[0].items.forEach(c=>{
    const colData=colItems.find(ci=>ci.name===c.id)||{};
    const iocCount=colData.ioc_count||colData.count||0;
    const lastRun=colData.last_run;
    h+=`<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;border:1px solid var(--border);background:var(--glass);transition:all .25s;cursor:pointer;" onmouseover="this.style.borderColor='var(--green-b)';this.style.boxShadow='0 2px 12px rgba(46,125,50,.08)'" onmouseout="this.style.borderColor='';this.style.boxShadow=''" onclick="window.open('${c.url}','_blank')">
      <div style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);flex-shrink:0;"></div>
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${c.name} <span style="font-size:9px;color:var(--green);font-weight:900;">🆓 FREE</span></div>
        <div style="font-size:10px;color:var(--text4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${c.desc}</div>
      </div>
      <div style="text-align:right;flex-shrink:0;">
        <div style="font-size:12px;font-weight:900;font-family:'JetBrains Mono';color:${iocCount>0?'var(--cyan)':'var(--text4)'};">${iocCount}</div>
        <div style="font-size:9px;color:var(--text4);">${ago(lastRun)}</div>
      </div>
      <button class="btn" style="padding:3px 8px;font-size:11px;flex-shrink:0;" onclick="event.stopPropagation();apiPost('/api/collect/${c.id}');toast('Collecting ${c.name}...')">▶</button>
    </div>`;
  });
  h+=`</div></div>`;
  // ═══ API KEY COLLECTORS -  DYNAMIC SORT: ACTIVE FIRST ═══
  // Count only key-requiring collectors (not free ones)
  // Count keys from enterprise/status response directly (not by cross-referencing)
  const keyReqIds=_collectors[1].items.map(c=>c.id);
  // Count from eItems: any collector with key_configured=true that is in our key-required list
  let keyActiveCount=0;
  eItems.forEach(e=>{
    if(e.key_configured||e.key_hint){keyActiveCount++;}
  });
  // If that gives 0, try counting from the raw response by checking all 42 collectors
  if(keyActiveCount===0 && ent){
    Object.values(ent).forEach(v=>{
      if(v && (v.key_configured||v.key_hint)) keyActiveCount++;
    });
  }
  const keyTotal=_collectors[1].items.length;
  // Sort: active collectors first, then locked
  const sortedKeyCollectors=[..._collectors[1].items].sort((a,b)=>{
    const aData=eItems.find(e=>e.name===a.id)||(ent?ent[a.id]:null)||{};
    const bData=eItems.find(e=>e.name===b.id)||(ent?ent[b.id]:null)||{};
    const aActive=aData.active||aData.key_configured||false;
    const bActive=bData.active||bData.key_configured||false;
    if(aActive&&!bActive)return -1;if(!aActive&&bActive)return 1;return 0;
  });
  h+=`<div style="margin-bottom:24px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
      <span style="font-size:24px;">🔑</span>
      <div style="flex:1;"><div style="font-size:18px;font-weight:800;color:var(--text);">${_collectors[1].cat}</div>
      <div style="font-size:12px;color:var(--text3);">Premium threat intelligence feeds -  paste your API key to activate</div></div>
      <div style="text-align:right;padding:8px 16px;border-radius:10px;background:${keyActiveCount>0?'var(--green-g)':'rgba(198,40,40,.06)'};border:1.5px solid ${keyActiveCount>0?'var(--green-b)':'rgba(198,40,40,.15)'};">
        <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:${keyActiveCount>0?'var(--green)':'#c62828'};">${keyActiveCount}/${keyTotal}</div>
        <div style="font-size:9px;color:var(--text4);font-weight:700;">${keyActiveCount>0?'KEYS ACTIVE':'NO KEYS SET'}</div>
      </div>
    </div>`;
  // Show active collectors section if any
  const activeKeys=sortedKeyCollectors.filter(c=>{
    const d=eItems.find(e=>e.name===c.id)||(ent?ent[c.id]:null)||{};
    return d.active||d.key_configured;
  });
  const lockedKeys=sortedKeyCollectors.filter(c=>{
    const d=eItems.find(e=>e.name===c.id)||(ent?ent[c.id]:null)||{};
    return !(d.active||d.key_configured);
  });
  if(activeKeys.length){
    h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--green);margin-bottom:8px;display:flex;align-items:center;gap:6px;"><span style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse-glow 2s infinite;"></span> Active Collectors (${activeKeys.length})</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:10px;margin-bottom:20px;">`;
    activeKeys.forEach(c=>{
      const entData=eItems.find(e=>e.name===c.id)||(ent?ent[c.id]:null)||{};
      const keyHint=entData.key_hint||'';
      const col=c.color||'#e65c00';
      const priceColor=c.price==='Free tier'?'var(--green)':c.price==='Enterprise'?'#7b1fa2':'#c62828';
      const priceIcon=c.price==='Free tier'?'🆓':c.price==='Enterprise'?'🏢':'💰';
      h+=`<div style="padding:14px;border-radius:14px;border:2px solid var(--green-b);background:linear-gradient(135deg,rgba(46,125,50,.04),rgba(230,92,0,.02));transition:all .3s;box-shadow:0 0 20px rgba(46,125,50,.08),0 0 40px rgba(46,125,50,.04);position:relative;overflow:hidden;animation:hero-glow-pulse 4s ease-in-out infinite;">
        <div style="position:absolute;top:8px;right:8px;width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:pulse-glow 2s infinite;"></div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <div style="width:36px;height:36px;border-radius:10px;background:${col}12;display:flex;align-items:center;justify-content:center;font-size:18px;border:1px solid ${col}25;">📡</div>
          <div style="flex:1;"><div style="font-size:15px;font-weight:800;color:var(--text);cursor:pointer;" onclick="window.open('${c.url}','_blank')">${c.name} <span style="font-size:10px;opacity:.6;">↗</span></div>
          <div style="font-size:11px;color:var(--green);font-weight:700;">✓ ACTIVE · collecting IOCs</div></div>
          <span style="font-size:9px;font-weight:700;padding:2px 7px;border-radius:8px;background:${priceColor}10;color:${priceColor};border:1px solid ${priceColor}20;">${priceIcon} ${c.price}</span>
        </div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:8px;line-height:1.4;">${c.desc}</div>
        ${keyHint?`<div style="font-size:10px;font-family:'JetBrains Mono';color:var(--green);margin-bottom:6px;padding:4px 8px;border-radius:6px;background:var(--green-g);border:1px solid var(--green-b);display:inline-block;">🔑 Key: ${keyHint}</div>`:''}
        <div style="display:flex;gap:6px;">
          <button class="btn" style="flex:1;font-size:11px;padding:6px 12px;background:var(--green-g);color:var(--green);border-color:var(--green-b);" onclick="triggerEnterprise('${c.id}')">▶ Run Now</button>
          <button class="btn" style="font-size:11px;padding:6px 10px;color:#c62828;" onclick="if(confirm('Remove key for ${c.name}?')){saveEntKey('${c.id}')}" title="Remove key">🗑️</button>
        </div>
      </div>`;
    });
    h+=`</div>`;
  }
  // Locked collectors -  greenish fancy cards
  if(lockedKeys.length){
    const _cIcons={'grayhatwarfare':'☁️','leakix':'🔓','otx':'👽','urlscan':'🔗','hibp':'💧','github':'🐙','socradar':'🛡️','shodan':'🔍','virustotal':'☣️','intelx':'🕵️','censys':'🌐','greynoise':'📡','binaryedge':'⚡','leakcheck':'🔑','spycloud':'👤','recordedfuture':'📊','crowdstrike':'🦅','mandiant':'🔥','flare':'🌑','cyberint':'🛡️'};
    h+=`<div style="padding:16px;border-radius:16px;background:linear-gradient(135deg,rgba(0,137,123,.05),rgba(46,125,50,.03));border:1.5px solid rgba(0,137,123,.15);margin-bottom:8px;">
      <div style="font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--cyan);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
        <span style="width:10px;height:10px;border-radius:50%;background:rgba(0,137,123,.4);"></span> 
        Unlock Premium Collectors (${lockedKeys.length})
        <span style="margin-left:auto;font-size:11px;color:var(--text4);font-weight:500;text-transform:none;letter-spacing:0;">Paste your API key -> click Activate -> instant green</span>
      </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px;">`;
    lockedKeys.forEach((c,idx)=>{
      const col=c.color||'#00897b';
      const tierColor=c.price==='Free tier'?'#00897b':c.price==='Enterprise'?'#7b1fa2':c.price.includes('$')?'#e65100':'#1565c0';
      const priceColor=c.price==='Free tier'?'#00897b':c.price==='Enterprise'?'#7b1fa2':'#e65100';
      const priceIcon=c.price==='Free tier'?'🆓':c.price==='Enterprise'?'🏢':'💰';
      const icon=_cIcons[c.id]||'📡';
      const isFree=c.price==='Free tier'||c.price==='Free';
      h+=`<div style="padding:14px;border-radius:14px;border:1.5px solid ${isFree?'rgba(0,137,123,.2)':'rgba(123,31,162,.12)'};background:linear-gradient(135deg,${isFree?'rgba(0,137,123,.03),rgba(46,125,50,.02)':'rgba(123,31,162,.02),rgba(0,137,123,.01)'});transition:all .3s;position:relative;" onmouseover="this.style.transform='translateY(-2px)';this.style.borderColor='${tierColor}50';this.style.boxShadow='0 6px 24px ${tierColor}12'" onmouseout="this.style.transform='';this.style.borderColor='';this.style.boxShadow=''">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div style="width:38px;height:38px;border-radius:10px;background:${tierColor}10;display:flex;align-items:center;justify-content:center;font-size:20px;border:1px solid ${tierColor}20;flex-shrink:0;">${icon}</div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:14px;font-weight:800;color:var(--text);cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" onclick="window.open('${c.url}','_blank')">${c.name} <span style="font-size:10px;opacity:.5;">↗</span></div>
            <div style="display:flex;gap:4px;margin-top:3px;">
              <span style="font-size:9px;font-weight:700;padding:2px 7px;border-radius:8px;background:${priceColor}10;color:${priceColor};border:1px solid ${priceColor}20;">${priceIcon} ${c.price}</span>
              ${isFree?'<span style="font-size:9px;font-weight:700;padding:2px 7px;border-radius:8px;background:rgba(0,137,123,.08);color:#00897b;border:1px solid rgba(0,137,123,.15);">⚡ 2 min setup</span>':''}
            </div>
          </div>
        </div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:10px;line-height:1.4;">${c.desc}</div>
        <div style="display:flex;gap:6px;align-items:center;">
          <input class="btn" style="flex:1;text-align:left;font-size:12px;padding:8px 12px;border-color:${tierColor}20;" placeholder="${c.placeholder}" id="ekey-${c.id}" onfocus="this.style.borderColor='${tierColor}'" onblur="this.style.borderColor=''">
          <button class="btn" style="font-size:12px;padding:8px 16px;background:${tierColor}10;color:${tierColor};border:1.5px solid ${tierColor}30;font-weight:700;" onclick="saveEntKey('${c.id}')" onmouseover="this.style.background='${tierColor}20'" onmouseout="this.style.background='${tierColor}10'">Activate</button>
        </div>
        <div style="margin-top:8px;display:flex;justify-content:space-between;align-items:center;">
          <a href="${c.url}" target="_blank" style="font-size:10px;color:${tierColor};text-decoration:none;font-weight:600;">📄 Get API Key -></a>
          ${isFree?'<span style="font-size:10px;color:#00897b;font-weight:600;">✨ Free -  no credit card</span>':''}
        </div>
      </div>`;
    });
    h+=`</div></div>`;
  }
  h+=`</div>`;
  document.getElementById('set-content').innerHTML=h;
}
async function saveProviderKey(provider){
  const key=document.getElementById('key-'+provider)?.value;
  if(!key){toast('Enter API key','error');return;}
  await apiPost('/api/settings/ai-keys',{provider:provider,api_key:key});
  toast('Key saved for '+provider);switchAI(provider);loadSet();refreshAIHeaderStatus();
}
async function saveEntKey(source){
  const key=document.getElementById('ekey-'+source)?.value;
  if(!key){toast('Enter API key','error');return;}
  await apiPost('/api/settings/ai-keys',{provider:source,api_key:key});
  toast('Key saved for '+source+' -  collector activated');loadSet();refreshAIHeaderStatus();
}
async function switchAI(p){
  const _map={local:'ollama',claude:'anthropic',openai:'openai',google:'google',ollama:'ollama',anthropic:'anthropic',auto:'auto'};
  _aiProvider=_map[p]||p;
  await apiPost('/api/settings/active-provider',{provider:_aiProvider}).catch(()=>{});
  toast('AI -> '+p);
  refreshAIHeaderStatus();
}
async function refreshAIHeaderStatus(){
  // Fetch real AI provider status and update header buttons
  const ai=await api('/api/settings/ai').catch(()=>null);
  const providers=await api('/api/agent/providers').catch(()=>null);
  // Determine the active provider
  const active=ai?.active_provider||ai?.provider||providers?.current||'ollama';
  // Map backend names to button data-p values
  const backendToBtn={'ollama':'local','anthropic':'anthropic','openai':'openai','google':'google'};
  const activeBtnId=backendToBtn[active]||'local';
  document.querySelectorAll('.ai-btn').forEach(b=>{
    const p=b.dataset.p;
    const isActive=p===activeBtnId;
    b.classList.toggle('active',isActive);
    // Also show key status: check if provider has a key configured
    let hasKey=false;
    if(p==='local') hasKey=true; // no key needed
    else if(providers?.providers){
      const prov=providers.providers[p==='anthropic'?'anthropic':p];
      hasKey=prov?.has_key||false;
    } else {
      if(p==='anthropic') hasKey=ai?.anthropic_configured||false;
      if(p==='openai') hasKey=ai?.openai_configured||false;
      if(p==='google') hasKey=ai?.google_configured||false;
    }
    // Update dot color: green=active, orange=has key but not active, gray=no key
    const dot=b.querySelector('.ai-dot');
    if(dot){
      if(isActive) dot.style.cssText='background:var(--green);box-shadow:0 0 6px var(--green);';
      else if(hasKey) dot.style.cssText='background:var(--orange);box-shadow:0 0 4px var(--orange);';
      else dot.style.cssText='background:var(--text4);box-shadow:none;';
    }
  });
}
// Refresh AI status on page load
setTimeout(refreshAIHeaderStatus,1500);

// ═══ SLA - /api/sla/breaches, /api/escalation/overdue ═══
async function loadSLA(){
  const [breaches,overdue]=await Promise.all([api('/api/sla/breaches'),api('/api/escalation/overdue')]);
  document.getElementById('sla-stats').innerHTML=`
    <div class="stat red"><div class="stat-num red">${breaches?.breaches?.length||breaches?.length||0}</div><div class="stat-lbl">SLA Breaches</div></div>
    <div class="stat orange"><div class="stat-num orange">${overdue?.length||0}</div><div class="stat-lbl">Overdue Escalations</div></div>`;
  const items=[...(breaches?.breaches||breaches||[]),...(overdue?.items||overdue||[])];
  document.getElementById('sla-grid').innerHTML=items.map(s=>{
    const breached=s.breached;
    return`<div class="sla-card ${breached?'breached':'ok'}">
      <div class="sla-top"><span class="font-bold">${s.customer_name||'-'}</span>${sevTag(s.severity)}<span class="tag ${breached?'crit':'green'}" style="margin-left:auto;">${breached?'BREACHED':'OK'}</span></div>
      <div class="sla-detail"><span>Finding #${s.finding_id||'-'}</span><span>Target: <b>${s.sla_hours||'-'}h</b></span><span>Actual: <b class="${breached?'text-red':'text-green'}">${s.actual_hours||'-'}h</b></span></div>
    </div>`;}).join('')||'<div class="empty">No SLA breaches - great job!</div>';
}

// ═══ FP PATTERNS - /api/fp-patterns ═══
async function loadFP(){
  const [patterns,stats]=await Promise.all([api('/api/fp-patterns'),api('/api/fp-patterns/stats')]);
  const items=patterns?.patterns||patterns||[];
  // Stats
  const autoClose=items.filter(p=>p.auto_close).length;
  const totalHits=items.reduce((s,p)=>s+(p.hit_count||0),0);
  const avgConf=items.length?items.reduce((s,p)=>s+(p.confidence||0),0)/items.length:0;
  if(stats||items.length)document.getElementById('fp-stats').innerHTML=
    `<div class="stat-card"><div class="stat-val">${items.length}</div><div class="stat-label">Active Patterns</div></div>
    <div class="stat-card"><div class="stat-val">${autoClose}</div><div class="stat-label">Auto-Closeable</div></div>
    <div class="stat-card"><div class="stat-val">${totalHits}</div><div class="stat-label">Analyst Hours Saved</div></div>
    <div class="stat-card"><div class="stat-val">${avgConf.toFixed(0)}%</div><div class="stat-label">Avg Confidence</div></div>`;
  // Filters by IOC type
  const byType={};items.forEach(p=>{const t=p.ioc_type||'unknown';byType[t]=(byType[t]||0)+1;});
  document.getElementById('fp-filters').innerHTML=
    `<button class="btn ${!window._fpFilter?'pri':''}" style="font-size:11px;padding:4px 10px;" onclick="window._fpFilter=null;loadFP()">All (${items.length})</button>`+
    Object.entries(byType).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([t,c])=>
      `<button class="btn ${window._fpFilter===t?'pri':''}" style="font-size:11px;padding:4px 10px;" onclick="window._fpFilter='${t}';loadFP()">${t} (${c})</button>`
    ).join('');
  // Grid
  let filtered=window._fpFilter?items.filter(p=>p.ioc_type===window._fpFilter):items;
  document.getElementById('fp-grid').innerHTML=filtered.length?filtered.map(p=>{
    const conf=p.confidence||0;
    const confColor=conf>=80?'#2e7d32':conf>=50?'#e65c00':'#c62828';
    return`<div style="padding:14px;border-radius:12px;background:var(--surface);border:1px solid var(--border);margin-bottom:8px;border-left:3px solid ${confColor};">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <span class="mono" style="font-size:13px;font-weight:700;word-break:break-all;flex:1;">${escHtml(p.ioc_value_pattern||p.pattern_hash||'-')}</span>
        <span class="tag" style="background:${confColor}15;color:${confColor};font-size:10px;">${conf}% confidence</span>
        <span class="tag green" style="font-size:10px;">${p.hit_count||0} suppressed</span>
        ${p.auto_close?'<span class="tag" style="background:rgba(0,137,123,.1);color:var(--cyan);font-size:10px;">⚡ Auto-close</span>':''}
      </div>
      <div style="font-size:12px;color:var(--text2);margin-bottom:6px;">${escHtml(p.reason||'No reason recorded')}</div>
      <div style="display:flex;gap:6px;align-items:center;">
        <span class="tag" style="font-size:10px;">${p.ioc_type||'?'}</span>
        <span class="text-xs text-muted">${p.customer_name||'global'}</span>
        <span class="text-xs text-muted">${ago(p.created_at)}</span>
        <span style="margin-left:auto;display:flex;gap:4px;">
          <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="fpAiAnalyze('${escHtml(p.ioc_value_pattern||'')}','${p.ioc_type||''}')">🤖 Analyze</button>
          <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="fpTestAgainst('${escHtml(p.ioc_value_pattern||'')}')">🧪 Test</button>
          <button class="btn" style="font-size:10px;padding:2px 8px;color:#c62828;" onclick="fpRemove(${p.id})">✕</button>
        </span>
      </div>
    </div>`}).join(''):'<div style="padding:24px;text-align:center;color:var(--text3);">No FP patterns yet. Mark findings as False Positive to start learning, or click <b>🤖 AI Suggest</b> to auto-discover.</div>';
}

// FP: AI analyzes WHY a pattern is false positive
async function fpAiAnalyze(pattern,iocType){
  showDrilldown('🤖 AI Analyzing FP Pattern...','<div style="text-align:center;padding:30px;"><span class="loading-spin" style="display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span> Analyzing with AI...</div>');
  const r=await apiPost('/api/ai/chat',{question:`Analyze this false positive pattern and explain: 1) Why does "${pattern}" (type: ${iocType}) trigger false positives? 2) What legitimate uses produce this pattern? 3) Should it be auto-closed or reviewed? 4) Risk of suppressing real threats by auto-closing this pattern.`});
  const answer=r?.response||r?.answer||'AI unavailable';
  showDrilldown('🤖 FP Analysis: '+pattern.substring(0,40),`<div style="padding:16px;font-size:14px;line-height:1.7;">${_linkEntities(escHtml(answer).replace(/\n/g,'<br>'))}</div>`);
}

// FP: AI suggests new patterns from recent analyst dismissals
async function fpAiSuggest(){
  const panel=document.getElementById('fp-ai-suggestions');
  panel.innerHTML=`<div style="padding:14px;border-radius:12px;background:rgba(123,31,162,.04);border:1px solid rgba(123,31,162,.1);"><div style="display:flex;align-items:center;gap:8px;"><span class="loading-spin" style="display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:#7b1fa2;border-radius:50%;animation:spin .6s linear infinite;"></span><span style="font-size:13px;font-weight:700;">AI analyzing recent false positive dismissals for learnable patterns...</span></div></div>`;
  const r=await apiPost('/api/ai/chat',{question:'Analyze all findings marked as false_positive in the last 30 days. Group by ioc_type and ioc_value pattern. For each group with 3+ occurrences, suggest a new FP suppression rule with: pattern, confidence level, and whether it should auto-close. Format as a numbered list.'});
  const answer=r?.response||r?.answer||'AI unavailable -  no suggestions';
  panel.innerHTML=`<div style="padding:14px;border-radius:12px;background:rgba(123,31,162,.04);border:1px solid rgba(123,31,162,.1);"><div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:8px;">🤖 AI-Suggested FP Patterns</div><div style="font-size:13px;line-height:1.7;color:var(--text2);">${escHtml(answer).replace(/\n/g,'<br>')}</div></div>`;
}

// FP: Test pattern against recent detections
async function fpTestPattern(){
  const pattern=prompt('Enter IOC value pattern to test (or part of it):');
  if(!pattern)return;
  const r=await api('/api/detections/?limit=100&search='+encodeURIComponent(pattern));
  const items=r?.items||r?.detections||r||[];
  showDrilldown('🧪 Pattern Test: "'+pattern.substring(0,40)+'"',
    `<div style="padding:12px;margin-bottom:12px;border-radius:8px;background:rgba(0,137,123,.04);font-size:14px;font-weight:700;">${items.length} detections match this pattern</div>`+
    (items.length?items.slice(0,20).map(d=>`<div style="padding:8px;border-bottom:1px solid var(--border);font-size:12px;display:flex;gap:8px;align-items:center;"><span class="tag" style="font-size:10px;">${d.ioc_type||'?'}</span><span class="mono" style="flex:1;word-break:break-all;">${escHtml((d.ioc_value||'').substring(0,60))}</span><span class="text-muted">${d.source||'?'}</span><span class="text-muted">${d.customer_name||'global'}</span></div>`).join(''):'<div class="text-muted" style="padding:12px;">No matches</div>'));
}

// FP: Test specific pattern against live detections
async function fpTestAgainst(pattern){
  const r=await api('/api/detections/?limit=50&search='+encodeURIComponent(pattern));
  const items=r?.items||r?.detections||r||[];
  toast(`Pattern matches ${items.length} recent detections`);
}

// FP: Remove pattern
async function fpRemove(id){
  if(!confirm('Remove this FP pattern? Future detections matching it will no longer be auto-suppressed.'))return;
  await fetch('/api/fp-patterns/'+id,{method:'DELETE'});
  toast('FP pattern removed');loadFP();
}

// ═══ SECTOR ADVISORIES - /api/sector/advisories, POST /api/sector/detect-now ═══
async function loadAdvisories(){
  const data=await api('/api/sector/advisories');const items=data?.advisories||data||[];
  document.getElementById('adv-list').innerHTML=items.map(a=>
    `<div class="adv-card">
      <div class="adv-head"><span class="tag high">${a.affected_industries||a.sector||'-'}</span>
        ${a.severity?sevTag(a.severity):''}
        <span class="text-xs text-muted" style="margin-left:auto;">${ago(a.created_at)}</span></div>
      <div class="adv-body">${a.ai_narrative||a.advisory_text||a.narrative||'-'}</div>
      <div class="adv-foot">
        ${a.affected_customer_count?`<span>👥 ${a.affected_customer_count} customers affected</span>`:''}
        ${a.finding_count?`<span>🎯 ${a.finding_count} related findings</span>`:''}
        ${a.campaign_id?`<span>⚔️ Campaign #${a.campaign_id}</span>`:''}
      </div>
    </div>`).join('')||'<div class="empty">Sector advisories generate when multiple customers in same industry face similar threats</div>';
}
async function triggerSectorDetect(){toast('Running sector campaign detection...');await apiPost('/api/sector/detect-now');setTimeout(loadAdvisories,2000);}

// ═══ UNATTRIBUTED - /api/unattributed-intel, POST /api/match-intel-all, POST /api/attribution/run ═══
async function loadUnattr(){
  const data=await api('/api/unattributed-intel');const items=data?.detections||data||[];
  document.getElementById('unattr-grid').innerHTML=items.slice(0,50).map(d=>
    `<div class="det-card">
      <div class="det-top"><span class="tag info">${d.ioc_type||'-'}</span><span class="text-xs text-muted">${ago(d.created_at||d.collected_at)}</span></div>
      <div class="mono text-sm font-bold" style="word-break:break-all;margin:6px 0;">${d.ioc_value||'-'}</div>
      <div class="det-meta"><span>📡 ${d.all_sources||d.source||'-'}</span><span class="mono">📊 ${d.confidence?d.confidence.toFixed(2):'-'}</span>
      <button class="btn text-xs" style="padding:2px 8px;margin-left:auto;" onclick="apiPost('/api/enrich/'+${d.id});toast('Enriching...')">🔬 Enrich</button></div>
    </div>`).join('')||'<div class="empty">All intel attributed! Run matching to check for new links.</div>';
}
async function triggerMatchAll(){toast('Running intel matching across all customers...');await apiPost('/api/match-intel-all');setTimeout(()=>{toast('Matching complete');loadUnattr();},2000);}
async function triggerCollect(){toast('Collecting from all 33 sources...');await apiPost('/api/collect-all');setTimeout(()=>{toast('Collection cycle started');loadOv();},1500);}

// ═══ AI CHAT - POST /api/ai/query, POST /api/agent/query ═══
function toggleAI(){document.getElementById('ai-panel')?.classList.toggle('open');}
async function sendAI(){
  const inp=document.getElementById('ai-input');const q=inp?.value?.trim();if(!q)return;
  const msgs=document.getElementById('ai-msgs');
  msgs.innerHTML+=`<div class="ai-msg user">${q}</div>`;inp.value='';msgs.scrollTop=msgs.scrollHeight;
  const r=await apiPost('/api/ai/query',{query:q,provider:_aiProvider});
  const answer=r?.response||r?.answer||r?.content||'No response - AI provider may be offline';
  msgs.innerHTML+=`<div class="ai-msg bot">${answer}</div>`;msgs.scrollTop=msgs.scrollHeight;
}

// ═══ AGENTIC AI QUERY BAR ═══
function askChip(el){
  const txt=el.textContent.replace(/^[^\s]+\s/,'');
  document.getElementById('ai-bar-q').value=txt;
  sendBarAI();
}

// Smart AI Bar -  Universal search + compromise check + AI chat
function classifyInput(q){
  q=q.trim();
  // ── Navigation commands (go directly to pages/entities) ──
  const navMatch=q.match(/^(?:open|go to|show|navigate)\s+(?:customer|cust)\s+(.+)/i);
  if(navMatch) return {type:'nav_customer',icon:'🏢',label:'Open Customer',param:navMatch[1]};
  const navFi=q.match(/^(?:open|show)\s+finding\s*#?\s*(\d+)/i);
  if(navFi) return {type:'nav_finding',icon:'🔍',label:'Open Finding',param:navFi[1]};
  if(/^(?:go to|show|open)\s+(findings|actors|darkweb|campaigns|customers|remediations|exposure|settings|detections)/i.test(q))
    return {type:'nav_page',icon:'📄',label:'Navigate',param:RegExp.$1.toLowerCase()};

  // ── IOC Classification (40+ types) ──
  // Email
  if(/^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$/.test(q)) return {type:'email',icon:'📧',label:'Email Compromise Check'};
  // Hashes
  if(/^[a-fA-F0-9]{32}$/.test(q)) return {type:'md5',icon:'#️⃣',label:'MD5 Hash Lookup'};
  if(/^[a-fA-F0-9]{40}$/.test(q)) return {type:'sha1',icon:'#️⃣',label:'SHA-1 Hash Lookup'};
  if(/^[a-fA-F0-9]{64}$/.test(q)) return {type:'sha256',icon:'#️⃣',label:'SHA-256 Hash Lookup'};
  if(/^[a-fA-F0-9]{128}$/.test(q)) return {type:'sha512',icon:'#️⃣',label:'SHA-512 Hash Lookup'};
  // IP / CIDR
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(q)) return {type:'ip',icon:'🌐',label:'IP Reputation Check'};
  if(/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(q)) return {type:'cidr',icon:'🌐',label:'CIDR Range Check'};
  // CVE
  if(/^CVE-\d{4}-\d{4,7}$/i.test(q)) return {type:'cve',icon:'🛡️',label:'CVE Lookup'};
  if(/^GHSA-[\w-]+$/i.test(q)) return {type:'advisory',icon:'🛡️',label:'Advisory Lookup'};
  // AWS Keys
  if(/^AKIA[0-9A-Z]{16}/.test(q)) return {type:'aws_key',icon:'🔐',label:'AWS Key Exposure Check'};
  if(/aws.?secret.?key/i.test(q)&&/[A-Za-z0-9\/+=]{40}/.test(q)) return {type:'aws_secret',icon:'🔐',label:'AWS Secret Key Check'};
  // GitHub tokens (all 5 types)
  if(/^ghp_[A-Za-z0-9]{36}/.test(q)) return {type:'github_token',icon:'🔐',label:'GitHub PAT Check'};
  if(/^github_pat_[A-Za-z0-9_]{20,}/.test(q)) return {type:'github_token',icon:'🔐',label:'GitHub Fine-Grained PAT'};
  if(/^gho_[A-Za-z0-9]{36}/.test(q)) return {type:'github_token',icon:'🔐',label:'GitHub OAuth Token'};
  if(/^ghs_[A-Za-z0-9]{36}/.test(q)) return {type:'github_token',icon:'🔐',label:'GitHub App Token'};
  if(/^ghu_[A-Za-z0-9]{36}/.test(q)) return {type:'github_token',icon:'🔐',label:'GitHub User Token'};
  // GitLab
  if(/^glpat-[A-Za-z0-9\-_]{20}/.test(q)) return {type:'gitlab_pat',icon:'🔐',label:'GitLab PAT Check'};
  // Stripe
  if(/^sk_live_[A-Za-z0-9]{24,}/.test(q)) return {type:'stripe_key',icon:'💳',label:'Stripe Key Check'};
  // OpenAI / Anthropic
  if(/^sk-ant-api\d{2}-/.test(q)) return {type:'anthropic_key',icon:'🔐',label:'Anthropic Key Check'};
  if(/^sk-(?:proj|prod|live)-/.test(q)||/^sk-[A-Za-z0-9]{48,}/.test(q)) return {type:'openai_key',icon:'🔐',label:'OpenAI Key Check'};
  // Slack
  if(/^xox[bp]-/.test(q)) return {type:'slack_token',icon:'🔐',label:'Slack Token Check'};
  // SendGrid
  if(/^SG\.[A-Za-z0-9\-_]{15,}\.[A-Za-z0-9\-_]{15,}/.test(q)) return {type:'sendgrid_key',icon:'🔐',label:'SendGrid Key Check'};
  // Google
  if(/^AIza[0-9A-Za-z\-_]{35}/.test(q)) return {type:'google_key',icon:'🔐',label:'Google API Key Check'};
  // Azure
  if(/\.blob\.core\.windows\.net.*sig=/.test(q)) return {type:'azure_sas',icon:'☁️',label:'Azure SAS Token Check'};
  // Private Key
  if(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(q)) return {type:'private_key',icon:'🔑',label:'Private Key Exposure'};
  // JWT
  if(/^ey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}$/.test(q)) return {type:'jwt',icon:'🔑',label:'JWT Token Check'};
  // OAuth
  if(/^ya29\.[A-Za-z0-9\-_]+$/.test(q)) return {type:'google_oauth',icon:'🔑',label:'Google OAuth Token'};
  // DB Connection String
  if(/^(?:mysql|postgresql|mongodb|redis):\/\//.test(q)) return {type:'db_conn',icon:'🗄️',label:'DB Connection String'};
  // Remote cred
  if(/^(?:rdp|ssh|vnc|ftp):\/\//.test(q)) return {type:'remote_cred',icon:'🔐',label:'Remote Credential Check'};
  // Onion
  if(/\.onion\b/.test(q)) return {type:'onion',icon:'🧅',label:'Dark Web Address'};
  // Financial PII
  if(/^\d{3}-\d{2}-\d{4}$/.test(q)) return {type:'ssn',icon:'⚠️',label:'SSN Check (local DB only)'};
  if(/^4\d{12,18}$/.test(q)||/^5[1-5]\d{14}$/.test(q)||/^3[47]\d{13}$/.test(q)) return {type:'card',icon:'💳',label:'Card Number Check'};
  if(/^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}/.test(q)) return {type:'iban',icon:'💳',label:'IBAN Check'};
  // Bitcoin/crypto
  if(/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(q)||/^bc1[a-z0-9]{39,59}$/.test(q)) return {type:'btc',icon:'₿',label:'Bitcoin Address Check'};
  if(/^0x[a-fA-F0-9]{40}$/.test(q)) return {type:'eth',icon:'⟠',label:'Ethereum Address Check'};
  // NTLM hash
  if(/^[a-fA-F0-9]{16,32}:[a-fA-F0-9]{32}$/.test(q)) return {type:'ntlm',icon:'🔐',label:'NTLM Hash Check'};
  // Domain (must be after all protocol checks)
  if(/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(q)&&q.includes('.')&&!q.includes(' '))
    return {type:'domain',icon:'🔗',label:'Domain Intel Lookup'};
  // Credential combos (email:password or user:pass)
  if(/^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}:.{6,}$/.test(q)) return {type:'cred_combo',icon:'🔓',label:'Credential Combo Check'};
  // URL
  if(/^https?:\/\//.test(q)) return {type:'url',icon:'🔗',label:'URL Check'};
  return {type:'natural_language',icon:'✦',label:'AI Analysis'};
}

function renderCompromiseResults(data,q){
  const cl=classifyInput(q);
  const sev=data.severity_summary||{};
  const critCount=sev.critical||0;const total=data.total_hits||0;const compromised=data.compromised;
  let statusColor=compromised?(critCount>0?'#c62828':'#e65100'):'#2e7d32';
  let statusBg=compromised?(critCount>0?'rgba(198,40,40,.06)':'rgba(230,92,0,.06)'):'rgba(46,125,50,.06)';
  let statusIcon=compromised?(critCount>0?'🚨':'⚠️'):'✅';
  let statusText=compromised?`COMPROMISED -  ${total} finding${total!==1?'s':''} across ${(data.sources_checked||[]).filter(s=>s.hits>0).length} sources`:'No compromise evidence found';
  let html=`<div style="padding:14px;border-radius:12px;background:${statusBg};border-left:4px solid ${statusColor};margin-bottom:12px;">
    <div style="display:flex;align-items:center;gap:8px;"><span style="font-size:20px;">${statusIcon}</span>
    <div><div style="font-weight:800;font-size:15px;color:${statusColor};">${statusText}</div>
    <div style="font-size:12px;color:var(--text3);margin-top:2px;">${cl.icon} ${cl.label}: <code style="background:var(--bg2);padding:2px 6px;border-radius:4px;font-size:12px;">${q.length>50?q.substring(0,50)+'...':q}</code> -  Type: <b>${data.query_type||'?'}</b></div></div></div></div>`;
  html+=`<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;">`;
  for(const src of (data.sources_checked||[])){
    const ok=src.status==='ok';const hits=src.hits||0;
    const color=hits>0?'#c62828':ok?'#2e7d32':'#9e9e9e';
    const bg=hits>0?'rgba(198,40,40,.08)':ok?'rgba(46,125,50,.06)':'rgba(0,0,0,.03)';
    html+=`<span style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;background:${bg};color:${color};border:1px solid ${color}22;">
      ${hits>0?'🔴':ok?'🟢':'⚪'} ${src.name} ${hits>0?'<b>'+hits+'</b>':ok?'clean':src.status.replace('skipped_no_key','no key').replace(/^http_/,'HTTP ').replace(/^error:.*/,'err')}</span>`;
  }
  html+=`</div>`;
  if(total>0){
    html+=`<div style="font-size:12px;font-weight:700;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Findings (${total})</div>`;
    for(const f of (data.findings||[]).slice(0,15)){
      const fsev=f.severity||'MEDIUM';
      const sevCol={CRITICAL:'#c62828',HIGH:'#e65100',MEDIUM:'#e65c00',LOW:'#2e7d32'}[fsev]||'#666';
      const sevBg={CRITICAL:'rgba(198,40,40,.05)',HIGH:'rgba(230,81,0,.05)',MEDIUM:'rgba(230,92,0,.05)',LOW:'rgba(46,125,50,.05)'}[fsev]||'transparent';
      const srcIcon={'arguswatch_db':'🗄️','arguswatch_findings':'📋','hudsonrock':'🪨','hibp':'🔓','sourcegraph':'🔍','virustotal':'🦠','darkweb_mention':'🌑'}[f.source]||'📌';
      const matchLabel={'exact':'Exact Match','partial':'Partial Match','stealer_log':'Stealer Log','breach':'Data Breach','code_leak':'Code Leak','malware_scan':'Malware Scan','finding':'Intel Finding','darkweb':'Dark Web'}[f.match_type]||f.match_type;
      html+=`<div style="padding:10px 12px;border-radius:8px;background:${sevBg};margin-bottom:6px;border-left:3px solid ${sevCol};">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-weight:700;font-size:13px;">${srcIcon} ${f.source} -  ${matchLabel}</span>
          <span style="font-size:11px;font-weight:800;color:${sevCol};padding:2px 8px;border-radius:4px;background:${sevCol}11;">${fsev}</span>
        </div>
        <div style="font-size:12px;color:var(--text2);margin-top:4px;line-height:1.4;">${(f.context||f.title||'').substring(0,200)}</div>
        ${f.breach_name?`<div style="font-size:11px;color:var(--text3);margin-top:3px;">Breach: <b>${f.breach_name}</b> (${f.breach_date||'?'}) -  ${(f.data_classes||[]).slice(0,4).join(', ')}</div>`:''}
        ${f.url?`<a href="${f.url}" target="_blank" style="font-size:11px;color:#e65c00;">View source -></a>`:''}
        ${f.found_at?`<div style="font-size:10px;color:var(--text4);margin-top:2px;">Detected: ${f.found_at}</div>`:''}
      </div>`;
    }
    if(total>15) html+=`<div style="text-align:center;font-size:12px;color:var(--text3);padding:8px;">... and ${total-15} more</div>`;
  }
  html+=`<div style="margin-top:12px;padding:10px;border-radius:8px;background:var(--bg2);font-size:12px;color:var(--text3);"><b>Try also:</b> `;
  if(data.query_type==='email'){const d=q.split('@')[1]||'';html+=`<a href="#" onclick="document.getElementById('ai-bar-q').value='${d}';sendBarAI();return false" style="color:#e65c00;">Check domain ${d}</a>`;}
  else if(data.query_type==='domain'){html+=`<a href="#" onclick="document.getElementById('ai-bar-q').value='admin@${q}';sendBarAI();return false" style="color:#e65c00;">admin@${q}</a> · <a href="#" onclick="document.getElementById('ai-bar-q').value='security@${q}';sendBarAI();return false" style="color:#e65c00;">security@${q}</a>`;}
  else{html+=`<a href="#" onclick="document.getElementById('ai-bar-q').value='admin@company.com';sendBarAI();return false" style="color:#e65c00;">Email check</a> · <a href="#" onclick="document.getElementById('ai-bar-q').value='CVE-2024-3400';sendBarAI();return false" style="color:#e65c00;">CVE lookup</a>`;}
  html+=`</div>`;
  return html;
}

async function sendBarAI(){
  const inp=document.getElementById('ai-bar-q');const q=inp?.value?.trim();if(!q)return;
  const resp=document.getElementById('ai-bar-resp');
  resp.classList.add('visible');
  const msgs=document.getElementById('ai-msgs');
  if(msgs)msgs.innerHTML+=`<div class="ai-msg user">${q}</div>`;
  const cl=classifyInput(q);

  // ═══ NAVIGATION COMMANDS -  go directly to pages/entities ═══
  if(cl.type==='nav_page'){
    const pageMap={findings:'findings',actors:'actors',darkweb:'darkweb',campaigns:'campaigns',customers:'customers',remediations:'remediations',exposure:'exposure',settings:'settings',detections:'detections'};
    const page=pageMap[cl.param]||cl.param;
    resp.innerHTML=`<div style="padding:10px;border-radius:10px;background:rgba(0,137,123,.04);border-left:3px solid var(--green);">📄 Navigating to <b>${page}</b>...</div>`;
    go(page);return;
  }
  if(cl.type==='nav_customer'){
    const name=cl.param;
    resp.innerHTML=`<div style="padding:10px;border-radius:10px;background:rgba(0,137,123,.04);"><span class="loading-spin" style="display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span> Finding customer "${name}"...</div>`;
    try{
      const custs=await apiGet('/api/customers');
      const list=Array.isArray(custs)?custs:(custs.items||custs.customers||[]);
      const match=list.find(c=>(c.name||'').toLowerCase().includes(name.toLowerCase()));
      if(match){resp.innerHTML=`<div style="padding:10px;border-radius:10px;background:rgba(0,137,123,.04);border-left:3px solid var(--green);">🏢 Opening <b>${escHtml(match.name)}</b>...</div>`;openCu(match.id);}
      else{resp.innerHTML=`<div style="padding:10px;border-radius:10px;background:rgba(198,40,40,.04);border-left:3px solid #c62828;">❌ No customer matching "${escHtml(name)}". <a href="#" onclick="go('customers');return false" style="color:#e65c00;">Browse all -></a></div>`;}
    }catch(e){resp.innerHTML=`<div style="color:var(--text3);">Error searching customers: ${e.message}</div>`;}
    return;
  }
  if(cl.type==='nav_finding'){
    const fid=cl.param;
    resp.innerHTML=`<div style="padding:10px;border-radius:10px;background:rgba(0,137,123,.04);border-left:3px solid var(--green);">🔍 Opening finding #${fid}...</div>`;
    openFi(parseInt(fid));return;
  }

  if(cl.type!=='natural_language'){
    resp.innerHTML=`<div style="display:flex;align-items:center;gap:8px;color:var(--text3);"><span class="loading-spin" style="display:inline-block;width:16px;height:16px;border:2px solid var(--border2);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span> ${cl.icon} ${cl.label}... checking HudsonRock, HIBP, Sourcegraph, local DB...</div>`;
    try{
      const r=await fetch('/api/search/compromise/'+encodeURIComponent(q)).then(r=>r.json());
      const html=renderCompromiseResults(r,q);
      resp.innerHTML=html;
      if(msgs){msgs.innerHTML+=`<div class="ai-msg bot">${html}</div>`;msgs.scrollTop=msgs.scrollHeight;}

      // ═══ AGENTIC: If compromised, auto-trigger AI investigation ═══
      if(r?.compromised && r?.total_hits > 0){
        const invDiv=document.createElement('div');
        invDiv.id='ai-investigate-panel';
        invDiv.innerHTML=`
          <div style="margin-top:12px;padding:14px 16px;border-radius:12px;background:linear-gradient(135deg,rgba(123,31,162,.03),rgba(230,92,0,.03));border:1px solid rgba(123,31,162,.1);">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
              <span style="font-size:16px;">🔍</span>
              <div style="flex:1;">
                <div style="font-size:12px;font-weight:800;color:var(--text);">AI Agent Investigating...</div>
                <div style="font-size:10px;color:var(--text3);" id="inv-status">Phase 1: LLM deciding what to investigate next</div>
              </div>
              <div style="font-size:11px;font-weight:800;font-family:'JetBrains Mono';color:var(--orange);" id="inv-timer">0s</div>
            </div>
            <div style="display:flex;gap:4px;height:3px;border-radius:2px;overflow:hidden;">
              <div id="inv-bar-1" style="flex:1;background:rgba(123,31,162,.15);border-radius:2px;position:relative;overflow:hidden;">
                <div style="position:absolute;left:0;top:0;bottom:0;width:0%;background:var(--purple);border-radius:2px;transition:width .3s;animation:inv-fill1 2s ease forwards;"></div>
              </div>
              <div id="inv-bar-2" style="flex:1;background:rgba(0,137,123,.1);border-radius:2px;"></div>
              <div id="inv-bar-3" style="flex:1;background:rgba(230,92,0,.1);border-radius:2px;"></div>
            </div>
            <div style="display:flex;justify-content:space-between;margin-top:4px;font-size:9px;color:var(--text4);">
              <span>Phase 1: Decide</span><span>Phase 2: Query</span><span>Phase 3: Brief</span>
            </div>
          </div>`;
        resp.appendChild(invDiv);

        // Timer
        const invStart=Date.now();
        const invMaxTime=_aiProvider==='ollama'?90:15;
        const invTimer=setInterval(()=>{
          const elapsed=Math.floor((Date.now()-invStart)/1000);
          const el=document.getElementById('inv-timer');
          const st=document.getElementById('inv-status');
          if(el)el.textContent=elapsed+'s';
          if(st&&elapsed<3)st.textContent='Phase 1: LLM deciding what to investigate next';
          if(st&&elapsed>=3&&elapsed<20)st.textContent=_aiProvider==='ollama'?'Phase 1: Qwen 3.5 reasoning (~15-30s local)...':'Phase 1: LLM reasoning (~2-5s)...';
          if(st&&elapsed>=20&&elapsed<25)st.textContent='Phase 2: Running follow-up queries...';
          if(st&&elapsed>=25&&elapsed<60)st.textContent=_aiProvider==='ollama'?'Phase 3: Writing analyst brief (~15-30s local)...':'Phase 3: Writing analyst brief...';
          if(st&&elapsed>=60)st.textContent='Still working -  local models take 45-90s total...';
        },500);

        // Call investigation endpoint
        try{
          const inv=await apiPost('/api/ai/investigate',{
            query:q, query_type:cl.type,
            compromise_results:r, provider:_aiProvider
          });
          clearInterval(invTimer);
          const invElapsed=((Date.now()-invStart)/1000).toFixed(1);

          // Render the brief
          const panel=document.getElementById('ai-investigate-panel');
          if(panel && inv?.brief){
            const t=inv.timing||{};
            panel.innerHTML=`
              <div style="margin-top:12px;padding:16px;border-radius:12px;background:linear-gradient(135deg,rgba(123,31,162,.04),rgba(230,92,0,.03));border:1px solid rgba(123,31,162,.12);">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
                  <span style="font-size:18px;">${inv.agentic?'🤖':'📋'}</span>
                  <div style="flex:1;">
                    <div style="font-size:13px;font-weight:800;background:linear-gradient(135deg,#7b1fa2,#e65c00);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">${inv.agentic?'AI Agent Investigation Complete':'Quick Assessment'}</div>
                  </div>
                  <span style="padding:3px 8px;border-radius:6px;background:rgba(0,137,123,.08);font-size:10px;font-weight:700;color:var(--cyan);">${invElapsed}s</span>
                </div>
                <div style="font-size:13px;color:var(--text);line-height:1.7;margin-bottom:10px;">${_linkEntities(inv.brief)}</div>
                ${inv.actions_taken&&inv.actions_taken[0]!=='skip'?`<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;">${inv.actions_taken.map(a=>`<span style="padding:2px 8px;border-radius:12px;background:rgba(123,31,162,.06);font-size:10px;font-weight:600;color:var(--purple);">${a.replace('check_','').replace('_',' ')}</span>`).join('')}</div>`:''}
                <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:9px;color:var(--text4);padding-top:6px;border-top:1px solid rgba(0,0,0,.04);">
                  <span>Provider: ${inv.provider||'?'}</span>
                  <span>Phase 1 (decide): ${t.phase1_decide||'?'}s ${t.phase1_method==='llm'?'🤖':'⚡'}</span>
                  <span>Phase 2 (query): ${t.phase2_queries||'?'}s ⚡</span>
                  <span>Phase 3 (brief): ${t.phase3_synthesize||'?'}s ${t.phase3_method==='llm'?'🤖':'⚡'}</span>
                  ${inv.agentic?'<span style="color:var(--purple);font-weight:700;">✅ Genuinely Agentic</span>':'<span>📋 Rule-based (clean result)</span>'}
                </div>
              </div>`;
            if(msgs){msgs.innerHTML+=`<div class="ai-msg bot">${panel.innerHTML}</div>`;msgs.scrollTop=msgs.scrollHeight;}
          }
        }catch(invErr){
          clearInterval(invTimer);
          const panel=document.getElementById('ai-investigate-panel');
          if(panel)panel.innerHTML=`<div style="margin-top:8px;font-size:11px;color:var(--text4);">AI investigation unavailable: ${invErr.message||'timeout'}. Compromise results above are still valid.</div>`;
        }
      }
    }catch(e){
      resp.innerHTML=`<div style="padding:12px;border-radius:10px;background:rgba(198,40,40,.04);border-left:3px solid #c62828;"><b>❌ Search Failed</b><br>${e.message||'Network error'}<br><span style="font-size:12px;color:var(--text4);">Check intel-proxy: <code>docker logs arguswatch-intel-proxy</code></span></div>`;
    }
    return;
  }
  resp.innerHTML=`<div id="ai-loading" style="padding:16px 20px;border-radius:14px;background:linear-gradient(135deg,rgba(230,92,0,.04),rgba(0,137,123,.03));border:1.5px solid rgba(230,92,0,.12);">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
      <div style="width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,rgba(230,92,0,.15),rgba(0,137,123,.1));display:flex;align-items:center;justify-content:center;"><span class="loading-spin" style="display:inline-block;width:16px;height:16px;border:2px solid rgba(230,92,0,.2);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span></div>
      <div style="flex:1;">
        <div style="font-size:13px;font-weight:800;color:var(--text);">ArgusWatch Agentic AI</div>
        <div style="font-size:11px;color:var(--text3);" id="ai-loading-status">Analyzing threat landscape with ${_aiProvider==='ollama'?'🦙 Qwen (local)':_aiProvider==='anthropic'?'🟣 Claude':_aiProvider==='openai'?'🤖 GPT':'💎 Gemini'}...</div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--orange);" id="ai-countdown">0s</div>
        <div style="font-size:9px;color:var(--text4);text-transform:uppercase;">elapsed</div>
      </div>
    </div>
    <div style="height:4px;border-radius:4px;background:rgba(230,92,0,.08);overflow:hidden;">
      <div id="ai-progress-bar" style="height:100%;border-radius:4px;background:linear-gradient(90deg,#e65c00,#ff8c42,#00897b);width:0%;transition:width .5s ease;"></div>
    </div>
    <div style="display:flex;gap:12px;margin-top:8px;font-size:10px;color:var(--text4);">
      <span>📡 Querying ${_stats?.total_detections||'...'} detections</span>
      <span>🏢 ${_stats?.active_customers||'...'} customers</span>
      <span>🎭 Matching actors to industries</span>
    </div>
  </div>`;
  // Countdown timer
  const _aiStart=Date.now();
  const _maxTime=_aiProvider==='ollama'?90:15;
  const _aiTimer=setInterval(()=>{
    const elapsed=Math.floor((Date.now()-_aiStart)/1000);
    const el=document.getElementById('ai-countdown');
    const bar=document.getElementById('ai-progress-bar');
    const status=document.getElementById('ai-loading-status');
    if(el)el.textContent=elapsed+'s';
    if(bar)bar.style.width=Math.min(elapsed/_maxTime*100,95)+'%';
    if(status&&elapsed>5&&elapsed<15)status.textContent='Building context from customer data...';
    if(status&&elapsed>=15&&elapsed<30)status.textContent='Calling tools: search_customers, search_findings...';
    if(status&&elapsed>=30&&elapsed<60)status.textContent='AI reasoning with tool results (local: 15-60s)...';
    if(status&&elapsed>=60)status.textContent='Deep analysis -  processing tool chain...';
  },500);
  // Use reliable two-phase endpoint for data questions (classify->query->summarize, no tool-calling dependency)
  const isDataQ=/customer|finding|actor|exposure|threat|critical|dark.?web|remediat|score|detect|mention|target|breach|leaked|compromis/i.test(q);
  const endpoint=isDataQ?'/api/ai/chat':'/api/ai/query';
  const r=await apiPost(endpoint,{query:q,provider:_aiProvider});
  clearInterval(_aiTimer);
  const _aiElapsed=((Date.now()-_aiStart)/1000).toFixed(1);
  const _toolsUsed=r?.tools_used||[];
  const _iterations=r?.iterations||0;
  const _isAgentic=r?.agentic||false;
  let answer=r?.response||r?.answer||r?.content||'';
  if(!answer||answer.includes('No response')||answer.includes('No AI provider configured')){
    const st=_stats||{};const ql=q.toLowerCase();
    if(ql.includes('critical')||ql.includes('attention')){
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(198,40,40,.04);border-left:3px solid #c62828;"><b>🚨 Critical Detections</b><br><b>${st.severity?.CRITICAL||0} CRITICAL</b> across ${st.active_customers||0} customers. <a href="#" onclick="go('findings');return false" style="color:#e65c00;font-weight:700;">View Findings -></a></div><div style="margin-top:8px;font-size:12px;color:var(--text4);">💡 Paste an email to check if compromised.</div>`;
    }else if(ql.includes('exposure')||ql.includes('score')){
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(230,92,0,.04);border-left:3px solid var(--orange);"><b>📈 Exposure</b><br>Max: <b>${st.max_exposure||' - '}/100</b>. <a href="#" onclick="drillExposureFormula();return false" style="color:#e65c00;font-weight:700;">D1-D5 Breakdown -></a></div>`;
    }else if(ql.includes('actor')||ql.includes('threat')){
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(123,31,162,.04);border-left:3px solid #7b1fa2;"><b>🎭 Actors</b><br>${st.total_actors||0} tracked. <a href="#" onclick="go('actors');return false" style="color:#e65c00;font-weight:700;">Browse -></a></div>`;
    }else if(ql.includes('dark web')||ql.includes('darkweb')||ql.includes('mention')){
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(123,31,162,.04);border-left:3px solid #7b1fa2;"><b>🌑 Dark Web</b><br>${st.darkweb_mentions||0} mentions. <a href="#" onclick="drillDarkWeb();return false" style="color:#e65c00;font-weight:700;">Details -></a></div>`;
    }else if(ql.includes('compromised')||ql.includes('breached')||ql.includes('leaked')||ql.includes('check my')||ql.includes('is my')){
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(0,137,123,.04);border-left:3px solid var(--green);"><b>🔍 Compromise Search</b><br>Paste directly into the bar:<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:6px;margin-top:8px;">
        <a href="#" onclick="document.getElementById('ai-bar-q').value='admin@yourcompany.com';sendBarAI();return false" class="btn" style="font-size:12px;">📧 Email</a>
        <a href="#" onclick="document.getElementById('ai-bar-q').value='yourcompany.com';sendBarAI();return false" class="btn" style="font-size:12px;">🔗 Domain</a>
        <a href="#" onclick="document.getElementById('ai-bar-q').value='192.168.1.1';sendBarAI();return false" class="btn" style="font-size:12px;">🌐 IP</a>
        <a href="#" onclick="document.getElementById('ai-bar-q').value='CVE-2024-3400';sendBarAI();return false" class="btn" style="font-size:12px;">🛡️ CVE</a></div>
        <div style="margin-top:8px;font-size:12px;color:var(--text3);">Auto-detects type and searches HudsonRock, HIBP, Sourcegraph, VirusTotal, and local DB.</div></div>`;
    }else if(ql.includes('asset')||ql.includes('unmonitor')||ql.includes('coverage')||ql.includes('gap')){
      const gaps=st.total_assets||0;const custs=st.total_customers||0;
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(0,137,123,.04);border-left:3px solid var(--green);">
        <b>🖥️ Asset Coverage</b>
        <div style="margin-top:8px;font-size:13px;color:var(--text2);line-height:1.6;">
          <b>${gaps}</b> total assets across <b>${custs}</b> customers.
        </div>
        <div style="margin-top:8px;padding:8px;border-radius:8px;background:var(--bg2);font-size:12px;color:var(--text3);line-height:1.5;">
          ⚠️ <b>Common gaps:</b> missing github_org (no code leak scanning), missing tech_stack (no CVE matching), missing IPs (no C2 correlation).<br>
          Open any customer -> click <b>📋 Onboarding</b> to see their completeness score.
        </div>
        <a href="#" onclick="go('customers');return false" style="display:inline-block;margin-top:8px;color:#e65c00;font-weight:700;font-size:12px;">View All Customers -></a>
      </div>`;
    }else if(ql.includes('changed')||ql.includes('24 hour')||ql.includes('today')||ql.includes('recent')||ql.includes('new')){
      const n24=st.new_24h||0;const crit=st.severity?.CRITICAL||0;const total=st.total_detections||0;
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(0,188,212,.04);border-left:3px solid var(--cyan);">
        <b>📈 Last 24 Hours</b>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:10px;">
          <div style="text-align:center;padding:8px;border-radius:8px;background:rgba(0,229,255,.06);"><div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:var(--cyan);">${n24}</div><div style="font-size:10px;color:var(--text4);">New IOCs</div></div>
          <div style="text-align:center;padding:8px;border-radius:8px;background:rgba(198,40,40,.06);"><div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:var(--red);">${crit}</div><div style="font-size:10px;color:var(--text4);">Critical Total</div></div>
          <div style="text-align:center;padding:8px;border-radius:8px;background:rgba(230,92,0,.06);"><div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:var(--orange);">${total}</div><div style="font-size:10px;color:var(--text4);">All Detections</div></div>
        </div>
        <div style="margin-top:8px;font-size:12px;color:var(--text3);">${n24>0?'⚡ '+n24+' new detections in last 24h -  ':'No new detections -  '}
          <a href="#" onclick="go('detections');return false" style="color:#e65c00;font-weight:700;">View Timeline -></a>
        </div>
      </div>`;
    }else if(ql.includes('risk')||ql.includes('reduc')||ql.includes('opportunit')||ql.includes('improve')||ql.includes('recommend')){
      const maxExp=st.max_exposure_score||0;const openF=st.open_findings||0;const critF=st.critical_findings||0;
      const noise=st.noise_elimination||{};const noisePct=noise.noise_pct||0;
      answer=`<div style="padding:12px;border-radius:10px;background:rgba(123,31,162,.04);border-left:3px solid #7b1fa2;">
        <b>🛡️ Risk Reduction Priorities</b>
        <div style="margin-top:10px;font-size:13px;color:var(--text2);line-height:1.8;">
          ${critF>0?'<div style="padding:6px 10px;border-radius:8px;background:rgba(198,40,40,.06);margin-bottom:6px;">🔴 <b>'+critF+' CRITICAL findings</b> -  patch/rotate immediately. <a href="#" onclick="go(\'findings\');return false" style="color:#e65c00;font-weight:700;">View -></a></div>':''}
          ${openF>0?'<div style="padding:6px 10px;border-radius:8px;background:rgba(230,92,0,.06);margin-bottom:6px;">🟠 <b>'+openF+' open findings</b> total -  triage and assign. <a href="#" onclick="go(\'findings\');return false" style="color:#e65c00;font-weight:700;">View -></a></div>':''}
          ${maxExp>50?'<div style="padding:6px 10px;border-radius:8px;background:rgba(198,40,40,.06);margin-bottom:6px;">📈 <b>Highest exposure: '+maxExp+'/100</b> -  open that customer and check D1-D5 breakdown.</div>':''}
          <div style="padding:6px 10px;border-radius:8px;background:rgba(0,137,123,.06);margin-bottom:6px;">🔍 <b>Quick wins:</b> Register tech_stack for all customers -> enables CVE matching. Register github_org -> enables code leak scanning.</div>
          ${noisePct>0?'<div style="padding:6px 10px;border-radius:8px;background:rgba(0,188,212,.06);">📊 <b>Signal vs noise:</b> '+Math.round(100-noisePct)+'% of IOCs attributed to customers, '+Math.round(noisePct)+'% global noise filtered.</div>':''}
        </div>
      </div>`;
    }else{
      answer=`<div style="padding:12px;border-radius:10px;background:var(--surface);border-left:3px solid var(--orange);">
        <b>📊 Platform Overview</b>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:10px;">
          <div style="text-align:center;padding:8px;border-radius:8px;background:rgba(0,188,212,.05);"><div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--cyan);">${st.total_detections||0}</div><div style="font-size:10px;color:var(--text4);">Detections</div></div>
          <div style="text-align:center;padding:8px;border-radius:8px;background:rgba(230,92,0,.05);"><div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--orange);">${st.total_findings||0}</div><div style="font-size:10px;color:var(--text4);">Findings</div></div>
          <div style="text-align:center;padding:8px;border-radius:8px;background:rgba(198,40,40,.05);"><div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--red);">${st.severity?.CRITICAL||0}</div><div style="font-size:10px;color:var(--text4);">Critical</div></div>
        </div>
        <div style="margin-top:12px;padding:10px;border-radius:8px;background:var(--bg2);font-size:12px;color:var(--text2);line-height:1.6;">
          <b>🔍 Smart Search:</b> Paste email, IP, hash, CVE, domain, or API key -  auto-detects and searches all sources.<br>
          <b>💬 Ask:</b> <a href="#" onclick="document.getElementById('ai-bar-q').value='What CRITICAL detections need attention?';sendBarAI();return false" style="color:#e65c00;">critical detections</a> · <a href="#" onclick="document.getElementById('ai-bar-q').value='Is my data compromised?';sendBarAI();return false" style="color:#e65c00;">compromise check</a> · <a href="#" onclick="document.getElementById('ai-bar-q').value='Any dark web mentions?';sendBarAI();return false" style="color:#e65c00;">dark web</a>
        </div></div>`;
    }
  }
  // Wrap AI-generated answers in a styled card (skip for builtin HTML cards that already have styling)
  const isBuiltinCard=answer.includes('border-left:')&&answer.includes('border-radius:10px');
  const provLabel=r?.provider==='ollama'?'🦙 Qwen (Local)':r?.provider==='anthropic'?'🟣 Claude':r?.provider==='openai'?'🤖 GPT-5.3':r?.provider==='google'?'💎 Gemini':r?.provider||'system';
  const modelName=r?.model||'';
  if(answer&&!isBuiltinCard){
    // Format markdown-like text
    let formatted=escHtml(answer)
      .replace(/\*\*(.*?)\*\*/g,'<b>$1</b>')
      .replace(/\n- /g,'<br>• ')
      .replace(/\n\d+\. /g,(m)=>'<br>'+m.trim()+' ')
      .replace(/\n/g,'<br>');
    // Entity linking -  make customer names, finding IDs, CVEs clickable
    formatted=_linkEntities(formatted);
    // Action bar -  contextual navigation buttons based on query intent
    const actionHtml=_actionBar(q,r);
    resp.innerHTML=`<div style="border-radius:14px;border:1.5px solid rgba(230,92,0,.12);overflow:hidden;">
      <div style="padding:14px 18px;background:linear-gradient(135deg,rgba(230,92,0,.06),rgba(0,137,123,.03));">
        <div style="display:flex;align-items:center;gap:10px;">
          <div style="width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#e65c00,#ff8c42);display:flex;align-items:center;justify-content:center;font-size:14px;color:#fff;font-weight:800;">⚡</div>
          <div style="flex:1;">
            <div style="font-size:13px;font-weight:800;background:linear-gradient(135deg,#e65c00,#00897b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">ArgusWatch Agentic AI</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="padding:3px 8px;border-radius:6px;background:rgba(230,92,0,.08);font-size:10px;font-weight:700;color:var(--orange);">${provLabel}</span>
            <span style="padding:3px 8px;border-radius:6px;background:rgba(0,137,123,.08);font-size:10px;font-weight:700;color:var(--cyan);">${_aiElapsed}s</span>
          </div>
        </div>
      </div>
      <div style="padding:16px 18px;font-size:14px;color:var(--text);line-height:1.7;">${formatted}${actionHtml}</div>
      ${modelName&&modelName!=='error'&&modelName!=='offline'&&modelName!=='slow'?`<div style="padding:8px 18px;border-top:1px solid rgba(230,92,0,.08);font-size:10px;color:var(--text4);display:flex;gap:12px;flex-wrap:wrap;">
        <span>Model: ${modelName}</span>
        <span>Response: ${_aiElapsed}s</span>
        <span>Provider: ${r?.provider||'?'}</span>
        ${_isAgentic?`<span style="color:var(--orange);font-weight:700;">⚡ Agentic (${_iterations} iterations)</span>`:''}
        ${r?.method==='reliable_two_phase'?`<span style="color:var(--green);font-weight:700;">✅ Two-Phase (classify->query->summarize)</span>`:''}
        ${r?.intents?.length?`<span style="color:var(--cyan);">🎯 Intents: ${r.intents.join(', ')}</span>`:''}
        ${_toolsUsed.length?`<span style="color:var(--cyan);">🔧 Tools: ${[...new Set(_toolsUsed)].join(', ')}</span>`:''}
      </div>`:''}
    </div>`;
  } else {
    resp.innerHTML=answer;
  }
  if(msgs){msgs.innerHTML+=`<div class="ai-msg bot">${resp.innerHTML}</div>`;msgs.scrollTop=msgs.scrollHeight;}
}

// ═══ Entity Linking -  convert customer/finding/actor names in AI text to clickable links ═══
function _linkEntities(html){
  if(!html||!_customers)return html;
  let out=html;
  // Link customer names
  for(const c of _customers){
    if(!c.name||c.name.length<3)continue;
    const escaped=c.name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const rx=new RegExp('\\b('+escaped+')\\b(?![^<]*>)','gi');
    out=out.replace(rx,`<a href="#" onclick="openCu(${c.id});return false" style="color:#e65c00;font-weight:600;text-decoration:underline dotted;" title="Open ${escHtml(c.name)}">$1</a>`);
  }
  // Link Finding #123 patterns
  out=out.replace(/\b(Finding|finding)\s*#?\s*(\d+)\b/g,
    '<a href="#" onclick="openFi($2);return false" style="color:#e65c00;font-weight:600;text-decoration:underline dotted;">$1 #$2</a>');
  // Link CVE-XXXX-XXXXX patterns
  out=out.replace(/\b(CVE-\d{4}-\d{4,7})\b/g,
    `<a href="#" onclick="document.getElementById('ai-bar-q').value='$1';sendBarAI();return false" style="color:#e65c00;font-weight:600;text-decoration:underline dotted;" title="Look up $1">$1</a>`);
  return out;
}

// ═══ Quick Action Bar -  show contextual actions after AI responses ═══
function _actionBar(q,r){
  const intents=r?.intents||[];
  const actions=[];
  if(intents.includes('findings')||/finding/i.test(q))
    actions.push(`<a href="#" onclick="go('findings');return false" class="btn" style="font-size:11px;">📋 View Findings</a>`);
  if(intents.includes('customers')||/customer/i.test(q))
    actions.push(`<a href="#" onclick="go('customers');return false" class="btn" style="font-size:11px;">🏢 Customers</a>`);
  if(intents.includes('actors')||/actor|threat|apt/i.test(q))
    actions.push(`<a href="#" onclick="go('actors');return false" class="btn" style="font-size:11px;">🎭 Actors</a>`);
  if(intents.includes('darkweb')||/dark.?web|mention/i.test(q))
    actions.push(`<a href="#" onclick="go('darkweb');return false" class="btn" style="font-size:11px;">🌑 Dark Web</a>`);
  if(intents.includes('exposure')||/exposure|score|risk/i.test(q))
    actions.push(`<a href="#" onclick="go('exposure');return false" class="btn" style="font-size:11px;">📊 Exposure</a>`);
  if(intents.includes('remediations')||/remediat|playbook/i.test(q))
    actions.push(`<a href="#" onclick="go('remediations');return false" class="btn" style="font-size:11px;">🔧 Remediations</a>`);
  if(!actions.length)return'';
  return`<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;padding-top:8px;border-top:1px solid rgba(0,0,0,.04);">${actions.join('')}</div>`;
}


async function drillSeverity(sev){
  showDrilldown(`${_sevEmoji[sev]} Loading ${sev} detections...`,'<div style="text-align:center;padding:30px;color:var(--text3);">Fetching data...</div>');
  const data=await api(`/api/detections/?limit=30&severity=${sev}`);
  const items=data?.items||data?.detections||data||[];
  // Group by source
  const bySrc={};items.forEach(d=>{const s=d.source||'unknown';if(!bySrc[s])bySrc[s]=[];bySrc[s].push(d);});
  const srcSummary=Object.entries(bySrc).sort((a,b)=>b[1].length-a[1].length);
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:${_sevColors[sev]};">${items.length}</div><div class="dd-stat-lbl">${sev} Detections</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${srcSummary.length}</div><div class="dd-stat-lbl">Source Feeds</div></div>
    <div style="flex:1;min-width:200px;padding:4px 0;">
      <div style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">Why ${sev}?</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.5;">${_sevExplain[sev]}</div>
    </div>
  </div>`;
  // Source breakdown mini-bars
  if(srcSummary.length){
    h+=`<div style="margin-bottom:16px;">`;
    srcSummary.forEach(([src,dets])=>{
      const pct=Math.round(dets.length/items.length*100);
      h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;">
        <span style="min-width:120px;font-size:12px;font-weight:600;color:var(--text2);">📡 ${src}</span>
        <div style="flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden;">
          <div style="width:${pct}%;height:100%;background:${_sevColors[sev]};border-radius:4px;box-shadow:0 0 6px ${_sevColors[sev]}40;"></div>
        </div>
        <span style="font-size:12px;font-weight:700;color:var(--text);min-width:50px;text-align:right;">${dets.length} (${pct}%)</span>
      </div>`;
    });
    h+=`</div>`;
  }
  // Detection cards
  h+=`<div class="dd-grid">${items.slice(0,18).map(d=>{
    const conf=d.confidence?(d.confidence*100).toFixed(0)+'%':'?';
    return`<div class="dd-card ${_sevCls[sev]}">
      <div class="dd-card-ioc">${d.ioc_value||'-'}</div>
      <div class="dd-card-meta">
        <span class="dd-pill type">${d.ioc_type||'-'}</span>
        <span class="dd-pill src">📡 ${d.source||'-'}</span>
        <span class="dd-pill conf">📊 ${conf}</span>
        <span class="dd-pill time">${ago(d.collected_at||d.created_at)}</span>
      </div>
    </div>`;}).join('')}</div>`;
  showDrilldown(`${_sevEmoji[sev]} ${sev} Detections -  ${items.length} found`,h);
}

async function drillSevOverview(){
  showDrilldown('📊 Loading severity overview...','<div style="text-align:center;padding:30px;">Fetching...</div>');
  const stats=_stats||await api('/api/stats');
  const sev=stats?.severity||{};
  const sevs=[
    {name:'CRITICAL',count:sev.CRITICAL||sev.critical||0,color:'#c62828',emoji:'🔴'},
    {name:'HIGH',count:sev.HIGH||sev.high||0,color:'#ef6c00',emoji:'🟠'},
    {name:'MEDIUM',count:sev.MEDIUM||sev.medium||0,color:'#f9a825',emoji:'🟡'},
    {name:'LOW',count:sev.LOW||sev.low||0,color:'#2e7d32',emoji:'🟢'}
  ];
  const total=sevs.reduce((a,s)=>a+s.count,0)||1;
  let h=`<div class="dd-summary">`;
  sevs.forEach(s=>{
    h+=`<div class="dd-stat" style="cursor:pointer;" onclick="drillSeverity('${s.name}')">
      <div class="dd-stat-num" style="color:${s.color};">${s.count}</div>
      <div class="dd-stat-lbl">${s.emoji} ${s.name}</div>
    </div>`;
  });
  h+=`<div class="dd-stat"><div class="dd-stat-num" style="color:var(--text);">${total}</div><div class="dd-stat-lbl">Total</div></div></div>`;
  sevs.forEach(s=>{
    const pct=Math.round(s.count/total*100);
    h+=`<div style="display:flex;align-items:center;gap:12px;margin:10px 0;cursor:pointer;padding:10px 14px;border-radius:10px;border:1px solid var(--border);transition:all .2s;" onclick="drillSeverity('${s.name}')" onmouseover="this.style.borderColor='${s.color}40';this.style.boxShadow='0 0 12px ${s.color}15'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
      <span style="font-size:22px;">${s.emoji}</span>
      <div style="flex:1;">
        <div style="font-size:14px;font-weight:700;color:var(--text);">${s.name}</div>
        <div style="font-size:12px;color:var(--text3);margin-top:2px;">${_sevExplain[s.name]}</div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${s.color};text-shadow:0 0 8px ${s.color}30;">${s.count}</div>
        <div style="font-size:11px;color:var(--text4);">${pct}%</div>
      </div>
    </div>`;
  });
  showDrilldown('📊 Detection Severity Breakdown -  Click any severity for details',h);
}

async function drillTimeline(){
  showDrilldown('📈 Loading timeline...','<div style="text-align:center;padding:30px;">Fetching...</div>');
  const timeline=await api('/api/stats/timeline');
  if(!timeline?.length){showDrilldown('📈 Detection Timeline','<div style="padding:20px;text-align:center;color:var(--text4);">No timeline data</div>');return;}
  const total=timeline.reduce((a,t)=>a+(t.count||0),0);
  const peak=timeline.reduce((a,t)=>(t.count||0)>a.count?t:a,{count:0});
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${total}</div><div class="dd-stat-lbl">Total 7 Days</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--red);">${peak.count}</div><div class="dd-stat-lbl">Peak Day</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${peak.date||'-'}</div><div class="dd-stat-lbl" style="font-size:10px;">Peak Date</div></div>
    <div style="flex:1;padding:4px 0;">
      <div style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">What this means</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.5;">Detection volume tracks raw IOCs ingested from ${Object.keys(_stats?.severity||{}).length?'all':'your'} collector feeds. Spikes indicate new feed runs or emerging campaigns. Each detection flows through the D1-D5 exposure formula.</div>
    </div>
  </div>`;
  // Day-by-day cards
  h+=`<div class="dd-grid">`;
  timeline.forEach(t=>{
    const ct=t.count||0;
    const pct=Math.round(ct/(peak.count||1)*100);
    const isToday=t.date===(new Date().toISOString().split('T')[0]);
    const cardColor=ct===peak.count?'var(--red)':ct>0?'var(--cyan)':'var(--text4)';
    h+=`<div class="dd-card type-card" style="cursor:pointer;${isToday?'border-color:var(--cyan-b);box-shadow:0 0 12px var(--cyan-g);':''}" onclick="drillDay('${t.date}')">
      <div style="display:flex;align-items:center;justify-content:space-between;">
        <div style="font-size:13px;font-weight:700;color:var(--text);">${t.date||'-'}${isToday?' <span style=\\"font-size:10px;color:var(--cyan);\\">TODAY</span>':''}</div>
        <div style="font-size:24px;font-weight:900;font-family:'JetBrains Mono';color:${cardColor};text-shadow:0 0 8px ${cardColor}25;">${ct}</div>
      </div>
      <div style="height:6px;background:var(--bg3);border-radius:3px;margin-top:10px;overflow:hidden;">
        <div style="width:${pct}%;height:100%;background:${cardColor};border-radius:3px;transition:width .5s;box-shadow:0 0 6px ${cardColor}40;"></div>
      </div>
      <div style="font-size:11px;color:var(--text4);margin-top:6px;">Click for daily breakdown ▸</div>
    </div>`;
  });
  h+=`</div>`;
  showDrilldown('📈 Detection Timeline -  7-Day Breakdown',h);
}

async function drillDay(date){
  showDrilldown(`📅 Loading ${date}...`,'<div style="text-align:center;padding:30px;">Fetching...</div>');
  const data=await api(`/api/detections/?limit=50&date=${date}`);
  const items=data?.items||data?.detections||data||[];
  // Group by source and severity
  const bySrc={},bySev={};
  items.forEach(d=>{
    const s=d.source||'unknown';if(!bySrc[s])bySrc[s]=0;bySrc[s]++;
    const sv=d.severity||d.sev||'UNKNOWN';if(!bySev[sv])bySev[sv]=0;bySev[sv]++;
  });
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${items.length}</div><div class="dd-stat-lbl">Detections on ${date}</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${Object.keys(bySrc).length}</div><div class="dd-stat-lbl">Sources Active</div></div>
    ${Object.entries(bySev).map(([sv,ct])=>`<div class="dd-stat"><div class="dd-stat-num" style="color:${_sevColors[sv]||'var(--text)'};">${ct}</div><div class="dd-stat-lbl">${_sevEmoji[sv]||'⚪'} ${sv}</div></div>`).join('')}
  </div>`;
  h+=`<div class="dd-grid">${items.slice(0,24).map(d=>{
    const sv=(d.severity||'LOW').toUpperCase();
    return`<div class="dd-card ${_sevCls[sv]||'sev-low'}">
      <div class="dd-card-ioc">${d.ioc_value||'-'}</div>
      <div class="dd-card-meta">
        <span class="dd-pill type">${d.ioc_type||'-'}</span>
        <span class="dd-pill src">📡 ${d.source||'-'}</span>
        ${d.confidence?`<span class="dd-pill conf">📊 ${(d.confidence*100).toFixed(0)}%</span>`:''}
      </div>
    </div>`;}).join('')}</div>`;
  showDrilldown(`📅 ${date} -  ${items.length} Detections`,h);
}

async function drillIocOverview(){
  showDrilldown('🔬 Loading IOC types...','<div style="text-align:center;padding:30px;">Fetching...</div>');
  const iocTypes=await api('/api/stats/ioc-types');
  const entries=Array.isArray(iocTypes)?iocTypes:Object.entries(iocTypes||{}).map(([k,v])=>({type:k,count:v}));
  const total=entries.reduce((a,e)=>a+(e.count||0),0)||1;
  const typeColors={'url':'#e65c00','cve_id':'#00897b','ipv4':'#c62828','advisory':'#7b1fa2','hash_sha256':'#e65100','domain':'#2e7d32','email':'#1565c0','hash_md5':'#ec4899','hash_sha1':'#ef6c00','api_key':'#ad1457','ssn':'#ff6f00','credential':'#00695c'};
  const typeEmoji={'url':'🔗','cve_id':'🛡️','ipv4':'🌐','advisory':'📢','hash_sha256':'#️⃣','domain':'🏷️','email':'📧','hash_md5':'#️⃣','credential':'🔑','api_key':'🔐'};
  const typeExplain={'url':'Malicious URLs from phishing, C2 infrastructure, and exploit kit landing pages','cve_id':'Known vulnerabilities matched against customer tech stacks -  feeds D2 (Active Exploitation)','ipv4':'Suspicious IP addresses from threat feeds, C2 servers, and scanning infrastructure','advisory':'Vendor security advisories and CERT notifications','hash_sha256':'File hashes linked to malware samples, ransomware, and trojans','domain':'Malicious or typosquatted domains targeting customer brands','email':'Compromised email addresses from breach databases and stealer logs','hash_md5':'Legacy file hashes from older malware intelligence feeds','credential':'Leaked username/password combos from dark web and paste sites','api_key':'Exposed API keys and tokens found in public repositories'};
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${entries.length}</div><div class="dd-stat-lbl">IOC Types</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${total}</div><div class="dd-stat-lbl">Total IOCs</div></div>
  </div>`;
  entries.forEach(e=>{
    const t=e.type||e.ioc_type||'?';
    const ct=e.count||0;
    const pct=Math.round(ct/total*100);
    const col=typeColors[t]||'var(--text2)';
    const emoji=typeEmoji[t]||'📦';
    const explain=typeExplain[t]||'Threat intelligence indicator';
    h+=`<div style="display:flex;align-items:center;gap:12px;margin:8px 0;cursor:pointer;padding:12px 16px;border-radius:10px;border:1px solid var(--border);transition:all .2s;" onclick="drillIocType('${t}')" onmouseover="this.style.borderColor='${col}40';this.style.boxShadow='0 0 12px ${col}15'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
      <span style="font-size:22px;">${emoji}</span>
      <div style="flex:1;">
        <div style="font-size:14px;font-weight:700;color:var(--text);font-family:'JetBrains Mono';">${t}</div>
        <div style="font-size:12px;color:var(--text3);margin-top:2px;">${explain}</div>
        <div style="height:5px;background:var(--bg3);border-radius:3px;margin-top:6px;overflow:hidden;max-width:300px;">
          <div style="width:${pct}%;height:100%;background:${col};border-radius:3px;box-shadow:0 0 6px ${col}40;"></div>
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${col};text-shadow:0 0 8px ${col}30;">${ct.toLocaleString()}</div>
        <div style="font-size:11px;color:var(--text4);">${pct}% of total</div>
      </div>
    </div>`;
  });
  showDrilldown('🔬 IOC Type Distribution -  Click any type for details',h);
}

async function drillIocType(type){
  showDrilldown(`🔬 Loading ${type}...`,'<div style="text-align:center;padding:30px;">Fetching...</div>');
  const data=await api(`/api/detections/?limit=30&ioc_type=${type}`);
  const items=data?.items||data?.detections||data||[];
  const bySrc={};items.forEach(d=>{const s=d.source||'?';if(!bySrc[s])bySrc[s]=0;bySrc[s]++;});
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${items.length}</div><div class="dd-stat-lbl">${type} detections</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${Object.keys(bySrc).length}</div><div class="dd-stat-lbl">Source Feeds</div></div>
  </div>`;
  h+=`<div class="dd-grid">${items.slice(0,24).map(d=>{
    const sv=(d.severity||'LOW').toUpperCase();
    return`<div class="dd-card type-card">
      <div class="dd-card-ioc">${d.ioc_value||'-'}</div>
      <div class="dd-card-meta">
        <span class="dd-pill sev" style="color:${_sevColors[sv]||'var(--text3)'};border-color:${_sevColors[sv]||'var(--border)'}30;background:${_sevColors[sv]||'var(--text3)'}10;">${_sevEmoji[sv]||'⚪'} ${sv}</span>
        <span class="dd-pill src">📡 ${d.source||'-'}</span>
        ${d.confidence?`<span class="dd-pill conf">📊 ${(d.confidence*100).toFixed(0)}%</span>`:''}
        <span class="dd-pill time">${ago(d.collected_at||d.created_at)}</span>
      </div>
    </div>`;}).join('')}</div>`;
  showDrilldown(`🔬 ${type} -  ${items.length} Detections`,h);
}

// ═══ HERO STAT DRILLDOWNS ═══

// 1. THREAT PRESSURE INDEX
// ═══ CUSTOMER STAT DRILLDOWNS (INLINE - switches tabs within customer modal) ═══
function cuStatDrill(stat,cid){
  const _explain={
    assets:{tab:6,emoji:'🖥️',title:'Assets',color:'var(--cyan)',desc:'Assets are what the correlation engine matches IOCs against. Every domain, IP, email, keyword, and tech stack entry is cross-referenced against all 33 collectors.',formula:'Assets feed <b>D4 (Attack Surface)</b> -  larger surfaces guarantee a minimum exposure floor (D4×0.20). Also feeds <b>D5 (Asset Criticality)</b> -  weighted importance of exposed assets scales the impact multiplier.'},
    detections:{tab:7,emoji:'📡',title:'Detections vs Findings',color:'var(--amber)',desc:'<b>Detections</b> = raw IOC matches from 33 collectors. Every URL, hash, CVE, IP, or credential found in threat feeds that matches a registered asset creates a detection.<br><br><b>Findings</b> = deduplicated, AI-assessed threats. Multiple detections for the same IOC merge into one finding. Example: 3 collectors all see <code>http://evil.com/malware.exe</code> -> 3 detections, 1 finding.',formula:`<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;">
        <div style="padding:12px;border-radius:10px;background:var(--cyan-g);border:1px solid var(--cyan-b);">
          <div style="font-size:16px;font-weight:900;color:var(--cyan);">📡 Detections</div>
          <div style="font-size:12px;color:var(--text2);margin-top:4px;">Raw collector hits. Same IOC from 3 feeds = 3 detections. Audit trail.</div>
          <div style="margin-top:6px;font-size:11px;color:var(--text3);">Pipeline: Collector -> Pattern Match -> IOC Extract -> Asset Correlation -> <b>Detection</b></div>
        </div>
        <div style="padding:12px;border-radius:10px;background:var(--orange-g);border:1px solid var(--orange-b);">
          <div style="font-size:16px;font-weight:900;color:var(--orange);">🔍 Findings</div>
          <div style="font-size:12px;color:var(--text2);margin-top:4px;">Merged, attributed, AI-scored threats. Same IOC from N feeds = 1 finding. What analysts work with.</div>
          <div style="margin-top:6px;font-size:11px;color:var(--text3);">Pipeline: Detection(s) -> Dedup -> AI Severity -> Attribution -> <b>Finding</b></div>
        </div>
      </div>
      <div style="margin-top:8px;padding:8px 12px;border-radius:8px;background:var(--surface);font-size:12px;color:var(--text3);border-left:3px solid var(--amber);">💡 Detections ≥ Findings always. If they're close, most IOCs came from single sources. If detections >> findings, you have good multi-source corroboration.</div>`},
    findings:{tab:7,emoji:'🔍',title:'Findings',color:'var(--orange)',desc:'Attributed, deduplicated, AI-assessed threats. Each finding represents a confirmed match between an IOC and this customer\'s registered assets.',formula:'Findings feed <b>D1 (Direct Exposure)</b> at <b>50% weight</b> -  the dominant input. More high-severity findings = higher D1 = higher exposure.'},
    critical:{tab:7,emoji:'🚨',title:'Critical Findings',color:'var(--red)',desc:'Findings rated CRITICAL by the AI assessment engine. These represent actively exploited vulnerabilities, confirmed breaches, or high-confidence stolen credentials.',formula:'Critical CVEs with CVSS ≥ 9.0 contribute up to <b>35 points to D1</b>. Each critical finding pushes D1 toward the maximum, which dominates at 50% weight.'},
    exposure:{tab:4,emoji:'📈',title:'Exposure Score -  Live Calculation',color:'var(--orange)',desc:'Loading live D1-D5 breakdown...',formula:'<div id="exp-live-calc" style="text-align:center;padding:20px;"><span class="loading-spin" style="display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:#e65c00;border-radius:50%;animation:spin .6s linear infinite;"></span> Computing D1-D5 dimensions...</div>'},
    sla:{tab:3,emoji:'⏱️',title:'SLA Compliance',color:'var(--green)',desc:'Measures how many findings were resolved within the contracted SLA window.',formula:`<b>Formula:</b> SLA % = (Resolved within deadline / Total findings) × 100
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:8px;">
        <div style="padding:6px 10px;border-radius:10px;background:#c6282808;border:1px solid #c6282815;text-align:center;"><div style="font-size:16px;font-weight:900;color:#c62828;">4h</div><div style="font-size:10px;color:var(--text4);">CRITICAL</div></div>
        <div style="padding:6px 10px;border-radius:10px;background:#e6510008;border:1px solid #e6510015;text-align:center;"><div style="font-size:16px;font-weight:900;color:#e65100;">24h</div><div style="font-size:10px;color:var(--text4);">HIGH</div></div>
        <div style="padding:6px 10px;border-radius:10px;background:var(--amber-g);text-align:center;"><div style="font-size:16px;font-weight:900;color:var(--amber);">72h</div><div style="font-size:10px;color:var(--text4);">MEDIUM</div></div>
        <div style="padding:6px 10px;border-radius:10px;background:var(--green-g);text-align:center;"><div style="font-size:16px;font-weight:900;color:var(--green);">168h</div><div style="font-size:10px;color:var(--text4);">LOW</div></div>
      </div>`}
  };
  const info=_explain[stat];if(!info)return;
  // Switch to relevant tab WITHIN the customer modal
  const tabs=document.querySelectorAll('#mc-body .tabs .tab');
  if(tabs[info.tab]){cuTab(tabs[info.tab],'cu-t-'+info.tab);}
  // Show explanation banner at top of the tab
  const tabEl=document.getElementById('cu-t-'+info.tab);
  if(tabEl){
    // Remove any previous explanation banner
    const prev=tabEl.querySelector('.stat-explain-banner');
    if(prev)prev.remove();
    const banner=document.createElement('div');
    banner.className='stat-explain-banner';
    banner.style.cssText='margin-bottom:14px;padding:16px;border-radius:14px;border:1px solid '+info.color.replace('var(','').replace(')','')+'25;background:linear-gradient(135deg,'+info.color.replace('var(','').replace(')','')+'04,transparent);animation:fadeIn .3s;';
    banner.innerHTML=`
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <span style="font-size:22px;">${info.emoji}</span>
        <div style="flex:1;"><div style="font-size:15px;font-weight:800;color:var(--text);">${info.title}</div></div>
        <span style="cursor:pointer;font-size:16px;color:var(--text4);padding:4px;" onclick="this.closest('.stat-explain-banner').remove()">✕</span>
      </div>
      <div style="font-size:13px;color:var(--text2);line-height:1.6;margin-bottom:10px;padding:10px 14px;border-radius:10px;background:var(--surface);border-left:3px solid ${info.color};">${info.desc}</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.6;">${info.formula}</div>`;
    tabEl.insertBefore(banner,tabEl.firstChild);
    banner.scrollIntoView({behavior:'smooth',block:'nearest'});
  }
  // Reload findings with filter if switching to findings tab
  if(info.tab===7 && cid){
    const filterSev=stat==='critical'?'CRITICAL':null;
    loadCuFindings(cid,filterSev);
  }
  // Live D1-D5 fetch for exposure drill
  if(stat==='exposure' && cid){
    (async()=>{
      const bd=await api(`/api/customers/${cid}/exposure-breakdown`);
      const el=document.getElementById('exp-live-calc');
      if(!el||!bd)return;
      const d=bd.dimensions||{};const s=bd.steps||{};const ctx=bd.context||{};
      const dColors={d1:'#c62828',d2:'#e65100',d3:'#7b1fa2',d4:'#1565c0',d5:'#2e7d32'};
      const dNames={d1:'D1: Direct Exposure',d2:'D2: Active Exploitation',d3:'D3: Actor Intent',d4:'D4: Attack Surface',d5:'D5: Asset Criticality'};
      const dWeightLabels={d1:'×0.50',d2:'×0.30',d3:'×0.20',d4:'floor ×0.20',d5:'impact ×0.00125'};
      const dDescriptions={d1:'Matched CVEs, stolen credentials, malicious URLs attributed to this customer',d2:'CISA KEV matches, CVSS ≥ 9.0, exploit PoCs available -  is it being weaponized NOW?',d3:'Threat actors targeting this industry/sector/tech stack',d4:'Internet-facing services, registered domains, IPs, tech stack breadth',d5:'Business criticality weighting of exposed assets'};
      let h='';
      // Step-by-step calculation with glow
      h+=`<div style="padding:16px;border-radius:14px;background:linear-gradient(135deg,rgba(230,92,0,.03),rgba(0,137,123,.02));border:1.5px solid rgba(230,92,0,.15);margin-bottom:14px;animation:hero-glow-pulse 4s ease-in-out infinite;">
        <div style="text-align:center;margin-bottom:12px;">
          <div style="font-size:42px;font-weight:900;font-family:'JetBrains Mono';color:var(--orange);text-shadow:0 0 20px rgba(230,92,0,.3);">${bd.final_score}</div>
          <div style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:1px;">Exposure Score · ${bd.label}</div>
        </div>
        <div style="font-family:'JetBrains Mono','Courier New',monospace;font-size:12px;line-height:2;padding:12px;background:var(--surface);border-radius:10px;border:1px solid var(--border);">
          <div style="color:var(--text4);">// Step 1: Weighted threat signals</div>
          <div>Exposure = <span style="color:#c62828;">${d.d1?.score||0}</span>×0.50 + <span style="color:#e65100;">${d.d2?.score||0}</span>×0.30 + <span style="color:#7b1fa2;">${d.d3?.score||0}</span>×0.20 = <b>${s.exposure_base}</b></div>
          <div style="color:var(--text4);">// Step 2: Attack surface floor guarantee</div>
          <div>Floor = <span style="color:#1565c0;">${d.d4?.score||0}</span>×0.20 = <b>${s.surface_floor}</b></div>
          <div style="color:var(--text4);">// Step 3: Take the higher of threat vs floor</div>
          <div>Base = max(${s.exposure_base}, ${s.surface_floor}) = <b style="color:var(--orange);">${s.base}</b></div>
          <div style="color:var(--text4);">// Step 4: Impact scaling from surface + criticality</div>
          <div>Impact = 0.75 + <span style="color:#1565c0;">${d.d4?.score||0}</span>×0.00125 + <span style="color:#2e7d32;">${d.d5?.score||0}</span>×0.00125 = <b>${s.impact_modifier}</b></div>
          <div style="margin-top:4px;padding-top:6px;border-top:1px dashed var(--border);font-size:14px;">
            <b style="color:var(--orange);text-shadow:0 0 8px rgba(230,92,0,.2);">Score = min(${s.base} × ${s.impact_modifier}, 100) = ${bd.final_score}</b>
          </div>
        </div>
      </div>`;
      // D1-D5 dimension cards with actual values
      h+=`<div style="display:grid;grid-template-columns:1fr;gap:8px;">`;
      ['d1','d2','d3','d4','d5'].forEach(dk=>{
        const dim=d[dk]||{};const col=dColors[dk];const score=dim.score||0;const pct=Math.min(score,100);
        const factors=dim.factors||{};
        const factorHtml=Object.entries(factors).map(([k,v])=>{
          const pts=v?.points||0;const detail=v?.detail||'';
          return pts>0?`<div style="font-size:11px;color:var(--text3);padding:3px 0;">+${pts}pts -  ${detail}</div>`:'';
        }).join('');
        h+=`<div style="padding:12px 16px;border-radius:12px;border:1px solid ${col}20;background:${col}05;transition:all .2s;" onmouseover="this.style.borderColor='${col}40';this.style.boxShadow='0 0 15px ${col}15'" onmouseout="this.style.borderColor='${col}20';this.style.boxShadow=''">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
            <div style="font-size:13px;font-weight:800;color:${col};flex:1;">${dNames[dk]}</div>
            <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${col};text-shadow:0 0 8px ${col}30;">${score}</div>
            <div style="font-size:11px;color:var(--text4);font-family:'JetBrains Mono';">${dWeightLabels[dk]}</div>
            <div style="font-size:11px;color:var(--text4);">= ${dim.weighted||0}</div>
          </div>
          <div style="height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin-bottom:6px;">
            <div style="width:${pct}%;height:100%;background:linear-gradient(90deg,${col},${col}80);border-radius:3px;box-shadow:0 0 8px ${col}40;transition:width .6s;"></div>
          </div>
          <div style="font-size:11px;color:var(--text4);">${dDescriptions[dk]}</div>
          ${factorHtml?`<div style="margin-top:6px;padding-top:6px;border-top:1px solid ${col}15;">${factorHtml}</div>`:''}
        </div>`;
      });
      h+=`</div>`;
      // Context
      const sevs=ctx.findings_by_severity||{};
      h+=`<div style="margin-top:10px;padding:10px 14px;border-radius:10px;background:var(--surface);border:1px solid var(--border);font-size:12px;color:var(--text3);">
        <b>Context:</b> ${ctx.detections||0} detections -> ${Object.values(sevs).reduce((a,b)=>a+b,0)||0} findings (${sevs.CRITICAL||0} critical, ${sevs.HIGH||0} high, ${sevs.MEDIUM||0} med, ${sevs.LOW||0} low) across ${ctx.assets||0} registered assets
      </div>`;
      el.innerHTML=h;
    })();
  }
}

// ═══ MAIN DASHBOARD DRILLDOWNS ═══

// DETECTIONS drilldown
async function drillDetections(){
  showDrilldown('📡 Loading detections...','<div style="text-align:center;padding:30px;">Analyzing detection pipeline...</div>');
  const [stats,sources,findings,customers]=await Promise.all([api('/api/stats'),api('/api/stats/sources'),api('/api/findings?limit=50'),api('/api/customers')]);
  const total=stats?.total_detections||0;
  const sev=stats?.severity||{};
  const crit=sev.CRITICAL||sev.critical||0,hi=sev.HIGH||sev.high||0,med=sev.MEDIUM||sev.medium||0,lo=sev.LOW||sev.low||0;
  const findArr=Array.isArray(findings)?findings:(findings?.items||findings?.findings||[]);
  const custArr=Array.isArray(customers)?customers:(customers?.items||customers?.customers||[]);
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${total}</div><div class="dd-stat-lbl">📡 Total Detections</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--red);">${crit}</div><div class="dd-stat-lbl">🔴 Critical</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:#e65100;">${hi}</div><div class="dd-stat-lbl">🟠 High</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--amber);">${med}</div><div class="dd-stat-lbl">🟡 Medium</div></div>
  </div>`;
  h+=`<div style="padding:12px 16px;border-radius:10px;background:var(--surface);border-left:3px solid var(--cyan);margin-bottom:16px;font-size:13px;color:var(--text2);line-height:1.6;">
    <b>What are detections?</b> Raw IOC matches from ${stats?.total_collectors||'33'} threat intelligence collectors. Every URL, hash, CVE, IP, or credential found in threat feeds is extracted, normalized, and matched against customer assets. The pipeline: <b>Collector -> Pattern Match -> IOC Extract -> Asset Correlation -> Detection</b>. Detections become Findings after AI severity assessment and deduplication.
  </div>`;

  // ═══ CUSTOMER RELATIONSHIP -  who is targeted? ═══
  const byCust={};findArr.forEach(f=>{const cn=f.customer_name||f.customer||'Unattributed';if(!byCust[cn])byCust[cn]={count:0,crit:0,high:0,id:f.customer_id};byCust[cn].count++;if((f.severity||'').toUpperCase()==='CRITICAL')byCust[cn].crit++;if((f.severity||'').toUpperCase()==='HIGH')byCust[cn].high++;});
  if(Object.keys(byCust).length){
    h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">🎯 Customer Impact -  Who Is Targeted?</div>`;
    Object.entries(byCust).sort((a,b)=>b[1].count-a[1].count).forEach(([name,d])=>{
      const pct=Math.round(d.count/Math.max(findArr.length,1)*100);
      h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;padding:10px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onmouseover="this.style.borderColor='var(--cyan-b)';this.style.boxShadow='0 2px 12px rgba(0,137,123,.08)'" onmouseout="this.style.borderColor='';this.style.boxShadow=''" ${d.id?`onclick="closeM('m-drilldown');openCu(${d.id})"`:''}>
        <div style="width:36px;height:36px;border-radius:10px;background:rgba(0,137,123,.08);display:flex;align-items:center;justify-content:center;font-size:18px;">🏢</div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:14px;font-weight:700;color:var(--text);">${escHtml(name)}</div>
          <div style="display:flex;gap:6px;margin-top:3px;">
            ${d.crit?`<span style="padding:1px 6px;border-radius:6px;font-size:10px;font-weight:700;background:rgba(198,40,40,.08);color:#c62828;border:1px solid rgba(198,40,40,.12);">${d.crit} CRITICAL</span>`:''}
            ${d.high?`<span style="padding:1px 6px;border-radius:6px;font-size:10px;font-weight:700;background:rgba(230,81,0,.08);color:#e65100;border:1px solid rgba(230,81,0,.12);">${d.high} HIGH</span>`:''}
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:var(--cyan);">${d.count}</div>
          <div style="font-size:10px;color:var(--text4);">${pct}% of total</div>
        </div>
        ${d.id?`<span style="font-size:10px;color:var(--orange);font-weight:600;">view -></span>`:''}
      </div>`;
    });
  }

  // Severity breakdown bars
  h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin:16px 0 8px;">Severity Distribution</div>`;
  const sevItems=[{name:'CRITICAL',val:crit,color:'#c62828',explain:'Actively exploited CVEs, confirmed credential breaches, C2 infrastructure matches. Require 4-hour SLA response.'},
    {name:'HIGH',val:hi,color:'#e65100',explain:'Known threat indicators with high confidence. Weaponized exploits, phishing domains, malware hashes. 24-hour SLA.'},
    {name:'MEDIUM',val:med,color:'#e65c00',explain:'Moderate confidence matches. Suspicious domains, IP reputation hits, non-critical CVEs. 72-hour SLA.'},
    {name:'LOW',val:lo,color:'#2e7d32',explain:'Informational indicators. Monitoring signals, low-confidence patterns, expired IOCs. 168-hour SLA.'}];
  sevItems.forEach(s=>{
    const pct=Math.round(s.val/Math.max(total,1)*100);
    h+=`<div style="display:flex;align-items:center;gap:10px;margin:8px 0;padding:10px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='${s.color}40'" onmouseout="this.style.borderColor=''">
      <div style="width:12px;height:12px;border-radius:50%;background:${s.color};box-shadow:0 0 6px ${s.color}40;flex-shrink:0;"></div>
      <div style="flex:1;"><div style="font-size:13px;font-weight:700;color:var(--text);">${s.name}</div>
        <div style="height:5px;background:var(--bg3);border-radius:3px;margin-top:4px;overflow:hidden;max-width:250px;">
          <div style="width:${pct}%;height:100%;background:${s.color};border-radius:3px;"></div></div>
        <div class="dd-exp hidden" style="font-size:12px;color:var(--text3);line-height:1.4;margin-top:6px;">${s.explain}</div>
      </div>
      <div style="text-align:right;"><div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:${s.color};">${s.val}</div><div style="font-size:11px;color:var(--text4);">${pct}%</div></div>
    </div>`;
  });
  // Source breakdown
  const srcArr=Array.isArray(sources)?sources:Object.entries(sources||{}).map(([k,v])=>({source:k,count:v}));
  if(srcArr.length){
    h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin:16px 0 8px;">📡 By Collector Source -  Where IOCs Come From</div>`;
    srcArr.sort((a,b)=>(b.count||0)-(a.count||0)).slice(0,10).forEach(s=>{
      const pct=Math.round((s.count||0)/Math.max(total,1)*100);
      const srcEmoji={'threatfox':'🦊','otx':'👽','feodo':'🤖','nvd':'🛡️','openphish':'🎣','urlhaus':'🔗','malwarebazaar':'☣️','paste':'📋','cisa_kev':'⚠️','rss':'📰','abuse_ch':'🚫','grep_app':'🔍','darksearch':'🌑','mitre':'⚔️','ransomfeed':'💧','pulsedive':'🫀','phishtank':'🐟','hudsonrock':'🪨'};
      h+=`<div style="display:flex;align-items:center;gap:10px;margin:4px 0;padding:8px 12px;border-radius:8px;border:1px solid var(--border);cursor:pointer;" onclick="drillCollector('${s.source||s.name||''}')">
        <span style="font-size:16px;">${srcEmoji[(s.source||s.name||'').toLowerCase()]||'📡'}</span>
        <span style="font-size:13px;font-weight:700;color:var(--text);flex:1;font-family:'JetBrains Mono';">${escHtml(s.source||s.name||'-')}</span>
        <div style="width:120px;height:5px;background:var(--bg3);border-radius:3px;overflow:hidden;"><div style="width:${pct}%;height:100%;background:var(--cyan);border-radius:3px;"></div></div>
        <span style="font-size:13px;font-weight:700;font-family:'JetBrains Mono';color:var(--cyan);min-width:50px;text-align:right;">${s.count||0}</span>
      </div>`;
    });
  }

  // Recent critical findings
  const critFindings=findArr.filter(f=>(f.severity||'').toUpperCase()==='CRITICAL').slice(0,5);
  if(critFindings.length){
    h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin:16px 0 8px;">🔴 Recent Critical Findings</div>`;
    critFindings.forEach(f=>{
      h+=`<div style="padding:10px 14px;border-radius:10px;border:1px solid rgba(198,40,40,.15);border-left:3px solid #c62828;margin:6px 0;cursor:pointer;transition:all .2s;" onmouseover="this.style.boxShadow='0 2px 10px rgba(198,40,40,.1)'" onmouseout="this.style.boxShadow=''" onclick="closeM('m-drilldown');openFi(${f.id})">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-family:'JetBrains Mono';font-size:13px;font-weight:700;color:var(--text);flex:1;word-break:break-all;">${escHtml(f.ioc_value||f.title||'-')}</span>
          <span style="padding:2px 8px;border-radius:8px;font-size:10px;background:var(--surface);color:var(--text3);border:1px solid var(--border);">${escHtml(f.ioc_type||'')}</span>
        </div>
        <div style="font-size:11px;color:var(--text4);margin-top:4px;">🏢 ${escHtml(f.customer_name||'-')} · 📡 ${escHtml(f.source||'-')} · 🕐 ${ago(f.created_at)}<span style="margin-left:auto;color:var(--orange);font-weight:600;float:right;">open -></span></div>
      </div>`;
    });
  }

  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('detections')">Browse All Detections -></button></div>`;
  showDrilldown(`📡 Detection Pipeline -  ${total} IOC Matches`,h);
}

// DARK WEB drilldown
async function drillDarkWeb(){
  showDrilldown('🌑 Loading dark web intel...','<div style="text-align:center;padding:30px;">Scanning dark web sources...</div>');
  const data=await api('/api/darkweb?limit=50');
  const mentions=Array.isArray(data)?data:(data?.mentions||data?.results||data?.items||[]);
  const total=mentions.length;
  const bySrc={};mentions.forEach(m=>{const s=m.source||'unknown';if(!bySrc[s])bySrc[s]=0;bySrc[s]++;});
  const byCust={};mentions.forEach(m=>{const c=m.customer_name||m.customer||'Unattributed';if(!byCust[c])byCust[c]=0;byCust[c]++;});
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:#7b1fa2;">${_stats?.darkweb_mentions||total}</div><div class="dd-stat-lbl">🌑 Total Mentions</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${Object.keys(bySrc).length}</div><div class="dd-stat-lbl">📡 Sources</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--red);">${Object.keys(byCust).length}</div><div class="dd-stat-lbl">🏢 Customers</div></div>
  </div>`;
  h+=`<div style="padding:12px 16px;border-radius:10px;background:rgba(123,31,162,.04);border-left:3px solid #7b1fa2;margin-bottom:16px;font-size:13px;color:var(--text2);line-height:1.6;">
    <b>Dark Web Monitoring</b> scans underground forums, paste sites, Telegram channels, dark web markets, and stealer log dumps for mentions of your customers' domains, brand names, executive names, and credentials. Each mention is attributed to a customer and scored by the correlation engine. Dark web hits are strong D1 signals in the exposure formula.
  </div>`;
  // Source breakdown
  if(Object.keys(bySrc).length){
    h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">By Source</div>`;
    Object.entries(bySrc).sort((a,b)=>b[1]-a[1]).forEach(([src,ct])=>{
      const _srcEmoji={'telegram':'📱','paste':'📋','forum':'💬','market':'🛒','stealer_log':'🔑','leak':'💧','ransomfeed':'🔴','ransomwatch':'🔴','ahmia':'🌑'};
      h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;padding:8px 12px;border-radius:8px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="closeM('m-drilldown');go('darkweb');setTimeout(()=>loadDW('${src}'),300)" onmouseover="this.style.borderColor='#7b1fa2';this.style.background='rgba(123,31,162,.04)'" onmouseout="this.style.borderColor='var(--border)';this.style.background=''">
        <span style="font-size:18px;">${_srcEmoji[src]||'🌐'}</span>
        <span style="font-size:13px;font-weight:700;color:var(--text);flex:1;">${src}</span>
        <span style="font-size:16px;font-weight:900;font-family:'JetBrains Mono';color:#7b1fa2;">${ct}</span>
        <span style="font-size:10px;color:var(--orange);">-></span>
      </div>`;
    });
  }
  // Recent mentions -  clickable cards
  if(mentions.length){
    // Store in _dwItems so openDWDetail works
    _dwItems=mentions;
    h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin:16px 0 8px;">Recent Mentions (click for details)</div>`;
    mentions.slice(0,10).forEach(m=>{
      const isRansom=m.source==='ransomwatch'||m.source==='ransomfeed'||m.mention_type==='ransomware_claim';
      const isPaste=m.source==='paste'||(m.mention_type||'').includes('paste');
      const sevColor=isRansom?'#dc2626':isPaste?'#ea580c':'#7c3aed';
      const typeIcon=isRansom?'🔴':isPaste?'📋':'🌐';
      const title=(m.content||m.title||m.keyword||m.value||m.mention||'Untitled').substring(0,120);
      const hasId=m.id!=null;
      h+=`<div style="padding:12px 14px;border-radius:10px;border:1px solid ${sevColor}20;margin:6px 0;cursor:pointer;transition:all .2s;background:${sevColor}03;" ${hasId?`onclick="closeM('m-drilldown');go('darkweb');setTimeout(()=>openDWDetail(${m.id}),500)"`:'onclick="closeM(\'m-drilldown\');go(\'darkweb\')"'} onmouseover="this.style.borderColor='${sevColor}';this.style.transform='translateX(4px)';this.style.background='${sevColor}08'" onmouseout="this.style.borderColor='${sevColor}20';this.style.transform='';this.style.background='${sevColor}03'">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:16px;">${typeIcon}</span>
          <div style="flex:1;min-width:0;">
            <div style="font-size:13px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escHtml(title)}</div>
            <div style="font-size:11px;color:var(--text4);margin-top:2px;">
              ${m.customer_name?'🏢 '+escHtml(m.customer_name)+' · ':''}📡 ${m.source||'-'} 
              ${m.threat_actor?' · 🎭 '+escHtml(m.threat_actor):''}
              ${m.ai_summary?' · 🤖 AI triaged':''}
            </div>
          </div>
          <span style="font-size:10px;color:${sevColor};font-weight:700;">details -></span>
        </div>
        ${m.ai_summary?`<div style="margin-top:6px;padding:6px 10px;border-radius:6px;background:rgba(230,92,0,.04);border-left:2px solid var(--orange);font-size:11px;color:var(--text2);">🤖 ${escHtml((m.ai_summary||'').substring(0,100))}</div>`:''}
      </div>`;
    });
  }
  if(!mentions.length)h+=`<div style="text-align:center;padding:20px;color:var(--text4);"><div style="font-size:32px;">🛡️</div><div style="font-size:14px;margin-top:8px;">No dark web mentions detected</div><div style="font-size:12px;margin-top:4px;">Customer brand names, domains, and keywords are being monitored</div></div>`;
  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('darkweb')">Open Dark Web Dashboard -></button></div>`;
  showDrilldown(`🌑 Dark Web Intelligence -  ${_stats?.darkweb_mentions||total} Mentions`,h);
}

async function drillThreatPressure(){
  showDrilldown('🎯 Loading threat pressure...','<div style="text-align:center;padding:30px;">Analyzing threat landscape...</div>');
  const tp=await api('/api/threat-pressure');
  const pval=tp?.pressure_index||0;
  const pColor=pval>=70?'#c62828':pval>=40?'#e65100':pval>=20?'#e65c00':'#2e7d32';
  const pLabel=pval>=70?'CRITICAL':pval>=40?'ELEVATED':pval>=20?'MODERATE':'LOW';
  const dashOff=327-(327*(Math.min(pval,100)/100));
  let h=`<div style="display:flex;gap:24px;align-items:center;margin-bottom:20px;flex-wrap:wrap;">
    <div style="position:relative;width:120px;height:120px;flex-shrink:0;">
      <svg viewBox="0 0 120 120" width="120" height="120">
        <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="8" opacity=".3"/>
        <circle cx="60" cy="60" r="52" fill="none" stroke="${pColor}" stroke-width="8" stroke-dasharray="327" stroke-dashoffset="${dashOff}" stroke-linecap="round" transform="rotate(-90 60 60)" style="filter:drop-shadow(0 0 8px ${pColor});"/>
      </svg>
      <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;">
        <div class="mono" style="font-size:36px;font-weight:900;color:${pColor};text-shadow:0 0 12px ${pColor}40;">${pval}</div>
        <div style="font-size:10px;color:var(--text4);">/ 100</div>
      </div>
    </div>
    <div style="flex:1;min-width:200px;">
      <div style="font-size:18px;font-weight:800;color:${pColor};text-transform:uppercase;letter-spacing:1px;text-shadow:0 0 8px ${pColor}20;">${pLabel} THREAT LEVEL</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.6;margin-top:8px;">The Threat Pressure Index measures your organization's real-time risk posture by combining three weighted signals into a 0-100 score. Higher = more urgent action needed.</div>
    </div>
  </div>`;
  // Formula breakdown
  const crit=tp?.critical_findings||0;
  const high=tp?.high_findings||0;
  const camps=tp?.active_campaigns||0;
  const new24=tp?.new_last_24h||0;
  const components=[
    {name:'Critical Findings',emoji:'🔴',value:crit,weight:'×12 pts each',contribution:crit*12,color:'#c62828',explain:'Confirmed high-severity threats requiring immediate action. Each critical finding adds 12 points because they represent active exploitation risk.'},
    {name:'High Findings',emoji:'🟠',value:high,weight:'×5 pts each',contribution:high*5,color:'#e65100',explain:'Elevated threats with confirmed indicators. Each high finding adds 5 points -  significant but not yet actively weaponized against you.'},
    {name:'Active Campaigns',emoji:'⚔️',value:camps,weight:'×8 pts each',contribution:camps*8,color:'#7b1fa2',explain:'Coordinated threat operations tracked across multiple IOCs. Campaigns indicate organized attackers, not opportunistic scanning.'},
    {name:'24h Velocity',emoji:'🔥',value:new24,weight:'×0.3 (max 30)',contribution:Math.min(new24,100)*0.3,color:'#e65c00',explain:'New detections in the last 24 hours measure how fast new threats are arriving. Capped at 30 points to prevent single-source spikes from dominating.'}
  ];
  h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin-bottom:12px;">Formula Breakdown</div>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:16px;">
    <div style="font-family:'JetBrains Mono';font-size:13px;color:var(--cyan);text-align:center;margin-bottom:14px;">
      Pressure = (Critical × 12) + (High × 5) + (Campaigns × 8) + min(New24h, 100) × 0.3
    </div>
    <div style="font-family:'JetBrains Mono';font-size:13px;color:var(--text);text-align:center;">
      = (${crit} × 12) + (${high} × 5) + (${camps} × 8) + min(${new24}, 100) × 0.3 = <span style="font-weight:900;color:${pColor};font-size:16px;">${pval}</span>
    </div>
  </div>`;
  components.forEach(c=>{
    const barW=Math.min(100,c.contribution/Math.max(pval,1)*100);
    h+=`<div style="display:flex;align-items:center;gap:12px;margin:10px 0;padding:12px 16px;border-radius:10px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='${c.color}40';this.style.boxShadow='0 0 12px ${c.color}15'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
      <span style="font-size:22px;">${c.emoji}</span>
      <div style="flex:1;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:14px;font-weight:700;color:var(--text);">${c.name}</span>
          <span style="font-size:11px;color:var(--text4);font-family:'JetBrains Mono';">${c.weight}</span>
        </div>
        <div style="height:6px;background:var(--bg3);border-radius:3px;margin-top:6px;overflow:hidden;max-width:300px;">
          <div style="width:${barW}%;height:100%;background:${c.color};border-radius:3px;box-shadow:0 0 6px ${c.color}40;"></div>
        </div>
        <div class="dd-exp hidden" style="font-size:12px;color:var(--text3);line-height:1.5;margin-top:8px;padding-top:6px;border-top:1px solid var(--border);">${c.explain}</div>
      </div>
      <div style="text-align:right;min-width:60px;">
        <div style="font-size:20px;font-weight:900;font-family:'JetBrains Mono';color:${c.color};text-shadow:0 0 8px ${c.color}30;">${c.value}</div>
        <div style="font-size:11px;color:var(--text4);">+${Math.round(c.contribution)} pts</div>
      </div>
    </div>`;
  });
  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('findings')">View All Findings -></button></div>`;
  showDrilldown(`🎯 Threat Pressure Index -  ${pval}/100 (${pLabel})`,h);
}

// 2. ACTORS DRILLDOWN
async function drillActors(){
  showDrilldown('🎭 Loading threat actors...','<div style="text-align:center;padding:30px;">Fetching actor intelligence...</div>');
  const data=await api('/api/actors?limit=50');
  const actors=Array.isArray(data)?data:(data?.actors||[]);
  // Group by origin
  const byCountry={};actors.forEach(a=>{const c=a.origin_country||a.country||'Unknown';if(!byCountry[c])byCountry[c]=[];byCountry[c].push(a);});
  const byMotiv={};actors.forEach(a=>{const m=a.motivation||a.motivations||'Unknown';if(!byMotiv[m])byMotiv[m]=0;byMotiv[m]++;});
  const countryEntries=Object.entries(byCountry).sort((a,b)=>b[1].length-a[1].length);
  const motivEntries=Object.entries(byMotiv).sort((a,b)=>b[1]-a[1]);
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--purple);">${actors.length}</div><div class="dd-stat-lbl">🎭 Tracked Actors</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${countryEntries.length}</div><div class="dd-stat-lbl">🌍 Countries</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${motivEntries.length}</div><div class="dd-stat-lbl">⚡ Motivations</div></div>
    <div style="flex:1;min-width:200px;padding:4px 0;">
      <div style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">What are Threat Actors?</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.5;">APT groups, cybercrime syndicates, and hacktivists cataloged from MITRE ATT&CK, government advisories, and dark web monitoring. Each actor is scored against your customer's industry in the D3 dimension of the exposure formula.</div>
    </div>
  </div>`;
  // Origin breakdown
  h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin:16px 0 8px;">By Origin Country</div>`;
  const _countryFlag={'China':'🇨🇳','Russia':'🇷🇺','Iran':'🇮🇷','North Korea':'🇰🇵','South Korea':'🇰🇷','Vietnam':'🇻🇳','Pakistan':'🇵🇰','India':'🇮🇳','Turkey':'🇹🇷','Israel':'🇮🇱','Nigeria':'🇳🇬','Ukraine':'🇺🇦','Unknown':'🏴'};
  countryEntries.slice(0,8).forEach(([country,acts])=>{
    const flag=_countryFlag[country]||'🏳️';
    const pct=Math.round(acts.length/actors.length*100);
    h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;padding:8px 12px;border-radius:8px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='var(--purple-b)';this.style.boxShadow='0 0 8px rgba(123,31,162,.1)'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
      <span style="font-size:24px;">${flag}</span>
      <div style="flex:1;">
        <div style="font-size:14px;font-weight:700;color:var(--text);">${country}</div>
        <div style="height:5px;background:var(--bg3);border-radius:3px;margin-top:4px;overflow:hidden;max-width:250px;">
          <div style="width:${pct}%;height:100%;background:var(--purple);border-radius:3px;box-shadow:0 0 6px rgba(123,31,162,.3);"></div>
        </div>
        <div class="dd-exp hidden" style="margin-top:6px;font-size:12px;color:var(--text3);">
          ${acts.slice(0,5).map(a=>`<span style="display:inline-block;margin:2px 4px 2px 0;padding:3px 8px;border-radius:16px;background:var(--purple-g);border:1px solid var(--purple-b);font-size:11px;font-weight:600;color:var(--purple);cursor:pointer;" onclick="event.stopPropagation();closeM('m-drilldown');go('actors');setTimeout(()=>openActDetail(${a.id}),300);">${a.name}${a.mitre_id?' ('+a.mitre_id+')':''}</span>`).join('')}
          ${acts.length>5?`<span style="font-size:11px;color:var(--text4);">+${acts.length-5} more</span>`:''}
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:20px;font-weight:900;font-family:'JetBrains Mono';color:var(--purple);text-shadow:0 0 8px rgba(123,31,162,.2);">${acts.length}</div>
        <div style="font-size:11px;color:var(--text4);">${pct}%</div>
      </div>
    </div>`;
  });
  // Motivation breakdown
  h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin:16px 0 8px;">By Motivation</div>`;
  const _motivEmoji={'espionage':'🕵️','financial':'💰','destruction':'💣','hacktivism':'✊','information theft':'📁','ransomware':'🔒','Unknown':'❓'};
  const _motivColor={'espionage':'#c62828','financial':'#e65100','destruction':'#7b1fa2','hacktivism':'#2e7d32','information theft':'#1565c0','ransomware':'#c62828','Unknown':'var(--text4)'};
  const _motivExplain={'espionage':'Nation-state sponsored intelligence gathering. Targets government, defense, and technology sectors for strategic advantage.','financial':'Profit-driven cybercrime. Deploys banking trojans, BEC scams, and carding operations against financial and retail targets.','destruction':'Wiper malware and sabotage operations. Aims to destroy infrastructure, often during geopolitical conflicts.','hacktivism':'Ideologically motivated attacks. DDoS, defacement, and data leaks to advance political causes.','information theft':'Targeted data exfiltration. Steals trade secrets, PII, and intellectual property for competitive advantage.','ransomware':'Encrypts victim data and demands payment. The most monetized cybercrime operation globally.'};
  motivEntries.forEach(([motiv,ct])=>{
    const emoji=_motivEmoji[motiv]||'⚡';
    const col=_motivColor[motiv]||'var(--text2)';
    const explain=_motivExplain[motiv]||'Threat actor motivation category';
    h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;padding:10px 14px;border-radius:8px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='${col}40'" onmouseout="this.style.borderColor=''">
      <span style="font-size:20px;">${emoji}</span>
      <div style="flex:1;">
        <div style="font-size:13px;font-weight:700;color:var(--text);text-transform:capitalize;">${motiv}</div>
        <div class="dd-exp hidden" style="font-size:12px;color:var(--text3);line-height:1.4;margin-top:4px;">${explain}</div>
      </div>
      <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:${col};">${ct}</div>
    </div>`;
  });
  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('actors')">Browse All Actors -></button></div>`;
  showDrilldown(`🎭 Threat Actor Intelligence -  ${actors.length} Tracked`,h);
}

// 3. MAX EXPOSURE + D1-D5 FORMULA
async function drillExposureFormula(){
  showDrilldown('📈 Loading exposure data...','<div style="text-align:center;padding:30px;">Fetching D1-D5 scores...</div>');
  const lb=await api('/api/exposure/leaderboard');
  const entries=Array.isArray(lb)?lb:[];
  const maxScore=entries.length?entries[0].max_exposure_score:0;
  const maxColor=maxScore>=70?'#c62828':maxScore>=40?'#e65100':maxScore>0?'#e65c00':'#2e7d32';
  // Formula explanation
  let h=`<div style="background:linear-gradient(135deg,rgba(198,40,40,.04),rgba(230,92,0,.04),rgba(0,137,123,.04));border:1px solid rgba(230,92,0,.15);border-radius:14px;padding:20px;margin-bottom:20px;">
    <div style="font-size:15px;font-weight:800;color:var(--orange);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">⚡ Hybrid Additive-Multiplicative Exposure Formula</div>
    <div style="font-family:'JetBrains Mono';font-size:13px;color:var(--text);background:var(--surface);padding:14px;border-radius:8px;margin-bottom:12px;line-height:1.8;">
      <div>Base = max( <span style="color:#c62828;">D1</span>×0.50 + <span style="color:#e65100;">D2</span>×0.30 + <span style="color:#7b1fa2;">D3</span>×0.20, &nbsp; <span style="color:#1565c0;">D4</span>×0.20 )</div>
      <div>Impact = 0.75 + <span style="color:#1565c0;">D4</span>×0.00125 + <span style="color:#2e7d32;">D5</span>×0.00125</div>
      <div style="margin-top:4px;font-weight:900;color:var(--orange);">Exposure = min( Base × Impact, 100 )</div>
    </div>
    <div style="font-size:13px;color:var(--text2);line-height:1.6;">D1 dominates (50%) because direct exposure is king. D2 amplifies when exploits exist in the wild. D3 adds actor intent for your industry. D4 provides a floor so large attack surfaces never score zero. D5 scales impact -  more assets means more damage potential.</div>
  </div>`;
  // D1-D5 dimension cards
  const dims=[
    {id:'D1',name:'Direct Exposure',weight:'50%',color:'#c62828',emoji:'🎯',key:'d1_score',explain:'Hard evidence: confirmed CVEs matched to customer tech stack, leaked credentials, dark web mentions with customer identifiers. This is "your front door is open."'},
    {id:'D2',name:'Active Exploitation',weight:'30%',color:'#e65100',emoji:'🔥',key:'d2_score',explain:'Weaponization signals: CISA KEV entries, EPSS probability > 10%, exploit code on GitHub/Metasploit. This answers "is someone actively exploiting this vulnerability class?"'},
    {id:'D3',name:'Actor Intent',weight:'20%',color:'#7b1fa2',emoji:'🎭',key:'d3_score',explain:'Threat actor targeting your customer\'s industry. If APT28 targets government and your customer is government -  D3 spikes. Derived from MITRE ATT&CK campaigns and dark web chatter.'},
    {id:'D4',name:'Attack Surface',weight:'floor + impact',color:'#1565c0',emoji:'🖥️',key:'d4_score',explain:'How many assets (domains, IPs, cloud resources) are exposed. Large surfaces guarantee a minimum score floor (D4×0.20) even with zero detections. Also scales the impact multiplier.'},
    {id:'D5',name:'Asset Criticality',weight:'impact modifier',color:'#2e7d32',emoji:'💎',key:'d5_score',explain:'Weighted importance of exposed assets. A leaked admin credential on a production database scores higher than a test server. Feeds the impact multiplier that scales the final score.'}
  ];
  h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin-bottom:12px;">Five Dimensions</div>`;
  dims.forEach(d=>{
    h+=`<div style="display:flex;align-items:center;gap:12px;margin:8px 0;padding:14px 16px;border-radius:12px;border:1px solid var(--border);cursor:pointer;transition:all .25s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='${d.color}40';this.style.boxShadow='0 0 14px ${d.color}12'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
      <div style="width:48px;height:48px;border-radius:12px;background:${d.color}10;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <span style="font-size:24px;">${d.emoji}</span>
      </div>
      <div style="flex:1;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-family:'JetBrains Mono';font-size:14px;font-weight:900;color:${d.color};">${d.id}</span>
          <span style="font-size:14px;font-weight:700;color:var(--text);">${d.name}</span>
          <span style="font-size:11px;color:var(--text4);font-family:'JetBrains Mono';">weight: ${d.weight}</span>
        </div>
        <div class="dd-exp hidden" style="font-size:12px;color:var(--text3);line-height:1.5;margin-top:8px;padding-top:6px;border-top:1px solid var(--border);">${d.explain}</div>
      </div>
    </div>`;
  });
  // Customer leaderboard
  if(entries.length){
    h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin:20px 0 12px;">Customer Exposure Leaderboard</div>`;
    entries.forEach((e,i)=>{
      const sc=e.max_exposure_score||0;
      const col=sc>=70?'#c62828':sc>=40?'#e65100':sc>0?'#e65c00':'#2e7d32';
      const label=sc>=70?'CRITICAL':sc>=40?'HIGH':sc>0?'MODERATE':'SAFE';
      h+=`<div style="display:flex;align-items:center;gap:12px;margin:6px 0;padding:10px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='${col}40'" onmouseout="this.style.borderColor=''">
        <div style="width:28px;height:28px;border-radius:50%;background:${col}15;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:${col};">${i+1}</div>
        <div style="flex:1;">
          <div style="font-size:14px;font-weight:700;color:var(--text);">${e.name||'-'} <span style="font-size:11px;color:var(--text4);font-weight:500;">${e.industry||''}</span></div>
          <div class="dd-exp hidden" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;">
            <span style="padding:3px 8px;border-radius:12px;font-size:11px;font-weight:700;font-family:'JetBrains Mono';background:#c6282810;color:#c62828;border:1px solid #c6282825;">D1: ${e.d1_score||0}</span>
            <span style="padding:3px 8px;border-radius:12px;font-size:11px;font-weight:700;font-family:'JetBrains Mono';background:#e6510010;color:#e65100;border:1px solid #e6510025;">D2: ${e.d2_score||0}</span>
            <span style="padding:3px 8px;border-radius:12px;font-size:11px;font-weight:700;font-family:'JetBrains Mono';background:#7b1fa210;color:#7b1fa2;border:1px solid #7b1fa225;">D3: ${e.d3_score||0}</span>
            <span style="padding:3px 8px;border-radius:12px;font-size:11px;font-weight:700;font-family:'JetBrains Mono';background:#1565c010;color:#1565c0;border:1px solid #1565c025;">D4: ${e.d4_score||0}</span>
            <span style="padding:3px 8px;border-radius:12px;font-size:11px;font-weight:700;font-family:'JetBrains Mono';background:#2e7d3210;color:#2e7d32;border:1px solid #2e7d3225;">D5: ${e.d5_score||0}</span>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${col};text-shadow:0 0 10px ${col}30;">${sc}</div>
          <div style="font-size:10px;font-weight:700;color:${col};">${label}</div>
        </div>
      </div>`;
    });
  }
  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('exposure')">Open Exposure Dashboard -></button></div>`;
  showDrilldown(`📈 Exposure Formula -  Max Score: ${maxScore} / 100`,h);
}

// 3b. CUSTOMERS DRILLDOWN
async function drillCustomers(){
  showDrilldown('🏢 Loading customers...','<div style="text-align:center;padding:30px;">Fetching customer portfolio...</div>');
  const custs=await api('/api/customers');
  const items=Array.isArray(custs)?custs:(custs?.customers||[]);
  // Calculate portfolio stats
  const total=items.length;
  const tiers={};items.forEach(c=>{const t=c.tier||'STANDARD';tiers[t]=(tiers[t]||0)+1;});
  const totalFindings=items.reduce((s,c)=>s+(c.finding_count||0),0);
  const totalAssets=items.reduce((s,c)=>s+(c.asset_count||0),0);
  const maxExp=items.reduce((m,c)=>Math.max(m,c.exposure_score||0),0);
  const avgExp=items.length?items.reduce((s,c)=>s+(c.exposure_score||0),0)/items.length:0;
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--green);">${total}</div><div class="dd-stat-lbl">🏢 Active Customers</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${totalFindings}</div><div class="dd-stat-lbl">🔍 Total Findings</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${totalAssets}</div><div class="dd-stat-lbl">🖥️ Total Assets</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--red);">${maxExp.toFixed(1)}</div><div class="dd-stat-lbl">📈 Max Exposure</div></div>
  </div>`;
  // What is a customer
  h+=`<div style="padding:12px 16px;border-radius:10px;background:var(--surface);border-left:3px solid var(--green);margin-bottom:16px;font-size:13px;color:var(--text2);line-height:1.6;">
    <b>What is a Customer?</b> Each customer represents a managed security client in the MSSP model. ArgusWatch monitors their registered assets (domains, IPs, emails, keywords) against all 33 threat intelligence collectors. Each customer has a dedicated <b>D1-D5 exposure score</b>, SLA compliance tracking, and AI-generated threat narratives. Customers progress through 5 onboarding stages: Created -> Assets Added -> Monitoring -> Tuning -> Production.
  </div>`;
  // Tier breakdown
  const tierColors={ENTERPRISE:'#7b1fa2',PREMIUM:'#1565c0',STANDARD:'var(--orange)',BASIC:'var(--text4)'};
  if(Object.keys(tiers).length){
    h+=`<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">`;
    Object.entries(tiers).forEach(([t,cnt])=>{
      const col=tierColors[t]||'var(--text3)';
      h+=`<div style="padding:8px 16px;border-radius:10px;border:1px solid ${col}25;background:${col}06;text-align:center;">
        <div style="font-size:18px;font-weight:900;font-family:'JetBrains Mono';color:${col};">${cnt}</div>
        <div style="font-size:10px;font-weight:700;color:${col};">${t}</div></div>`;
    });
    h+=`</div>`;
  }
  // Customer list
  h+=`<div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">Customer Portfolio -  sorted by exposure</div>`;
  items.sort((a,b)=>(b.exposure_score||0)-(a.exposure_score||0)).forEach((c,i)=>{
    const es=c.exposure_score||0;
    const col=es>=70?'#c62828':es>=40?'#e65100':es>0?'#e65c00':'#2e7d32';
    const label=es>=70?'CRITICAL':es>=40?'HIGH':es>0?'MODERATE':'SAFE';
    const fc=c.finding_count||0;const ac=c.asset_count||0;
    h+=`<div style="display:flex;align-items:center;gap:12px;margin:6px 0;padding:12px 14px;border-radius:12px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onmouseover="this.style.borderColor='${col}40';this.style.boxShadow='0 2px 12px ${col}10'" onmouseout="this.style.borderColor='';this.style.boxShadow=''" onclick="closeM('m-drilldown');openCu(${c.id})">
      <div style="width:32px;height:32px;border-radius:10px;background:${col}10;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:${col};flex-shrink:0;">${i+1}</div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:14px;font-weight:800;color:var(--text);">${c.name||'-'}</span>
          <span style="padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;background:${tierColors[c.tier]||'var(--text4)'}10;color:${tierColors[c.tier]||'var(--text4)'};">${c.tier||'STANDARD'}</span>
        </div>
        <div style="font-size:11px;color:var(--text4);margin-top:2px;">${c.primary_domain||''} · ${c.industry||'-'} · ${ac} assets · ${fc} findings</div>
      </div>
      <div style="text-align:right;flex-shrink:0;">
        <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${col};text-shadow:0 0 8px ${col}20;">${es.toFixed(1)}</div>
        <div style="font-size:10px;font-weight:700;color:${col};">${label}</div>
      </div>
    </div>`;
  });
  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('customers')">Open Customers Dashboard -></button></div>`;
  showDrilldown(`🏢 Customer Portfolio -  ${total} Active Customers`,h);
}

// 4. ASSETS DRILLDOWN
async function drillAssets(){
  showDrilldown('🖥️ Loading asset inventory...','<div style="text-align:center;padding:30px;">Fetching assets across all customers...</div>');
  const custs=_customers.length?_customers:(await api('/api/customers'))||[];
  const customers=Array.isArray(custs)?custs:(custs?.customers||[]);
  // Load assets per customer
  let allAssets=[];
  let custAssetMap={};
  for(const c of customers){
    const assets=await api('/api/customers/'+c.id+'/assets');
    const list=Array.isArray(assets)?assets:(assets?.assets||[]);
    custAssetMap[c.name||c.id]=list;
    list.forEach(a=>allAssets.push({...a,customer_name:c.name,customer_id:c.id}));
  }
  // Group by type
  const byType={};allAssets.forEach(a=>{const t=a.asset_type||(a.type?a.type:'other');if(!byType[t])byType[t]=[];byType[t].push(a);});
  const typeEntries=Object.entries(byType).sort((a,b)=>b[1].length-a[1].length);
  const total=allAssets.length;
  const _assetEmoji={'domain':'🏷️','ip':'🌐','cidr':'📡','email_domain':'📧','brand_name':'✨','keyword':'🔍','tech_stack':'⚙️','github_org':'💻','cloud_asset':'☁️','subdomain':'🔗','exec_name':'👤','org_name':'🏢','email':'📧','url':'🔗'};
  const _assetColor={'domain':'#e65c00','ip':'#c62828','cidr':'#1565c0','email_domain':'#7b1fa2','brand_name':'#e65100','keyword':'#00897b','tech_stack':'#ef6c00','github_org':'#2e7d32','cloud_asset':'#1565c0','subdomain':'#e65c00','exec_name':'#c62828','org_name':'#00897b'};
  const _assetExplain={
    'domain':'Primary business domains monitored for typosquatting, phishing clones, and DNS hijacking. Each domain is cross-referenced against all 33 collectors for IOC matches.',
    'ip':'IP addresses and ranges belonging to the customer. Matched against C2 blacklists, scanning reputation feeds, and Shodan/Censys exposure data.',
    'cidr':'Network CIDR ranges defining the customer\'s IP space. Enables bulk matching of any IOC that falls within these ranges.',
    'email_domain':'Email domains for credential breach monitoring. Every new combo list, stealer log, and paste site is checked against these domains.',
    'brand_name':'Brand keywords for typosquatting detection. Catches look-alike domains (paypa1.com, amaz0n-login.com) targeting customer brands.',
    'keyword':'Custom search terms for dark web monitoring. Triggered when keywords appear in forum posts, paste sites, or marketplace listings.',
    'tech_stack':'Technology stack entries (e.g., Apache 2.4, WordPress 6.x) enabling CVE->product matching. Without this, CVE detections cannot be attributed.',
    'github_org':'GitHub organization for code leak detection. Monitors for exposed secrets, API keys, and credentials in public repositories.',
    'cloud_asset':'Cloud resources (S3 buckets, Azure blobs, GCP projects) monitored for public exposure and misconfiguration.',
    'subdomain':'Discovered subdomains from recon engines. Expands attack surface visibility beyond primary domains.',
    'exec_name':'Executive and VIP names for targeted spearphishing and impersonation detection in dark web mentions.',
    'org_name':'Organization name variations for broad dark web monitoring and data leak attribution.'
  };
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--amber);">${total}</div><div class="dd-stat-lbl">🖥️ Total Assets</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${typeEntries.length}</div><div class="dd-stat-lbl">📋 Asset Types</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--green);">${customers.length}</div><div class="dd-stat-lbl">🏢 Customers</div></div>
    <div style="flex:1;min-width:200px;padding:4px 0;">
      <div style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">Why Assets Matter</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.5;">Assets are what the correlation engine matches IOCs against. More complete assets = better attribution = more accurate exposure scores. Feeds D4 (Attack Surface) and D5 (Asset Criticality) in the exposure formula.</div>
    </div>
  </div>`;
  // Asset type breakdown
  h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin:16px 0 8px;">Asset Types</div>`;
  typeEntries.forEach(([type,assets])=>{
    const emoji=_assetEmoji[type]||'📦';
    const col=_assetColor[type]||'var(--text2)';
    const explain=_assetExplain[type]||'Asset type registered for threat correlation';
    const pct=Math.round(assets.length/total*100);
    // Group by customer
    const byCust={};assets.forEach(a=>{const cn=a.customer_name||'?';if(!byCust[cn])byCust[cn]=[];byCust[cn].push(a);});
    h+=`<div style="display:flex;align-items:center;gap:12px;margin:8px 0;padding:12px 16px;border-radius:10px;border:1px solid var(--border);cursor:pointer;transition:all .25s;" onclick="this.querySelector('.dd-exp').classList.toggle('hidden')" onmouseover="this.style.borderColor='${col}40';this.style.boxShadow='0 0 12px ${col}12'" onmouseout="this.style.borderColor='';this.style.boxShadow=''">
      <span style="font-size:22px;">${emoji}</span>
      <div style="flex:1;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:14px;font-weight:700;color:var(--text);font-family:'JetBrains Mono';">${type}</span>
          <span style="font-size:11px;color:var(--text4);">${pct}% of total</span>
        </div>
        <div style="height:5px;background:var(--bg3);border-radius:3px;margin-top:6px;overflow:hidden;max-width:300px;">
          <div style="width:${pct}%;height:100%;background:${col};border-radius:3px;box-shadow:0 0 6px ${col}40;"></div>
        </div>
        <div class="dd-exp hidden" style="margin-top:8px;padding-top:6px;border-top:1px solid var(--border);">
          <div style="font-size:12px;color:var(--text3);line-height:1.5;margin-bottom:8px;">${explain}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;">
            ${assets.slice(0,12).map(a=>`<span style="padding:3px 8px;border-radius:12px;font-size:11px;font-weight:600;font-family:'JetBrains Mono';background:${col}08;color:${col};border:1px solid ${col}20;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${a.asset_value||a.value||''} (${a.customer_name||''})">${a.asset_value||a.value||'-'}</span>`).join('')}
            ${assets.length>12?`<span style="font-size:11px;color:var(--text4);padding:3px 8px;">+${assets.length-12} more</span>`:''}
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px;">
            ${Object.entries(byCust).map(([cn,ca])=>`<span style="font-size:10px;padding:2px 6px;border-radius:10px;background:var(--surface2);color:var(--text3);">🏢 ${cn}: ${ca.length}</span>`).join('')}
          </div>
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:22px;font-weight:900;font-family:'JetBrains Mono';color:${col};text-shadow:0 0 8px ${col}30;">${assets.length}</div>
      </div>
    </div>`;
  });
  // Per-customer summary
  h+=`<div style="font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin:20px 0 8px;">By Customer</div>`;
  customers.forEach(c=>{
    const alist=custAssetMap[c.name||c.id]||[];
    const types=new Set(alist.map(a=>a.asset_type||'other'));
    const pct=Math.round(alist.length/Math.max(total,1)*100);
    h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;padding:8px 12px;border-radius:8px;border:1px solid var(--border);cursor:pointer;transition:all .2s;" onclick="closeM('m-drilldown');openCu(${c.id})" onmouseover="this.style.borderColor='var(--orange-b)'" onmouseout="this.style.borderColor=''">
      <div style="width:32px;height:32px;border-radius:8px;background:var(--orange-g);display:flex;align-items:center;justify-content:center;font-weight:900;color:var(--orange);">${(c.name||'?')[0]}</div>
      <div style="flex:1;">
        <div style="font-size:13px;font-weight:700;color:var(--text);">${c.name||'-'}</div>
        <div style="font-size:11px;color:var(--text4);">${types.size} types · ${c.industry||'-'}</div>
      </div>
      <div style="font-size:16px;font-weight:900;font-family:'JetBrains Mono';color:var(--amber);">${alist.length}</div>
    </div>`;
  });
  h+=`<div style="margin-top:16px;text-align:center;"><button class="btn pri" onclick="closeM('m-drilldown');go('customers')">Manage Customer Assets -></button></div>`;
  showDrilldown(`🖥️ Asset Inventory -  ${total} Assets Across ${customers.length} Customers`,h);
}

async function drillCollector(src){
  showDrilldown(`📡 Loading ${src}...`,'<div style="text-align:center;padding:30px;">Fetching...</div>');
  const data=await api(`/api/detections/?limit=30&source=${encodeURIComponent(src)}`);
  const items=data?.items||data?.detections||data||[];
  const bySev={};items.forEach(d=>{const sv=(d.severity||'UNKNOWN').toUpperCase();if(!bySev[sv])bySev[sv]=0;bySev[sv]++;});
  const byType={};items.forEach(d=>{const t=d.ioc_type||'?';if(!byType[t])byType[t]=0;byType[t]++;});
  const _srcExplain={
    'cisa_kev':'CISA Known Exploited Vulnerabilities -  actively exploited CVEs mandated for federal patching. Highest confidence.',
    'openphish':'OpenPhish community feed -  verified phishing URLs updated hourly. Primary phishing detection source.',
    'urlhaus':'URLhaus by abuse.ch -  malware distribution URLs. Covers exploit kits, C2 droppers, and payload hosts.',
    'phishtank':'PhishTank community-verified phishing database. Cross-validated by human analysts.',
    'circl_misp':'CIRCL MISP feed -  European CSIRT sharing platform. Rich STIX-format threat intel from incident responders.',
    'nvd':'NIST National Vulnerability Database -  comprehensive CVE data with CVSS scores and CWE mappings.',
    'rss':'Security RSS aggregator -  advisories from vendors, CERTs, and security researchers.'
  };
  let h=`<div class="dd-summary">
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--cyan);">${items.length}</div><div class="dd-stat-lbl">Detections</div></div>
    <div class="dd-stat"><div class="dd-stat-num" style="color:var(--orange);">${Object.keys(byType).length}</div><div class="dd-stat-lbl">IOC Types</div></div>
    ${Object.entries(bySev).map(([sv,ct])=>`<div class="dd-stat"><div class="dd-stat-num" style="color:${_sevColors[sv]||'var(--text)'};">${ct}</div><div class="dd-stat-lbl">${_sevEmoji[sv]||'⚪'} ${sv}</div></div>`).join('')}
    <div style="flex:1;min-width:200px;padding:4px 0;">
      <div style="font-size:12px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">About this source</div>
      <div style="font-size:13px;color:var(--text2);line-height:1.5;">${_srcExplain[src]||'Threat intelligence collector -  ingests IOCs from external feed and stores in detection pipeline.'}</div>
    </div>
  </div>`;
  // IOC type breakdown bars
  const typeEntries=Object.entries(byType).sort((a,b)=>b[1]-a[1]);
  if(typeEntries.length){
    typeEntries.forEach(([t,ct])=>{
      const pct=Math.round(ct/items.length*100);
      h+=`<div style="display:flex;align-items:center;gap:10px;margin:6px 0;">
        <span style="min-width:100px;font-size:12px;font-weight:600;color:var(--text2);">${t}</span>
        <div style="flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden;">
          <div style="width:${pct}%;height:100%;background:var(--orange);border-radius:4px;box-shadow:0 0 6px rgba(0,137,123,.3);"></div>
        </div>
        <span style="font-size:12px;font-weight:700;color:var(--text);min-width:60px;text-align:right;">${ct} (${pct}%)</span>
      </div>`;
    });
  }
  h+=`<div class="dd-grid" style="margin-top:16px;">${items.slice(0,18).map(d=>{
    const sv=(d.severity||'LOW').toUpperCase();
    return`<div class="dd-card ${_sevCls[sv]||'sev-low'}">
      <div class="dd-card-ioc">${d.ioc_value||'-'}</div>
      <div class="dd-card-meta">
        <span class="dd-pill type">${d.ioc_type||'-'}</span>
        <span class="dd-pill sev" style="color:${_sevColors[sv]||'var(--text3)'};">${_sevEmoji[sv]||'⚪'} ${sv}</span>
        <span class="dd-pill time">${ago(d.collected_at||d.created_at)}</span>
      </div>
    </div>`;}).join('')}</div>`;
  showDrilldown(`📡 ${src} -  ${items.length} Detections`,h);
}

// ═══ 3D THREAT UNIVERSE (now served via iframe from /threat-universe) ═══
function loadTG(){}
function resetTG(){}

// ═══ PARTICLES ═══
(function(){const c=document.getElementById('particles');if(!c)return;const ctx=c.getContext('2d');let W,H,pts=[];
  function resize(){W=c.width=innerWidth;H=c.height=innerHeight;}resize();addEventListener('resize',resize);
  for(let i=0;i<50;i++)pts.push({x:Math.random()*2000,y:Math.random()*2000,r:Math.random()*1.5+.5,vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,a:Math.random()*.2+.05});
  (function draw(){ctx.clearRect(0,0,W,H);pts.forEach(p=>{p.x+=p.vx;p.y+=p.vy;if(p.x<0)p.x=W;if(p.x>W)p.x=0;if(p.y<0)p.y=H;if(p.y>H)p.y=0;
    ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fillStyle=`rgba(230,92,0,${p.a})`;ctx.fill();});
  for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);
    if(d<140){ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.strokeStyle=`rgba(230,92,0,${.04*(1-d/140)})`;ctx.stroke();}}
  requestAnimationFrame(draw);})();})();

// ═══ CLOCK ═══
setInterval(()=>{const el=document.getElementById('sb-time');if(el)el.textContent=new Date().toLocaleTimeString('en-US',{hour12:false});},1000);

// ═══ SIDEBAR: LIVE ACTIVITY FEED ═══
async function refreshActivity(){
  const el=document.getElementById('sb-activity');
  if(!el)return;
  try{
    const [cols,stats]=await Promise.all([api('/api/collectors/status'),api('/api/stats')]);
    const items=[];
    // Collector runs
    const colArr=cols?Object.entries(cols).map(([k,v])=>({id:k,...(typeof v==='object'?v:{status:v})})):[];
    const activeCollectors=colArr.filter(c=>(c.ioc_count||c.count||0)>0).sort((a,b)=>(b.ioc_count||b.count||0)-(a.ioc_count||a.count||0)).slice(0,4);
    activeCollectors.forEach(c=>{
      const cnt=c.ioc_count||c.count||0;
      const nm=c.name||c.id||'';
      items.push({dot:'ok',click:'detections',text:`<span style="color:#a89880;">${nm}</span> <span style="color:#f5f0e8;font-family:'JetBrains Mono';font-weight:800;">${cnt.toLocaleString()}</span> <span style="color:#8c7a65;">IOCs</span>`});
    });
    // Stats-based events
    if(stats){
      if(stats.total_detections)items.push({dot:'ok',click:'detections',text:`<span style="color:#f5f0e8;font-family:'JetBrains Mono';font-weight:800;">${stats.total_detections.toLocaleString()}</span> <span style="color:#a89880;">detections</span>`});
      if(stats.active_customers)items.push({dot:'ok',click:'customers',text:`<span style="color:#f5f0e8;font-family:'JetBrains Mono';font-weight:800;">${stats.active_customers}</span> <span style="color:#a89880;">customers monitored</span>`});
      if(stats.critical_findings)items.push({dot:'warn',click:'findings',text:`<span style="color:#e65100;font-family:'JetBrains Mono';font-weight:800;">${stats.critical_findings}</span> <span style="color:#a89880;">critical findings</span>`});
      if(stats.total_actors)items.push({dot:'ok',click:'actors',text:`<span style="color:#f5f0e8;font-family:'JetBrains Mono';font-weight:800;">${stats.total_actors}</span> <span style="color:#a89880;">MITRE actors</span>`});
    }
    // AI status
    try{
      const aiSt=await api('/api/settings/ai');
      if(aiSt){
        const prov=aiSt.active_provider||aiSt.provider||'ollama';
        items.unshift({dot:'ok',click:'settings',text:`<span style="color:#a89880;">AI:</span> <span style="color:#f5f0e8;font-weight:800;">${prov}</span> <span style="color:#8c7a65;">(${aiSt.model||'qwen3.5:9b'})</span>`});
      }
    }catch(e){}
    // Render -  bigger items, no timestamps, card-like
    el.innerHTML=items.slice(0,7).map(i=>{
      const dotCls=i.dot==='ok'?'background:#2e7d32;box-shadow:0 0 6px #2e7d32;':i.dot==='warn'?'background:#e65100;box-shadow:0 0 6px #e65100;':'background:#9e9e9e;';
      const click=i.click?`onclick="go('${i.click}')" style="cursor:pointer;`:`style="`;
      return`<div ${click}display:flex;align-items:center;gap:8px;padding:6px 8px;margin-bottom:3px;border-radius:8px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.04);color:#d4c8b8;font-size:13px;font-weight:600;transition:all .2s;" onmouseover="this.style.background='rgba(255,255,255,.08)';this.style.borderColor='rgba(255,255,255,.1)'" onmouseout="this.style.background='rgba(255,255,255,.03)';this.style.borderColor='rgba(255,255,255,.04)'">
        <span style="width:7px;height:7px;border-radius:50%;${dotCls}flex-shrink:0;"></span>
        <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${i.text}</span>
        ${i.click?'<span style="font-size:9px;color:#6b5b48;">&#8250;</span>':''}
      </div>`;
    }).join('');
  }catch(e){
    el.innerHTML='<div style="color:#6b5b48;font-size:10px;">Loading...</div>';
  }
}
refreshActivity();
setInterval(refreshActivity,30000);

// ═══ GLOBAL SEARCH ═══
document.getElementById('global-search')?.addEventListener('keydown',async function(e){
  if(e.key==='Enter'&&this.value.trim()){toast('Searching: '+this.value);go('findings');}});

// ═══ AUTO-REFRESH ═══
function startAutoRefresh(){_refreshTimer=setInterval(()=>{const active=document.querySelector('.view.active');
  if(active?.id==='view-overview')loadOv();},REFRESH_MS);}

// ═══ INIT ═══
document.addEventListener('DOMContentLoaded',()=>{checkAuth().then(()=>{showLegalIfNeeded();loadOv().then(()=>{
    // Auto-trigger collection if no detections exist yet
    if(_stats && (_stats.total_detections||0)===0){
      toast('📡 No data yet -  auto-triggering all 16 free collectors...','info');
      apiPost('/api/collect-all').then(()=>{
        toast('⚡ Collection cycle started -  data will appear shortly');
        setTimeout(()=>{loadOv();toast('🔄 Refreshing dashboard...');},15000);
        setTimeout(()=>{loadOv();},30000);
        setTimeout(()=>{loadOv();},60000);
      }).catch(()=>toast('Collection trigger sent -  Intel Proxy will collect when ready'));
    }
  });
  api('/api/customers').then(d=>{_customers=Array.isArray(d)?d:(d?.customers||[]);});
  startAutoRefresh();updateUserBadge();});});


// ═══════════════════════════════════════════════════════════════
// IOC REGISTRY -  Dashboard Tab
// ═══════════════════════════════════════════════════════════════

let _iocRegistry=[];
let _iocFilter='all';

async function loadIocRegistry(){
  const data=await api('/api/admin/ioc-types');
  _iocRegistry=data?.types||[];
  const stats=document.getElementById('ioc-reg-stats');
  const cats={};const sevs={};let mitreMapped=0,kcMapped=0,enrichMapped=0;
  _iocRegistry.forEach(t=>{
    cats[t.category||'Other']=(cats[t.category||'Other']||0)+1;
    sevs[t.base_severity||'MEDIUM']=(sevs[t.base_severity||'MEDIUM']||0)+1;
    if(t.mitre_technique)mitreMapped++;
    if(t.kill_chain_stage)kcMapped++;
    if(t.enrichment_source)enrichMapped++;
  });
  stats.innerHTML=`
    <div class="stat-card"><div class="stat-val">${_iocRegistry.length}</div><div class="stat-label">Total Types</div></div>
    <div class="stat-card"><div class="stat-val">${sevs.CRITICAL||0}</div><div class="stat-label">CRITICAL</div></div>
    <div class="stat-card"><div class="stat-val">${mitreMapped}</div><div class="stat-label">MITRE Mapped</div></div>
    <div class="stat-card"><div class="stat-val">${kcMapped}</div><div class="stat-label">Kill Chain</div></div>
    <div class="stat-card"><div class="stat-val">${enrichMapped}</div><div class="stat-label">Enrichable</div></div>
  `;
  // Filters
  const filters=document.getElementById('ioc-reg-filters');
  const allCats=['all',...Object.keys(cats).sort()];
  filters.innerHTML=allCats.map(c=>`<button class="btn ${_iocFilter===c?'pri':''}" style="font-size:11px;padding:4px 10px;" onclick="_iocFilter='${c}';renderIocGrid()">${c==='all'?'All ('+_iocRegistry.length+')':c+' ('+cats[c]+')'}</button>`).join('');
  renderIocGrid();
}

function renderIocGrid(){
  const grid=document.getElementById('ioc-reg-grid');
  let items=_iocRegistry;
  if(_iocFilter!=='all')items=items.filter(t=>(t.category||'Other')===_iocFilter);
  grid.innerHTML=`<table style="width:100%;font-size:12px;border-collapse:collapse;">
    <tr style="background:var(--bg2);font-weight:700;text-transform:uppercase;font-size:10px;color:var(--text3);">
      <td style="padding:8px;">Type</td><td>Severity</td><td>MITRE</td><td>Kill Chain</td><td>Playbook</td><td>Enrichment</td><td>Status</td><td>Actions</td>
    </tr>
    ${items.map(t=>{
      const sevCls=t.base_severity==='CRITICAL'?'crit':t.base_severity==='HIGH'?'high':t.base_severity==='MEDIUM'?'med':'low';
      return`<tr style="border-bottom:1px solid var(--border);">
        <td style="padding:6px 8px;font-family:'JetBrains Mono';font-weight:600;">${escHtml(t.type_name)}</td>
        <td><span class="tag ${sevCls}" style="font-size:10px;">${t.base_severity||'?'}</span></td>
        <td style="font-size:11px;color:var(--text3);">${t.mitre_technique||' - '}<br><span style="font-size:9px;">${escHtml(t.mitre_tactic||'')}</span></td>
        <td style="font-size:11px;">${t.kill_chain_stage||' - '}</td>
        <td style="font-size:11px;">${t.playbook_key||'generic'}</td>
        <td style="font-size:11px;">${t.enrichment_source||' - '}</td>
        <td><span style="font-size:10px;padding:2px 6px;border-radius:4px;background:${t.status==='PROVEN'?'rgba(46,125,50,.1)':t.status==='WORKING'?'rgba(230,92,0,.1)':'rgba(158,158,158,.1)'};color:${t.status==='PROVEN'?'#2e7d32':t.status==='WORKING'?'#e65c00':'#9e9e9e'}">${t.status||'?'}</span></td>
        <td style="display:flex;gap:4px;">
          <button class="btn" style="font-size:10px;padding:2px 8px;" onclick="iocPreviewScoreFor('${t.type_name}')">📊</button>
          <button class="btn" style="font-size:10px;padding:2px 8px;${t.active?'':'color:var(--text4);'}" onclick="iocToggleType('${t.type_name}',${!t.active})">${t.active?'🟢':'🔴'}</button>
        </td>
      </tr>`}).join('')}
  </table>`;
}

async function iocAddType(){
  const res=document.getElementById('ioc-add-result');
  const body={
    type_name:document.getElementById('ioc-add-name').value.trim().toLowerCase().replace(/\s+/g,'_'),
    regex:document.getElementById('ioc-add-regex').value||null,
    category:document.getElementById('ioc-add-cat').value,
    base_severity:document.getElementById('ioc-add-sev').value,
    mitre_technique:document.getElementById('ioc-add-mitre').value,
    mitre_tactic:document.getElementById('ioc-add-tactic').value,
    mitre_description:document.getElementById('ioc-add-desc').value,
    kill_chain_stage:document.getElementById('ioc-add-kc').value,
    playbook_key:document.getElementById('ioc-add-pb').value,
    enrichment_source:document.getElementById('ioc-add-enrich').value||null,
  };
  if(!body.type_name){res.innerHTML='<div style="color:#c62828;">Type name required</div>';return;}
  const r=await apiPost('/api/admin/ioc-types',body);
  if(r?.status==='created'){
    res.innerHTML=`<div style="color:#2e7d32;padding:8px;border-radius:8px;background:rgba(46,125,50,.06);">✅ <b>${body.type_name}</b> added! Live in 60 seconds.</div>`;
    toast(`IOC type ${body.type_name} added`);
    loadIocRegistry();
  }else{
    res.innerHTML=`<div style="color:#c62828;padding:8px;border-radius:8px;background:rgba(198,40,40,.06);">❌ ${r?.error||'Failed'}</div>`;
  }
}

async function iocTestRegex(){
  const regex=document.getElementById('ioc-add-regex').value;
  const sample=prompt('Paste sample text to test regex against:');
  if(!sample)return;
  const r=await apiPost('/api/admin/ioc-types/test-regex',{regex,sample_text:sample});
  const res=document.getElementById('ioc-add-result');
  if(r?.valid){
    res.innerHTML=`<div style="padding:8px;border-radius:8px;background:rgba(0,137,123,.06);color:var(--text);">
      ✅ Regex valid. <b>${r.match_count}</b> matches found.<br>
      ${r.matches.slice(0,5).map(m=>`<code style="background:var(--bg2);padding:1px 4px;border-radius:3px;font-size:11px;">${escHtml(m.substring(0,60))}</code>`).join(' ')}
    </div>`;
  }else{
    res.innerHTML=`<div style="color:#c62828;">❌ Invalid regex: ${r?.error||'unknown'}</div>`;
  }
}

async function iocPreviewScore(){
  const type_name=document.getElementById('ioc-add-name').value.trim().toLowerCase().replace(/\s+/g,'_');
  const industry=prompt('Customer industry (e.g. healthcare, financial, technology):','technology');
  const r=await apiPost('/api/admin/ioc-types/preview-score',{
    ioc_type:type_name,customer_industry:industry||'',
    enrichment:{active:true},exposure_confirmed:true,detection_age_days:0,
  });
  const res=document.getElementById('ioc-add-result');
  if(r?.score!==undefined){
    const factors=r.factors||{};
    res.innerHTML=`<div style="padding:10px;border-radius:8px;background:rgba(230,92,0,.04);border-left:3px solid var(--orange);">
      <div style="font-size:14px;font-weight:800;margin-bottom:6px;">Auto-Score: <span class="tag ${r.severity==='CRITICAL'?'crit':r.severity==='HIGH'?'high':'med'}">${r.severity}</span> (${(r.score*100).toFixed(0)}%) -> SLA ${r.sla_hours}h</div>
      <div style="font-size:11px;color:var(--text3);line-height:1.6;">
        ${Object.entries(factors).map(([k,v])=>`${k}: <b>${(v.value*100).toFixed(0)}%</b> × ${v.weight} = ${(v.contribution*100).toFixed(1)}%`).join('<br>')}
      </div>
      <div style="margin-top:6px;font-size:11px;color:var(--orange);">${r.override_reason||''}</div>
    </div>`;
  }
}

async function iocPreviewScoreFor(typeName){
  const r=await apiPost('/api/admin/ioc-types/preview-score',{
    ioc_type:typeName,customer_industry:'technology',
    enrichment:{active:true},exposure_confirmed:true,detection_age_days:0,
  });
  if(r?.score!==undefined){
    showDrilldown(`📊 Auto-Score: ${typeName}`,`
      <div style="padding:16px;">
        <div style="font-size:18px;font-weight:800;margin-bottom:12px;">
          ${typeName} -> <span class="tag ${r.severity==='CRITICAL'?'crit':r.severity==='HIGH'?'high':'med'}">${r.severity}</span> (${(r.score*100).toFixed(0)}%) SLA: ${r.sla_hours}h
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          ${Object.entries(r.factors||{}).map(([k,v])=>`<div style="padding:8px;border-radius:8px;background:var(--bg2);">
            <div style="font-size:10px;text-transform:uppercase;color:var(--text3);">${k.replace(/_/g,' ')}</div>
            <div style="font-size:16px;font-weight:700;">${(v.value*100).toFixed(0)}%</div>
            <div style="font-size:10px;color:var(--text4);">weight: ${v.weight} -> ${(v.contribution*100).toFixed(1)}%</div>
          </div>`).join('')}
        </div>
        <div style="margin-top:12px;padding:8px;border-radius:8px;background:rgba(230,92,0,.04);font-size:12px;color:var(--orange);">${r.override_reason||''}</div>
      </div>
    `);
  }
}

async function iocToggleType(typeName,activate){
  if(activate){
    await apiPost('/api/admin/ioc-types/'+typeName,{active:true},'PUT');
    toast(`${typeName} activated`);
  }else{
    if(!confirm(`Deactivate ${typeName}? It won't match new detections.`))return;
    await fetch('/api/admin/ioc-types/'+typeName,{method:'DELETE'});
    toast(`${typeName} deactivated`);
  }
  loadIocRegistry();
}

// ═══ AUTO-DISCOVERY: Scan detections for unknown patterns ═══
async function iocRunAutoDiscover(){
  const panel=document.getElementById('ioc-auto-discoveries');
  panel.innerHTML=`<div style="padding:16px;border-radius:12px;background:rgba(123,31,162,.04);border:1px solid rgba(123,31,162,.1);">
    <div style="display:flex;align-items:center;gap:8px;"><span class="loading-spin" style="display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:#7b1fa2;border-radius:50%;animation:spin .6s linear infinite;"></span>
    <span style="font-size:13px;font-weight:700;color:var(--text);">Scanning recent detections for unknown IOC patterns...</span></div>
  </div>`;
  const r=await api('/api/admin/ioc-types/auto-discover');
  if(!r?.suggestions?.length){
    panel.innerHTML=`<div style="padding:12px;border-radius:10px;background:rgba(46,125,50,.04);border-left:3px solid #2e7d32;">✅ No unknown patterns found. All recent detections match registered IOC types.</div>`;
    return;
  }
  panel.innerHTML=`<div style="padding:12px;border-radius:10px;background:rgba(230,92,0,.04);border-left:3px solid var(--orange);margin-bottom:12px;">
    <b>🔍 ${r.suggestions.length} unknown pattern(s) found</b> in recent detections. Review and add to registry:</div>
    ${r.suggestions.map((s,i)=>`<div style="padding:10px;border-radius:8px;background:var(--surface);border:1px solid var(--border);margin-bottom:8px;display:flex;align-items:center;gap:12px;">
      <div style="flex:1;">
        <div style="font-family:'JetBrains Mono';font-weight:700;font-size:13px;">${escHtml(s.suggested_type||s.ioc_type||'unknown')}</div>
        <div style="font-size:11px;color:var(--text3);">${s.count||0} detections | Sample: <code>${escHtml((s.sample||'').substring(0,50))}</code></div>
        ${s.suggested_regex?`<div style="font-size:10px;color:var(--text4);margin-top:2px;">Suggested regex: <code>${escHtml(s.suggested_regex)}</code></div>`:''}
      </div>
      <button class="btn pri" style="font-size:11px;" onclick="iocAdoptSuggestion(${i})">+ Add</button>
      <button class="btn" style="font-size:11px;" onclick="this.closest('div[style]').remove()">Dismiss</button>
    </div>`).join('')}`;
  window._iocSuggestions=r.suggestions;
}

function iocAdoptSuggestion(idx){
  const s=window._iocSuggestions?.[idx];
  if(!s)return;
  document.getElementById('ioc-add-name').value=s.suggested_type||s.ioc_type||'';
  document.getElementById('ioc-add-regex').value=s.suggested_regex||'';
  openM('m-add-ioc');
}
