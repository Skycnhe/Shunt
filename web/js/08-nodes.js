// 节点：可折叠的策略组卡片 + 策略选择
let PROXIES={},NSORT=localStorage.getItem('mp_nsort')||'default',GL=[],GALL=[],HIDEDEAD=localStorage.getItem('mp_hidedead')==='1';
let HEALTHR={},HEALTHC={},HF=localStorage.getItem('mp_hf')||'all';  // 健康数据、健康配置、健康筛选
let DIRECT_D;  // 直连国内延迟：DIRECT 是国内直连，与概览百度卡片同口径
const isDead=n=>!isGroup(n)&&(()=>{const d=lastDelay(n);return d!==undefined&&d<=0})();
function toggleDead(){HIDEDEAD=!HIDEDEAD;localStorage.setItem('mp_hidedead',HIDEDEAD?'1':'0');renderGroups();if(TAB==='概览')loadQS()}
let GOPEN=(()=>{try{const o=JSON.parse(localStorage.getItem('mp_gopen')||'{}');return o&&typeof o==='object'&&!Array.isArray(o)?o:{}}catch{return {}}})();
const HCURL='https://www.gstatic.com/generate_204';
const GT={Selector:'手动选择',URLTest:'自动测速',Smart:'智能竞技',Fallback:'故障转移',LoadBalance:'负载均衡',Relay:'链式代理'};
const GTC={Selector:'k-sel',URLTest:'k-auto',Smart:'k-auto',Fallback:'k-fb',LoadBalance:'k-lb'};
const LBS={'consistent-hashing':'一致性哈希','round-robin':'轮询','sticky-sessions':'粘性会话'};
const isGroup=n=>!!(PROXIES[n]&&PROXIES[n].all);
async function loadProxies(){document.querySelectorAll('#nsort button').forEach(b=>{b.classList.toggle('on',b.dataset.v===NSORT);b.onclick=()=>{NSORT=b.dataset.v;localStorage.setItem('mp_nsort',NSORT);renderGroups()}});
  document.querySelectorAll('#hf button').forEach(b=>{b.classList.toggle('on',b.dataset.v===HF);b.onclick=()=>{HF=b.dataset.v;localStorage.setItem('mp_hf',HF);renderGroups()}});
  try{PROXIES=await loadPX();try{const j=await api('/api/direct_delay');if(j.ms>0)DIRECT_D=j.ms}catch(e){}
  try{const h=await api('/api/health/status');HEALTHR=h.records||{};HEALTHC=h.cfg||{}}catch(e){}
  renderGroups()}catch(e){$('#groups').innerHTML=`<div class="card bad">${esc(e.message)}</div>`;$('#policies').innerHTML=''}}
// 健康等级：ok/warn/bad/hidden；返回图标
function hLevel(n){const r=HEALTHR[n];if(!r)return 'ok';if(r.hidden)return 'hidden';
  const fd=r.fail_days||0,wc=HEALTHC.warn_days||3,hc=HEALTHC.hide_days||7;
  if(fd>=hc)return 'hidden';if(fd>=wc)return 'bad';if(fd>0)return 'warn';return 'ok'}
function hIcon(n){const l=hLevel(n);return l==='warn'?'🟡 ':l==='bad'?'🔴 ':l==='hidden'?'🚫 ':''}
// 健康筛选：当前选中的节点始终显示，避免界面混乱
function hfVisible(n,now){const l=hLevel(n);if(n===now)return true;
  if(HF==='normal')return l==='ok';if(HF==='bad')return l==='warn'||l==='bad';if(HF==='hidden')return true;return l!=='hidden'}
async function unhideNode(n){try{const j=await api('/api/health/unhide','POST',{node_id:n});toast(j.message);const h=await api('/api/health/status');HEALTHR=h.records||{};renderGroups()}catch(e){toast(e.message)}}
function rawDelay(n){if(n==='DIRECT'&&DIRECT_D!==undefined)return DIRECT_D;const p=PROXIES[n];if(!p)return undefined;if(p._d!==undefined)return p._d;
  let best;[p.history||[],...Object.values(p.extra||{}).map(x=>x?.history||[])].forEach(h=>{const e=h[h.length-1];if(e&&(!best||String(e.time||'')>String(best.time||'')))best=e});
  return best?best.delay:undefined}
// 负载均衡组没有单一的“当前节点”，组延迟取成员中最快的可用节点；成员都没测过时再用组自身的记录
// 选择 / 自动测速 / 故障转移组的延迟 = 当前实际使用节点的延迟（组自身的记录很少更新，会忽有忽无）
function lastDelay(n,_d){const p=PROXIES[n];if(!p)return undefined;
  if(p.all&&p.type!=='LoadBalance'&&p.type!=='Smart'&&p.now&&PROXIES[p.now]&&(_d||0)<5){const d=lastDelay(p.now,(_d||0)+1);if(d!==undefined)return d}
  if((p.type==='LoadBalance'||p.type==='Smart')&&(_d||0)<4){let best,tested=false;for(const m of (p.all||[])){const d=lastDelay(m,(_d||0)+1);if(d===undefined)continue;tested=true;if(d>0&&(best===undefined||d<best))best=d}
    if(tested)return best===undefined?0:best}
  return rawDelay(n)}
function groupOrder(){const order=(PROXIES.GLOBAL&&PROXIES.GLOBAL.all)||Object.keys(PROXIES);
  return order.filter(n=>isGroup(n)).concat(['GLOBAL']).filter((v,i,a)=>a.indexOf(v)===i&&PROXIES[v])}
function nowChain(g){const out=[];let n=PROXIES[g]?.type==='Smart'?'':PROXIES[g]?.now,k=0;while(n&&k++<5){out.push(n);n=isGroup(n)&&PROXIES[n].type!=='Smart'?PROXIES[n].now:''}return out}
// 默认只展开「🚀 节点选择」和「🖐️ 手动选择」，其他组收成一行；展开 / 收起会被记住
function gOpen(g){if(NF.q||NF.r)return true;return g in GOPEN?GOPEN[g]:(g===SEL||g===G_MANUAL)}
// 筛选：关键词 + 地区（地区 = 「xx竞技」组的成员）
let NF={q:'',r:''};
const AUTO_TAIL='竞技';
function regionGroups(){return Object.keys(PROXIES).filter(n=>isGroup(n)&&n.endsWith(AUTO_TAIL)&&['URLTest','Smart'].includes(PROXIES[n].type))}
function nfVisible(n){const q=NF.q,r=NF.r;
  if(q&&!n.toLowerCase().includes(q))return false;
  if(r){const lab=r.slice(0,-AUTO_TAIL.length).split(' ').pop();if(isGroup(n))return n.includes(lab);return (PROXIES[r]?.all||[]).includes(n)}
  return true}
function renderNF(){const rg=regionGroups();$('#nf-r').innerHTML=rg.length?[`<button class="chipf ${NF.r?'':'on'}" onclick="NF.r='';renderGroups()">全部</button>`]
  .concat(rg.map(g=>`<button class="chipf ${NF.r===g?'on':''}" onclick="NF.r=${esc(JSON.stringify(g))};renderGroups()">${esc(g.slice(0,-AUTO_TAIL.length))}</button>`)).join(''):''}
// 分流组（YouTube / Google 等）在顶部「策略选择」里用下拉切换，下面不再重复显示卡片
function policyOnly(g){return g!=='GLOBAL'&&g!==SEL&&g!==G_MANUAL&&PROXIES[g].type==='Selector'&&(PROXIES[g].all||[]).length>1}
function saveOpen(){localStorage.setItem('mp_gopen',JSON.stringify(GOPEN))}
function toggleG(i){const g=GL[i];GOPEN[g]=!gOpen(g);saveOpen();document.getElementById('gc'+i)?.classList.toggle('open',GOPEN[g])}
function setAllOpen(v){GL.forEach(g=>GOPEN[g]=v);saveOpen();document.querySelectorAll('.gcard').forEach(e=>e.classList.toggle('open',v))}
function gTag(g){const p=PROXIES[g],m=(STATE.group_meta||{})[g]||{};
  return `<span class="tag ${GTC[p.type]||''}">${esc(GT[p.type]||p.type)}</span>`+(m.kind==='custom'?'<span class="tag k-cus">自定义</span>':'')}
function renderGroups(){
  GL=groupOrder();GALL=[];
  const key=n=>{const d=lastDelay(n);return d===undefined?1e9-1:d<=0?1e9:d};
  renderNF();const filt=!!(NF.q||NF.r);
  $('#groups').innerHTML=GL.map((g,i)=>{const p=PROXIES[g],m=(STATE.group_meta||{})[g]||{};
    const all0=NSORT==='delay'?p.all.slice().sort((a,b)=>key(a)-key(b)):p.all.slice();GALL[i]=all0;
    if(policyOnly(g))return '';
    const vis=filt?all0.filter(nfVisible):all0;if(filt&&!vis.length&&!(NF.q&&g.toLowerCase().includes(NF.q)))return '';
    const all=HIDEDEAD?vis.filter(n=>n===p.now||!isDead(n)):vis,hid=vis.length-all.length;
    const allH=all.filter(n=>hfVisible(n,p.now)),hidH=all.length-allH.length;
    const ch=nowChain(g),dl=lastDelay(g),lb=p.type==='LoadBalance';
    const sub=lb?`策略：<b>${esc(LBS[m.strategy]||m.strategy||'-')}</b>`:p.type==='Smart'?(p.fixed?'已固定 → <b>'+esc(p.fixed)+'</b>':'智能竞技：按延迟 / 丢包 / 速度打分'+(p.uselightgbm||p.useLightGBM?' + LightGBM':'')):ch.length?'→ <b>'+ch.map(esc).join(' → ')+'</b>':'';
    const nodesN=allH.filter(n=>!isGroup(n)).length,groupsN=allH.length-nodesN;
    const cnt=[nodesN?nodesN+' 个节点':'',groupsN?groupsN+' 个分组':'',hid?`<span class="bad">已隐藏 ${hid} 个超时</span>`:'',hidH?`<span class="bad">健康隐藏 ${hidH} 个</span>`:''].filter(Boolean).join(' · ');
    const pin=p.fixed?`<span class="tag pin" title="点击取消固定，恢复自动选择" onclick="event.stopPropagation();unfix(${i})">📌 已固定 ✕</span>`:'';
    const ico=p.icon?`<img class="gico" src="${esc(p.icon)}" alt="" onerror="this.remove()">`:'';
    const dots=allH.slice(0,80).map(n=>`<i class="${dcls(lastDelay(n))==='mut'?'':dcls(lastDelay(n))}"></i>`).join('');
    return `<div class="card gcard ${gOpen(g)?'open':''}" id="gc${i}"><div class="ghead" onclick="toggleG(${i})">
      <span class="chev"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg></span>${ico}
      <div class="gt"><div class="gname">${esc(g)} ${gTag(g)} ${pin}</div><div class="gsub">${sub}${sub&&cnt?' · ':''}${cnt}</div><div class="dots">${dots}</div></div>
      ${dl!==undefined?`<span class="gdl ${dcls(dl)}"${lb?' title="成员中最快的可用节点"':''}>${lb&&dl>0?'最快 ':''}${dtxt(dl)}</span>`:''}
      <button class="btn g sm" onclick="event.stopPropagation();testGroup(${i},this)">测速</button></div>
      <div class="gbody"><div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(min(100%,178px),1fr));gap:10px">${allH.map(n=>{const j=all0.indexOf(n),d=lastDelay(n),sg=isGroup(n);
        const s2=sg?`<div class="sub2">${esc(GT[PROXIES[n].type]||'')}${PROXIES[n].now?' → '+esc(PROXIES[n].now):''}</div>`:'';
        const unh=hLevel(n)==='hidden'?`<button class="btn g sm" onclick="event.stopPropagation();unhideNode(${jsq(n)})">取消隐藏</button>`:'';
        return `<div class="node ${n===p.now&&!lb?'sel':''} ${lb?'lbm':''}" onclick="pick(${i},${j})" title="${esc(n)}">
        <div class="n">${hIcon(n)}${sg?'📁 ':''}${esc(n)}</div>${s2}<div class="d"><span class="mut">${esc(sg?'分组':PROXIES[n]?.type||'')}</span> <span class="${dcls(d)}">${dtxt(d)}</span></div>${unh}</div>`}).join('')}</div></div></div>`}).join('')||(filt?'<div class="card mut">没有匹配的节点</div>':'<div class="card mut">还没有节点，先去“订阅”添加订阅或导入节点</div>');
  $('#hidedead').classList.toggle('on',HIDEDEAD);$('#hidedead').textContent=HIDEDEAD?'显示超时':'隐藏超时';
  renderPolicies()}
function renderPolicies(){const sel=GL.filter(g=>g!=='GLOBAL'&&PROXIES[g].type==='Selector'&&(PROXIES[g].all||[]).length>1);
  $('#pol-card').classList.toggle('hide',!sel.length);
  $('#policies').innerHTML=sel.map(g=>{const p=PROXIES[g],i=GL.indexOf(g),d=lastDelay(g);
    return `<div class="pitem"><div class="pl"><span>${esc(g)}</span>${(STATE.group_meta||{})[g]?.kind==='custom'?'<span class="tag k-cus">自定义</span>':''}<span class="sp"></span><span class="${dcls(d)} small">${d!==undefined?dtxt(d):''}</span></div>
      <select onchange="pickName(${i},this.value)">${p.all.map(n=>`<option ${n===p.now?'selected':''} value="${esc(n)}">${isGroup(n)?'📁 ':''}${esc(n)}</option>`).join('')}</select></div>`}).join('')}
async function pickName(i,n){const g=GL[i],p=PROXIES[g];if(!p)return;
  if(p.type==='LoadBalance'){toast('负载均衡组按策略自动分配连接，不能手动指定节点');return}
  if(!['Selector','URLTest','Fallback','Smart'].includes(p.type)){toast('该组不支持手动切换');return}
  try{await core('/proxies/'+encodeURIComponent(g),'PUT',{name:n});
    toast(p.type==='Selector'?`${g} → ${n}`:`${g} 已固定为 ${n}（点 📌 取消固定恢复自动）`);loadProxies()}catch(e){toast(e.message)}}
function pick(i,j){pickName(i,GALL[i][j])}
async function unfix(i){try{await core('/proxies/'+encodeURIComponent(GL[i]),'DELETE');toast('已取消固定，恢复自动选择');loadProxies()}catch(e){toast(e.message)}}
async function testGroup(i,btn){btn.disabled=true;btn.textContent='测速中…';
  await testGroupKeep(GL[i]);
  btn.disabled=false;btn.textContent='测速';loadProxies()}
async function testAll(btn){btn.disabled=true;btn.textContent='测速中…';
  const gs=['GLOBAL'].concat(PROXIES[G_MANUAL]?[G_MANUAL]:[]);
  await Promise.all(gs.map(g=>core(`/group/${encodeURIComponent(g)}/delay?url=${encodeURIComponent(HCURL)}&timeout=5000`).catch(()=>{})));
  btn.disabled=false;btn.textContent='全部测速';loadProxies()}

// 订阅节点管理：勾选一个或多个订阅节点「从订阅删除」（按订阅 + 节点原名记入该订阅的已删除名单）
// SNS：本次打开时的订阅快照。SN 是和策略组页共用的全局变量，切到策略组页会被重新加载，不能直接用来渲染 / 按序号取订阅
let SNI=[],SNS=[],SNSEL=new Set();
async function toggleSN(){const b=$('#sn-box'),open=b.classList.contains('hide');b.classList.toggle('hide',!open);$('#sn-toggle').textContent=open?'收起':'选择节点删除';if(open)await reloadSN()}
async function reloadSN(){await loadSN();SNI=[];SNS=SN.subs;SNS.forEach(s=>s.nodes.forEach(n=>SNI.push({sub:s.name,orig:n.orig,name:n.name,groups:n.groups||[]})));SNSEL=new Set();renderSN()}
function snVis(q){return SNI.map((x,i)=>i).filter(i=>!q||SNI[i].name.toLowerCase().includes(q)||SNI[i].sub.toLowerCase().includes(q))}
function renderSN(){const q=$('#sn-q').value.trim().toLowerCase(),vis=snVis(q),by={};vis.forEach(i=>(by[SNI[i].sub]=by[SNI[i].sub]||[]).push(i));
  $('#sn-list').innerHTML=SNS.map((s,si)=>{const ids=by[s.name]||[];if(!ids.length)return q?'':`<div class="mut small" style="margin:4px 0">${esc(s.name)}：${s.known?'没有节点':'节点未加载'}</div>`;
    const all=ids.every(i=>SNSEL.has(i));
    return `<div style="margin-bottom:10px"><label class="row small" style="gap:6px;margin:2px 0 4px"><input type="checkbox" ${all?'checked':''} onchange="snAll(${si},this.checked)"><b>${esc(s.name)}</b><span class="mut">${ids.length} 个${q?'匹配':''}</span></label>
    ${ids.slice(0,500).map(i=>{const x=SNI[i];return `<label class="row small" style="gap:6px;padding:2px 0 2px 18px" title="${esc(x.name)}"><input type="checkbox" ${SNSEL.has(i)?'checked':''} onchange="snTog(${i},this.checked)"><span class="sp" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.name)}</span>${x.groups.length?`<span class="tag k-cus" title="${esc(x.groups.join('、'))}">在 ${x.groups.length} 个自定义组</span>`:''}</label>`}).join('')}${ids.length>500?`<div class="mut small">还有 ${ids.length-500} 个，请搜索</div>`:''}</div>`}).join('')
    ||`<span class="mut small">${SNS.length?'没有匹配的订阅节点':'还没有订阅'}</span>`;
  $('#sn-cnt').textContent=`已选 ${SNSEL.size} 个`}
function snTog(i,on){on?SNSEL.add(i):SNSEL.delete(i);$('#sn-cnt').textContent=`已选 ${SNSEL.size} 个`}
function snAll(si,on){const s=SNS[si];if(!s)return;const q=$('#sn-q').value.trim().toLowerCase();snVis(q).filter(i=>SNI[i].sub===s.name).forEach(i=>on?SNSEL.add(i):SNSEL.delete(i));renderSN()}
function snClear(){SNSEL=new Set();renderSN()}
async function snDelete(btn){const items=[...SNSEL].map(i=>SNI[i]).filter(Boolean);if(!items.length)return toast('请先勾选要删除的订阅节点');
  const used=items.filter(x=>x.groups.length),gs=[...new Set(used.flatMap(x=>x.groups))];
  let msg=`从订阅删除 ${items.length} 个节点？\n`+items.slice(0,8).map(x=>x.sub+' · '+x.name).join('\n')+(items.length>8?`\n… 等 ${items.length} 个`:'')+'\n\n订阅更新后也不会再出现，可在「订阅」页恢复。';
  if(used.length)msg+=`\n\n⚠️ 其中 ${used.length} 个节点被自定义策略组勾选（${gs.slice(0,5).join('、')}${gs.length>5?' 等':''}），删除后这些组不再使用它们，并在策略组页显示「已失效」。`;
  if(!confirm(msg))return;btn.disabled=true;
  try{toast('正在删除并应用…');const j=await api('/api/subs/nodes/remove','POST',{items:items.map(x=>({sub:x.sub,name:x.orig}))});toast(j.message);await reloadSN();loadProxies()}catch(e){toast(e.message)}
  btn.disabled=false}
