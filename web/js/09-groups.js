// 策略组管理
let GI=null,CGF=null,GCF={},_pv=0,SN={subs:[]};
const TYN={'select':'手动选择','url-test':'自动测速','fallback':'故障转移','load-balance':'负载均衡'};
const TYC={'select':'k-sel','url-test':'k-auto','fallback':'k-fb','load-balance':'k-lb'};
async function loadGroupsPage(){try{[GI]=await Promise.all([api('/api/groups'),loadState().catch(()=>{}),loadSN()])}catch(e){return toast(e.message)}
  GCF=Object.assign({},GI.cfg,{on:GI.region_groups});renderGC();renderRegions();renderCGList();if(CGF)renderCGSChosen();$('#gc-lb-sb').classList.toggle('hide',GI.core!=='singbox')}
// 订阅节点清单（节点显示名 + 原名 + 引用它的自定义组）：策略组编辑器勾选、节点页「从订阅删除」共用
async function loadSN(){try{SN=await api('/api/subs/nodes')}catch(e){SN={subs:[]}}if(!SN||!Array.isArray(SN.subs))SN={subs:[]};return SN}
const snKey=(sub,name)=>sub+'\n'+name;
function snIndex(){const m=new Map(),st=new Map();SN.subs.forEach(s=>{st.set(s.name,s);s.nodes.forEach(n=>m.set(snKey(s.name,n.orig),n.name))});return {m,st}}
// 勾选的订阅节点已失效：订阅已删除、节点已从订阅删除，或订阅里已经没有它（订阅节点未加载时不判失效）
function snStale(x,ix){ix=ix||snIndex();const s=ix.st.get(x.sub);if(!s)return true;if((s.removed||[]).includes(x.name))return true;return s.known&&!ix.m.has(snKey(x.sub,x.name))}
function renderGC(){const c=GCF;$('#gc-on').checked=c.on;$('#gc-on').onchange=e=>{GCF.on=e.target.checked;renderGC()};
  $('#gc-box').classList.toggle('dim',!c.on);$('#gc-box').style.opacity=c.on?'':'.5';
  [['#gc-lb','lb'],['#gc-extra','extra'],['#gc-other','other'],['#gc-lazy','lazy'],['#gc-lgbm','lgbm']].forEach(([k,f])=>{$(k).checked=!!c[f];$(k).onchange=e=>{GCF[f]=e.target.checked;if(f==='lgbm')saveGC()}});  // LightGBM 开关点了直接保存
  const iv=$('#gc-int');if(![...iv.options].some(o=>o.value===String(c.interval)))iv.insertAdjacentHTML('beforeend',`<option value="${c.interval}">${c.interval} 秒</option>`);
  iv.value=String(c.interval);iv.onchange=e=>GCF.interval=+e.target.value;$('#gc-tol').value=c.tolerance;$('#gc-tol').onchange=e=>GCF.tolerance=+e.target.value;
  $('#gc-url').value=c.url;$('#gc-url').onchange=e=>GCF.url=e.target.value.trim()}
async function lgbmUpdate(b){b.disabled=true;toast('正在下载 LightGBM 模型…');try{const j=await api('/api/coreupdate','POST',{action:'lgbm',core:'smart'});toast(j.message)}catch(e){toast(e.message)}b.disabled=false}
async function saveGC(){const c=GCF;const body={region_groups:c.on,lb:c.lb,extra:c.extra,other:c.other,lazy:c.lazy,lgbm:!!c.lgbm,
    interval:+$('#gc-int').value,tolerance:+$('#gc-tol').value,url:$('#gc-url').value.trim()};
  try{toast('正在校验并应用…');const j=await api('/api/groups/cfg','PUT',body);toast(j.message);await loadGroupsPage();
    if(body.lgbm&&!GI.cfg.lgbm)toast('LightGBM 开关没有保存成功：面板服务端还是旧版本，请确认「面板更新」显示 6.8.1 并重启面板服务')}catch(e){toast(e.message);loadGroupsPage()}}
function renderRegions(){$('#gc-regions').innerHTML=GI.regions.map(r=>`<tr><td><b style="font-weight:600">${esc(r.name)}</b></td>
    <td>${r.unknown&&!r.total?'<span class="mut">订阅未加载</span>':r.total+(r.unknown?'+':'')}${r.manual&&r.manual!==r.total?` <span class="mut small">（手动 ${r.manual}）</span>`:''}</td>
    <td class="w">${r.groups.map(g=>`<span class="tag ${TYC[GI.meta[g]?.type]||''}" style="margin:1px 4px 1px 0;display:inline-block">${esc(g)} · ${esc(TYN[GI.meta[g]?.type]||'')}</span>`).join('')}</td></tr>`).join('')
  ||`<tr><td colspan="3" class="mut">${GI.region_groups?'没有识别出地区（还没有节点或订阅）':'地区分组已关闭'}</td></tr>`;
  $('#gc-sel').innerHTML=(GI.selector||[]).map(g=>`<span class="mchip grp" style="padding-right:10px"><span>${esc(g)}</span></span>`).join('')||'<span class="mut small">-</span>'}
async function refreshRegions(btn){btn.disabled=true;try{const j=await api('/api/groups/refresh','POST');toast(j.message)}catch(e){toast(e.message)}btn.disabled=false;loadGroupsPage()}
function polIdx(r){const p=r.split(',');let i=p.length-1;while(i>0&&['no-resolve','src'].includes(p[i].trim().toLowerCase()))i--;return [p,i]}
function cgRefs(n){let c=0;(STATE.rules||[]).forEach(r=>{if(r.startsWith('#'))return;const [p,i]=polIdx(r);if(i>0&&p[i].trim()===n)c++});
  (STATE.rulesets||[]).forEach(r=>{if(r.target===n)c++});(GI.custom||[]).forEach(g=>{if(g.proxies.includes(n))c++});
  const dn=STATE.dns||{};[...(dn.direct||[]),...(dn.proxy||[]),...(dn.pserver||[]),...(dn.policies||[]).flatMap(p=>p.servers)].forEach(x=>{if(x.includes('#')&&x.split('#')[1].split('&')[0]===n)c++});return c}
function renderCGList(){const ix=snIndex();$('#cg-list').innerHTML=(GI.custom||[]).map((g,i)=>{const sn=g.sub_nodes||[],bad=sn.filter(x=>snStale(x,ix)).length;
    const mem=[g.proxies.slice(0,3).map(esc).join('、')+(g.proxies.length>3?` 等 ${g.proxies.length} 项`:''),sn.length?`订阅节点 ${sn.length} 个`+(bad?` <span class="bad">（${bad} 个已失效）</span>`:''):''].filter(Boolean).join('<br>');
    const ex=GI.meta[g.name];return `<tr><td class="w" style="min-width:120px"><b style="font-weight:600">${g.icon?`<img class="gico" style="width:18px;height:18px;vertical-align:-4px;margin-right:4px" src="${esc(g.icon)}" onerror="this.remove()">`:''}${esc(g.name)}</b>${g.expose?'':'<div class="mut small">不加入分流组候选</div>'}</td>
    <td><span class="tag ${TYC[g.type]}">${TYN[g.type]}</span>${g.type==='load-balance'?`<div class="mut small">${LBS[g.strategy]||''}</div>`:''}${ex&&ex.sb_from?'<div class="warn small">sing-box 下按自动测速</div>':''}</td>
    <td class="w small" style="max-width:260px">${mem||''}${g.filter?`${mem?'<br>':''}<span class="mut">正则：</span><code>${esc(g.filter)}</code>${g.subs?'':' <span class="mut">（仅手动节点）</span>'}`:''}${ex?'':'<div class="warn small">未生效</div>'}</td>
    <td>${cgRefs(g.name)}</td><td style="text-align:right;white-space:nowrap"><button class="btn g sm" onclick="editCG(${i})">编辑</button> <button class="btn r sm" onclick="delCG(${i})">删除</button></td></tr>`}).join('')
    ||'<tr><td colspan="5" class="mut">还没有自定义策略组。例如：把美国和日本节点合成一个「🎯 美日均衡」负载均衡组，或建一个「🎮 游戏」组给规则引用</td></tr>'}
function newCG(){CGF={orig:'',name:'',icon:'',type:'select',proxies:[],sub_nodes:[],filter:'',subs:true,expose:true,strategy:'consistent-hashing',interval:'',tolerance:''};openCG('新建策略组')}
function editCG(i){const g=GI.custom[i];CGF=JSON.parse(JSON.stringify(Object.assign({strategy:'consistent-hashing',interval:'',tolerance:''},g,{orig:g.name})));
  if(!Array.isArray(CGF.sub_nodes))CGF.sub_nodes=[];if(!CGF.interval)CGF.interval='';if(!CGF.tolerance)CGF.tolerance='';openCG('编辑策略组：'+g.name)}
function openCG(t){$('#cg-title').textContent=t;$('#cg-form').classList.remove('hide');$('#cg-name').value=CGF.name;$('#cg-icon').value=CGF.icon||'';
  $('#cg-filter').value=CGF.filter||'';$('#cg-subs').checked=CGF.subs!==false;$('#cg-expose').checked=CGF.expose!==false;$('#cg-search').value='';$('#cg-ssearch').value='';
  $('#cg-st').value='consistent-hashing';$('#cg-int').value=CGF.interval||'';$('#cg-tol').value=CGF.tolerance||'';
  cgType();renderCGChosen();renderCGSChosen();previewCG();$('#cg-form').scrollIntoView({behavior:'smooth',block:'start'})}
function cgType(){segv('#cg-type',CGF.type,v=>{CGF.type=v;cgType()});const t=CGF.type;$('#cg-adv').classList.toggle('hide',t==='select');
  $('#cg-tol').classList.toggle('hide',t!=='url-test')}
function closeCG(){$('#cg-form').classList.add('hide');CGF=null}
function cgCands(){return GI.groups.filter(g=>g!==CGF.orig).concat(['DIRECT','REJECT']).concat(GI.manual)}
function renderCGChosen(){$('#cg-chosen').innerHTML=CGF.proxies.map((m,i)=>`<span class="mchip ${GI.groups.includes(m)?'grp':''}" title="${esc(m)}"><span>${GI.groups.includes(m)?'📁 ':''}${esc(m)}</span>${i?`<button title="上移" onclick="cgMove(${i})">↑</button>`:''}<button title="移除" onclick="cgDel(${i})">✕</button></span>`).join('')||'<span class="mut small">还没有成员（也可以只用下方正则筛选）</span>';renderCGPick()}
function renderCGPick(){const q=$('#cg-search').value.trim().toLowerCase();const c=cgCands().filter(n=>!CGF.proxies.includes(n)&&(!q||n.toLowerCase().includes(q)));
  $('#cg-pick').innerHTML=c.slice(0,160).map(n=>`<span class="mchip add ${GI.groups.includes(n)?'grp':''}" onclick="cgAdd(this.dataset.n)" data-n="${esc(n)}"><span>${GI.groups.includes(n)?'📁 ':''}${esc(n)}</span></span>`).join('')+(c.length>160?`<span class="mut small">还有 ${c.length-160} 项，请搜索</span>`:'')||'<span class="mut small">无匹配项</span>'}
function renderCGSChosen(){const ix=snIndex();$('#cg-schosen').innerHTML=CGF.sub_nodes.map((x,i)=>{const st=snStale(x,ix),d=ix.m.get(snKey(x.sub,x.name))||x.name;
    return `<span class="mchip" title="${esc(x.sub+' · '+x.name)}"><span>${esc(x.sub)} · ${esc(d)}</span>${st?'<b class="bad small">已失效</b>':''}<button title="移除" onclick="cgSDel(${i})">✕</button></span>`}).join('')||'<span class="mut small">没有勾选订阅节点</span>';renderCGSPick()}
function cgSMatch(s,q){return s.nodes.filter(n=>!q||n.name.toLowerCase().includes(q)||s.name.toLowerCase().includes(q))}
function renderCGSPick(){const q=$('#cg-ssearch').value.trim().toLowerCase(),sel=new Set(CGF.sub_nodes.map(x=>snKey(x.sub,x.name)));
  $('#cg-spick').innerHTML=SN.subs.map(s=>{const ns=cgSMatch(s,q);if(q&&!ns.length)return '';
    return `<div style="margin-bottom:8px"><div class="row" style="gap:6px;margin:2px 0 6px"><b class="sp small">${esc(s.name)} <span class="mut">${s.known||s.nodes.length?s.nodes.length+' 个节点':'节点未加载'}</span></b>${ns.length?`<button class="btn g sm" data-s="${esc(s.name)}" onclick="cgSAll(this.dataset.s,1)">全选${q?'匹配':''}</button> <button class="btn g sm" data-s="${esc(s.name)}" onclick="cgSAll(this.dataset.s,0)">取消${q?'匹配':'全部'}</button>`:''}</div>
    <div class="mchips">${ns.slice(0,300).map(n=>{const on=sel.has(snKey(s.name,n.orig));return `<span class="mchip add ${on?'grp':''}" data-s="${esc(s.name)}" data-o="${esc(n.orig)}" onclick="cgSTog(this.dataset.s,this.dataset.o)" title="${esc(n.name)}"><span>${on?'✓ ':''}${esc(n.name)}</span></span>`}).join('')}${ns.length>300?`<span class="mut small">还有 ${ns.length-300} 个，请搜索</span>`:''}</div></div>`}).join('')
    ||`<span class="mut small">${SN.subs.length?'无匹配节点':'还没有订阅'}</span>`}
// 按「订阅名 + 节点原名」勾选（不按序号：切换页面 / 删除节点后 SN 会重新加载，旧序号可能指向别的节点）
function cgSTog(sub,orig){if(!CGF||typeof sub!=='string'||typeof orig!=='string')return;const i=CGF.sub_nodes.findIndex(x=>x.sub===sub&&x.name===orig);
  if(i>=0)CGF.sub_nodes.splice(i,1);else CGF.sub_nodes.push({sub,name:orig});renderCGSChosen()}
function cgSAll(sub,on){const s=SN.subs.find(x=>x.name===sub);if(!s||!CGF)return;const q=$('#cg-ssearch').value.trim().toLowerCase(),ns=cgSMatch(s,q).map(n=>n.orig);
  if(on)ns.forEach(o=>{if(!CGF.sub_nodes.some(x=>x.sub===sub&&x.name===o))CGF.sub_nodes.push({sub,name:o})});
  else if(!q)CGF.sub_nodes=CGF.sub_nodes.filter(x=>x.sub!==sub);  // 「取消全部」：连同已失效的勾选一起去掉
  else{const rm=new Set(ns);CGF.sub_nodes=CGF.sub_nodes.filter(x=>!(x.sub===sub&&rm.has(x.name)))}renderCGSChosen()}
function cgSDel(i){CGF.sub_nodes.splice(i,1);renderCGSChosen()}
function cgAdd(n){if(!CGF.proxies.includes(n))CGF.proxies.push(n);renderCGChosen()}
function cgDel(i){CGF.proxies.splice(i,1);renderCGChosen()}
function cgMove(i){const a=CGF.proxies;[a[i-1],a[i]]=[a[i],a[i-1]];renderCGChosen()}
function previewCG(){clearTimeout(_pv);_pv=setTimeout(async()=>{const f=$('#cg-filter').value.trim();if(!f){$('#cg-prev').textContent='';return}
  try{const r=await api('/api/groups/preview','POST',{filter:f,subs:$('#cg-subs').checked});
    $('#cg-prev').innerHTML=`匹配 <b>${r.total}</b> / ${r.of} 个节点`+(r.matched.length?'：'+r.matched.slice(0,12).map(esc).join('、')+(r.total>12?' …':''):'')}
  catch(e){$('#cg-prev').innerHTML=`<span class="bad">${esc(e.message)}</span>`}},300)}
async function saveCG(){const b=Object.assign({},CGF,{name:$('#cg-name').value.trim(),icon:$('#cg-icon').value.trim(),filter:$('#cg-filter').value.trim(),
    subs:$('#cg-subs').checked,expose:$('#cg-expose').checked,strategy:$('#cg-st').value,interval:+$('#cg-int').value||0,tolerance:+$('#cg-tol').value||0});
  if(!b.name)return toast('请填写名称');const btn=$('#cg-save');btn.disabled=true;
  try{toast('正在校验并应用…');const j=await api('/api/groups','POST',b);toast(j.message);closeCG();await loadGroupsPage()}catch(e){toast(e.message)}btn.disabled=false}
async function delCG(i){const n=GI.custom[i].name;const refs=cgRefs(n);
  if(!confirm(`删除策略组「${n}」？`+(refs?`\n有 ${refs} 处引用（规则 / 规则集 / DNS 会改为「🚀 节点选择」，其他组中会移除它）`:'')))return;
  try{const j=await api('/api/groups','DELETE',{name:n,force:refs>0});toast(j.message)}catch(e){toast(e.message)}loadGroupsPage()}

