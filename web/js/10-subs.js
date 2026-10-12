// 订阅
let EDIT_SUB=null;
async function loadSubs(){await loadState();let prov={};try{prov=(await core('/providers/proxies')).providers||{}}catch(e){}
  if(!EDIT_SUB&&!$('#sub-exclude').value)$('#sub-exclude').value=STATE.default_exclude||'';
  $('#subs').innerHTML=STATE.subs.map(s=>{const p=prov[s.name]||{};const si=p.subscriptionInfo||{};
    const used=(si.Upload||0)+(si.Download||0);const exp=si.Expire?new Date(si.Expire*1000).toLocaleDateString('zh-CN'):'-';
    const exc=s.exclude===undefined?STATE.default_exclude:s.exclude;
    const pct=si.Total?Math.min(100,used/si.Total*100):0,days=si.Expire?Math.ceil((si.Expire*1000-Date.now())/864e5):null;
    return `<tr><td class="subn" title="${esc(s.url)}"><div class="subu" style="font-size:inherit">${esc(s.name)}</div><div class="mut subu">${esc(s.url)}</div></td><td>${(p.proxies||[]).length}</td>
    <td class="subf" title="${esc((s.filter?'保留：'+s.filter+'\n':'')+(exc?'排除：'+exc:'不过滤'))}">${s.filter?'<div>保留：'+esc(s.filter)+'</div>':''}${exc?'<div class="mut">排除：'+esc(exc)+'</div>':'<div class="mut">不过滤</div>'}</td>
    <td>${si.Total?`${fmt(used)} / ${fmt(si.Total)}<div class="ubar"><i class="${pct>90?'bad':pct>70?'warn':''}" style="width:${pct.toFixed(1)}%"></i></div>`:'-'}</td>
    <td>${exp}${days!==null?`<div class="small ${days<=3?'bad':days<=7?'warn':'mut'}">${days<0?'已过期':'剩 '+days+' 天'}</div>`:''}</td><td>${p.updatedAt?new Date(p.updatedAt).toLocaleString('zh-CN',{hour12:false}):'-'}</td>
    <td><button class="btn g sm" onclick="updSub('${encodeURIComponent(s.name)}',this)">更新</button> <button class="btn g sm" onclick="editSub('${encodeURIComponent(s.name)}')">编辑</button> <button class="btn r sm" onclick="delSub('${encodeURIComponent(s.name)}')">删除</button></td></tr>`}).join('')||'<tr><td class="mut">暂无订阅</td></tr>';
  renderNodes(prov)}
function editSub(n){const s=STATE.subs.find(x=>x.name===decodeURIComponent(n));if(!s)return;EDIT_SUB=s.name;
  $('#sub-name').value=s.name;$('#sub-name').disabled=true;$('#sub-url').value=s.url;$('#sub-filter').value=s.filter||'';
  $('#sub-exclude').value=s.exclude===undefined?STATE.default_exclude:s.exclude;$('#sub-btn').textContent='保存修改';$('#sub-cancel').classList.remove('hide');
  $('#sub-title').textContent='编辑订阅：'+s.name;$('#sub-title').scrollIntoView({behavior:'smooth'})}
function resetSubForm(){EDIT_SUB=null;['#sub-name','#sub-url','#sub-filter'].forEach(k=>$(k).value='');$('#sub-name').disabled=false;
  $('#sub-exclude').value=STATE.default_exclude||'';$('#sub-btn').textContent='添加并应用';$('#sub-cancel').classList.add('hide');
  $('#sub-title').textContent='添加订阅（Clash / Mihomo YAML 或 Base64 节点链接均可）'}
async function addSub(){const name=$('#sub-name').value.trim(),url=$('#sub-url').value.trim();if(!name||!url)return toast('请填写名称和链接');
  try{toast('正在应用…');await api('/api/subs','POST',{name,url,filter:$('#sub-filter').value.trim(),exclude:$('#sub-exclude').value.trim()});
    toast(EDIT_SUB?'订阅已更新':'订阅已添加');resetSubForm();setTimeout(loadSubs,1500)}catch(e){toast(e.message)}}
async function updSub(n,btn){btn.disabled=true;btn.textContent='更新中…';try{const j=await api('/api/subs/update','POST',{name:decodeURIComponent(n)});toast(j.message)}catch(e){toast(e.message)}btn.disabled=false;btn.textContent='更新';loadSubs()}
async function delSub(n){if(!confirm('删除订阅 '+decodeURIComponent(n)+'？'))return;try{await api('/api/subs','DELETE',{name:decodeURIComponent(n)});toast('已删除');loadSubs()}catch(e){toast(e.message)}}
async function renderNodes(){let px={};try{px=await loadPX()}catch(e){}
  $('#mynodes').innerHTML=(STATE.nodes||[]).map(n=>{const q=px[n.name]||{},h=q.history||[];const d=q._d!==undefined?q._d:h.length?h[h.length-1].delay:undefined;
    return `<tr><td class="w">${esc(n.name)}</td><td>${esc(n.type)}</td><td class="w">${esc(n.server)}:${esc(n.port)}</td><td class="${dcls(d)}">${dtxt(d)}</td>
    <td style="text-align:right"><button class="btn g sm" onclick="testNode('${encodeURIComponent(n.name)}',this)">测速</button> <button class="btn r sm" onclick="delNode('${encodeURIComponent(n.name)}')">删除</button></td></tr>`}).join('')||'<tr><td class="mut">暂无手动节点</td></tr>'}
async function importNodes(){const links=$('#node-links').value.trim();if(!links)return toast('请粘贴节点链接');
  try{toast('正在导入…');const j=await api('/api/nodes','POST',{links});toast(j.message);$('#node-links').value='';loadSubs()}catch(e){toast(e.message)}}
async function delNode(n){if(!confirm('删除节点 '+decodeURIComponent(n)+'？'))return;try{await api('/api/nodes','DELETE',{name:decodeURIComponent(n)});toast('已删除');loadSubs()}catch(e){toast(e.message)}}
async function testNode(n,btn){btn.disabled=true;try{const r=await core(`/proxies/${n}/delay?url=${encodeURIComponent('https://www.gstatic.com/generate_204')}&timeout=5000`);toast(decodeURIComponent(n)+'：'+r.delay+' ms')}catch(e){toast(decodeURIComponent(n)+'：超时')}btn.disabled=false;renderNodes()}

