// DNS：列表编辑器 / hosts / nameserver-policy / 泄露检测
let DNSF=null,DNS_DIRTY=false;
const DNS_LISTS=[
  {k:'direct',t:'直连 DNS',d:'国内域名（geosite:cn）、DIRECT 连接使用；请用国内 DNS',ph:'https://doh.pub/dns-query'},
  {k:'proxy',t:'代理 DNS',d:'未知 / 国外域名使用（默认上游）；加 #策略组 表示经该组节点发出查询',ph:'https://1.1.1.1/dns-query#🚀 节点选择'},
  {k:'default',t:'默认 DNS（bootstrap）',d:'必须是 IP，用于解析上面 DoH / DoT 服务器自身的域名',ph:'223.5.5.5',ip:true},
  {k:'pserver',t:'节点域名解析（proxy-server-nameserver）',d:'解析订阅节点的服务器域名；留空则使用直连 DNS。不能带 #策略组',ph:'https://doh.pub/dns-query',nogrp:true},
  {k:'fake_filter',t:'Fake-IP 过滤（fake-ip-filter）',d:'这些域名返回真实 IP（局域网、NTP、游戏 STUN 等）',ph:'+.example.com',ff:true}];
const DNS_SRV_RX=/^(?:(?:https|tls|quic|udp|tcp|h3):\/\/[^\s#]+|dhcp:\/\/[\w.\-]+|system(?::\/\/)?|\[?[0-9a-fA-F:.]+\]?(?::\d+)?)(?:#\S.*)?$/;
const IP_RX=/^(?:(?:udp|tcp|tls|https):\/\/)?\[?[0-9a-fA-F:.]+\]?(?::\d+)?(?:\/.*)?$/;
function dnsItemErr(L,v){if(L.ff)return /^(?:geosite:|rule-set:)?[\w*+.\-!@:]+$/.test(v)?'':'格式无效';
  if(!DNS_SRV_RX.test(v))return '格式无效：应为 IP、udp:// tcp:// tls:// https:// quic:// dhcp:// 或 system，可加 #策略组';
  if(L.ip&&!IP_RX.test(v))return '默认 DNS 必须是 IP';if((L.ip||L.nogrp)&&v.includes('#'))return '这里不能指定 #策略组';
  const g=v.includes('#')?v.split('#')[1].split('&')[0]:'';if(g&&!g.includes('=')&&STATE.groups&&!STATE.groups.concat(['DIRECT','REJECT']).includes(g))return '策略组不存在：'+g;return ''}
async function loadDNSPage(){await loadState().catch(()=>{});if(!DNS_DIRTY||!DNSF)fillDNS();renderDNS()}
function fillDNS(){const d=STATE.dns||{};DNSF=JSON.parse(JSON.stringify(d));DNS_DIRTY=false}
function dirty(){DNS_DIRTY=true;$('#dns-dirty').classList.remove('hide')}
function renderDNS(){const f=DNSF;$('#dns-dirty').classList.toggle('hide',!DNS_DIRTY);
  segv('#dns-mode',f.mode,v=>{f.mode=v;dirty();renderDNS()});segv('#dns-cache',f.cache,v=>{f.cache=v;dirty();renderDNS()});
  [['#dns-policy','policy'],['#dns-rr','respect_rules'],['#dns-bb','block_bypass']].forEach(([k,n])=>{$(k).checked=!!f[n];$(k).onchange=e=>{f[n]=e.target.checked;dirty()}});
  $('#dns-lists').innerHTML=DNS_LISTS.filter(L=>!L.ff||f.mode==='fake-ip').map(L=>{const arr=f[L.k]||[];
    return `<div class="lbox"><div class="lhead"><b>${L.t}</b><span class="mut small">${arr.length} 项</span></div><div class="dsc">${esc(L.d)}${L.k==='pserver'&&!arr.length?' · <span class="ok">当前使用直连 DNS</span>':''}</div>
    <div class="lrows" data-k="${L.k}">${arr.map((v,i)=>`<div class="lrow" draggable="true" data-i="${i}"><span class="grip" title="拖动排序">⋮⋮</span><span class="li">${i+1}</span><code class="lv">${esc(v)}</code>
      <button class="lb" title="上移" ${i?'':'disabled'} onclick="dnsMove('${L.k}',${i},-1)">↑</button><button class="lb" title="下移" ${i<arr.length-1?'':'disabled'} onclick="dnsMove('${L.k}',${i},1)">↓</button><button class="lb del" title="删除" onclick="dnsDel('${L.k}',${i})">✕</button></div>`).join('')||'<div class="mut small" style="padding:6px 2px">（空）</div>'}</div>
    <div class="row ladd"><input id="add-${L.k}" placeholder="${esc(L.ph)}" class="sp" onkeydown="if(event.key==='Enter')dnsAdd('${L.k}')"><button class="btn g sm" onclick="dnsAdd('${L.k}')">＋ 添加</button></div><div class="bad small" id="err-${L.k}"></div></div>`}).join('');
  document.querySelectorAll('#dns-lists .lrows').forEach(box=>dragSort(box,(a,b)=>{const arr=f[box.dataset.k];arr.splice(b,0,arr.splice(a,1)[0]);dirty();renderDNS()}));
  renderHosts();renderPols()}
function dragSort(box,done){let from=-1;box.querySelectorAll('.lrow').forEach(r=>{r.ondragstart=e=>{from=+r.dataset.i;r.classList.add('drag');e.dataTransfer.effectAllowed='move'};
  r.ondragend=()=>r.classList.remove('drag');r.ondragover=e=>{e.preventDefault();r.classList.add('over')};r.ondragleave=()=>r.classList.remove('over');
  r.ondrop=e=>{e.preventDefault();r.classList.remove('over');const to=+r.dataset.i;if(from>=0&&from!==to)done(from,to);from=-1}})}
function dnsAdd(k){const L=DNS_LISTS.find(x=>x.k===k),inp=$('#add-'+k);const vals=inp.value.split(/[,\n]+/).map(s=>s.trim()).filter(Boolean);if(!vals.length)return;
  const arr=DNSF[k]=DNSF[k]||[];for(const v of vals){const e=dnsItemErr(L,v);if(e){$('#err-'+k).textContent=v+'：'+e;return}if(arr.includes(v)){$('#err-'+k).textContent=v+' 已存在';return}}
  arr.push(...vals);dirty();renderDNS();setTimeout(()=>$('#add-'+k)?.focus(),0)}
function dnsDel(k,i){DNSF[k].splice(i,1);dirty();renderDNS()}
function dnsMove(k,i,d){const a=DNSF[k];[a[i],a[i+d]]=[a[i+d],a[i]];dirty();renderDNS()}
const HOST_RX=/^(?:\+\.|\*\.)?(?:[a-z0-9_*](?:[a-z0-9_\-*]{0,61}[a-z0-9_*])?\.)*[a-z0-9_\-]{1,63}$/;
const isIPv=v=>/^\d{1,3}(\.\d{1,3}){3}$/.test(v)||(/^[0-9a-f:]+$/i.test(v)&&v.includes(':'));
function renderHosts(){const h=DNSF.hosts||[];$('#hosts-list').innerHTML=h.map((x,i)=>`<div class="lrow"><code class="lv" style="flex:1 1 40%">${esc(x.domain)}</code><span class="mut">→</span><code class="lv" style="flex:1 1 50%">${x.value.map(esc).join(', ')}</code><button class="lb del" title="删除" onclick="delHost(${i})">✕</button></div>`).join('')||'<div class="mut small" style="padding:4px 2px">还没有静态记录</div>'}
function addHost(){const dom=$('#hosts-dom').value.trim().toLowerCase(),vals=$('#hosts-val').value.split(/[\s,]+/).filter(Boolean),err=$('#hosts-err');err.textContent='';
  if(!HOST_RX.test(dom))return err.textContent='域名格式无效';if(!vals.length)return err.textContent='请填写 IP';
  if(!(vals.every(isIPv)||(vals.length===1&&/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(vals[0]))))return err.textContent='值应为一个或多个 IP，或单个别名域名';
  (DNSF.hosts=DNSF.hosts||[]).push({domain:dom,value:vals});$('#hosts-dom').value='';$('#hosts-val').value='';dirty();renderHosts()}
function delHost(i){DNSF.hosts.splice(i,1);dirty();renderHosts()}
const POL_DOM=/^(?:\+\.|\*\.|\.)?(?:[a-z0-9_*\-]+\.)*[a-z0-9_*\-]+$/i,POL_NAME=/^[\w@!\-.]+$/;
function normPol(m){const p=m.split(',').map(s=>s.trim()).filter(Boolean);for(const pre of ['geosite:','rule-set:'])if(p.length&&p[0].toLowerCase().startsWith(pre))return pre+p.map(x=>x.toLowerCase().startsWith(pre)?x.slice(pre.length):x).join(',');return p.join(',')}
function polErr(m){if(!m)return '请填写匹配项';const k=/^(geosite|rule-set):/i.exec(m),parts=(k?m.slice(k[0].length):m).split(',');
  return parts.every(x=>!x.includes(':')&&(k?POL_NAME:POL_DOM).test(x))?'':'匹配项格式无效：一条只能是 geosite:a,b、rule-set:x 或 域名列表，不能混用'}
function renderPols(){const p=DNSF.policies||[];
  $('#pol-list').innerHTML=p.map((x,i)=>`<div class="lrow"><span class="li">${i+1}</span><code class="lv" style="flex:1 1 38%">${esc(x.match)}</code><span class="mut">→</span><code class="lv" style="flex:1 1 52%">${x.servers.map(esc).join(', ')}</code>
    <button class="lb" ${i?'':'disabled'} onclick="polMove(${i},-1)">↑</button><button class="lb del" title="删除" onclick="delPol(${i})">✕</button></div>`).join('')||'<div class="mut small" style="padding:4px 2px">还没有自定义策略</div>';
  const short=a=>(a||[]).slice(0,2).join(', ')+((a||[]).length>2?' …':'');
  $('#pol-builtin').innerHTML=(DNSF.policy&&(DNSF.proxy||[]).length?`<div><code>geosite:cn,private</code> → 直连 DNS（${esc(short(DNSF.direct))}）</div>`:'')+
    `<div>其他所有域名 → ${(DNSF.proxy||[]).length?'代理 DNS（'+esc(short(DNSF.proxy))+'）':'<span class="bad">直连 DNS（未设置代理 DNS，会泄露）</span>'}</div>`+(STATE.adblock_on?'<div>广告拦截开启「DNS 层拦截」时，拦截列表 → NXDOMAIN（最先匹配）</div>':'')}
function addPol(){const key=normPol($('#pol-match').value),sv=$('#pol-srv').value.split(/[,\n]+/).map(s=>s.trim()).filter(Boolean),err=$('#pol-err');err.textContent='';
  const pe=polErr(key);if(pe)return err.textContent=pe;if(!sv.length)return err.textContent='请填写 DNS 服务器';
  for(const v of sv){if(!/^rcode:\/\/\w+$/.test(v)){const e=dnsItemErr({},v);if(e)return err.textContent=v+'：'+e}}
  if((DNSF.policies||[]).some(x=>x.match===key))return err.textContent='已存在相同匹配项';
  (DNSF.policies=DNSF.policies||[]).push({match:key,servers:sv});$('#pol-match').value='';$('#pol-srv').value='';dirty();renderPols()}
function delPol(i){DNSF.policies.splice(i,1);dirty();renderPols()}
function polMove(i,d){const a=DNSF.policies;[a[i],a[i+d]]=[a[i+d],a[i]];dirty();renderPols()}
async function saveDNS(){const f=DNSF,body={mode:f.mode,cache:f.cache,policy:f.policy,respect_rules:f.respect_rules,block_bypass:f.block_bypass,hosts:f.hosts||[],policies:f.policies||[]};
  DNS_LISTS.forEach(L=>body[L.k]=f[L.k]||[]);
  try{toast('正在校验并应用…');const j=await api('/api/dns','PUT',body);toast(j.message);await loadState();fillDNS();renderDNS()}catch(e){toast(e.message)}}
async function resetDNS(){if(!confirm('恢复默认 DNS 设置？（hosts 与自定义策略会清空）'))return;try{const j=await api('/api/dns','PUT',{reset:true});toast(j.message);await loadState();fillDNS();renderDNS()}catch(e){toast(e.message)}}
async function applyAntiLeak(){if(!confirm('一键应用防泄露设置？\n· fake-ip + respect-rules\n· 未知 / 国外域名走代理 DNS，国内域名走直连 DNS\n· 从代理 DNS 移除国内解析器，删除把国外域名交给国内 DNS 的自定义策略\n· 开启「阻止客户端绕过 DNS」与域名嗅探'))return;
  try{toast('正在校验并应用…');const j=await api('/api/dns','PUT',{preset:'antileak'});toast(j.message);await loadState();fillDNS();renderDNS();leakCheck()}catch(e){toast(e.message)}}
async function flushDNS(){try{await core('/cache/dns/flush','POST');toast('DNS 缓存已清空')}catch(e){toast(e.message)}}
async function leakCheck(){const b=$('#leak-btn');b.disabled=true;b.textContent='检测中…';$('#leak-r').innerHTML='<span class="mut small">正在检查配置并在线测试，约需 10 秒…</span>';
  try{const r=await api('/api/dnsleak');const lv=r.live;
    let h=`<div class="small ${r.bad?'bad':r.warn?'warn':'ok'}" style="margin:2px 0 4px;font-weight:600">${r.bad?'● 发现 '+r.bad+' 项泄露风险':r.warn?'● 未发现泄露，'+r.warn+' 项建议优化':'● 未发现泄露'}</div>`;
    h+=r.items.map(x=>{const c=x.ok===true?'ok':x.ok==='warn'?'warn':'bad';
      return `<div class="diag"><span class="ic ${c}">${c==='ok'?'✓':c==='warn'?'!':'✕'}</span><div class="sp"><b style="font-weight:600">${esc(x.name)}</b><div class="mut small w">${esc(x.detail)}</div>${x.fix?`<div class="small ${c}" style="margin-top:2px">→ ${esc(x.fix)}</div>`:''}</div></div>`}).join('');
    if(lv&&lv.resolvers&&lv.resolvers.length)h+=`<div class="lbl">bash.ws 记录到的上游解析器</div><div class="tw"><table><thead><tr><th>解析器 IP</th><th>国家 / 地区</th><th>运营商</th></tr></thead><tbody>${lv.resolvers.map(x=>`<tr><td>${esc(x.ip)}</td><td class="${x.cn?'bad':''}">${esc(x.country_name||x.country)}${x.cn?' · 泄露':''}</td><td class="w small">${esc(x.org)}</td></tr>`).join('')}</tbody></table></div>`+
      (lv.egress.length?`<div class="mut small mt">出口 IP：${lv.egress.map(x=>esc(x.ip)+'（'+esc(x.country_name||x.country)+'）').join('、')}</div>`:'');
    $('#leak-r').innerHTML=h}catch(e){$('#leak-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false;b.textContent='重新检测'}
async function dnsQuery(){const n=$('#dq-name').value.trim();if(!n)return toast('请输入域名');const b=$('#dq-btn');b.disabled=true;$('#dq-r').innerHTML='<span class="mut">查询中…</span>';
  try{const r=await api('/api/dnsquery','POST',{name:n,type:$('#dq-type').value});const TY={1:'A',5:'CNAME',28:'AAAA',15:'MX',16:'TXT',2:'NS',65:'HTTPS',33:'SRV'};
    const RC={0:'NOERROR',2:'SERVFAIL',3:'NXDOMAIN（不存在或被拦截）',5:'REFUSED'};
    $('#dq-r').innerHTML=`<div class="row small mb"><span class="${r.status===0?'ok':'bad'}">● ${esc(RC[r.status]||('Status '+r.status))}</span><span class="mut">${r.ms} ms</span></div><div class="mut small mb">上游：${esc(r.policy)}</div>`+
      (r.answer.length?`<div class="tw"><table><thead><tr><th>名称</th><th>类型</th><th>TTL</th><th>结果</th></tr></thead><tbody>${r.answer.map(a=>`<tr><td>${esc(a.name)}</td><td>${TY[a.type]||a.type}</td><td>${a.TTL}</td><td class="w">${esc(a.data)}</td></tr>`).join('')}</tbody></table></div>`:'<span class="mut small">无记录</span>')}
  catch(e){$('#dq-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false}
function fillSchedule(){const s=STATE.schedule||{};$('#sc-sub').value=s.sub_update||'';$('#sc-restart').value=s.core_restart||'';$('#sc-geo').value=s.geo_update||'';$('#sc-lat').value=String(s.latency||0);
  $('#sc-events').innerHTML=(STATE.sched_events||[]).slice(0,6).map(e=>`<div class="ev"><span class="mut">${new Date(e.t*1000).toLocaleString('zh-CN',{hour12:false})}</span> ${esc(e.msg)}</div>`).join('')}
async function saveSchedule(){try{const j=await api('/api/schedule','PUT',{sub_update:$('#sc-sub').value,core_restart:$('#sc-restart').value,geo_update:$('#sc-geo').value,latency:+$('#sc-lat').value});toast(j.message);await loadState();fillSchedule()}catch(e){toast(e.message)}}
async function runTask(k){if(k==='core_restart'&&!confirm('立即重启核心？'))return;try{toast('执行中…');const j=await api('/api/schedule/run','POST',{task:k});toast(j.message)}catch(e){toast(e.message)}await loadState();fillSchedule()}
async function fillHealthCfg(){try{const j=await api('/api/health/status');const c=j.cfg||{};$('#hc-enabled').checked=!!c.enabled;$('#hc-time').value=c.time||'03:00';$('#hc-warn').value=c.warn_days||3;$('#hc-hide').value=c.hide_days||7;
  const st=j.running?'检查中…':(j.last_run?('上次：'+new Date(j.last_run*1000).toLocaleString('zh-CN',{hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'})):'未运行过');
  $('#hc-status').textContent='健康检查：'+(c.enabled?'已启用':'未启用')+'，'+st}catch(e){}}
async function saveHealthCfg(){try{const j=await api('/api/health/cfg','PUT',{enabled:$('#hc-enabled').checked,time:$('#hc-time').value,warn_days:+$('#hc-warn').value,hide_days:+$('#hc-hide').value});if(!j.ok)toast(j.message||'保存失败');fillHealthCfg()}catch(e){toast(e.message)}}
async function runHealthCheck(){try{toast('开始检查…');const j=await api('/api/health/check','POST');toast(j.message);const poll=setInterval(async()=>{try{const s=await api('/api/health/status');fillHealthCfg();if(!s.running){clearInterval(poll);if(TAB==='nodes')loadProxies()}}catch(e){clearInterval(poll)}},3000)}catch(e){toast(e.message)}}
async function loadHistory(){try{const h=await api('/api/history');
  $('#hist').innerHTML=h.map(x=>`<div class="row ev" style="padding:6px 0"><span class="mut" style="min-width:118px">${new Date(x.t*1000).toLocaleString('zh-CN',{hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'})}</span><span class="sp">修改前：${x.changed.map(esc).join('、')}</span><button class="btn g sm" onclick="restoreHist('${x.id}')">恢复</button></div>`).join('')||'<span class="mut">还没有快照</span>'}catch(e){}}
async function restoreHist(id){if(!confirm('恢复到这份快照？当前设置会先保存为新快照。'))return;try{toast('正在校验并应用…');const j=await api('/api/history','POST',{id});toast(j.message);await loadState();renderSettings()}catch(e){toast(e.message)}}
async function loadLogInfo(){try{const j=await api('/api/logs/info');$('#log-sizes').innerHTML=j.files.map(f=>`<div class="row" style="padding:3px 0"><span class="sp mut" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${esc(f.path)}</span><b>${f.size<0?'不存在':fmt(f.size)}</b></div>`).join('')}catch(e){}}
async function cleanLogs(){try{const j=await api('/api/logs/clean','POST');toast(j.message);loadLogInfo()}catch(e){toast(e.message)}}
async function saveDevNames(){const d={};for(const l of lines($('#dev-names').value)){const i=l.search(/[=\s]/);if(i<0)continue;const k=l.slice(0,i).trim(),v=l.slice(i).replace(/^[\s=]+/,'').trim();if(k&&v)d[k]=v}
  try{const j=await api('/api/devices','PUT',{devices:d});toast(j.message);await loadDevs();$('#dev-names').value=Object.entries(STATE.devices||{}).map(([k,v])=>k+' = '+v).join('\n')}catch(e){toast(e.message)}}
const SVC_TXT={start:'启动',stop:'停止',restart:'重启'};
function svcBusy(on){['#h-restart','#h-stop','#h-start'].forEach(k=>{const b=$(k);if(b){b.disabled=on;b.style.opacity=on?.5:''}})}
async function svc(a){if(a==='stop'&&!confirm('停止代理核心？\n停止后经旁路由的设备将无法上网（看门狗不会自动拉起，需手动启动）。'))return;
  if(a==='restart'&&!confirm('重启代理核心？现有连接会断开。'))return;
  if(!SVC_TXT[a]){try{toast('执行中…');const j=await api('/api/service','POST',{action:a});toast(j.message||'完成');setTimeout(loadState,1500)}catch(e){toast(e.message)}return}
  svcBusy(true);
  try{const j=await api('/api/service','POST',{action:a});toast(j.message||'执行中…');
    let s=j;for(let i=0;i<300&&s.busy;i++){await new Promise(r=>setTimeout(r,400));try{s=await api('/api/service')}catch(e){}}
    toast(s.busy?SVC_TXT[a]+'仍在进行，请稍后刷新':(s.message||'完成'))}
  catch(e){toast(e.message)}
  finally{svcBusy(false);STATE_VER=-1;try{await loadState()}catch(e){}}}
async function flushFake(){try{await core('/cache/fakeip/flush','POST');toast('已清空')}catch(e){toast(e.message)}}
function saveTg(){saveSettings({tg_token:$('#tg-token').value.trim(),tg_chat:$('#tg-chat').value.trim()},'Telegram 设置已保存').catch(()=>{})}
async function tgTest(){try{toast('发送中…');const j=await api('/api/tg/test','POST',{tg_token:$('#tg-token').value.trim(),tg_chat:$('#tg-chat').value.trim()});toast(j.message)}catch(e){toast(e.message)}}

