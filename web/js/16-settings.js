// 设置
function seg(sel,on,fn){document.querySelectorAll(sel+' button').forEach(b=>{b.classList.toggle('on',(b.dataset.v==='1')===!!on);b.onclick=()=>fn(b.dataset.v==='1')})}
function segv(sel,cur,fn){document.querySelectorAll(sel+' button').forEach(b=>{b.classList.toggle('on',b.dataset.v===String(cur));b.onclick=()=>fn(b.dataset.v)})}
function sw(sel,on,fn){const e=$(sel);e.checked=!!on;e.onchange=async()=>{const v=e.checked;try{await fn(v)}catch(err){e.checked=!v}}}
const PM_DESC={tproxy:'TProxy：nftables 把局域网 TCP/UDP 透明转发到 mihomo 7893 端口，DNS 劫持到 1053。兼容性最好。',
  tun:'TUN：mihomo 创建虚拟网卡并接管路由（auto-route），旁路由转发的流量进入 TUN；nftables 只保留 DNS 重定向。需要 tun 内核模块。',
  off:'关闭：不做透明代理，客户端可手动设置 HTTP/SOCKS 代理 本机IP:7890。'};
let TUNF={};
let SG=localStorage.getItem('mp_sg')||'net';
function renderSG(){document.querySelectorAll('#snav button').forEach(b=>{b.classList.toggle('on',b.dataset.g===SG);b.onclick=()=>{SG=b.dataset.g;localStorage.setItem('mp_sg',SG);renderSG()}});
  document.querySelectorAll('[data-sg]').forEach(c=>c.classList.toggle('hide',c.dataset.sg!==SG));balanceSG()}
// v7.7.0 桌面双栏：把较短一栏的最后一张卡片拉长，两栏底部对齐
function balanceSG(){requestAnimationFrame(()=>{const cs=[...document.querySelectorAll('.sgrid>.card')];cs.forEach(c=>c.style.minHeight='');
  if(MQ.matches||TAB!=='设置')return;const vis=cs.filter(c=>!c.classList.contains('hide')&&c.offsetHeight),col={};
  vis.forEach(c=>(col[c.offsetLeft]=col[c.offsetLeft]||[]).push(c));const ks=Object.keys(col);if(ks.length<2)return;
  const bot=k=>Math.max(...col[k].map(c=>c.offsetTop+c.offsetHeight)),mx=Math.max(...ks.map(bot));
  ks.forEach(k=>{const d=mx-bot(k);if(d>1){const l=col[k].reduce((a,c)=>c.offsetTop>a.offsetTop?c:a);l.style.minHeight=(l.offsetHeight+d)+'px'}})})}
addEventListener('resize',()=>{if(TAB==='设置')balanceSG()});
document.addEventListener('click',e=>{if(TAB==='设置'&&e.target.closest('.sgrid'))setTimeout(balanceSG,60)});
async function renderSettings(){renderSG();renderLook();await loadState().catch(()=>{});fillSettings();loadCoreSw();if(!CORE_POLL){$('#core-kind').value=STATE.core||'mihomo';coreKindUI()}
  segv('#pm',STATE.proxy_mode,v=>setPM(v));$('#pm-desc').textContent=PM_DESC[STATE.proxy_mode]||'';
  TUNF=Object.assign({},STATE.tun);renderTunForm();setTimeout(balanceSG,200);setTimeout(balanceSG,1500);
  sw('#v6',STATE.ipv6,v=>saveSettings({ipv6:v},'IPv6 已'+(v?'开启':'关闭')));
  sw('#wd',STATE.watchdog,v=>saveSettings({watchdog:v},'看门狗已'+(v?'开启':'关闭')));
  sw('#https',STATE.https,async v=>{if(!confirm(`面板将以 ${v?'HTTPS':'HTTP'} 重启，确定？`))throw 0;
    try{const j=await api('/api/https','PUT',{enable:v});toast(j.message+'，3 秒后跳转');setTimeout(()=>location.href=`${j.scheme}://${location.host}/`,3000)}catch(e){toast(e.message);throw e}});
  fillSchedule();loadLogInfo();loadHistory();
  sw('#sniff',STATE.sniffer!==false,v=>saveSettings({sniffer:v},'域名嗅探已'+(v?'开启':'关闭')));
  loadSysopt();$('#pv').textContent='当前 v'+(STATE.panel_version||'-');$('#cv').textContent='当前 '+(STATE.version||'-');
  if(!CORE_POLL)api('/api/coreupdate/status').then(j=>{if(j.busy)corePoll()}).catch(()=>{});if(document.activeElement!==$('#gh-proxy'))$('#gh-proxy').value=STATE.gh_proxy||'';
  segv('#log-limit',STATE.log_limit,v=>saveSettings({log_limit:+v},'日志上限已设为 '+v+' MB').then(renderSettings).catch(()=>{}));
  await loadDevs();$('#dev-names').value=Object.entries(STATE.devices||{}).map(([k,v])=>k+' = '+v).join('\n')}
function renderTunForm(){const t=TUNF;segv('#tun-stack',t.stack,v=>{TUNF.stack=v;renderTunForm()});$('#tun-dev').value=t.device||'Meta';
  $('#tun-ar').checked=!!t.auto_redirect;$('#tun-ar').onchange=e=>TUNF.auto_redirect=e.target.checked;
  $('#tun-sr').checked=!!t.strict_route;$('#tun-sr').onchange=e=>TUNF.strict_route=e.target.checked;
  const on=STATE.proxy_mode==='tun';$('#tun-panel').classList.toggle('dim',!on);$('#tun-tag').textContent=on?'当前生效':'选择 TUN 后生效'}
async function setPM(mode,force){if(mode===STATE.proxy_mode&&!force)return;
  if(!confirm(`切换代理方式为「${PM_TXT[mode]==='已关闭'?'关闭':PM_TXT[mode]}」？\n切换时局域网代理会短暂中断。`))return;
  TUNF.device=$('#tun-dev').value.trim()||'Meta';
  try{toast('正在切换…');const j=await api('/api/proxymode','PUT',{mode,tun:TUNF});toast(j.message)}catch(e){toast(e.message)}renderSettings()}
function applyTun(){setPM('tun',true)}
