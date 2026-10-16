// WARP：与核心二选一的透明代理 + 优选 IP
let WS={},WARP_T=null,WARP_CONF_DIRTY=false;
const WPORTS={common:'2408,500,1701,4500,878,894,7559,8854','2408':'2408'};
function warpPoll(on){clearInterval(WARP_T);WARP_T=null;if(on)WARP_T=setInterval(()=>{if(TAB==='WARP')loadWarp(true)},(WS.scan_job&&WS.scan_job.busy)||(WS.job&&WS.job.busy)?1500:8000)}
async function loadWarp(quiet){
  try{WS=await api('/api/warp')}catch(e){if(!quiet)toast(e.message);return}
  renderWarp();warpPoll(true)}
function upTxt(s){if(!s)return '';const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h?`${h} 小时 ${m} 分`:m?`${m} 分钟`:`${s} 秒`}
function renderWarp(){const s=WS,run=s.running,busy=s.job&&s.job.busy;
  $('#w-dot').className='dot '+(run?'on':'off');
  $('#w-run').textContent=busy?({start:'启动中…',stop:'停止中…',restart:'重启中…'}[s.job.act]||'处理中…'):run?'运行中'+(s.uptime?' · '+upTxt(s.uptime):''):'已停止';
  $('#w-start').classList.toggle('hide',run);$('#w-restart').classList.toggle('hide',!run);$('#w-stop').classList.toggle('hide',!run);
  ['#w-start','#w-restart','#w-stop'].forEach(k=>$(k).disabled=!!busy);
  $('#w-core').innerHTML=s.core_running?'<span class="ok">● 运行中</span>':'<span class="mut">● 已停止</span>';
  $('#w-core-dsc').textContent=s.core_running?(run?'核心与 WARP 同时在运行，请停止其中一个':'核心正在接管流量；启动 WARP 会先自动停止核心，避免端口冲突'):(run?'核心已停止，局域网流量经 WARP':'核心与 WARP 都已停止，局域网直连');
  $('#w-core-dsc').className='dsc'+(s.core_running&&run?' bad':'');
  $('#w-ep').textContent=s.endpoint||'-';$('#w-addr').textContent=s.address?'WARP 内网地址：'+s.address:(s.conf_err||'还没有配置');
  $('#w-eng').textContent=s.engine||'未安装内核';
  $('#w-cn').checked=!!s.cn_direct;$('#w-cn-dsc').textContent='国内域名 / IP 不走 WARP（使用主核心已下载的 geosite / geoip 数据）'+(s.cn_ok?'':'；当前没有找到这些数据文件，启动时会全部走 WARP');
  $('#w-acc').textContent=s.account&&s.account.has?(s.account.type==='unlimited'||s.account.type==='plus'||s.account.license?'WARP+ 账户':'免费账户'):(s.conf?'自定义配置':'未注册');
  if(!WARP_CONF_DIRTY&&document.activeElement!==$('#w-conf'))$('#w-conf').value=s.conf||'';
  $('#w-conf').oninput=()=>{WARP_CONF_DIRTY=true};
  $('#w-conf-err').textContent=s.conf_err?'配置有误：'+s.conf_err:'';
  if(!$('#w-ranges').value)$('#w-ranges').value=(s.ranges||[]).join('\n');
  if(!$('#w-ports').value)$('#w-ports').value=WPORTS.common;
  WPORTS.all=(s.all_ports||[]).join(',');
  const sj=s.scan_job||{};$('#w-scan-btn').disabled=!!sj.busy;
  $('#w-scan-st').textContent=sj.busy?`${sj.stage} ${sj.done}/${sj.total}`:(sj.message||(s.scan_t?'上次测试：'+ago(s.scan_t):''));
  renderWarpScan();
  $('#w-events').innerHTML=(s.events||[]).map(e=>`<div><span class="mut">${new Date(e.t*1000).toLocaleString('zh-CN',{hour12:false})}</span> ${esc(e.msg)}</div>`).join('')||'<span class="mut">暂无事件</span>';
  $('#w-log').textContent=(s.log||[]).join('\n')||'(空)';
  if(s.job&&!s.job.busy&&s.job.t&&s.job.t!==renderWarp._t){if(renderWarp._t!==undefined&&s.job.message)toast(s.job.message);renderWarp._t=s.job.t}}
let WSPEED={};
function renderWarpScan(){const rows=WS.scan||[];
  $('#w-scan').innerHTML=rows.map((r,i)=>{const ep=r.ip.includes(':')?`[${r.ip}]:${r.port}`:`${r.ip}:${r.port}`,cur=ep===WS.endpoint,k=r.ip+'|'+r.port;
    const sp=WSPEED[k]==='busy'?'<span class="mut">测速中…</span>':r.mbps!=null?`<b>${r.mbps}</b> <span class="mut">Mbps</span>`:`<button class="btn g sm" onclick="warpSpeed(${i})">测速</button>`;
    return `<tr><td><code>${esc(ep)}</code>${cur?' <span class="tag ok">使用中</span>':''}</td><td class="${dcls(r.ms)}">${r.ms} ms</td><td class="${r.loss?'warn':'ok'}">${r.loss}%</td><td>${sp}</td>
      <td style="text-align:right"><button class="btn sm" ${cur?'disabled':''} onclick="warpUse(${i})">使用</button></td></tr>`}).join('')
    ||'<tr><td colspan="5" class="mut">还没有测试结果：点「开始测试」</td></tr>'}
async function warpAct(a){
  if(a==='start'&&WS.core_running&&!confirm('mihomo / sing-box 核心正在运行。\n启动 WARP 会先停止核心，局域网改走 WARP，继续？'))return;
  if(a==='stop'&&!confirm('停止 WARP？停止后局域网直连（不经过任何代理）。'))return;
  try{const j=await api('/api/warp','POST',{action:a});toast(j.message)}catch(e){toast(e.message)}
  renderWarp._t=0;await loadWarp(true);STATE_VER=-1;setTimeout(()=>loadState().catch(()=>{}),4000)}
async function warpTrace(){$('#w-trace').textContent='检测中…';
  try{const j=await api('/api/warp/trace');$('#w-trace').innerHTML=j.ok?`出口 <b>${esc(j.ip)}</b> · ${esc(j.loc)} · 机房 ${esc(j.colo)} · warp=${esc(j.warp)} · ${j.ms} ms`:'<span class="bad">'+esc(j.error)+'</span>'}
  catch(e){$('#w-trace').textContent=e.message}}
async function warpCn(on){try{const j=await api('/api/warp/opts','PUT',{cn_direct:on});toast(j.message)}catch(e){toast(e.message)}}
async function warpSave(restart){try{const j=await api('/api/warp/conf','PUT',{conf:$('#w-conf').value,restart});WARP_CONF_DIRTY=false;toast(j.message);loadWarp(true)}catch(e){toast(e.message)}}
async function warpReg(){if(WS.conf&&!confirm('注册新账户会替换当前配置里的密钥和地址（已优选的 Endpoint 保留），继续？'))return;
  toast('正在向 Cloudflare 注册…');try{const j=await api('/api/warp/register','POST',{});WARP_CONF_DIRTY=false;toast(j.message);loadWarp(true)}catch(e){toast(e.message)}}
async function warpLic(){const k=$('#w-lic').value.trim();if(!k){toast('请填入 WARP+ 许可证');return}
  try{const j=await api('/api/warp/license','POST',{license:k});toast(j.message);loadWarp(true)}catch(e){toast(e.message)}}
function warpPorts(k){$('#w-ports').value=WPORTS[k]||WPORTS.common}
async function warpScan(){const ports=$('#w-ports').value.split(/[,，\s]+/).map(Number).filter(p=>p>0&&p<65536);
  if(!ports.length){toast('请填写端口');return}
  try{const j=await api('/api/warp/scan','POST',{ranges:lines($('#w-ranges').value),ports,per:+$('#w-per').value||20,rounds:+$('#w-rounds').value||3});toast(j.message);loadWarp(true)}catch(e){toast(e.message)}}
async function warpSpeed(i){const r=(WS.scan||[])[i];if(!r)return;const k=r.ip+'|'+r.port;WSPEED[k]='busy';renderWarpScan();
  try{const j=await api('/api/warp/speed','POST',{ip:r.ip,port:r.port});if(j.ok)r.mbps=j.mbps;else toast(`${r.ip}:${r.port} 测速失败：${j.error}`)}catch(e){toast(e.message)}
  delete WSPEED[k];renderWarpScan()}
async function warpSpeedTop(){const n=Math.min(5,(WS.scan||[]).length);if(!n){toast('先「开始测试」');return}
  for(let i=0;i<n;i++)await warpSpeed(i);toast('前 '+n+' 个测速完成')}
async function warpUse(i){const r=(WS.scan||[])[i];if(!r)return;toast('正在应用…');
  try{const j=await api('/api/warp/use','POST',{ip:r.ip,port:r.port});WARP_CONF_DIRTY=false;toast(j.message)}catch(e){toast(e.message)}loadWarp(true)}
