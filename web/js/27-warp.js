// Cloudflare WARP 代理（WireGuard）
let WARP={status:null};
async function loadWarpPage(){try{
    WARP.status=await api('/api/warp/status');
    renderWarp();
    await warpLoadConfig(true);
    await warpLoadCustomIps(true);
  }catch(e){$('#warp').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
function renderWarp(){const st=WARP.status||{};
  $('#warp-inst').innerHTML=
    (st.installed_wg?'<span class="ok">● wireguard-tools</span>':'<span class="bad">● 未装 wireguard-tools</span>')+' '+
    (st.installed_wgcf?'<span class="ok">● wgcf</span>':'<span class="bad">● 未装 wgcf</span>');
  $('#warp-inst-hint').classList.toggle('hide',!!(st.installed_wg&&st.installed_wgcf));
  $('#warp-conn').innerHTML=st.connected?'<span class="ok">● 已连接'+(st.ip?`（${esc(st.ip)}）`:'')+'</span>':'<span class="mut">○ 未连接</span>';
  $('#warp-disc').classList.toggle('hide',!st.connected);
  $('#warp-conn-btn').classList.toggle('hide',!!st.connected);
  $('#warp-setup-btn').classList.toggle('hide',!!st.registered||!st.installed_wgcf);
  $('#warp-mutex').checked=!!st.mutex;
  $('#warp-core').innerHTML=st.core_running?'<span class="ok">● 内核运行中</span>':'<span class="mut">○ 内核已停止</span>'}
async function warpSetup(){if(!confirm('初始化 WARP？\n（wgcf 会向 Cloudflare 注册一个免费账号并生成 WireGuard 配置）'))return;
  $('#warp-r').innerHTML='<span class="mut">正在注册…</span>';
  try{const j=await api('/api/warp/setup','POST');
    $('#warp-r').innerHTML=`<span class="${j.ok?'ok':'bad'}">${esc(j.message)}</span>`;
    await warpRefresh()}catch(e){$('#warp-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}}
async function warpConnect(){if(!confirm('连接 Cloudflare WARP？\n（互斥开关开着时会自动停止内核）'))return;
  $('#warp-r').innerHTML='<span class="mut">正在连接…</span>';
  try{const j=await api('/api/warp/connect','POST');WARP.status=j;renderWarp();
    $('#warp-r').innerHTML=`<span class="${j.ok?'ok':'bad'}">${esc(j.message)}</span>`}
  catch(e){$('#warp-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}}
async function warpDisconnect(){if(!confirm('断开 WARP？\n（内核不会自动重启，需手动启动）'))return;
  try{const j=await api('/api/warp/disconnect','POST');WARP.status=j;renderWarp();
    $('#warp-r').innerHTML=`<span class="${j.ok?'ok':'mut'}">${esc(j.message)}</span>`}
  catch(e){toast(e.message)}}
async function warpSetMutex(on){try{const j=await api('/api/warp/mutex','POST',{on});WARP.status.mutex=j.mutex}
  catch(e){toast(e.message);await warpRefresh()}}
async function warpRefresh(){try{WARP.status=await api('/api/warp/status');renderWarp()}catch(e){}}
async function warpLoadConfig(silent){try{
    const j=await api('/api/warp/config');
    if(j.ok){$('#warp-conf').value=j.content||'';$('#warp-conf-r').innerHTML=''}
    else{$('#warp-conf').value='';if(!silent)$('#warp-conf-r').innerHTML=`<span class="mut small">${esc(j.message)}</span>`}
  }catch(e){if(!silent)$('#warp-conf-r').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
async function warpSaveConfig(){const content=$('#warp-conf').value;
  if(!content.trim()){$('#warp-conf-r').innerHTML='<span class="bad small">配置内容为空</span>';return}
  if(!confirm('保存 WireGuard 配置？\n（原配置会自动备份；连接中保存需断开重连生效）'))return;
  $('#warp-conf-r').innerHTML='<span class="mut small">保存中…</span>';
  try{const j=await api('/api/warp/config','POST',{content});
    let msg=`<span class="${j.ok?'ok':'bad'} small">${esc(j.message||'')}</span>`;
    if(j.ok&&(WARP.status||{}).connected)msg+='<br><span class="warn small">WARP 连接中，新配置需断开重连后生效</span>';
    $('#warp-conf-r').innerHTML=msg}
  catch(e){$('#warp-conf-r').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
async function warpLoadCustomIps(silent){try{
    const j=await api('/api/warp/custom_ips');
    if(j.ok){$('#warp-custom-ips').value=(j.ips||[]).join('\n');if(!silent)$('#warp-custom-r').innerHTML=''}
    else if(!silent){$('#warp-custom-r').innerHTML=`<span class="bad small">${esc(j.message||'')}</span>`}
  }catch(e){if(!silent)$('#warp-custom-r').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
async function warpSaveCustomIps(){
  if(!confirm('保存自定义 IP？\n（每行一个，无效 IP 会被跳过）'))return;
  $('#warp-custom-r').innerHTML='<span class="mut small">保存中…</span>';
  try{const j=await api('/api/warp/custom_ips','POST',{ips:$('#warp-custom-ips').value});
    $('#warp-custom-r').innerHTML=`<span class="${j.ok?'ok':'bad'} small">${esc(j.message||'')}</span>`;
    if(j.ok)$('#warp-custom-ips').value=(j.ips||[]).join('\n')}
  catch(e){$('#warp-custom-r').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
function warpSelPorts(){return Array.from(document.querySelectorAll('#warp-pref-ports input:checked')).map(i=>parseInt(i.value,10)).filter(Boolean)}
async function warpPreferred(){const el=$('#warp-pref-list'),ports=warpSelPorts();
  el.innerHTML='<span class="mut small">正在测试候选池 IP × 端口（TCP 延迟 3 次 + Cloudflare 参考下载速度）…</span>';
  try{const j=await api('/api/warp/preferred','POST',{ports});
    if(!j.ok||!j.servers.length){el.innerHTML=`<span class="bad small">${esc(j.message||'测试失败')}</span>`;return}
    el.innerHTML=(j.ref_speed?`<div class="mut small" style="margin-bottom:8px">参考下载速度：${esc(j.ref_speed)}（当前网络到 Cloudflare，供参考）</div>`:'')+
      '<table class="tbl"><tr><th>IP</th><th>端口</th><th>平均延迟</th><th>最小延迟</th><th>状态</th><th></th></tr>'+
      j.servers.map(s=>`<tr><td class="mono">${esc(s.ip)}</td><td class="mono">${s.port}</td><td>${s.ok?s.avg_ms+' ms':'-'}</td><td>${s.ok?s.min_ms+' ms':'-'}</td><td>${s.ok?'<span class="ok">● 可用</span>':'<span class="bad">● 超时</span>'}</td><td>${s.ok?`<button class="btn g sm" onclick="warpApplyIp('${esc(s.ip)}',${s.port})">使用</button>`:''}</td></tr>`).join('')+'</table>'}
  catch(e){el.innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
async function warpApplyIp(ip,port){if(!confirm(`把 Endpoint 换成 ${ip}:${port}？\n（原配置自动备份；连接中需断开重连生效）`))return;
  $('#warp-pref-r').innerHTML='<span class="mut small">应用中…</span>';
  try{const j=await api('/api/warp/apply_ip','POST',{ip,port});
    let msg=`<span class="${j.ok?'ok':'bad'} small">${esc(j.message||'')}</span>`;
    if(j.ok){await warpLoadConfig(true);
      if((WARP.status||{}).connected)msg+='<br><span class="warn small">WARP 连接中，新 IP 需断开重连后生效</span>'}
    $('#warp-pref-r').innerHTML=msg}
  catch(e){$('#warp-pref-r').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
