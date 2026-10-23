// 设置扩展
function fillSettings(){$('#bypass').value=(STATE.bypass||[]).join('\n');$('#tests').value=(STATE.tests||[]).map(t=>t.name+'|'+t.url).join('\n');
  $('#sub-int').value=String(STATE.sub_interval||86400);
  $('#tg-token').value=STATE.tg_token||'';$('#tg-chat').value=STATE.tg_chat||''}
async function saveSettings(o,msg){try{toast('保存中…');const j=await api('/api/settings','PUT',o);toast(msg||j.message);await loadState();fillSettings()}catch(e){toast(e.message);throw e}}
function saveBypass(){saveSettings({bypass:$('#bypass').value.split('\n').map(s=>s.trim()).filter(Boolean)},'绕过设备已生效').catch(()=>{})}
function saveTests(){const t=$('#tests').value.split('\n').map(l=>l.split('|')).filter(a=>a.length>=2&&a[1].trim().startsWith('http')).map(a=>({name:a[0].trim(),url:a.slice(1).join('|').trim()}));
  if(!t.length)return toast('格式：名称|网址');saveSettings({tests:t},'已保存').then(()=>testSites(1)).catch(()=>{})}
function saveGroupOpts(){saveSettings({sub_interval:+$('#sub-int').value},'已应用').catch(()=>{})}
async function backup(){try{const j=await api('/api/backup');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(j,null,2)],{type:'application/json'}));
  a.download='shunt-backup-'+new Date().toISOString().slice(0,10)+'.json';a.click()}catch(e){toast(e.message)}}
async function restore(){const inp=$('#restore-file'),f=inp.files[0];inp.value='';if(!f)return;if(!confirm(`用「${f.name}」恢复设置？当前设置会先保存为配置快照。`))return;try{const j=JSON.parse(await f.text());const r=await api('/api/restore','POST',j);toast(r.message);loadState().then(fillSettings)}catch(e){toast('恢复失败：'+e.message)}}
let _rz=0;addEventListener('resize',()=>{clearTimeout(_rz);_rz=setTimeout(()=>{drawChart();if(TAB==='统计')drawDays()},120)});
async function start(){
  try{await loadState()}catch(e){if(e.message==='未登录')return;toast('面板服务连接失败：'+e.message)}
  $('#app').classList.remove('hide');go(tabFromHash(location.hash),1);
  const vis=f=>()=>{if(!document.hidden)f()};
  // 设备名单只在用得到它的概览 / 连接 / 统计页轮询（统计页 loadStats 自带）；站点延迟卡片只在概览，测速也只在概览跑
  timers.forEach(clearInterval);timers=[setInterval(tick,1000),setInterval(vis(()=>{if(TAB==='概览')testSites()}),60000),setInterval(vis(()=>loadState().catch(()=>{})),15000),
    setInterval(vis(()=>{if(TAB==='概览'||TAB==='连接')loadDevs()}),30000),
    setInterval(vis(()=>{if(TAB==='统计')loadStats();if(TAB==='概览')loadAdStat();if(TAB==='广告拦截'&&!AB?.updating)loadAB()}),30000)];
  loadDevs();tick();bgSync()}
// 切回前台时立即刷新一次
document.addEventListener('visibilitychange',()=>{if(document.hidden||$('#app').classList.contains('hide'))return;_skip=0;tick();loadState().catch(()=>{});if(TAB==='节点')loadProxies()});
start();  // 不再需要登录
