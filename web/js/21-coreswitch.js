// 内核切换
let SW_SEL='';
async function loadCoreSw(){try{const j=await api('/api/coreswitch');SW_SEL=j.core;const v=j.versions||{};
    $('#sw-cur').textContent='当前 '+CORE_LABEL[j.core];
    $('#sw-ver').innerHTML=`mihomo ${v.mihomo?esc(v.mihomo):'<span class="warn">未安装</span>'} · Smart ${v.smart?esc(v.smart):'<span class="mut">未安装（切换时自动下载）</span>'}${j.core==='smart'?' · LightGBM 模型 '+(j.lgbm?'已下载':'<span class="mut">未下载</span>'):''} · sing-box ${v.singbox?esc(v.singbox):'<span class="mut">未安装（切换时自动下载最新正式版）</span>'}`;
    const pick=x=>{SW_SEL=x;segv('#sw-seg',x,pick);swRender(j)};pick(j.core);if(j.busy&&!SW_POLL)swPoll()}catch(e){$('#sw-ver').textContent=e.message}}
function swRender(j){const to=SW_SEL,diff=to!==j.core;$('#sw-btn').disabled=!diff;$('#sw-btn').textContent=diff?'切换到 '+CORE_LABEL[to]:'切换内核';
  const sbNote='<div class="warn">sing-box 与 mihomo 的差异：</div><ul style="margin:4px 0 0 18px;padding:0">'+
    '<li>没有负载均衡 / 故障转移组：地区「⚖️ 哈希」组并入同地区「竞技」，自定义的这两类组按自动测速运行</li>'+
    '<li>订阅由面板下载并解析（Clash YAML / Base64 / 分享链接），按「订阅自动更新间隔」刷新；ssr、snell、wireguard 节点会被跳过</li>'+
    '<li>GEO 与规则集改用 .srs 格式，由面板下载；mihomo 专用的 .mrs 规则集（MetaCubeX 的除外）无法使用</li>'+
    '<li>每组 DNS 只用列表里的第一个服务器；hosts 只支持精确域名 → IP</li>'+
    '<li>URLTest 组不能手动固定节点</li></ul>';
  let h='';if(j.core==='singbox'&&(j.warn||[]).length)h+='<div class="warn">当前配置的兼容提示：</div><ul style="margin:4px 0 8px 18px;padding:0">'+j.warn.map(w=>`<li>${esc(w)}</li>`).join('')+'</ul>';
  if(to==='singbox'||j.core==='singbox')h+=sbNote;
  if(to==='smart'||j.core==='smart')h+='<div class="warn">mihomo Smart（vernesong/mihomo 预览版）：</div><ul style="margin:4px 0 0 18px;padding:0">'+
    '<li>地区「竞技」组和「⚡ 全局自动选择」改用 smart 类型：按延迟、丢包、速度综合打分选节点；切回 mihomo 时自动恢复 url-test</li>'+
    '<li>「⚖️ 哈希」组、自定义策略组、规则、DNS 都不变</li>'+
    '<li>LightGBM 模型在「策略组 → 地区分组」开关，开启后自动下载 Model.bin（约 9 MB）并每 72 小时更新，会多占一些内存</li></ul>';
  $('#sw-note').innerHTML=h}
let SW_POLL=null;
async function switchCore(){const to=SW_SEL;if(!confirm(`切换到 ${CORE_LABEL[to]}？\n会生成并校验新配置，然后重启核心，局域网会断网几秒。失败会自动切回。`))return;
  try{await saveGhProxy();await api('/api/coreswitch','POST',{core:to});swPoll()}catch(e){toast(e.message)}}
function swPoll(){$('#sw-prog').classList.remove('hide');$('#sw-btn').disabled=true;clearInterval(SW_POLL);
  const tick=async()=>{let j;try{j=await api('/api/coreupdate/status')}catch(e){return}
    $('#sw-bar').style.width=(j.pct||0)+'%';$('#sw-log').textContent=(j.log||[]).join('\n');
    if(!j.busy){clearInterval(SW_POLL);SW_POLL=null;toast(j.message||(j.ok?'已切换':'切换失败'));await loadState().catch(()=>{});loadCoreSw();
      $('#sw-log').textContent=(j.ok?'✓ ':'✗ ')+(j.message||'')+'\n'+(j.log||[]).slice(1).join('\n')}};
  tick();SW_POLL=setInterval(tick,1500)}
function corePoll(){$('#core-prog').classList.remove('hide');['#core-btn','#core-rb','#core-chk'].forEach(x=>$(x).disabled=true);clearInterval(CORE_POLL);
  const tick=async()=>{let j;try{j=await api('/api/coreupdate/status')}catch(e){return}  // 核心重启时请求可能短暂失败
    $('#core-bar').style.width=(j.pct||0)+'%';$('#core-log').textContent=(j.log||[]).join('\n');
    if(!j.busy){clearInterval(CORE_POLL);CORE_POLL=null;['#core-btn','#core-rb','#core-chk'].forEach(x=>$(x).disabled=false);
      $('#core-r').innerHTML=`<span class="${j.ok?'ok':'bad'}">● ${esc(j.message||'')}</span>`;toast(j.ok?'内核操作完成':'内核操作失败');
      if(j.ok){await loadState();api('/api/coreupdate?channel='+coreCh()+'&core='+coreKind()).then(coreShow).catch(()=>{})}}};
  tick();CORE_POLL=setInterval(tick,1500)}
async function rollbackPanel(){if(!confirm('回滚到上次更新前的面板版本？'))return;try{const j=await api('/api/selfupdate','POST',{action:'rollback'});toast(j.message);setTimeout(()=>location.reload(),5000)}catch(e){toast(e.message)}}

