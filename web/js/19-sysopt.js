// 系统优化
let SO=null;
async function loadSysopt(){try{SO=await api('/api/sysopt');renderSysopt()}catch(e){$('#so-list').innerHTML=`<span class="bad small">${esc(e.message)}</span>`}}
function renderSysopt(){if(!SO)return;$('#so-hw').textContent=`${SO.cpu} 核 · ${SO.mem} MB · ${SO.kernel}`+(SO.container?` · ${SO.container==='lxc'?'LXC':SO.container}  容器`:'');
  $('#so-list').innerHTML=SO.items.map(it=>{const st=!it.ok?`<span class="mut">不支持：${esc(it.why||'')}</span>`:it.active?'<span class="ok">● 已生效</span>':it.enabled?'<span class="warn">● 已开启，未完全生效</span>':'<span class="mut">○ 未开启</span>';
    const sh=Object.entries(it.show||{}).map(([k,v])=>`${esc(k)} ${esc(v)}`).join(' · ');
    return `<div class="opt"><div class="sp"><div class="t">${esc(it.name)}${it.rec?' <span class="tag">推荐</span>':''}</div><div class="dsc">${esc(it.desc)}</div>
      <div class="small" style="margin-top:3px">${st}${sh?' · <span class="mut">'+sh+'</span>':''}${it.part?'<br><span class="mut">'+esc(it.part)+'</span>':''}</div></div>
      <label class="sw"><input type="checkbox" data-so="${esc(it.id)}" ${it.enabled?'checked':''} ${it.ok?'':'disabled'}><span></span></label></div>`}).join('')}
function soPick(rec){document.querySelectorAll('[data-so]').forEach(x=>{if(!x.disabled){const it=SO.items.find(i=>i.id===x.dataset.so);x.checked=rec?it.rec:false}})}
async function soApply(ids){if(!ids)ids=[...document.querySelectorAll('[data-so]')].filter(x=>x.checked).map(x=>x.dataset.so);
  const b=$('#so-btn');b.disabled=true;$('#so-r').innerHTML='<span class="mut">正在应用…（首次开启时间同步需安装 chrony，约 10–30 秒）</span>';
  try{const j=await api('/api/sysopt','POST',{ids});SO=j;renderSysopt();$('#so-r').innerHTML=`<span class="${j.ok?'ok':'warn'}">● ${esc(j.message)}</span>`}
  catch(e){$('#so-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false}
async function soRevert(){if(!confirm('关闭全部优化，并把参数恢复为优化前的原值？'))return;soPick(false);soApply([])}
async function speedTest(via,b){b.disabled=true;const r=$('#sp-r'),lab=via==='proxy'?'经代理':'直连';r.innerHTML=`<span class="mut">${lab}测速中…（约 10 秒）</span>`;
  try{const j=await api('/api/speedtest?via='+via);r.dataset[via]=j.ok?`${lab} <b>${j.mbps} Mbps</b>（首包 ${j.ttfb} ms，下载 ${j.mb} MB）`:`${lab} <span class="bad">失败：${esc(j.error)}</span>`}
  catch(e){r.dataset[via]=`${lab} <span class="bad">${esc(e.message)}</span>`}
  r.innerHTML=[r.dataset.direct,r.dataset.proxy].filter(Boolean).join('<br>');b.disabled=false}

