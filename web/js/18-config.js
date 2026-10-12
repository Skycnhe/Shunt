// 配置查看 / 面板更新
let CFG_TXT='';
async function viewConfig(){const box=$('#cfg-box');if(!box.classList.contains('hide')){box.classList.add('hide');$('#cfg-btn').textContent='查看';return}
  try{const j=await api('/api/config');CFG_TXT=j.text;$('#cfg-path').textContent=j.path+' · '+fmt(j.size)+' · 控制器密钥已隐藏';findCfg();box.classList.remove('hide');$('#cfg-btn').textContent='收起'}catch(e){toast(e.message)}}
function findCfg(){const q=$('#cfg-q').value.trim().toLowerCase();const el=$('#cfg-view');
  if(!q){el.textContent=CFG_TXT;return}const ls=CFG_TXT.split('\n');const hit=ls.map((l,i)=>[i,l]).filter(([,l])=>l.toLowerCase().includes(q));
  el.textContent=hit.length?hit.slice(0,400).map(([i,l])=>String(i+1).padStart(5)+'  '+l).join('\n'):'无匹配'}
async function downloadConfig(){try{const r=await fetch('/api/config?download=1',{headers:{'X-Shunt':'1'}});if(!r.ok)throw new Error('HTTP '+r.status);
  const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=STATE.core==='singbox'?'config.json':'config.yaml';a.click()}catch(e){toast(e.message)}}
async function saveGhProxy(){const v=$('#gh-proxy').value.trim();if(v!==(STATE.gh_proxy||'')){await api('/api/settings','PUT',{gh_proxy:v});await loadState()}}
async function checkUpdate(){const b=$('#upd-chk');b.disabled=true;$('#upd-r').innerHTML='<span class="mut">正在检查…</span>';
  try{await saveGhProxy();const j=await api('/api/selfupdate');verSave('panel','v'+j.current,j.remote||'',!!(j.changed&&j.changed.length));
    $('#upd-r').innerHTML=j.changed.length?`<span class="warn">● 有更新</span> 远端 v${esc(j.remote)}（当前 v${esc(j.current)}），变更文件：${j.changed.map(esc).join('、')}`:`<span class="ok">● 已是最新</span> v${esc(j.current)}`}
  catch(e){$('#upd-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false}
async function doUpdate(){if(!confirm('从 GitHub 下载并更新面板文件？更新后面板自动重启（核心不受影响）。'))return;const b=$('#upd-btn');b.disabled=true;
  $('#upd-r').innerHTML='<span class="mut">正在下载并校验…</span>';
  try{await saveGhProxy();const j=await api('/api/selfupdate','POST',{});$('#upd-r').innerHTML=`<span class="ok">● ${esc(j.message)}</span>`;
    if(j.changed&&j.changed.length)setTimeout(()=>location.reload(),5000)}catch(e){$('#upd-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false}
