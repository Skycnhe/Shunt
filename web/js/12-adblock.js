// 广告拦截
let AB=null,_abt=0;
async function loadAB(){try{AB=await api('/api/adblock')}catch(e){return toast(e.message)}renderAB();clearTimeout(_abt);if(AB.updating)_abt=setTimeout(loadAB,2500)}
function abLists(){return AB.lists.map(({name,url,enabled})=>({name,url,enabled}))}
function renderAB(){const a=AB;$('#ab-on').checked=a.enabled;$('#ab-on').onchange=e=>abSave({enabled:e.target.checked},e.target.checked?'广告拦截已开启':'广告拦截已关闭');
  $('#ab-dns').checked=a.dns;$('#ab-dns').onchange=e=>abSave({dns:e.target.checked},'DNS 层拦截已'+(e.target.checked?'开启':'关闭'));
  $('#ab-int').value=String(a.interval);
  const total=Object.entries(a.loaded).filter(([k])=>k!=='ad-allow').reduce((s,[,v])=>s+(v||0),0);
  $('#ab-total').textContent=a.enabled?total.toLocaleString('zh-CN',{hour12:false}):'未开启';$('#ab-today').textContent=a.stats.today.toLocaleString('zh-CN',{hour12:false});
  $('#ab-nlist').textContent=a.lists.filter(l=>l.enabled).length+' / '+a.lists.length;
  $('#ab-last').textContent=ago(Math.max(0,...a.lists.map(l=>l.updated||0)));
  $('#ab-msg').innerHTML=a.updating?'<span class="warn">● 正在更新…</span>':esc(a.msg||'');document.querySelectorAll('#ab-upd,.abhd').forEach(b=>b.disabled=a.updating);
  $('#ab-lists').innerHTML=a.lists.map((l,i)=>{const ld=a.loaded['ad-'+l.id];
    return `<tr><td><label class="sw sm"><input type="checkbox" ${l.enabled?'checked':''} onchange="abToggle(${i},this.checked)"><span></span></label></td>
    <td class="w" style="min-width:150px"><b style="font-weight:600">${esc(l.name)}</b><div class="mut" style="font-size:11px;max-width:300px">${esc(l.url)}</div></td>
    <td>${l.count!=null?Number(l.count).toLocaleString('zh-CN',{hour12:false}):'-'}${l.allow?`<div class="mut" style="font-size:11px">例外 ${l.allow}</div>`:''}${a.enabled&&l.enabled&&ld==null&&l.count?'<div class="warn" style="font-size:11px">未加载</div>':''}</td>
    <td>${(l.hits||0).toLocaleString('zh-CN',{hour12:false})}</td>
    <td class="w" style="font-size:12px;min-width:90px">${l.error?`<span class="bad" title="${esc(l.error)}">失败：${esc(l.error.slice(0,40))}</span>`:ago(l.updated)}</td>
    <td style="text-align:right;white-space:nowrap"><button class="btn g sm" onclick="abUpdate('${l.id}')">更新</button> <button class="btn r sm" onclick="abDel(${i})">删除</button></td></tr>`}).join('')
    +(a.black.length?`<tr><td></td><td><b style="font-weight:600">自定义黑名单</b></td><td>${(a.loaded['ad-custom']??a.black.length).toLocaleString('zh-CN',{hour12:false})}</td><td>${(a.custom_hits||0).toLocaleString('zh-CN',{hour12:false})}</td><td></td><td></td></tr>`:'')
    ||'<tr><td colspan="6" class="mut">还没有列表，点下方内置规则一键添加</td></tr>';
  const cats=[...new Set(a.presets.map(p=>p.cat||'其他'))];
  $('#ab-presets').innerHTML=cats.map(c=>`<div class="abpr"><span class="mut small abpc">${esc(c)}</span><span class="row">`+a.presets.map((p,i)=>(p.cat||'其他')!==c?'':`<button class="btn g sm" title="${esc(p.dsc||'')}" onclick="abPreset(${i})" ${a.lists.some(l=>l.url===p.url)?'disabled':''}>${esc(p.name)}</button>`).join('')+'</span></div>').join('');
  if(document.activeElement!==$('#ab-black'))$('#ab-black').value=a.black.join('\n');
  if(document.activeElement!==$('#ab-white'))$('#ab-white').value=a.white.join('\n');
  const top=a.stats.top||[],mx=top.length?top[0][1]:1;
  $('#ab-top').innerHTML=top.map(([d,n])=>`<tr><td class="w">${esc(d)}</td><td><div class="bar" style="width:${Math.max(2,n/mx*100)}%"></div></td><td>${n}</td></tr>`).join('')||'<tr><td class="mut" colspan="3">今天还没有拦截记录</td></tr>'}
async function abSave(patch,msg){try{toast('正在应用…');const j=await api('/api/adblock','PUT',patch);toast(msg&&!/下载/.test(j.message)?msg:j.message);}catch(e){toast(e.message)}loadAB()}
function abPreset(i){const p=AB.presets[i];abSave({lists:abLists().concat([{name:p.name,url:p.url,enabled:true}]),enabled:true},'已添加 '+p.name)}
function abAdd(){const url=$('#ab-url').value.trim(),name=$('#ab-name').value.trim();if(!/^https?:\/\//.test(url))return toast('请填写列表地址');
  $('#ab-url').value='';$('#ab-name').value='';abSave({lists:abLists().concat([{name,url,enabled:true}])})}
function abDel(i){if(!confirm('删除列表 '+AB.lists[i].name+'？'))return;const l=abLists();l.splice(i,1);abSave({lists:l},'已删除')}
function abToggle(i,v){const l=abLists();l[i].enabled=v;abSave({lists:l},v?'已启用':'已停用')}
async function abUpdate(id){try{const j=await api('/api/adblock/update','POST',id?{ids:[id]}:{});toast(j.message)}catch(e){toast(e.message)}setTimeout(loadAB,800)}
function abSaveBW(){abSave({black:lines($('#ab-black').value),white:lines($('#ab-white').value)},'自定义规则已生效')}
async function abCheck(){const d=$('#ab-check').value.trim();if(!d)return toast('请输入域名');
  try{const r=await api('/api/adblock/check','POST',{domain:d});
    const st=r.blocked?'<span class="bad">● 会被拦截</span>':r.blocked_by.length&&r.allowed_by.length?'<span class="ok">● 放行（白名单优先）</span>':r.blocked_by.length&&!r.enabled?'<span class="warn">● 命中列表，但广告拦截未开启</span>':'<span class="ok">● 不拦截</span>';
    $('#ab-check-r').innerHTML=`<div class="kv"><span>域名</span><b>${esc(r.host)}</b><span>结果</span><span>${st}</span>
      <span>命中拦截</span><span>${r.blocked_by.map(x=>esc(x.name)+' <span class="tag">'+esc(x.rule)+'</span>').join('<br>')||'-'}</span>
      <span>命中放行</span><span>${r.allowed_by.map(x=>esc(x.name)+' <span class="tag">'+esc(x.rule)+'</span>').join('<br>')||'-'}</span></div>`}
  catch(e){$('#ab-check-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}}

