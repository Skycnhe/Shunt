// 规则
async function loadRules(){await loadState();
  $('#r-target').innerHTML=STATE.groups.concat(['DIRECT','REJECT']).map(g=>`<option>${esc(g)}</option>`).join('');
  $('#myrules').innerHTML=STATE.rules.map((r,i)=>`<tr><td class="w">${esc(r)}</td><td style="text-align:right"><button class="btn r sm" onclick="delRule(${jsq(r)})">删除</button></td></tr>`).join('')||'<tr><td class="mut">暂无自定义规则</td></tr>';
  $('#r-bulk').value=STATE.rules.join('\n');
  renderRS();
  try{ACTIVE_RULES=(await core('/rules')).rules||[]}catch(e){ACTIVE_RULES=[]}renderActiveRules()}
function renderActiveRules(){const f=$('#r-filter').value.toLowerCase();
  $('#rules').innerHTML=ACTIVE_RULES.map((r,i)=>[i,r]).filter(([i,r])=>!f||JSON.stringify(r).toLowerCase().includes(f)).slice(0,500)
    .map(([i,r])=>`<tr><td class="mut">${i+1}</td><td>${esc(r.type)}</td><td class="w">${esc(r.payload)}</td><td>${esc(r.proxy)}</td></tr>`).join('')}
async function saveRules(rules){try{toast('正在应用…');await api('/api/rules','PUT',{rules});toast('规则已生效');loadRules()}catch(e){toast(e.message)}}
function addRule(){const t=$('#r-type').value,v=$('#r-val').value.trim(),g=$('#r-target').value;if(!v)return toast('请填写内容');
  let r=`${t},${v},${g}`;if(['IP-CIDR','GEOIP'].includes(t))r+=',no-resolve';$('#r-val').value='';saveRules(STATE.rules.concat([r]))}
// 按规则内容删除（不按序号）：STATE 每 15 秒在后台刷新而列表不重画，别的窗口改过规则后序号会指向另一条规则
function delRule(v){const r=STATE.rules.slice(),i=r.indexOf(v);if(i<0){toast('该规则已不存在，列表已刷新');return loadRules()}r.splice(i,1);saveRules(r)}
function saveBulk(){saveRules($('#r-bulk').value.split('\n'))}
async function ruleTest(){const t=$('#rt-target').value.trim();if(!t)return toast('请输入域名或 IP');const b=$('#rt-btn');b.disabled=true;
  $('#rt-result').innerHTML='<span class="mut">测试中…</span>';
  try{const r=await api('/api/ruletest','POST',{target:t});const live=r.method==='live';
    let h=`<div class="tw"><table><tbody><tr><th>目标</th><td>${esc(r.host)}</td></tr>
      <tr><th>方式</th><td class="w">${live?'<span class="ok">实时</span>（经 mixed 端口发起真实连接，读取核心匹配结果）':'<span class="warn">静态推断</span>（实时检测失败：'+esc(r.live_error||'-')+'）'}</td></tr>
      <tr><th>命中规则</th><td class="w"><b>${esc(r.rule)}</b> ${esc(r.payload||'')}</td></tr>
      <tr><th>节点链路</th><td class="w">${esc((r.chain||[]).join(' → ')||'-')}</td></tr>${r.note?`<tr><th>说明</th><td class="w mut">${esc(r.note)}</td></tr>`:''}</tbody></table></div>`;
    if(!live&&r.uncertain&&r.uncertain.length)h+=`<div class="mut small" style="margin-top:6px">以下规则（GEOSITE/GEOIP/RULE-SET 等）无法静态判断，排在命中规则之前，实际可能先命中：<br>${r.uncertain.map(esc).join('<br>')}</div>`;
    $('#rt-result').innerHTML=h}catch(e){$('#rt-result').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false}

