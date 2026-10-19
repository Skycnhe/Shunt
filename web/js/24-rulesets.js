// 规则集
const RS_BASE='https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/';
function presetRS(name,site,target){saveRS(STATE.rulesets.filter(r=>r.name!==name).concat([{name,url:RS_BASE+site+'.mrs',behavior:'domain',format:'mrs',target}]))}
function addRS(){const name=$('#rs-name').value.trim(),url=$('#rs-url').value.trim();if(!name||!url)return toast('请填写名称和链接');
  saveRS(STATE.rulesets.filter(r=>r.name!==name).concat([{name,url,behavior:$('#rs-beh').value,format:$('#rs-fmt').value,target:$('#rs-target').value}]))}
async function saveRS(rs){try{toast('正在应用…');await api('/api/settings','PUT',{rulesets:rs});toast('规则集已生效');loadRules()}catch(e){toast(e.message)}}
function delRS(i){const r=STATE.rulesets.slice();r.splice(i,1);saveRS(r)}
async function renderRS(){$('#rs-target').innerHTML=$('#r-target').innerHTML;let prov={};try{prov=(await core('/providers/rules')).providers||{}}catch(e){}
  $('#rulesets').innerHTML=STATE.rulesets.map((r,i)=>{const p=prov[r.name]||{};return `<tr><td>${esc(r.name)}<div class="mut w" style="font-size:11px;max-width:360px">${esc(r.url)}</div></td><td>${esc(r.behavior)}/${esc(r.format)}</td><td>${esc(r.target)}</td>
    <td>${p.ruleCount??'-'}</td><td><button class="btn g sm" onclick="updRS(${jsq(encodeURIComponent(r.name))})">更新</button></td><td><button class="btn r sm" onclick="delRS(${i})">删除</button></td></tr>`}).join('')||'<tr><td class="mut">暂无规则集</td></tr>'}
async function updRS(n){try{await core('/providers/rules/'+n,'PUT');toast('已更新');renderRS()}catch(e){toast(e.message)}}

