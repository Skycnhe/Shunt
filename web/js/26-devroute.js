// 按设备分流：设备 → 策略组 / 直连 / 拦截（data.json 的 device_routes，经 /api/settings 保存）
const DR_T={DIRECT:'直连',REJECT:'拦截'},DR_MAC=/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;let DR_EDIT=-1;
const drList=()=>(STATE.device_routes||[]).map(e=>Object.assign({},e));
const drTargets=()=>(STATE.groups||[]).concat(['DIRECT','REJECT']);
const drTname=t=>DR_T[t]||t;
const drMac=m=>String(m||'').toLowerCase().replace(/-/g,':');
function drOpts(sel){const ts=drTargets();if(sel&&!ts.includes(sel))ts.unshift(sel);return ts.map(g=>`<option value="${esc(g)}"${g===sel?' selected':''}>${esc(drTname(g))}</option>`).join('')}
// IPv4 网段包含判断（IPv6 只比较完全相同）
function drIn(ip,net){const v4=x=>{const p=String(x).split('.');return p.length===4&&p.every(y=>/^\d+$/.test(y)&&+y<256)?p.reduce((a,y)=>a*256+(+y),0):null};
  const [n,l]=String(net).split('/'),a=v4(ip),b=v4(n);if(a===null||b===null)return String(ip).toLowerCase()===String(net).toLowerCase().replace(/\/128$/,'');
  const len=l===undefined?32:+l;if(!(len>=0&&len<=32))return false;const k=2**(32-len);return Math.floor(a/k)===Math.floor(b/k)}
// MAC 条目当前对应的 IP（来自设备名单）
const drIps=e=>e.mac?Object.entries(DEVS||{}).filter(([ip,v])=>drMac(v.mac)===drMac(e.mac)).map(([ip])=>ip):[e.ip];
function drBypassed(e){const bl=STATE.bypass||[],ips=drIps(e),macs=e.mac?[drMac(e.mac)]:ips.map(ip=>drMac(DEVS[ip]?.mac)).filter(Boolean);
  return bl.some(b=>DR_MAC.test(b)?macs.includes(drMac(b)):ips.some(ip=>ip&&!ip.includes('/')&&drIn(ip,b))||(!e.mac&&e.ip===b))}
function renderDR(){if(!$('#dr-list'))return;const ts=drTargets(),l=drList();
  if(document.activeElement!==$('#dr-target'))$('#dr-target').innerHTML=drOpts(DR_EDIT>=0?(l[DR_EDIT]||{}).target:$('#dr-target').value||ts[0]);
  $('#dr-list').innerHTML=l.map((e,i)=>{const ips=e.mac?drIps(e):[],miss=!ts.includes(e.target),bp=drBypassed(e);
    const addr=e.mac?`${esc(e.mac)}<div class="mut" style="font-size:11px">${ips.length?'当前 '+ips.map(esc).join('、'):'当前未发现该设备'}</div>`:esc(e.ip);
    const note=(miss?'<div class="bad small">策略组不存在，暂不生效</div>':'')+(bp?'<div class="warn small">已在「绕过设备」中，流量不经过核心，此设置不生效</div>':'');
    return `<tr><td class="w">${esc(e.name||'')}</td><td class="w">${addr}</td><td class="w">${esc(drTname(e.target))}${note}</td>
      <td><label class="sw sm"><input type="checkbox"${e.enabled!==false?' checked':''} onchange="drToggle(${i},this.checked)"><span></span></label></td>
      <td style="text-align:right;white-space:nowrap"><button class="btn g sm" onclick="drEdit(${i})">编辑</button><button class="btn r sm" onclick="drDel(${i})">删除</button></td></tr>`}).join('')||'<tr><td class="mut" colspan="5">暂无，添加后该设备的流量按所选目标走</td></tr>'}
async function drSave(l){try{await saveSettings({device_routes:l})}catch(e){return false}renderDR();return true}
function drReset(){DR_EDIT=-1;$('#dr-name').value='';$('#dr-addr').value='';$('#dr-add').textContent='添加';$('#dr-cancel').classList.add('hide');renderDR()}
async function drSubmit(){const a=$('#dr-addr').value.trim(),t=$('#dr-target').value;if(!a)return toast('请填写 IP、网段或 MAC');if(!t)return toast('请选择目标');
  const e={name:$('#dr-name').value.trim(),ip:'',mac:'',target:t,enabled:true};if(DR_MAC.test(a))e.mac=drMac(a);else e.ip=a;
  const l=drList();if(DR_EDIT>=0&&l[DR_EDIT]){e.enabled=l[DR_EDIT].enabled!==false;l[DR_EDIT]=e}else l.push(e);
  if(await drSave(l))drReset()}
function drEdit(i){const e=drList()[i];if(!e)return;DR_EDIT=i;$('#dr-name').value=e.name||'';$('#dr-addr').value=e.mac||e.ip||'';
  $('#dr-add').textContent='保存';$('#dr-cancel').classList.remove('hide');renderDR();$('#dr-addr').focus()}
// 删除正在编辑的条目前面的一条时，编辑序号跟着前移（保存失败时还原）：以前不调整，点「保存」会覆盖掉后面一条、正在编辑的那条不变；
// 删除的正是正在编辑的条目时清空表单（以前表单还留着，点「保存」会把刚删的又加回来）
async function drDel(i){const l=drList();if(!l[i]||!confirm(`删除「${l[i].name||l[i].ip||l[i].mac}」的分流设置？`))return;l.splice(i,1);
  const e=DR_EDIT;if(e===i)DR_EDIT=-1;else if(e>i)DR_EDIT=e-1;if(!await drSave(l)){DR_EDIT=e;return}if(e===i)drReset()}
function drToggle(i,on){const l=drList();if(!l[i])return;l[i].enabled=on;drSave(l)}
// 从设备列表快速设置：已有条目则编辑，否则预填名称和地址（有 MAC 用 MAC，换 IP 也跟着走）
function drQuick(ip){go('设置');setTimeout(()=>{if(SG!=='net'){SG='net';localStorage.setItem('mp_sg',SG);renderSG()}
  const mac=drMac(DEVS[ip]?.mac),i=drList().findIndex(e=>(mac&&drMac(e.mac)===mac)||e.ip===ip);
  if(i>=0)drEdit(i);else{drReset();$('#dr-name').value=dname(ip)||'';$('#dr-addr').value=mac||ip}
  $('#dr-card').scrollIntoView({block:'center'});$('#dr-target').focus()},200)}
