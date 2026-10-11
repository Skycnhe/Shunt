// 设备名称
async function loadDevs(){try{const j=await api('/api/devices');DEVS=j.map||{};STATE.devices=j.custom||{}}catch(e){}}
const dname=ip=>(DEVS[ip]&&DEVS[ip].name)||'';
const devCell=ip=>{if(!ip||ip==='?')return '<span class="mut">mihomo 内部（DNS 等）</span>';const n=dname(ip);return n?`<span class="dev">${esc(n)}<small>${esc(ip)}</small></span>`:esc(ip)};
async function editDev(ip){const mac=DEVS[ip]?.mac;const cur=(STATE.devices||{})[ip]||(mac&&(STATE.devices||{})[mac])||dname(ip);
  const v=prompt(`设备 ${ip}${mac?'（'+mac+'）':''} 的备注名称（留空删除）`,cur);if(v===null)return;
  const d=Object.assign({},STATE.devices||{});delete d[ip];if(mac)delete d[mac];if(v.trim())d[mac||ip]=v.trim();
  try{await api('/api/devices','PUT',{devices:d});STATE.devices=d;await loadDevs();toast('已保存');if(TAB==='统计')loadStats()}catch(e){toast(e.message)}}

