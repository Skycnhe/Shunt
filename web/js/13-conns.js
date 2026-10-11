// 连接
const prevConn={};
let _lastConnRender=0;
function renderConns(list){const f=$('#c-filter').value.toLowerCase();const now=Date.now();
  list.sort((a,b)=>new Date(b.start)-new Date(a.start));
  // 速率基线每秒更新（/s 显示准确），DOM 全量重绘降频到每 2 秒
  const rates=new Map();
  for(const c of list){const p=prevConn[c.id];rates.set(c.id,p?[c.download-p.d,c.upload-p.u]:[0,0]);prevConn[c.id]={d:c.download,u:c.upload}}
  if(now-_lastConnRender<2000)return;
  _lastConnRender=now;
  $('#conns').innerHTML=list.filter(c=>!f||(JSON.stringify(c)+dname(c.metadata?.sourceIP)).toLowerCase().includes(f)).slice(0,300).map(c=>{const m=c.metadata||{};
    const r=rates.get(c.id),ds=r[0],us=r[1];
    const host=(m.host||m.sniffHost||m.destinationIP)+':'+m.destinationPort;const sec=Math.floor((now-new Date(c.start))/1000);
    return `<tr><td class="w" style="max-width:260px">${esc(host)}</td><td>${devCell(m.sourceIP)}</td><td>${esc(m.network)}</td><td>${esc(c.rule)}${c.rulePayload?' <span class="mut">'+esc(c.rulePayload.length>40?c.rulePayload.slice(0,40)+'…':c.rulePayload)+'</span>':''}</td>
    <td class="w">${esc((c.chains||[]).slice().reverse().join(' → '))}</td><td>${fmt(ds)}/s</td><td>${fmt(us)}/s</td><td>${fmt(c.download)}</td>
    <td>${sec<60?sec+'s':Math.floor(sec/60)+'m'}</td><td><button class="btn g sm" onclick="closeConn('${c.id}')">断开</button></td></tr>`}).join('')||'<tr><td class="mut" colspan="10">暂无连接</td></tr>'}
async function closeConn(id){try{await core('/connections/'+id,'DELETE')}catch(e){toast(e.message)}}
async function closeAll(){if(!confirm('断开全部连接？'))return;try{await core('/connections','DELETE');toast('已断开')}catch(e){toast(e.message)}}

