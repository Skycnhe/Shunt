// 连接
const prevConn={};
function renderConns(list){const f=$('#c-filter').value.toLowerCase();const now=Date.now();
  list.sort((a,b)=>new Date(b.start)-new Date(a.start));
  $('#conns').innerHTML=list.filter(c=>!f||(JSON.stringify(c)+dname(c.metadata?.sourceIP)).toLowerCase().includes(f)).slice(0,300).map(c=>{const m=c.metadata||{};
    const p=prevConn[c.id];const ds=p?(c.download-p.d):0,us=p?(c.upload-p.u):0;prevConn[c.id]={d:c.download,u:c.upload};
    const host=(m.host||m.sniffHost||m.destinationIP)+':'+m.destinationPort;const sec=Math.floor((now-new Date(c.start))/1000);
    return `<tr><td class="w" style="max-width:260px">${esc(host)}</td><td>${devCell(m.sourceIP)}</td><td>${esc(m.network)}</td><td>${esc(c.rule)}${c.rulePayload?' <span class="mut">'+esc(c.rulePayload.length>40?c.rulePayload.slice(0,40)+'…':c.rulePayload)+'</span>':''}</td>
    <td class="w">${esc((c.chains||[]).slice().reverse().join(' → '))}</td><td>${fmt(ds)}/s</td><td>${fmt(us)}/s</td><td>${fmt(c.download)}</td>
    <td>${sec<60?sec+'s':Math.floor(sec/60)+'m'}</td><td><button class="btn g sm" onclick="closeConn('${c.id}')">断开</button></td></tr>`}).join('')||'<tr><td class="mut" colspan="10">暂无连接</td></tr>'}
async function closeConn(id){try{await core('/connections/'+id,'DELETE')}catch(e){toast(e.message)}}
async function closeAll(){if(!confirm('断开全部连接？'))return;try{await core('/connections','DELETE');toast('已断开')}catch(e){toast(e.message)}}

