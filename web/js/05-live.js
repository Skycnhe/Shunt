// 每秒：/api/live（速率、累计、内存）；概览 / 连接页额外拉取连接列表
// 页面不可见时全部暂停；连续失败按 2、4、8…最多 30 秒退避；连接列表只在概览（每 3 秒）和连接页（每秒，暂停时不拉）获取
let _cn=0,_busy=false,_fail=0,_skip=0;
async function tick(){
  if(document.hidden||_busy)return;if(_skip>0){_skip--;return}_busy=true;
  try{await tickOnce()}finally{_busy=false}}
async function tickOnce(){
  try{LIVE=await api('/api/live');renderHdr(LIVE);pushHist(LIVE.up||0,LIVE.down||0);_fail=0}
  catch(e){['#h-up','#h-down','#h-mem'].forEach(k=>$(k).textContent='-');_fail++;_skip=Math.min(30,2**_fail);return}
  _cn++;
  if((TAB==='连接'&&!$('#c-pause').checked)||(TAB==='概览'&&_cn%3===0)){
    try{const c=await api('/api/conns');CONNS=c.connections||[];$('#s-conn').textContent=CONNS.length;
      $('#s-devs').textContent=new Set(CONNS.map(x=>x.metadata?.sourceIP).filter(Boolean)).size+' 台设备';
      if(TAB==='连接'&&!$('#c-pause').checked)renderConns(CONNS)}catch(e){$('#s-conn').textContent='-'}}}
