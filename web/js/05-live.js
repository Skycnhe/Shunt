// 每秒：/api/live（速率、累计、内存）；概览 / 连接页额外拉取连接列表
// 页面不可见时全部暂停；连续失败按 2、4、8…最多 30 秒退避；连接页每秒拉完整连接列表（暂停时不拉），概览每 3 秒只拉连接数 / 设备数
let _cn=0,_busy=false,_fail=0,_skip=0;
async function tick(){
  if(document.hidden||_busy)return;if(_skip>0){_skip--;return}_busy=true;
  try{await tickOnce()}finally{_busy=false}}
async function tickOnce(){
  try{LIVE=await api('/api/live');renderHdr(LIVE);pushHist(LIVE.up||0,LIVE.down||0);_fail=0}
  catch(e){['#h-up','#h-down','#h-mem'].forEach(k=>$(k).textContent='-');_fail++;_skip=Math.min(30,2**_fail);return}
  _cn++;
  if(TAB==='连接'&&!$('#c-pause').checked){
    try{const c=await api('/api/conns');CONNS=c.connections||[];showConnStat(CONNS.length,new Set(CONNS.map(x=>x.metadata?.sourceIP).filter(Boolean)).size);
      renderConns(CONNS)}catch(e){$('#s-conn').textContent='-'}}
  else if(TAB==='概览'&&_cn%3===0){ // 概览只要两个数字：走轻量的 /api/conns/stats，不再拉完整连接列表
    try{const s=await api('/api/conns/stats');showConnStat(s.count,s.devices)}catch(e){$('#s-conn').textContent='-'}}}
function showConnStat(n,d){$('#s-conn').textContent=n;$('#s-devs').textContent=d+' 台设备'}
