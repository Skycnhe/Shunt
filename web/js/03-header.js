// 顶栏：核心状态 + 启停 + 实时数据
const PM_TXT={tproxy:'TProxy',tun:'TUN',off:'已关闭'};
let STATE_VER=-1; // data.json 的版本（每次 save 自增），变化时才拉全量 /api/state
async function loadState(){
  let v=null;
  try{v=(await api('/api/ping')).version}catch(e){/* 心跳失败则回退全量拉取 */}
  if(v!==null&&v===STATE_VER&&STATE.running!==undefined)return; // 配置无变化：顶栏运行状态由 1 秒实时流保持
  STATE=await api('/api/state');STATE_VER=v;
  renderCore(STATE.running);renderMode();renderWD();renderPMStat()}
function renderCore(run){$('#h-dot').className='dot '+(run?'on':'off');$('#h-run').textContent=run?'运行中':'已停止';
  $('#h-ver').textContent=run&&STATE.version&&STATE.version!=='-'?STATE.version:'';
  $('#h-restart').classList.toggle('hide',!run);$('#h-stop').classList.toggle('hide',!run);$('#h-start').classList.toggle('hide',run)}
function renderHdr(l){$('#h-up').textContent=fmt(l.up)+'/s';$('#h-down').textContent=fmt(l.down)+'/s';
  $('#h-ut').textContent=fmt(l.upTotal);$('#h-dt').textContent=fmt(l.downTotal);$('#h-mem').textContent=l.inuse?fmt(l.inuse):'-';
  $('#ov-up').textContent=fmt(l.up)+'/s';$('#ov-down').textContent=fmt(l.down)+'/s';
  $('#ov-tot').textContent=`累计 ↑${fmt(l.upTotal)} ↓${fmt(l.downTotal)} · 内存 ${l.inuse?fmt(l.inuse):'-'}`;
  if(l.running!==undefined&&l.running!==STATE.running){STATE.running=l.running;renderCore(l.running)}}
function renderOverview(){renderMode();renderWD();renderPMStat();loadDevs();loadAdStat();loadQS()}
