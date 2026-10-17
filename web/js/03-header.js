// 顶栏：核心状态 + 启停 + 实时数据
const PM_TXT={tproxy:'TProxy',tun:'TUN',off:'已关闭'};
let AD_TODAY=null; // 今日拦截数（/api/ping 每 15 秒带回）
function renderAdChip(){const el=$('#h-ad');if(!el)return;const on=STATE.adblock_on!==false;
  el.querySelector('b').textContent=!on||AD_TODAY==null?'-':(+AD_TODAY||0).toLocaleString('zh-CN');
  el.title=on?'今天拦截的广告请求（本地时间 0 点清零，与概览「今日拦截广告」一致），点击查看':'广告拦截未开启，点击去开启'}
let STATE_VER=-1; // data.json 的版本（每次 save 自增），变化时才拉全量 /api/state
async function loadState(){
  let v=null;
  try{const pg=await api('/api/ping');v=pg.version;AD_TODAY=pg.ad_today}catch(e){/* 心跳失败则回退全量拉取 */}
  renderAdChip();
  if(v!==null&&v===STATE_VER&&STATE.running!==undefined)return; // 配置无变化：顶栏运行状态由 1 秒实时流保持
  STATE=await api('/api/state');STATE_VER=v;
  renderCore(STATE.running);renderAdChip();renderMode();renderWD();renderPMStat();renderVer()}
function renderCore(run){$('#h-dot').className='dot '+(run?'on':'off');$('#h-run').textContent=run?'运行中':'已停止';
  $('#h-mode').innerHTML=run?'<span class="ok">● 代理</span>':'<span class="mut">● 直连</span>';
  $('#h-ver').textContent=run&&STATE.version&&STATE.version!=='-'?STATE.version:'';$('#h-run').parentNode.title=run&&STATE.version&&STATE.version!=='-'?(CORE_LABEL[STATE.core]||STATE.core||'')+' '+STATE.version:'';
  $('#h-restart').classList.toggle('hide',!run);$('#h-stop').classList.toggle('hide',!run);$('#h-start').classList.toggle('hide',run)}
function renderHdr(l){$('#h-up').textContent=fmt(l.up)+'/s';$('#h-down').textContent=fmt(l.down)+'/s';
  $('#h-ut').textContent=fmt(l.upTotal);$('#h-dt').textContent=fmt(l.downTotal);$('#h-mem').textContent=l.inuse?fmt(l.inuse):'-';
  $('#ov-up').textContent=fmt(l.up)+'/s';$('#ov-down').textContent=fmt(l.down)+'/s';
  $('#ov-tot').textContent=`累计 ↑${fmt(l.upTotal)} ↓${fmt(l.downTotal)} · 内存 ${l.inuse?fmt(l.inuse):'-'}`;
  if(l.running!==undefined&&l.running!==STATE.running){STATE.running=l.running;renderCore(l.running)}}
function renderOverview(){renderMode();renderWD();renderPMStat();loadDevs();loadAdStat();loadQS();loadIpInfo();if(Date.now()-SITES_T>55e3)testSites()}

// 顶栏版本：面板 / 内核当前版本，有更新时标「有更新」。检查结果按版本缓存 6 小时（检查要访问 GitHub API，
// 未登录每小时 60 次，不能每次打开都查）；设置页手动检查后也会刷新这里
const VER_TTL=6*3600e3,VER_BUSY={};
function verCache(k){try{return JSON.parse(localStorage.getItem('ver-'+k)||'null')}catch(e){return null}}
function verSave(k,cur,remote,upd){localStorage.setItem('ver-'+k,JSON.stringify({cur,remote,upd,t:Date.now()}));renderVer()}
function verChip(id,cur,c){const el=$(id);if(!el)return;const has=!!(c&&c.cur===cur&&c.upd);
  el.classList.toggle('new',has);el.querySelector('b').textContent=cur||'-';
  el.querySelector('.k').innerHTML=(id==='#hv-panel'?'面板':'内核')+(has?'<em>有更新</em>':'');
  el.title=(has?`有更新：${cur} → ${c.remote}，`:'')+'点击去设置检查更新'}
function coreChFor(){const k=STATE.core||'mihomo',v=String(STATE.version||'');
  return k==='smart'||/alpha/i.test(v)?'alpha':'stable'}
async function verCheck(k,url,cur){if(VER_BUSY[k]||!cur||cur==='-')return;const c=verCache(k);
  if(c&&c.cur===cur&&Date.now()-c.t<VER_TTL)return;VER_BUSY[k]=1;
  try{const j=await api(url);verSave(k,cur,j.remote||'',k==='panel'?!!(j.changed&&j.changed.length):!j.latest)}catch(e){}VER_BUSY[k]=0}
function renderVer(){const pv=STATE.panel_version?'v'+STATE.panel_version:'',cv=STATE.version&&STATE.version!=='-'?String(STATE.version):'';
  verChip('#hv-panel',pv,verCache('panel'));verChip('#hv-core',cv,verCache('core-'+(STATE.core||'mihomo')));
  verCheck('panel','/api/selfupdate',pv);
  verCheck('core-'+(STATE.core||'mihomo'),`/api/coreupdate?channel=${coreChFor()}&core=${STATE.core||'mihomo'}`,cv)}
function goUpd(id){go('设置');setTimeout(()=>{const b=$('#'+id),g=b&&b.closest('[data-sg]');if(g&&g.dataset.sg!==SG){SG=g.dataset.sg;localStorage.setItem('mp_sg',SG);renderSG()}if(b){b.scrollIntoView({block:'center'});b.click()}},150)}
