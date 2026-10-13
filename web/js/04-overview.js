// 概览：🚀 节点选择 快速切换
const SEL='🚀 节点选择',G_MANUAL='\u{1F590}\uFE0F 手动选择';
// /proxies 只返回 config 里的节点和策略组；订阅（proxy-providers）节点及其延迟在 /providers/proxies 里，需合并
async function testGroupKeep(g){const fx=PROXIES[g]?.fixed;
  try{await core(`/group/${encodeURIComponent(g)}/delay?url=${encodeURIComponent(HCURL)}&timeout=5000`)}catch(e){}
  if(fx)try{await core('/proxies/'+encodeURIComponent(g),'PUT',{name:fx})}catch(e){}}
// 面板合并 /proxies 与订阅节点，并用缓存补上核心暂时没有的延迟（重载 / 重启后核心记录会清空）
async function loadPX(){const j=await api('/api/px');return j.proxies||{}}
async function loadQS(){let px;try{px=await loadPX()}catch(e){$('#qs-card').classList.add('hide');return}
  try{const j=await api('/api/direct_delay');if(j.ms>0)DIRECT_D=j.ms}catch(e){}
  const g=px[SEL];$('#qs-card').classList.toggle('hide',!g);if(!g)return;PROXIES=px;
  const ch=nowChain(SEL);$('#qs-now').textContent=ch.length?'当前：'+ch.join(' → '):'';
  $('#qs').innerHTML=g.all.map((n,j)=>{if(HIDEDEAD&&n!==g.now&&isDead(n))return '';const d=lastDelay(n),p=px[n]||{},sub=p.type==='Smart'?'智能竞技':p.now?'→ '+p.now:(p.type==='LoadBalance'?'负载均衡':'');
    return `<div class="node ${n===g.now?'sel':''}" onclick="qsPick(${j})" title="${esc(n)}"><div class="n">${esc(n)}</div><div class="d"><span class="mut" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(sub)}</span><span class="${dcls(d)}">${dtxt(d)}</span></div></div>`}).join('')}
async function qsPick(j){const n=PROXIES[SEL].all[j];try{await core('/proxies/'+encodeURIComponent(SEL),'PUT',{name:n});toast(SEL+' → '+n);loadQS()}catch(e){toast(e.message)}}
async function qsTest(b){b.disabled=true;b.textContent='测速中…';
  const gs=[SEL].concat((PROXIES[SEL]?.all||[]).filter(n=>PROXIES[n]?.all));
  await Promise.all(gs.map(testGroupKeep));
  b.disabled=false;b.textContent='测速';loadQS()}
function renderPMStat(){$('#s-pm').textContent=PM_TXT[STATE.proxy_mode]||'-';
  $('#s-pm2').textContent=STATE.proxy_mode==='tun'?`${STATE.tun.stack} · ${STATE.tun.device}`:STATE.proxy_mode==='tproxy'?('nftables'+(STATE.ipv6?' · IPv4+IPv6':' · IPv4')):'仅 7890 端口可用'}
// 迷你曲线：平滑折线 + 渐变填充，null 视为缺数据跳过
function spark(vals,col,empty){let pts=vals.map((v,i)=>[i,v]).filter(p=>p[1]!=null);
  if(!pts.length)return `<div class="spk mut small" style="display:grid;place-items:center">${empty||'暂无数据'}</div>`;
  if(pts.length===1){vals=[pts[0][1],pts[0][1]];pts=[[0,pts[0][1]],[1,pts[0][1]]]}  // 只有一个点时画一条平线
  const n=vals.length-1||1,mx=Math.max(...pts.map(p=>p[1]))||1,mn=Math.min(0,...pts.map(p=>p[1])),W=200,H=60,
    xy=pts.map(([i,v])=>[i/n*W,H-4-(v-mn)/(mx-mn||1)*(H-10)]);
  let d='M'+xy[0][0].toFixed(1)+','+xy[0][1].toFixed(1);for(let k=1;k<xy.length;k++){const [x0,y0]=xy[k-1],[x1,y1]=xy[k],cx=(x0+x1)/2;d+=` C${cx.toFixed(1)},${y0.toFixed(1)} ${cx.toFixed(1)},${y1.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`}
  const id='g'+Math.random().toString(36).slice(2,8);
  return `<svg class="spk" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${col}" stop-opacity=".28"/><stop offset="1" stop-color="${col}" stop-opacity=".02"/></linearGradient></defs>
    <path d="${d} L${xy[xy.length-1][0].toFixed(1)},${H} L${xy[0][0].toFixed(1)},${H} Z" fill="url(#${id})"/><path d="${d}" fill="none" stroke="${col}" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/></svg>`}
async function loadAdStat(){let a;try{a=await api('/api/adblock')}catch(e){return}
  const n=v=>(+v||0).toLocaleString('zh-CN'),rules=Object.entries(a.loaded||{}).filter(([k])=>k!=='ad-allow').reduce((s,[,v])=>s+(v||0),0);
  $('#s-ad').textContent=a.enabled?n(a.stats.today):'未开启';AD_TODAY=a.stats.today;STATE.adblock_on=a.enabled;renderAdChip();$('#s-ad2').textContent=a.enabled?'规则 '+n(rules)+' 条':'在“广告拦截”中开启';
  const on=$('#ovab-on');on.checked=a.enabled;on.disabled=!!a.updating;
  on.onchange=async e=>{const v=e.target.checked;try{toast('正在应用…');const j=await api('/api/adblock','PUT',{enabled:v});toast(/下载/.test(j.message||'')?j.message:'广告拦截已'+(v?'开启':'关闭'))}catch(x){toast(x.message)}loadAdStat()};
  const H=a.stats.hours||[],req=H.reduce((s,h)=>s+h.req,0),blk=H.reduce((s,h)=>s+h.blk,0),dv=H.filter(h=>h.dns!=null),
    D=a.stats.dns||{},dns=D.avg!=null?Math.round(D.avg):dv.length?Math.round(dv.reduce((s,h)=>s+h.dns,0)/dv.length):null,
    dser=D.series||H.map(h=>h.dns),dsub=D.samples?(D.mode==='recent'?'最近 '+D.series.length+' 次':'24 小时 · '+D.samples+' 次')+(D.last!=null?' · 最新 '+D.last+' ms':''):'',pct=req?(blk/req*100).toFixed(1)+'%':'',
    top=(a.stats.top||[]).slice(0,5),tmx=top.length?top[0][1]:1,O='#ff9f0a';
  $('#ovab-body').innerHTML=`<div class="dft">
    <div class="card dfc"><div class="k row"><span class="sp">平均解析耗时</span><span class="mut" style="font-size:11.5px">${esc(dsub)}</span></div><div class="v">${dns==null?'-':dns+'<small>ms</small>'}</div>${spark(dser,cssv('--ok'),D.core==='singbox'?'sing-box 内核不支持':'等待首次检测（约 10 秒）')}</div>
    <div class="card dfc"><div class="k">连接请求</div><div class="v">${n(req)}</div>${spark(H.map(h=>h.req),cssv('--pri'))}</div>
    <div class="card dfc"><div class="k row"><span class="sp">已拦截</span><span style="color:${O}">${a.enabled?pct:'未开启'}</span></div><div class="v" style="color:${O}">${n(blk)}</div>${spark(H.map(h=>h.blk),O)}</div>
    <div class="card dfc dfrank"><div class="k">被拦截域名排行</div><div class="dtop">${top.length?top.map(([d,c])=>`<div class="dti" title="${esc(d)}：${n(c)} 次"><div class="row"><span class="sp w">${esc(d)}</span><b>${n(c)}</b></div><div class="dtb"><i style="width:${Math.max(3,c/tmx*100)}%"></i></div></div>`).join(''):'<div class="mut small" style="margin-top:8px">'+(a.enabled?'今天还没有拦截记录':'广告拦截未开启')+'</div>'}</div></div>
  </div>${a.dns&&a.enabled?'<div class="mut small" style="margin-top:8px">已开启 DNS 层拦截：直接返回 NXDOMAIN 的请求不经过连接，不计入拦截次数</div>':''}`}
function renderMode(){document.querySelectorAll('#mode button').forEach(b=>{b.classList.toggle('on',b.dataset.m===STATE.mode);
  b.onclick=async()=>{try{await api('/api/mode','PUT',{mode:b.dataset.m});STATE.mode=b.dataset.m;renderMode();toast('已切换模式')}catch(e){toast(e.message)}}})}
const WDS={ok:['ok','正常'],restarting:['warn','正在重启核心'],direct:['bad','已切换直连'],stopped:['mut','核心已手动停止'],off:['mut','已关闭']};function renderWD(){const w=STATE.wd||{};const s=WDS[w.status]||['mut',w.status||'-'];
  $('#wd-status').innerHTML=`<span class="${s[0]}">● ${s[1]}</span>`+(w.last_check?` <span class="mut small">上次检查 ${new Date(w.last_check*1000).toLocaleTimeString('zh-CN',{hour12:false})}</span>`:'');
  $('#wd-events').innerHTML=(w.events||[]).map(e=>`<div class="ev"><span class="mut">${new Date(e.t*1000).toLocaleString('zh-CN',{hour12:false})}</span> ${esc(e.msg)}</div>`).join('')||'<div class="mut small">暂无事件</div>'}

// IP 信息：本地公网 / 代理出口 + 归属地。隐藏时 IP 和归属地都换成假的（本地公网换成别的省市运营商，
// 代理出口只留国家），截图不泄露真实位置；同一浏览器每次显示同一个假地址，不会刷新一下变一个
let IPMASK=localStorage.getItem('ipmask')==='1';
const DECOY_LOC=['中国 广东 深圳 电信','中国 浙江 杭州 移动','中国 上海 联通','中国 江苏 南京 电信','中国 四川 成都 移动',
  '中国 湖北 武汉 联通','中国 北京 电信','中国 福建 厦门 移动','中国 山东 青岛 联通','中国 陕西 西安 电信'];
function decoySeed(){let s=+localStorage.getItem('ipmask-seed');
  if(!s){s=1+Math.floor(Math.random()*2147483646);localStorage.setItem('ipmask-seed',s)}return s}
const CN_A=[36,39,58,60,61,101,106,110,111,112,113,114,115,116,117,118,119,120,121,123,124,180,182,183,222,223];
function decoy(k){const s=(decoySeed()*(k+7)*2654435761>>>0);
  return {ip:[k?1+s%223:CN_A[s%CN_A.length],(s>>>8)%256,(s>>>16)%256,1+(s>>>24)%254].join('.'),loc:DECOY_LOC[s%DECOY_LOC.length]}}
// 有一边没查到（核心刚重启、开机网络未就绪）时，按后端给的 retry 秒数自动重查，只在概览页
let IP_RETRY=null,IP_FAIL=0;
function ipRetry(sec){clearTimeout(IP_RETRY);IP_RETRY=setTimeout(()=>{IP_RETRY=null;if(TAB!=='概览')return;if(document.hidden)ipRetry(sec);else loadIpInfo()},sec*1000)}
async function loadIpInfo(){let j;try{j=await api('/api/ipinfo')}catch(e){IP_FAIL++;ipRetry(Math.min(60,5*2**(IP_FAIL-1)));return}
  IP_FAIL=0;if(j.retry)ipRetry(j.retry);else{clearTimeout(IP_RETRY);IP_RETRY=null}
  const set=(ipEl,locEl,d,k)=>{const el=$(ipEl),f=decoy(k);
    if(!d.ip){el.textContent=j.retry?'查询中…':'-';el.title=j.retry?j.retry+' 秒后自动重试（核心刚启动时可能暂时查不到）':'';$(locEl).textContent=d.loc||'';return}
    if(IPMASK){el.textContent=f.ip;el.title='已隐藏，显示的是假地址';
      $(locEl).textContent=k?((d.loc||'').split(' ')[0]||''):f.loc}
    else{el.textContent=d.ip;el.title='';$(locEl).textContent=d.loc||''}};
  set('#ip-direct','#loc-direct',j.direct||{},0);set('#ip-proxy','#loc-proxy',j.proxy||{},1);
  $('#ipmask-btn').textContent=IPMASK?'显示 IP':'隐藏 IP'}
function toggleIpMask(){IPMASK=!IPMASK;localStorage.setItem('ipmask',IPMASK?'1':'0');loadIpInfo()}
