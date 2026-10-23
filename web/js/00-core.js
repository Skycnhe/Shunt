const $=s=>document.querySelector(s);
let STATE={},TAB='概览',ACTIVE_RULES=[],timers=[],DEVS={},LIVE={},CONNS=[];
const TABS=['概览','节点','策略组','订阅','规则','DNS','广告拦截','连接','统计','日志','设置'];
const HOME='概览';  // 主页：不在抽屉菜单里列出，点抽屉顶部的 Shunt 图标回来
// 地址栏 #hash ↔ 页面：#nodes 等英文名或中文页名都能直达；#overview / #home / 空 hash / 不认识的都回主页
const TAB_SLUG={节点:'nodes',策略组:'groups',订阅:'subs',规则:'rules',DNS:'dns',广告拦截:'adblock',连接:'conns',统计:'stats',日志:'logs',设置:'settings'};
const SLUG_ALIAS={proxies:'节点',node:'节点',group:'策略组',proxygroups:'策略组',sub:'订阅',subscriptions:'订阅',subscription:'订阅',rule:'规则',
  ad:'广告拦截',ads:'广告拦截',connections:'连接',connection:'连接',conn:'连接',stat:'统计',statistics:'统计',log:'日志',setting:'设置'};
function tabFromHash(h){h=String(h??'').replace(/^#\/?/,'').split(/[?&/]/)[0];try{h=decodeURIComponent(h)}catch(e){}
  const k=h.trim().toLowerCase();if(!k)return HOME;
  if(TABS.includes(h.trim()))return h.trim();
  return Object.keys(TAB_SLUG).find(t=>TAB_SLUG[t]===k)||SLUG_ALIAS[k]||HOME}
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// 内联事件属性里的字符串参数：onclick="f(${jsq(x)})"。不能写成 '${esc(x)}'：属性值里的 &#39; 会先被还原成单引号再交给 JS，
// 节点名带 ' 就能跳出字符串执行代码（订阅里的节点名不可信）；encodeURIComponent 也不转义 ' ( )
const jsq=s=>esc(JSON.stringify(String(s??'')));
const fmt=b=>{b=+b||0;const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(i?(b<10?2:1):0)+' '+u[i]};
const dcls=ms=>ms===undefined?'mut':ms<=0?'bad':ms<300?'ok':ms<800?'warn':'bad';
const dtxt=ms=>ms===undefined?'--':ms<0||ms===0?'超时':ms+' ms';
const cssv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const ago=t=>{if(!t)return '-';const s=Math.floor(Date.now()/1000-t);return s<60?'刚刚':s<3600?Math.floor(s/60)+' 分钟前':s<86400?Math.floor(s/3600)+' 小时前':Math.floor(s/86400)+' 天前'};
const lines=v=>v.split('\n').map(s=>s.trim()).filter(Boolean);
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('show');clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove('show'),t.length>60?7000:3500)}
function toggleTheme(){applySkin(document.documentElement.dataset.theme==='light'?'dark':'light')}
