const $=s=>document.querySelector(s);
let STATE={},TAB='概览',ACTIVE_RULES=[],timers=[],DEVS={},LIVE={},CONNS=[];
const TABS=['概览','节点','策略组','订阅','规则','DNS','广告拦截','WARP','连接','统计','日志','设置'];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=b=>{b=+b||0;const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(i?(b<10?2:1):0)+' '+u[i]};
const dcls=ms=>ms===undefined?'mut':ms<=0?'bad':ms<300?'ok':ms<800?'warn':'bad';
const dtxt=ms=>ms===undefined?'--':ms<0||ms===0?'超时':ms+' ms';
const cssv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const ago=t=>{if(!t)return '-';const s=Math.floor(Date.now()/1000-t);return s<60?'刚刚':s<3600?Math.floor(s/60)+' 分钟前':s<86400?Math.floor(s/3600)+' 小时前':Math.floor(s/86400)+' 天前'};
const lines=v=>v.split('\n').map(s=>s.trim()).filter(Boolean);
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('show');clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove('show'),t.length>60?7000:3500)}
function toggleTheme(){applySkin(document.documentElement.dataset.theme==='light'?'dark':'light')}
