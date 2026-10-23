// 导航：所有宽度统一用左侧抽屉（点左上角 Shunt 图标打开），不再有横向标签栏 / 手机底部导航
const MQ=matchMedia('(max-width:720px)');  // 手机布局（设置页分栏等用）
let DRAWER_RET=null;
const drawerOpen=()=>$('#drawer').classList.contains('open');
function openDrawer(){const d=$('#drawer'),m=$('#drawer-mask');if(drawerOpen())return;nav();
  DRAWER_RET=document.activeElement;d.removeAttribute('inert');d.setAttribute('aria-hidden','false');m.classList.remove('hide');
  void d.offsetWidth;d.classList.add('open');m.classList.add('on');document.body.classList.add('drawer-on');
  $('#menu-btn').setAttribute('aria-expanded','true');
  (d.querySelector('[aria-current="page"]')||d.querySelector('button')).focus({preventScroll:true})}
function closeDrawer(back){const d=$('#drawer'),m=$('#drawer-mask');if(!drawerOpen())return;
  d.classList.remove('open');m.classList.remove('on');document.body.classList.remove('drawer-on');
  d.setAttribute('aria-hidden','true');d.setAttribute('inert','');$('#menu-btn').setAttribute('aria-expanded','false');
  setTimeout(()=>{if(!drawerOpen())m.classList.add('hide')},220);
  if(back!==false){const r=DRAWER_RET&&DRAWER_RET.isConnected&&DRAWER_RET!==document.body?DRAWER_RET:$('#menu-btn');r.focus({preventScroll:true})}DRAWER_RET=null}
function toggleDrawer(){drawerOpen()?closeDrawer():openDrawer()}
// 抽屉里选中一页：关抽屉、切页，焦点回到左上角菜单按钮（键盘用户能接着再开菜单）
function pickNav(t){closeDrawer(false);go(t);$('#menu-btn').focus({preventScroll:true})}
document.addEventListener('keydown',e=>{if(!drawerOpen())return;
  if(e.key==='Escape'){e.preventDefault();closeDrawer();return}
  if(e.key==='Tab'){const f=[...$('#drawer').querySelectorAll('button,a[href]')].filter(x=>!x.disabled&&x.offsetParent!==null);if(!f.length)return;
    const a=f[0],z=f[f.length-1];if(e.shiftKey&&document.activeElement===a){e.preventDefault();z.focus()}else if(!e.shiftKey&&document.activeElement===z){e.preventDefault();a.focus()}}
  if(e.key==='ArrowDown'||e.key==='ArrowUp'){const f=[...$('#drawer').querySelectorAll('button')],i=f.indexOf(document.activeElement);if(i<0)return;
    e.preventDefault();f[(i+(e.key==='ArrowDown'?1:f.length-1))%f.length].focus()}});
// 地址栏同步当前页（#nodes …，主页不带 hash）：可收藏 / 分享，手机返回键回到上一页
function setHash(t,replace){const h=t===HOME?'':'#'+(TAB_SLUG[t]||encodeURIComponent(t));
  if(location.hash===h||(!h&&!location.hash))return;
  try{history[replace?'replaceState':'pushState'](null,'',h||location.pathname+location.search)}catch(e){if(!replace)location.hash=h}}
addEventListener('hashchange',()=>{closeDrawer(false);const t=tabFromHash(location.hash);if(t!==TAB)go(t,1)});
addEventListener('popstate',()=>{const t=tabFromHash(location.hash);if(t!==TAB)go(t,1)});
function go(t,fromHash){if(!TABS.includes(t))t=HOME;if(TAB==='日志'&&t!=='日志')stopLive();TAB=t;nav();scrollTo({top:0});setHash(t,fromHash);
  ({节点:loadProxies,策略组:loadGroupsPage,订阅:loadSubs,规则:loadRules,DNS:loadDNSPage,广告拦截:loadAB,统计:loadStats,日志:openLogs,设置:renderSettings,概览:renderOverview,连接:loadDevs})[t]?.()}
// Chrome「桌面版网站」：手机按约 980px 宽的电脑布局显示、整体缩得很小（这个模式下浏览器不认 viewport 设置，网页改不了）。
// 认出来后加 dsk 类（顶栏、抽屉再放大一档），并在抽屉底部提示怎么关
const DSK=(()=>{try{const sw=Math.min(screen.width,screen.height);return matchMedia('(hover:none) and (pointer:coarse)').matches&&innerWidth>720&&sw<=540&&innerWidth>=sw*1.5}catch(e){return false}})();
if(DSK){document.documentElement.classList.add('dsk');
  $('#d-foot').innerHTML='手机上显示得很小？可能开了 Chrome「桌面版网站」：点浏览器右上角 ⋮ 取消勾选，即可使用手机布局'}
