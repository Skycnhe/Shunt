// 导航两种布局（设置 → 外观 → 界面布局）：抽屉（默认，点左上角 Shunt 图标从左侧滑出菜单）/ 经典（顶栏下横向标签栏，所有宽度都在顶部，放不下换行）。
// 两种布局共用 go() 切页、#hash 同步与返回键；布局按设备保存（localStorage mp_layout），切换立即生效
const MQ=matchMedia('(max-width:720px)');  // 手机布局（设置页分栏等用）
const LAYOUTS=['drawer','classic'];
let LAYOUT=(()=>{try{return localStorage.getItem('mp_layout')==='classic'?'classic':'drawer'}catch(e){return 'drawer'}})();
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
// 左上角 Shunt 图标：抽屉布局开 / 关抽屉，经典布局回概览（标签栏里本来就有各页）
function brandClick(){if(LAYOUT==='classic')go(HOME);else toggleDrawer()}
// 经典布局：标签栏点选后 nav() 会重画标签，焦点落回新的当前页标签（不然键盘焦点掉到 body）
function pickTab(t){const a=document.activeElement,inBar=!!(a&&$('#tabbar').contains?.(a));go(t);
  if(inBar){const b=$('#tabbar').querySelector('[aria-current="page"]');(b||$('#menu-btn'))?.focus({preventScroll:true})}}
// 左上角按钮的无障碍属性跟随布局：抽屉布局是「打开菜单」的弹窗按钮，经典布局是普通的回主页按钮
function layoutAttrs(){const b=$('#menu-btn'),cl=LAYOUT==='classic';document.documentElement.dataset.layout=LAYOUT;
  if(cl){['aria-controls','aria-expanded','aria-haspopup'].forEach(k=>b.removeAttribute(k));b.setAttribute('title','回到概览')}
  else{b.setAttribute('aria-controls','drawer');b.setAttribute('aria-expanded',String(drawerOpen()));b.setAttribute('aria-haspopup','dialog');b.setAttribute('title','打开菜单')}}
function renderLayoutOpt(){document.querySelectorAll('#ly-opts [data-ly]').forEach(b=>{const on=b.dataset.ly===LAYOUT;
  b.classList.toggle('on',on);b.setAttribute('aria-checked',String(on));b.tabIndex=on?0:-1})}
// 切换布局：先关掉打开着的抽屉；焦点原来在导航里的（即将隐藏）落到左上角按钮，在设置页选项上的留在选中项
function setLayout(l,save){l=LAYOUTS.includes(l)?l:'drawer';
  if(save!==false)try{localStorage.setItem('mp_layout',l)}catch(e){}
  const a=document.activeElement,inNav=!!a&&['#drawer','#tabbar'].some(s=>$(s)?.contains?.(a));
  closeDrawer(false);
  LAYOUT=l;layoutAttrs();nav();renderLayoutOpt();
  if(inNav)$('#menu-btn').focus({preventScroll:true});
  else if(a&&a.dataset&&a.dataset.ly){const b=document.querySelector(`#ly-opts [data-ly="${l}"]`);b?.focus({preventScroll:true})}}
// 别的标签页改了布局（同一浏览器同一设备）：跟着切换
addEventListener('storage',e=>{if(e.key==='mp_layout'){const l=e.newValue==='classic'?'classic':'drawer';if(l!==LAYOUT)setLayout(l,false)}});
// 设置页单选组：左右 / 上下方向键切换
document.addEventListener('keydown',e=>{const b=e.target&&e.target.closest?.('#ly-opts [data-ly]');if(!b)return;
  if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)){e.preventDefault();setLayout(b.dataset.ly==='classic'?'drawer':'classic')}});
// 打开的抽屉里：Esc 关闭，Tab 在里面循环
function trapTab(e,box){const f=[...box.querySelectorAll('button,a[href]')].filter(x=>!x.disabled&&x.offsetParent!==null);if(!f.length)return;
  const a=f[0],z=f[f.length-1];if(e.shiftKey&&document.activeElement===a){e.preventDefault();z.focus()}else if(!e.shiftKey&&document.activeElement===z){e.preventDefault();a.focus()}}
document.addEventListener('keydown',e=>{
  if(!drawerOpen())return;
  if(e.key==='Escape'){e.preventDefault();closeDrawer();return}
  if(e.key==='Tab')trapTab(e,$('#drawer'));
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
layoutAttrs();
