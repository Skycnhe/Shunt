// 界面布局回归测试用（tests/test_v1038.py、tests/test_v1039.py 调用）：在 node 里用最小 DOM 桩跑 00-core.js、01-theme.js 的 nav() 和 02-layout.js，
// 验证：默认抽屉、localStorage mp_layout 持久化、经典布局有横向标签栏且含全部页面（含「概览」）、抽屉布局无标签栏、
// 两种布局即时切换（关闭抽屉、焦点、左上角按钮属性）、v10.3.9 起手机上经典布局也是顶部标签栏（无底部栏 /「更多」）、共用 go() 与 #hash
const fs=require('fs'),vm=require('vm');
const root=process.argv[2];
const src=f=>fs.readFileSync(root+'/web/js/'+f,'utf8');
const TABS=['概览','节点','策略组','订阅','规则','DNS','广告拦截','连接','统计','日志','设置'];
function make(store,mobile){
  const ctx={};
  class El{constructor(id,tag){this.id=id;this.tagName=(tag||'div').toUpperCase();this.attrs={};this.cls=new Set();this.textContent='';this._html='';this.children=[];this.dataset={};this.isConnected=true;this.offsetParent={};this.disabled=false;this.parentNode=null;
    const s=this.cls;this.classList={add:(...c)=>c.forEach(x=>s.add(x)),remove:(...c)=>c.forEach(x=>s.delete(x)),contains:c=>s.has(c),toggle:(c,f)=>{const on=f===undefined?!s.has(c):!!f;on?s.add(c):s.delete(c);return on}}}
    setAttribute(k,v){this.attrs[k]=String(v)}getAttribute(k){return k in this.attrs?this.attrs[k]:null}removeAttribute(k){delete this.attrs[k]}hasAttribute(k){return k in this.attrs}
    focus(){ctx.document.activeElement=this}get offsetWidth(){return 1}appendChild(c){c.parentNode=this}
    set innerHTML(h){this._html=h;this.children=[...h.matchAll(/<button([^>]*)>([\s\S]*?)<\/button>/g)].map(m=>{const b=new El((/id="([^"]*)"/.exec(m[1])||[])[1]||'','button');b.parentNode=this;
      const c=/class="([^"]*)"/.exec(m[1]);if(c)c[1].split(/\s+/).filter(Boolean).forEach(x=>b.cls.add(x));if(/aria-current="page"/.test(m[1]))b.attrs['aria-current']='page';
      const ex=/aria-expanded="([^"]*)"/.exec(m[1]);if(ex)b.attrs['aria-expanded']=ex[1];
      b.textContent=m[2].replace(/<[^>]+>/g,'');b.onclickSrc=(/onclick="([^"]*)"/.exec(m[1])||[])[1];return b})}
    get innerHTML(){return this._html}
    kids(){return this===E.drawer?[E['d-home'],...E.nav.children]:this===E['more-sheet']?E['more-list'].children:this.children}
    contains(x){return x===this||this.kids().includes(x)}
    querySelectorAll(sel){const all=[...this.kids()];if(sel==='[aria-current="page"]')return all.filter(b=>b.attrs['aria-current']==='page');return all}
    querySelector(sel){return this.querySelectorAll(sel)[0]||null}}
  const E={};['drawer','drawer-mask','menu-btn','d-home','nav','h-page','d-foot','tabbar','more-sheet','more-list','header'].forEach(i=>E[i]=new El(i,i==='drawer'?'aside':i==='nav'||i==='tabbar'?'nav':i==='header'?'header':'button'));
  E['drawer-mask'].cls.add('hide');E['more-sheet'].cls.add('hide');E.drawer.attrs['aria-hidden']='true';E.drawer.attrs.inert='';
  Object.assign(E['menu-btn'].attrs,{'aria-expanded':'false','aria-controls':'drawer','aria-haspopup':'dialog'});E.tabbar.parentNode=E.header;
  const lyBtns=['classic','drawer'].map(l=>{const b=new El('','button');b.dataset.ly=l;return b});
  const sections=TABS.map(t=>{const s=new El('','section');s.dataset.tab=t;return s});
  const listeners={},docListeners={keydown:[]},loaded=[],sets=[];let mqCb=null;
  const loc={hash:'',pathname:'/',search:''};
  const html=new El('html','html');const body=new El('body','body');
  Object.assign(ctx,{console,setTimeout:(f)=>f(),clearTimeout(){},
    document:{activeElement:body,body,documentElement:html,
      querySelectorAll:s=>s==='section'?sections:s==='#ly-opts [data-ly]'?lyBtns:[],
      querySelector:s=>{const m=/data-ly="(\w+)"/.exec(s);return m?lyBtns.find(b=>b.dataset.ly===m[1]):null},
      addEventListener:(k,f)=>{(docListeners[k]=docListeners[k]||[]).push(f)}},
    addEventListener:(k,f)=>{listeners[k]=f},location:loc,
    history:{pushState:(a,b,u)=>{loc.hash=u.startsWith('#')?u:''},replaceState:(a,b,u)=>{loc.hash=u.startsWith('#')?u:''}},
    matchMedia:q=>q.includes('max-width:720px')?{get matches(){return mobile.on},addEventListener:(k,f)=>{mqCb=f}}:{matches:false,addEventListener(){}},
    screen:{width:412,height:915},innerWidth:390,scrollTo(){},
    localStorage:{getItem:k=>k in store?store[k]:null,setItem:(k,v)=>{store[k]=String(v);sets.push(k+'='+v)}},LOADED:loaded});
  ctx.$=s=>(s[0]==='#'?E[s.slice(1)]||E.tabbar.children.find(b=>b.id===s.slice(1)):E[s])||null;  // #more-btn 是 nav() 生成在标签栏里的ctx.window=ctx;
  vm.createContext(ctx);
  const theme=src('01-theme.js');const end="document.querySelectorAll('section').forEach(s=>s.classList.toggle('hide',s.dataset.tab!==TAB))}";
  const navFn=theme.slice(theme.indexOf('// 导航有两种布局'),theme.indexOf(end)+end.length);
  const core=src('00-core.js').replace(/^const \$=.*$/m,'');
  vm.runInContext(core+'\n'+navFn+'\n'+src('02-layout.js')+`
var stopLive=()=>{};${['loadProxies','loadGroupsPage','loadSubs','loadRules','loadDNSPage','loadAB','loadStats','openLogs','renderSettings','renderOverview','loadDevs'].map(f=>`var ${f}=()=>LOADED.push('${f}');`).join('')}
this.R={go,openDrawer,closeDrawer,drawerOpen,setLayout,brandClick,pickTab,getTab:()=>TAB,getLayout:()=>LAYOUT,has:n=>{try{return typeof eval(n)==='function'}catch(e){return false}}};`,ctx);
  const key=k=>docListeners.keydown.forEach(f=>f({key:k,preventDefault(){},target:ctx.document.activeElement}));
  const snap=()=>({layout:ctx.R.getLayout(),attr:html.dataset.layout,tab:ctx.R.getTab(),
    tabs:E.tabbar.children.map(b=>b.textContent),tabCur:E.tabbar.children.filter(b=>b.attrs['aria-current']==='page').map(b=>b.textContent),
    tabOn:E.tabbar.children.filter(b=>b.cls.has('on')).map(b=>b.textContent),np:E.tabbar.children.filter(b=>b.cls.has('np')).map(b=>b.textContent),
    drawerItems:E.nav.children.map(b=>b.textContent),drawerOpen:ctx.R.drawerOpen(),moreBtn:E.tabbar.children.some(b=>b.id==='more-btn'||b.cls.has('more')),icons:/<svg/.test(E.tabbar.innerHTML),
    btn:{exp:E['menu-btn'].getAttribute('aria-expanded'),ctl:E['menu-btn'].getAttribute('aria-controls'),pop:E['menu-btn'].getAttribute('aria-haspopup'),label:E['menu-btn'].getAttribute('aria-label'),title:E['menu-btn'].getAttribute('title')},
    page:E['h-page'].textContent,pageHidden:E['h-page'].cls.has('hide'),bottom:E.tabbar.cls.has('bottom'),inBody:E.tabbar.parentNode===body,hasbn:body.cls.has('hasbn'),
    focus:ctx.document.activeElement===E['menu-btn']?'menu-btn':ctx.document.activeElement.dataset&&ctx.document.activeElement.dataset.ly?'ly:'+ctx.document.activeElement.dataset.ly:(ctx.document.activeElement.textContent||ctx.document.activeElement.id),
    opts:lyBtns.map(b=>b.dataset.ly+':'+b.getAttribute('aria-checked')),visible:sections.filter(s=>!s.cls.has('hide')).map(s=>s.dataset.tab),hash:loc.hash,store:store.mp_layout??null,loaded:loaded.slice(-1)[0]||null});
  return {ctx,R:ctx.R,E,store,sets,listeners,key,snap,lyBtns,mq:()=>mqCb&&mqCb(),body};
}
const out={};
// 1. 没有保存过：默认抽屉，无标签栏
{const m=make({},{on:false});m.R.go('概览',1);out.fresh=m.snap();m.R.go('节点');out.freshNodes=m.snap()}
// 2. 不认识的值也按抽屉
{const m=make({mp_layout:'foo'},{on:false});m.R.go('概览',1);out.bogus=m.snap()}
// 3. 保存过经典（电脑宽度）：横向标签栏含概览、当前页高亮；Shunt 图标回概览；标签栏点选
{const m=make({mp_layout:'classic'},{on:false});m.R.go('概览',1);out.classic=m.snap();
  m.R.go('节点');out.classicNodes=m.snap();
  m.R.brandClick();out.classicBrand=m.snap();
  m.ctx.document.activeElement=m.E.tabbar.children[2];m.R.pickTab('策略组');out.pickTab=m.snap();
  m.ctx.location.hash='#logs';m.listeners.hashchange();out.classicHash=m.snap();
  // 4. 经典 → 抽屉（设置页单选按钮上切换）：标签栏清空，左上角恢复菜单按钮属性，焦点留在选中项
  m.ctx.document.activeElement=m.lyBtns[1];m.R.setLayout('drawer');out.toDrawer=m.snap();out.toDrawerSets=m.sets.slice();
  // 5. 抽屉开着时切回经典：抽屉关闭、焦点落到左上角按钮
  m.R.openDrawer();out.drawerOpened=m.R.drawerOpen();m.R.setLayout('classic');out.toClassicFromOpenDrawer=m.snap();
  // 6. 另一个标签页改了布局（storage 事件）：跟着切换，不重复写 localStorage
  const n=m.sets.length;m.store.mp_layout='drawer';m.listeners.storage({key:'mp_layout',newValue:'drawer'});out.storageEvt=m.snap();out.storageEvtWrites=m.sets.length-n}
// 7. 经典布局 + 手机宽度（v10.3.9）：标签栏仍在顶栏里（不移到 body 底部），含全部页面，没有「更多」；切页 / 切换布局 / 窗口宽度变化都不会生成底部栏
{const mob={on:true};const m=make({mp_layout:'classic'},mob);m.R.go('概览',1);out.mobile=m.snap();
  m.ctx.document.activeElement=m.E.tabbar.children[9];m.R.pickTab('日志');out.mobilePick=m.snap();
  m.R.setLayout('drawer');out.mobileToDrawer=m.snap();m.R.setLayout('classic');out.mobileBack=m.snap();
  mob.on=false;m.mq();out.mqDesktop=m.snap();mob.on=true;m.mq();out.mqMobile=m.snap();
  m.key('Escape');out.mobileEsc=m.snap();
  out.gone=['openMore','closeMore','pickMore','moreOpen','placeNav'].filter(n=>m.R.has(n));out.probe=m.R.has('go')&&m.R.has('pickTab')}
// 8. 刷新（新上下文读 localStorage）后保持上次的选择
{const store={};const a=make(store,{on:false});a.R.setLayout('classic');const b=make(store,{on:false});b.R.go('概览',1);out.persistClassic=b.snap();
  b.R.setLayout('drawer');const c=make(store,{on:false});c.R.go('概览',1);out.persistDrawer=c.snap()}
process.stdout.write(JSON.stringify(out));
