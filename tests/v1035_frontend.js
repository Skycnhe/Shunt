// v10.3.5 回归测试用（tests/test_v1035.py 调用）：在 node 里用最小 DOM 桩跑 00-core.js、02-layout.js 和 01-theme.js 的 nav()，
// 验证抽屉导航（开关、aria-expanded、焦点、Esc、选中后关闭、当前页高亮、菜单里没有「概览」）与 #hash 切页
const fs=require('fs'),vm=require('vm');
const root=process.argv[2];
const src=f=>fs.readFileSync(root+'/web/js/'+f,'utf8');
class El{constructor(id,tag){this.id=id;this.tagName=(tag||'div').toUpperCase();this.attrs={};this.cls=new Set();this.textContent='';this._html='';this.children=[];this.dataset={};this.isConnected=true;this.offsetParent={};this.disabled=false;
  const s=this.cls;this.classList={add:(...c)=>c.forEach(x=>s.add(x)),remove:(...c)=>c.forEach(x=>s.delete(x)),contains:c=>s.has(c),toggle:(c,f)=>{const on=f===undefined?!s.has(c):!!f;on?s.add(c):s.delete(c);return on}}}
  setAttribute(k,v){this.attrs[k]=String(v)}getAttribute(k){return k in this.attrs?this.attrs[k]:null}removeAttribute(k){delete this.attrs[k]}hasAttribute(k){return k in this.attrs}
  focus(){ctx.document.activeElement=this}get offsetWidth(){return 1}appendChild(c){c.parentNode=this}contains(x){return false}
  set innerHTML(h){this._html=h;this.children=[...h.matchAll(/<button([^>]*)>([\s\S]*?)<\/button>/g)].map(m=>{const b=new El('','button');
    const c=/class="([^"]*)"/.exec(m[1]);if(c)c[1].split(/\s+/).filter(Boolean).forEach(x=>b.cls.add(x));if(/aria-current="page"/.test(m[1]))b.attrs['aria-current']='page';
    b.textContent=m[2].replace(/<[^>]+>/g,'');b.onclickSrc=(/onclick="([^"]*)"/.exec(m[1])||[])[1];return b})}
  get innerHTML(){return this._html}
  querySelectorAll(sel){const all=[...(this===E.drawer?[E['d-home'],...E.nav.children]:this.children)];
    if(sel==='[aria-current="page"]')return all.filter(b=>b.attrs['aria-current']==='page');return all}
  querySelector(sel){return this.querySelectorAll(sel)[0]||null}}
const E={};['drawer','drawer-mask','menu-btn','d-home','nav','h-page','d-foot','tabbar','more-sheet','more-list','header'].forEach(i=>E[i]=new El(i,i==='drawer'?'aside':i==='nav'?'nav':'button'));
E['drawer-mask'].cls.add('hide');E['more-sheet'].cls.add('hide');E.tabbar.parentNode=E.header;E.drawer.attrs['aria-hidden']='true';E.drawer.attrs.inert='';E['menu-btn'].attrs['aria-expanded']='false';
const sections=['概览','节点','策略组','订阅','规则','DNS','广告拦截','连接','统计','日志','设置'].map(t=>{const s=new El('','section');s.dataset.tab=t;return s});
const listeners={},docListeners={};const loaded=[];let pushes=[];
const loc={hash:'',pathname:'/',search:''};
const ctx={console,setTimeout:(f)=>f(),clearTimeout(){},
  document:{activeElement:null,body:new El('body','body'),querySelectorAll:s=>s==='section'?sections:[],addEventListener:(k,f)=>{docListeners[k]=f},documentElement:new El('html','html')},
  addEventListener:(k,f)=>{listeners[k]=f},location:loc,
  history:{pushState:(a,b,u)=>{pushes.push(u);loc.hash=u.startsWith('#')?u:''},replaceState:(a,b,u)=>{pushes.push('R'+u);loc.hash=u.startsWith('#')?u:''}},
  matchMedia:()=>({matches:false,addEventListener(){}}),screen:{width:412,height:915},innerWidth:390,scrollTo(){},
  localStorage:{getItem:()=>null,setItem(){}}};
ctx.$=s=>(s[0]==='#'?E[s.slice(1)]:E[s])||null;ctx.window=ctx;
vm.createContext(ctx);
const theme=src('01-theme.js');const navFn=theme.slice(theme.indexOf('// 导航有两种布局'),theme.indexOf("document.querySelectorAll('section').forEach(s=>s.classList.toggle('hide',s.dataset.tab!==TAB))}")+"document.querySelectorAll('section').forEach(s=>s.classList.toggle('hide',s.dataset.tab!==TAB))}".length);
const core=src('00-core.js').replace(/^const \$=.*$/m,'');
vm.runInContext(core+'\n'+navFn+'\n'+src('02-layout.js')+`
var stopLive=()=>{};${['loadProxies','loadGroupsPage','loadSubs','loadRules','loadDNSPage','loadAB','loadStats','openLogs','renderSettings','renderOverview','loadDevs'].map(f=>`var ${f}=()=>LOADED.push('${f}');`).join('')}
this.R={go,openDrawer,closeDrawer,toggleDrawer,pickNav,tabFromHash,drawerOpen,getTab:()=>TAB,DSK};`,Object.assign(ctx,{LOADED:loaded}));
const R=ctx.R,out={};
out.hash=Object.fromEntries(['','#','#overview','#home','#nodes','#/nodes','#proxies','#groups','#subs','#rules','#dns','#adblock','#conns','#connections','#stats','#logs','#settings',
  '#'+encodeURIComponent('策略组'),'#'+encodeURIComponent('广告拦截'),'#NODES','#bogus','#%E0%A4%A'].map(h=>[h,R.tabFromHash(h)]));
R.go('概览',1);out.home={items:E.nav.children.map(b=>b.textContent),page:E['h-page'].textContent,pageHidden:E['h-page'].cls.has('hide'),homeCur:E['d-home'].attrs['aria-current'],
  label:E['menu-btn'].attrs['aria-label'],visible:sections.filter(s=>!s.cls.has('hide')).map(s=>s.dataset.tab),pushes:pushes.slice()};
ctx.document.activeElement=E['menu-btn'];
R.openDrawer();out.open={open:R.drawerOpen(),exp:E['menu-btn'].attrs['aria-expanded'],hidden:E.drawer.attrs['aria-hidden'],inert:'inert' in E.drawer.attrs,mask:!E['drawer-mask'].cls.has('hide'),
  focus:ctx.document.activeElement===E['d-home'],bodyLock:ctx.document.body.cls.has('drawer-on')};
docListeners.keydown({key:'Escape',preventDefault(){}});
out.esc={open:R.drawerOpen(),exp:E['menu-btn'].attrs['aria-expanded'],hidden:E.drawer.attrs['aria-hidden'],inert:'inert' in E.drawer.attrs,mask:E['drawer-mask'].cls.has('hide'),focus:ctx.document.activeElement===E['menu-btn']};
pushes=[];R.openDrawer();R.pickNav('节点');
out.pick={open:R.drawerOpen(),tab:R.getTab(),hash:loc.hash,pushes:pushes.slice(),loaded:loaded.slice(-1)[0],page:E['h-page'].textContent,cur:E.nav.children.filter(b=>b.attrs['aria-current']==='page').map(b=>b.textContent),
  on:E.nav.children.filter(b=>b.cls.has('on')).map(b=>b.textContent),homeCur:E['d-home'].attrs['aria-current']||null,visible:sections.filter(s=>!s.cls.has('hide')).map(s=>s.dataset.tab),focus:ctx.document.activeElement===E['menu-btn']};
R.openDrawer();out.focusCurrent=ctx.document.activeElement.textContent;R.toggleDrawer();out.toggled=R.drawerOpen();
loc.hash='#logs';listeners.hashchange();out.hashchange={tab:R.getTab(),loaded:loaded.slice(-1)[0]};
loc.hash='#overview';listeners.popstate();out.popHome={tab:R.getTab(),loaded:loaded.slice(-1)[0]};
pushes=[];R.go('节点');R.go('节点');out.dupPush=pushes;
pushes=[];R.go('不存在的页');out.unknown={tab:R.getTab(),pushes};
out.DSK=R.DSK;out.tabbar=E.tabbar.innerHTML;
process.stdout.write(JSON.stringify(out));
