// ===== 外观：主题 + 背景图 =====
const SKINS=[['dark','默认深色','#0a0c13','#0a84ff','#5e5ce6',0],['light','默认浅色','#eef0f7','#007aff','#5856d6',1],
  ['cyber','赛博朋克','#0b0418','#ff2bd6','#00e5ff',0],['aurora','极光','#050f14','#2ee6a6','#7b61ff',0],['ocean','深海','#03101f','#22b8ff','#1f6bff',0],
  ['sunset','落日','#170812','#ff7a45','#ff3d81',0],['matrix','黑客帝国','#000a03','#00ff66','#00b347',0],['gold','黑金','#0c0a07','#e6b85c','#b8862e',0],
  ['sakura','樱花','#fbf0f4','#e8508a','#b45cd6',1],['mint','薄荷','#ecf8f4','#0fa47a','#2b8ad8',1]];
function curSkin(){const d=document.documentElement;return d.dataset.skin||d.dataset.theme||'dark'}
function applySkin(k){const d=document.documentElement,sk=SKINS.find(x=>x[0]===k)||SKINS[0];
  d.dataset.theme=sk[5]?'light':'dark';if(k==='dark'||k==='light'){delete d.dataset.skin;localStorage.setItem('mp_theme',k)}else d.dataset.skin=k;
  localStorage.setItem('mp_skin',k);const m=document.querySelector('meta[name=theme-color]');if(m)m.content=sk[3];
  renderSkins();try{drawChart();if(TAB==='统计')drawDays()}catch(e){}}
function renderSkins(){const el=$('#skins');if(!el)return;const c=curSkin();
  el.innerHTML=SKINS.map(([k,n,bg,a,b,l])=>`<button class="skin ${c===k?'on':''}" onclick="applySkin('${k}')"><div class="pv" style="background:radial-gradient(60px 50px at 20% 10%,${a}66,transparent),radial-gradient(70px 60px at 90% 90%,${b}66,transparent),${bg}">
    <b style="background:linear-gradient(135deg,${a},${b})"></b><i style="background:${l?'rgba(255,255,255,.7)':'rgba(255,255,255,.08)'}"></i></div><span class="nm">${n}</span></button>`).join('')}
let BG=(()=>{try{return Object.assign({src:'',blur:6,dim:45},JSON.parse(localStorage.getItem('mp_bg')||'{}'))}catch{return {src:'',blur:6,dim:45}}})();
// 路由器上的图（链接下载 / 每日壁纸）不经过上传时的压缩，可能是 4K 以上的原图：整张解码后再加模糊、铺满固定层，
// iOS Safari 等会超出图层 / 内存上限，只画出一部分。显示前在本机缩到最长边 2560px（只处理同源 /bg，外链图会污染画布）
const BG_MAXPX=2560;let BGFIT={src:'',url:''};
function bgFit(src,cb){if(!src||!src.startsWith('/bg')||typeof document.createElement!=='function'){cb(src);return}
  if(BGFIT.src===src){cb(BGFIT.url||src);return}
  const img=new Image();img.onload=()=>{const w=img.naturalWidth,h=img.naturalHeight,m=Math.max(w,h);
      if(!m||m<=BG_MAXPX){BGFIT={src,url:''};cb(src);return}
      try{const s=BG_MAXPX/m,c=document.createElement('canvas');c.width=Math.round(w*s);c.height=Math.round(h*s);
        c.getContext('2d').drawImage(img,0,0,c.width,c.height);
        c.toBlob(b=>{if(!b){cb(src);return}if(BGFIT.url)URL.revokeObjectURL(BGFIT.url);BGFIT={src,url:URL.createObjectURL(b)};cb(BGFIT.url)},'image/jpeg',.9)}
      catch(e){cb(src)}};
  img.onerror=()=>cb(src);img.src=src}
function bgApply(){const d=document.documentElement,on=!!BG.src;d.classList.toggle('has-bg',on);
  const im=$('#bgimg'),dm=$('#bgdim');if(!im)return;
  im.style.filter=BG.blur?`blur(${BG.blur}px)`:'';dm.style.opacity=(BG.dim/100).toFixed(2);
  const pv=$('#bg-pv');if(pv)pv.textContent=on?'':'未设置';
  if(!on){im.style.backgroundImage='';if(pv)pv.style.backgroundImage=''}
  else{const want=BG.src;bgFit(want,u=>{if(BG.src!==want)return;const css=`url("${u.replace(/"/g,'%22')}")`;
    im.style.backgroundImage=css;const p2=$('#bg-pv');if(p2)p2.style.backgroundImage=css})}
  if($('#bg-blur')){$('#bg-blur').value=BG.blur;$('#bg-dim').value=BG.dim;$('#bg-blur-v').textContent=BG.blur+'px';$('#bg-dim-v').textContent=BG.dim+'%'}}
function bgSave(){localStorage.setItem('mp_bg',JSON.stringify(BG));bgApply()}
function bgSet(){BG.blur=+$('#bg-blur').value;BG.dim=+$('#bg-dim').value;bgSave()}
// 上传前在浏览器里压缩到最长边 2560px 的 JPEG，手机原图也只有几百 KB
function bgUpload(inp){const f=inp.files&&inp.files[0];inp.value='';if(!f)return;
  const rd=new FileReader();rd.onload=()=>{const img=new Image();img.onload=async()=>{
      let data=rd.result;if(f.type!=='image/gif'){const s=Math.min(1,2560/Math.max(img.width,img.height)),c=document.createElement('canvas');
        c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);c.getContext('2d').drawImage(img,0,0,c.width,c.height);data=c.toDataURL('image/jpeg',.86)}
      try{const r=await api('/api/bg','POST',{data});BG.src='/bg?v='+r.v;bgSave();toast('背景图已更新')}catch(e){toast(e.message)}};
    img.onerror=()=>toast('无法读取这张图片');img.src=rd.result};rd.readAsDataURL(f)}
// 图片链接由路由器下载保存（所有设备共用、无防盗链问题）；路由器下载失败时退回由当前浏览器直接加载
let BGM={url:'',daily:false};
function bgMeta(r){BGM={url:r&&r.exists&&r.url||'',daily:!!(r&&r.daily)};const row=$('#bg-daily-row');if(!row)return;
  row.classList.toggle('hide',!BGM.url);$('#bg-daily').checked=BGM.daily;$('#bg-url-d').textContent=BGM.url?'路由器每天重新下载一次这个链接（适合必应每日壁纸）：'+BGM.url:''}
async function bgUrl(){const u=prompt('图片链接（https://…）',BGM.url||(/^https?:/.test(BG.src)?BG.src:''));if(u===null)return;const url=u.trim();
  if(!/^https?:\/\/\S+$/.test(url)){toast('请输入 http(s) 开头的图片链接');return}
  toast('路由器正在下载图片…');
  try{const r=await api('/api/bg/url','POST',{url,daily:BGM.daily||/bing|daily|每日/i.test(url)});BG.src='/bg?v='+r.v;bgSave();toast(r.message);bgSync()}
  catch(e){BG.src=url;bgSave();bgMeta(null);toast(e.message+'，改为由当前浏览器直接加载（仅本机有效）')}}
async function bgDaily(on){try{const r=await api('/api/bg/daily','POST',{daily:on});BGM.daily=on;toast(r.message)}catch(e){toast(e.message);$('#bg-daily').checked=!on}}
async function bgClear(){if(BG.src.startsWith('/bg'))try{await api('/api/bg','DELETE')}catch(e){}BG.src='';bgSave();bgMeta(null);toast('已移除背景图')}
// 路由器上的图可能已被每日更新替换：用新的修改时间刷新地址，避免浏览器一直显示缓存的旧图
async function bgSync(){if(BG.src&&!BG.src.startsWith('/bg'))return;
  try{const r=await api('/api/bg');bgMeta(r);const s=r.exists?'/bg?v='+r.v:'';if(s!==BG.src){BG.src=s;bgSave()}}catch(e){}}
async function renderLook(){renderSkins();renderLayoutOpt();bgApply();bgSync()}
bgApply();

async function api(path,method='GET',body){
  const r=await fetch(path,{method,headers:{'X-Shunt':'1','Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const t=await r.text();let j;try{j=t?JSON.parse(t):{}}catch{j={message:r.ok?t:t.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim().slice(0,200)}}  // 出错时反代 / 网关返回的 HTML 错误页：去标签截断，不把整页塞进提示
  if(!r.ok)throw new Error(j.message||('HTTP '+r.status));return j}
const core=(p,m,b)=>api('/api/core'+p,m,b);

// 导航有两种布局（设置 → 外观 → 界面布局，按设备保存在 localStorage mp_layout）：
// 抽屉（默认）：概览是主页（抽屉顶部的 Shunt 图标回主页），其余页面列在左侧抽屉里；
// 经典：顶栏下方横向标签栏（含概览，所有宽度都在顶部；放不下时换行，不用底部栏 /「更多」）
const NAV_ICO={"概览": "<path d=\"M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z\"/>",
  "节点": "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M3 12h18M12 3c2.8 3.2 2.8 14.8 0 18M12 3c-2.8 3.2-2.8 14.8 0 18\"/>",
  "策略组": "<rect x=\"3\" y=\"4\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"4\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><path d=\"M17.5 14v7M14 17.5h7\"/>",
  "订阅": "<path d=\"M5 5a14 14 0 0 1 14 14M5 11a8 8 0 0 1 8 8\"/><circle cx=\"6\" cy=\"18\" r=\"1.6\"/>",
  "规则": "<path d=\"M9 6h11M9 12h11M9 18h11\"/><path d=\"M4 6h.01M4 12h.01M4 18h.01\"/>",
  "DNS": "<rect x=\"3\" y=\"4\" width=\"18\" height=\"7\" rx=\"2\"/><rect x=\"3\" y=\"13\" width=\"18\" height=\"7\" rx=\"2\"/><path d=\"M7 7.5h.01M7 16.5h.01\"/>",
  "广告拦截": "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.6 5.6l12.8 12.8\"/>",
  "连接": "<path d=\"M7 7h11l-3-3M17 17H6l3 3\"/>",
  "统计": "<path d=\"M4 20V10M10 20V4M16 20v-7M22 20H2\"/>",
  "日志": "<path d=\"M6 3h9l4 4v14H6z\"/><path d=\"M9 11h7M9 15h7\"/>",
  "设置": "<circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z\"/>"};
const svgI=t=>`<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${NAV_ICO[t]||''}</svg>`;
// 切页 / 换布局后重画：抽屉里的页面列表或经典标签栏（当前页高亮）、顶栏 Shunt 旁的当前页名、只显示当前页的 section
function nav(){const home=TAB===HOME,cl=LAYOUT==='classic',tb=$('#tabbar');
  if(cl)tb.innerHTML=TABS.map(t=>`<button type="button"${t===TAB?' class="on" aria-current="page"':''} onclick="pickTab(${jsq(t)})">${esc(t)}</button>`).join('');
  else if(tb.innerHTML)tb.innerHTML='';
  $('#nav').innerHTML=TABS.filter(t=>t!==HOME).map(t=>`<button type="button" class="${t===TAB?'on':''}"${t===TAB?' aria-current="page"':''} onclick="pickNav(${jsq(t)})">${svgI(t)}<span>${esc(t)}</span></button>`).join('');
  $('#d-home').classList.toggle('on',home);if(home)$('#d-home').setAttribute('aria-current','page');else $('#d-home').removeAttribute('aria-current');
  const pg=$('#h-page');pg.textContent=home||cl?'':TAB;pg.classList.toggle('hide',home||cl);
  $('#menu-btn').setAttribute('aria-label',cl?'Shunt，回到概览':(home?'Shunt 主页':'Shunt · '+TAB)+'，打开菜单');
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('hide',s.dataset.tab!==TAB))}
