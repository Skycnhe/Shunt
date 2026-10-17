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
function bgApply(){const d=document.documentElement,on=!!BG.src;d.classList.toggle('has-bg',on);
  const im=$('#bgimg'),dm=$('#bgdim');if(!im)return;
  im.style.backgroundImage=on?`url("${BG.src.replace(/"/g,'%22')}")`:'';im.style.filter=BG.blur?`blur(${BG.blur}px)`:'';dm.style.opacity=(BG.dim/100).toFixed(2);
  const pv=$('#bg-pv');if(pv){pv.style.backgroundImage=on?`url("${BG.src.replace(/"/g,'%22')}")`:'';pv.textContent=on?'':'未设置'}
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
async function renderLook(){renderSkins();bgApply();bgSync()}
bgApply();

async function api(path,method='GET',body){
  const r=await fetch(path,{method,headers:{'X-Shunt':'1','Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const t=await r.text();let j;try{j=t?JSON.parse(t):{}}catch{j={message:r.ok?t:t.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim().slice(0,200)}}  // 出错时反代 / 网关返回的 HTML 错误页：去标签截断，不把整页塞进提示
  if(!r.ok)throw new Error(j.message||('HTTP '+r.status));return j}
const core=(p,m,b)=>api('/api/core'+p,m,b);

const NAV_ICO={"概览": "<path d=\"M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z\"/>", "节点": "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M3 12h18M12 3c2.8 3.2 2.8 14.8 0 18M12 3c-2.8 3.2-2.8 14.8 0 18\"/>", "连接": "<path d=\"M7 7h11l-3-3M17 17H6l3 3\"/>", "日志": "<path d=\"M6 3h9l4 4v14H6z\"/><path d=\"M9 11h7M9 15h7\"/>", "更多": "<circle cx=\"5\" cy=\"12\" r=\"1.6\"/><circle cx=\"12\" cy=\"12\" r=\"1.6\"/><circle cx=\"19\" cy=\"12\" r=\"1.6\"/>"};
const PRIMARY=['概览','节点','连接','日志'];
const svgI=t=>`<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${NAV_ICO[t]||''}</svg>`;
function nav(){const np=!PRIMARY.includes(TAB);
  $('#nav').innerHTML=TABS.map(t=>`<button class="${t===TAB?'on':''} ${PRIMARY.includes(t)?'':'np'}" onclick="go('${t}')">${svgI(t)}<span>${t}</span></button>`).join('')
    +`<button class="more ${np?'on':''}" onclick="openMore()">${svgI('更多')}<span>${np?TAB:'更多'}</span></button>`;
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('hide',s.dataset.tab!==TAB))}
function openMore(){$('#more-list').innerHTML=TABS.filter(t=>!PRIMARY.includes(t)).map(t=>`<button class="${t===TAB?'on':''}" onclick="$('#more-sheet').classList.add('hide');go('${t}')">${t}</button>`).join('');$('#more-sheet').classList.remove('hide')}
