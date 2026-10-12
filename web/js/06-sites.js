// 站点延迟：每个站点一张卡片，图标 + 最近 30 次延迟柱状图 + 当前值；柱高按 max(300ms, 近期最大值) 缩放，超时为满高红柱
const SITE_SVG='<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.8 3.2 2.8 14.8 0 18M12 3c-2.8 3.2-2.8 14.8 0 18"/></svg>';
function favFail(im){const p=im.parentNode;p.classList.add('nf');p.innerHTML=esc(p.dataset.l)||SITE_SVG}
async function testSites(force){const el=$('#sites');if(!el.children.length)el.innerHTML='<div class="card mut" style="margin:0;padding:16px">站点延迟检测中…</div>';
  try{const r=await api('/api/delay'+(force?'?force=1':''));if(!r.length){el.innerHTML='<div class="card mut" style="margin:0;padding:16px">没有检测站点，在 设置 → 测试站点 中添加</div>';return}
    el.innerHTML=r.map(s=>{const h=(s.hist&&s.hist.length?s.hist:[s.ms]).slice(-30),mx=Math.max(300,...h.filter(v=>v>0)),ok=s.ms>0;
      const bars=Array(30-h.length).fill('<i class="e"></i>').join('')+h.map(v=>`<i class="${dcls(v)}" style="height:${v>0?Math.max(8,v/mx*100):100}%" title="${dtxt(v)}"></i>`).join('');
      const l=(s.name||'?').trim().charAt(0).toUpperCase();
      return `<div class="card stile" title="${esc(s.name)}：${dtxt(s.ms)}" onclick="testSites(1)"><div class="fv" data-l="${esc(l)}"><img src="/api/favicon?u=${encodeURIComponent(s.url||'')}" alt="" onerror="favFail(this)"></div>
        <div class="sb">${bars}</div><div class="si"><div class="sn">${esc(s.name)}</div><div class="sv ${dcls(s.ms)}">${ok?s.ms+'<small>ms</small>':'超时'}</div></div></div>`}).join('')}
  catch(e){el.innerHTML=`<div class="card bad" style="margin:0;padding:16px">${esc(e.message)}</div>`}}
async function testUnlock(){const b=$('#unlock-btn');b.disabled=true;b.textContent='检测中…';$('#unlock').innerHTML='<span class="mut" style="grid-column:1/-1">检测中，约需 10 秒…</span>';
  try{const r=await api('/api/unlock');$('#unlock').innerHTML=r.map(s=>{const c=s.ok===true?'ok':s.ok==='partial'?'warn':'bad';
    return `<div class="node"><div class="n">${esc(s.name)}</div><div class="d ${c}" style="font-size:14px;font-weight:600;justify-content:flex-start">${esc(s.text)}${s.region?` <span class="tag">${esc(s.region)}</span>`:''}</div></div>`}).join('')}
  catch(e){$('#unlock').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false;b.textContent='检测';balanceSG()}

