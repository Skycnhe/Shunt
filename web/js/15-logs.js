// 日志：实时（SSE）+ 文件
let ES=null,LOGS=[],LOG_SRC='live';
const LVC={debug:'mut',info:'ok',warning:'warn',error:'bad'};
function openLogs(){document.querySelectorAll('#log-src button').forEach(b=>{b.classList.toggle('on',b.dataset.s===LOG_SRC);b.onclick=()=>{LOG_SRC=b.dataset.s;openLogs()}});
  const live=LOG_SRC==='live';$('#livelog').classList.toggle('hide',!live);$('#filelog').classList.toggle('hide',live);
  ['#log-level','#log-kw','#log-pause'].forEach(k=>$(k).closest('label')?$(k).closest('label').classList.toggle('hide',!live):$(k).classList.toggle('hide',!live));
  if(live)startLive();else{stopLive();loadLogs()}}
async function startLive(){stopLive();if(TAB!=='日志'||LOG_SRC!=='live')return;
  let tk;try{tk=(await api('/api/logticket','POST',{})).ticket}catch(e){$('#log-st').innerHTML='<span class="bad">● '+esc(e.message)+'</span>';return}
  if(TAB!=='日志'||LOG_SRC!=='live'||ES)return;
  ES=new EventSource(`/api/logstream?level=${$('#log-level').value}&ticket=${encodeURIComponent(tk)}`);
  $('#log-st').textContent='连接中…';
  ES.onopen=()=>{$('#log-st').innerHTML='<span class="ok">● 实时</span>'};
  ES.onerror=()=>{$('#log-st').innerHTML='<span class="warn">● 重连中</span>';if(ES){ES.close();ES=null}clearTimeout(startLive._t);startLive._t=setTimeout(startLive,3000)};
  ES.onmessage=e=>{let j;try{j=JSON.parse(e.data)}catch{j={type:'info',payload:e.data}}
    const L=LOGS[LOGS.length-1];if(j.retry&&L&&L.p===j.payload){L.n=(L.n||1)+1;L.t2=new Date().toLocaleTimeString('zh-CN',{hour12:false});if(!$('#log-pause').checked)renderLive();return}  // 内核重启期间每 3 秒重连一次：同一条提示只显示一行
    LOGS.push({t:new Date().toLocaleTimeString('zh-CN',{hour12:false}),l:j.type||'info',p:j.payload||''});if(LOGS.length>2000)LOGS.splice(0,LOGS.length-2000);
    if(!$('#log-pause').checked)renderLive()}}
function stopLive(){if(ES){ES.close();ES=null}const s=$('#log-st');if(s)s.textContent=''}
function clearLive(){LOGS=[];renderLive()}
let _lr=0;function renderLive(){if(_lr)return;_lr=requestAnimationFrame(()=>{_lr=0;const el=$('#livelog');const kw=$('#log-kw').value.toLowerCase();
  const stick=el.scrollTop+el.clientHeight>=el.scrollHeight-30;
  el.innerHTML=LOGS.filter(x=>!kw||x.p.toLowerCase().includes(kw)).slice(-800).map(x=>`<div><span class="mut">${x.t}</span> <span class="lv ${LVC[x.l]||''}">${esc(x.l)}</span>${esc(x.p)}${x.n?` <span class="mut">（已重试 ${x.n} 次，最近 ${x.t2}）</span>`:''}</div>`).join('')||'<span class="mut">等待日志…</span>';
  if(stick)el.scrollTop=el.scrollHeight})}
async function loadLogs(){try{const j=await api('/api/logs');const el=$('#logs');el.textContent=j.log||'(空)';el.scrollTop=el.scrollHeight}catch(e){toast(e.message)}}

