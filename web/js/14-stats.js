// 统计
let STATS=null,ST_P='today';
async function loadStats(){try{STATS=await api('/api/stats');await loadDevs()}catch(e){return toast(e.message)}
  const t=STATS.today||{},m=STATS.month||{};
  $('#st-today').textContent=fmt(t.up)+' / '+fmt(t.down);$('#st-today-sum').textContent=fmt((t.up||0)+(t.down||0));
  $('#st-month').textContent=fmt(m.up)+' / '+fmt(m.down);$('#st-month-sum').textContent=fmt((m.up||0)+(m.down||0));
  document.querySelectorAll('#st-period button').forEach(b=>{b.classList.toggle('on',b.dataset.p===ST_P);b.onclick=()=>{ST_P=b.dataset.p;loadStats()}});
  const p=STATS[ST_P]||{},arp=STATS.arp||{};
  $('#st-dev').innerHTML=(p.dev||[]).map(([n,u,d])=>`<tr><td class="w">${devCell(n)}${!dname(n)&&arp[n]?'<div class="mut" style="font-size:11px">'+esc(arp[n])+'</div>':''}</td><td>${fmt(u)}</td><td>${fmt(d)}</td><td>${fmt(u+d)} <button class="icon" style="font-size:12px;padding:0 6px;margin-left:4px" title="设置备注" onclick="editDev(${jsq(n)})">✎</button></td></tr>`).join('')||'<tr><td class="mut">暂无数据</td></tr>';
  $('#st-node').innerHTML=(p.node||[]).map(([n,u,d])=>`<tr><td class="w">${esc(n)}</td><td>${fmt(u)}</td><td>${fmt(d)}</td><td>${fmt(u+d)}</td></tr>`).join('')||'<tr><td class="mut">暂无数据</td></tr>';
  drawDays()}
function drawDays(){const c=$('#daychart');if(!c||c.offsetParent===null||!STATS)return;const r=devicePixelRatio,w=c.width=c.clientWidth*r,h=c.height=180*r,x=c.getContext('2d');
  const days=(STATS.days||[]).slice(-30);x.clearRect(0,0,w,h);x.font=(11*r)+'px -apple-system,sans-serif';x.fillStyle=cssv('--sub');
  if(!days.length){x.fillText('暂无数据',8,20*r);return}
  const max=Math.max(1,...days.map(d=>d.up+d.down)),top=18*r,bot=18*r,ch=h-top-bot,bw=w/30;
  x.fillText(fmt(max),4,12*r);x.strokeStyle=cssv('--line');x.beginPath();x.moveTo(0,h-bot);x.lineTo(w,h-bot);x.stroke();
  days.forEach((d,i)=>{const px=i*bw+bw*.18,bwi=bw*.64,hd=d.down/max*ch,hu=d.up/max*ch;
    x.fillStyle=cssv('--pri');x.fillRect(px,h-bot-hd,bwi,hd);x.fillStyle=cssv('--ok');x.fillRect(px,h-bot-hd-hu,bwi,hu);
    if(days.length<=10||i%Math.ceil(days.length/10)===0||i===days.length-1){x.fillStyle=cssv('--sub');x.fillText(d.date.slice(5),px,h-4*r)}})}

