// 流量曲线
const HIST={up:[],down:[]};
function pushHist(u,d){HIST.up.push(u);HIST.down.push(d);if(HIST.up.length>120){HIST.up.shift();HIST.down.shift()}if(TAB==='概览')drawChart()}
function drawChart(){const c=$('#chart');if(!c||c.offsetParent===null)return;const r=devicePixelRatio,w=c.width=c.clientWidth*r,h=c.height=110*r,x=c.getContext('2d');
  x.clearRect(0,0,w,h);const max=Math.max(1024,...HIST.up,...HIST.down)*1.15;x.font=(11*r)+'px -apple-system,sans-serif';
  x.strokeStyle=cssv('--line');x.lineWidth=1;for(let i=1;i<=3;i++){const y=Math.round(h-i*(h-8*r)/3)+.5;x.beginPath();x.moveTo(0,y);x.lineTo(w,y);x.stroke()}
  x.fillStyle=cssv('--sub');x.fillText(fmt(max)+'/s',6*r,14*r);
  [[HIST.down,cssv('--pri')],[HIST.up,cssv('--ok')]].forEach(([a,col])=>{if(a.length<2)return;const pts=a.map((v,i)=>[w-(a.length-1-i)*(w/119),h-3*r-(v/max)*(h-22*r)]);
    const g=x.createLinearGradient(0,0,0,h);g.addColorStop(0,col+'55');g.addColorStop(1,col+'00');x.beginPath();x.moveTo(pts[0][0],h);pts.forEach(p=>x.lineTo(p[0],p[1]));x.lineTo(pts[pts.length-1][0],h);x.closePath();x.fillStyle=g;x.fill();
    x.strokeStyle=col;x.lineWidth=2*r;x.lineJoin='round';x.beginPath();pts.forEach((p,i)=>i?x.lineTo(p[0],p[1]):x.moveTo(p[0],p[1]));x.stroke()})}
