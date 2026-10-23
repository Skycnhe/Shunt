// v8.4.11 回归测试用（tests/test_v8411.py 调用）：在 node 里用最小 DOM 桩跑 03-header.js 的 renderCore 与 17-dns.js 的 svc / svcBusy，
// 验证点按钮立即显示「重启中…」、进行中按钮不被实时流切换、0.2 秒轮询、完成后立即按结果刷新顶栏
const fs=require('fs'),vm=require('vm');
const root=process.argv[2];
const src=f=>fs.readFileSync(root+'/web/js/'+f,'utf8');
class El{constructor(id,txt){this.id=id;this.cls=new Set();this.textContent='';this.dataset={};this.disabled=false;this.style={};this.className='';this.innerHTML='';this.title='';
  const s=this.cls;this.classList={add:c=>s.add(c),remove:c=>s.delete(c),contains:c=>s.has(c),toggle:(c,f)=>{const on=f===undefined?!s.has(c):!!f;on?s.add(c):s.delete(c);return on}};
  if(txt!==undefined){this.tx=new El(id+'.tx');this.tx.textContent=txt}this.parentNode={title:''}}
  querySelector(s){return s==='.tx'?this.tx||null:null}}
const E={'h-restart':new El('h-restart','重启'),'h-stop':new El('h-stop','停止'),'h-start':new El('h-start','启动')};
['h-dot','h-run','h-mode','h-ver'].forEach(i=>E[i]=new El(i));E['h-start'].cls.add('hide');
const intervals=[],toasts=[];let script=[];
const ctx={console,toast:m=>toasts.push(m),confirm:()=>true,STATE:{running:true,version:'1.0',core:'mihomo'},CORE_LABEL:{},STATE_VER:0,
  setTimeout:(f,ms)=>{intervals.push(ms);mid&&mid();f()},
  api:async(u,m,b)=>{const r=script.shift();if(!r)throw new Error('no more');return r},loadState:async()=>{}};
let mid=null;
ctx.$=s=>E[s.slice(1)]||null;
vm.createContext(ctx);
const hdr=src('03-header.js'),dns=src('17-dns.js');
const rc=hdr.slice(hdr.indexOf('function renderCore('),hdr.indexOf('function renderHdr('));
const sv=dns.slice(dns.indexOf("const SVC_TXT="),dns.indexOf('async function flushFake('));
vm.runInContext(rc+'\n'+sv+'\nthis.R={svc,svcBusy,renderCore};',ctx);
const R=ctx.R,out={};
const snap=()=>({label:E['h-restart'].tx.textContent,labels:['h-restart','h-stop','h-start'].map(k=>E[k].tx.textContent),run:E['h-run'].textContent,
  disabled:['h-restart','h-stop','h-start'].map(k=>E[k].disabled),hidden:['h-restart','h-stop','h-start'].map(k=>E[k].cls.has('hide'))});
(async()=>{
  script=[{busy:true,act:'restart',message:'正在重启核心…'},{busy:false,ok:true,message:'核心已重启',alive:true,act:'restart'}];
  // 第一次轮询前：实时流报核心不在（旧核心已退出），进行中不能把「重启」换成「启动」
  mid=()=>{if(!out.busy){ctx.STATE.running=false;R.renderCore(false);out.busy=snap()}};
  await R.svc('restart');
  out.done=snap();out.done.toast=toasts[toasts.length-1];out.intervals=[...new Set(intervals)];
  mid=null;script=[{busy:true,act:'stop'},{busy:false,ok:true,message:'核心已停止',alive:false,act:'stop'}];
  await R.svc('stop');out.stop=snap();
  process.stdout.write(JSON.stringify(out));
})().catch(e=>{console.error(e);process.exit(1)});
