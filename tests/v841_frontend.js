// v8.4.1 回归测试用（tests/test_v841.py 调用）：在 node 里跑 09-groups.js / 10-subs.js，验证按值而非按序号勾选 / 恢复
const fs=require('fs'),vm=require('vm');
const root=process.argv[2];
const pre=`
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const jsq=s=>esc(JSON.stringify(String(s??'')));
const els={};const $=s=>els[s]||(els[s]={value:'',innerHTML:'',textContent:'',checked:false,classList:{toggle(){},add(){},remove(){},contains(){return false}},style:{},scrollIntoView(){}});
let CALLS=[];const api=async(p,m,b)=>{CALLS.push([p,m,b]);return {message:'ok'}};const toast=()=>{};const confirm=()=>true;
let STATE={subs:[]};const loadState=async()=>{};const core=async()=>({providers:{}});const segv=()=>{};const LBS={};
`;
const code=pre+fs.readFileSync(root+'/web/js/09-groups.js','utf8')+'\n'+fs.readFileSync(root+'/web/js/10-subs.js','utf8')+`
loadSubs=async()=>{};
const unent=s=>s.replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
(async()=>{const out={};
const odd="HK \\"01\\" <b>'x'</b> & y";
SN={subs:[{name:'A',known:true,nodes:[{name:'n1',orig:'n1'},{name:odd,orig:odd}],removed:[]}]};
CGF={sub_nodes:[{sub:'A',name:'gone'}],proxies:[]};
renderCGSPick();
const chips=[...$('#cg-spick').innerHTML.matchAll(/data-s="([^"]*)" data-o="([^"]*)" onclick="cgSTog\\(this\\.dataset\\.s,this\\.dataset\\.o\\)"/g)].map(m=>[unent(m[1]),unent(m[2])]);
out.chips=chips;
// 列表刷新（节点顺序变了）后点旧页面上的第二个芯片：按值勾选，不会勾到别的节点
SN={subs:[{name:'A',known:true,nodes:[{name:odd,orig:odd},{name:'n3',orig:'n3'}],removed:[]}]};
cgSTog(...chips[1]);out.after_tog=JSON.parse(JSON.stringify(CGF.sub_nodes));
cgSAll('A',0);out.after_clear=CGF.sub_nodes.length;
// 已删节点按名字恢复
STATE={subs:[{name:'S',removed:['x','y']}]};RMV='S';renderRemoved();
const btn=[...$('#sub-removed').innerHTML.matchAll(/data-n="([^"]*)" onclick="restoreNodes\\(this\\.dataset\\.n,this\\)"/g)].map(m=>unent(m[1]));
out.btns=btn;STATE={subs:[{name:'S',removed:['y']}]};
await restoreNodes(btn[1],{disabled:false});await restoreNodes(null,{disabled:false});out.calls=CALLS.map(c=>c[2]);
process.stdout.write(JSON.stringify(out));})().catch(e=>{process.stdout.write('ERR '+e.stack)});
`;
vm.runInThisContext(code);
