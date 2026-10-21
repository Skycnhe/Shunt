// v10.3.1 回归测试用（tests/test_v1031.py 调用）：在 node 里跑 26-devroute.js，验证删除条目后编辑序号跟着调整
const fs=require('fs'),vm=require('vm');
const root=process.argv[2];
const pre=`
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const jsq=s=>esc(JSON.stringify(String(s??'')));
const els={};const $=s=>els[s]||(els[s]={value:'',innerHTML:'',textContent:'',checked:false,classList:{toggle(){},add(){},remove(){},contains(){return false}},style:{},scrollIntoView(){},focus(){}});
const document={activeElement:null};const toast=()=>{};const confirm=()=>true;let DEVS={};let FAIL=false;
let STATE={groups:['G1'],bypass:[],device_routes:[]};let SAVED=[];
const saveSettings=async o=>{if(FAIL)throw new Error('x');SAVED.push(JSON.parse(JSON.stringify(o.device_routes)));STATE.device_routes=o.device_routes};
`;
const code=pre+fs.readFileSync(root+'/web/js/26-devroute.js','utf8')+`
(async()=>{const out={};
STATE.device_routes=[{name:'a',ip:'10.0.0.1',mac:'',target:'G1',enabled:true},{name:'b',ip:'10.0.0.2',mac:'',target:'G1',enabled:true},
  {name:'c',ip:'10.0.0.3',mac:'',target:'G1',enabled:true}];
drEdit(2);await drDel(0);out.edit_after_del_before=DR_EDIT;
$('#dr-name').value='c2';$('#dr-addr').value='10.0.0.3';$('#dr-target').value='DIRECT';await drSubmit();
out.list1=STATE.device_routes.map(e=>e.name+'|'+e.target);
// 删除的正是正在编辑的条目：表单清空，保存不会把它加回来
drEdit(1);await drDel(1);out.edit_after_del_self=DR_EDIT;out.form=$('#dr-addr').value;
// 保存失败：编辑序号还原
STATE.device_routes=[{name:'a',ip:'10.0.0.1',mac:'',target:'G1',enabled:true},{name:'b',ip:'10.0.0.2',mac:'',target:'G1',enabled:true}];
drEdit(1);FAIL=true;await drDel(0);out.edit_after_fail=DR_EDIT;FAIL=false;
process.stdout.write(JSON.stringify(out));})().catch(e=>{process.stdout.write('ERR '+e.stack)});
`;
vm.runInThisContext(code);
