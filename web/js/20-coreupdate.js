// 内核更新
let CORE_POLL=null;
function coreCh(){return $('#core-ch').value}
function coreKind(){return $('#core-kind').value}
const CORE_LABEL={mihomo:'mihomo',smart:'mihomo Smart',singbox:'sing-box'};
function coreKindUI(){const sm=coreKind()==='smart';if(sm)$('#core-ch').value='alpha';$('#core-ch').disabled=sm}
async function coreCheck(){const b=$('#core-chk');b.disabled=true;$('#core-r').innerHTML='<span class="mut">正在检查…</span>';
  try{await saveGhProxy();const j=await api('/api/coreupdate?channel='+coreCh()+'&core='+coreKind());coreShow(j)}
  catch(e){$('#core-r').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false}
function coreShow(j){if(j.current&&coreKind()===(STATE.core||'mihomo')&&j.current===String(STATE.version))verSave('core-'+coreKind(),j.current,j.remote||'',!j.latest);$('#cv').textContent='当前 '+(j.current||'-');
  $('#core-r').innerHTML=(j.latest?`<span class="ok">● 已是最新</span> ${esc(j.current)}`:`<span class="warn">● 有更新</span> ${esc(j.current)} → ${esc(j.remote)}`)+
    ` · 架构 ${esc(j.arch)}`+(j.backup?` · 可回滚到 ${esc(j.backup)}`:'');$('#core-btn').textContent=j.latest?'重新安装':'更新内核';$('#core-btn').dataset.force=j.latest?'1':''}
async function coreUpdate(){const force=!!$('#core-btn').dataset.force;
  const k=coreKind(),live=k===(STATE.core||'mihomo');
  if(!confirm(`${force?'重新下载并安装':'下载并更新'} ${CORE_LABEL[k]} ${coreCh()==='alpha'?'预览版':'稳定版'}？\n${live?'更新后核心会重启，网络中断几秒。':'当前没有使用它，只替换程序，不会重启。'}`))return;
  try{await saveGhProxy();await api('/api/coreupdate','POST',{channel:coreCh(),force,core:k});corePoll()}catch(e){toast(e.message)}}
async function coreRollback(){if(!confirm(`回滚 ${CORE_LABEL[coreKind()]} 到上一个版本？正在使用时核心会重启。`))return;
  try{const j=await api('/api/coreupdate','POST',{action:'rollback',core:coreKind()});if(j.message&&coreKind()==='singbox'){toast(j.message);coreCheck()}else corePoll()}catch(e){toast(e.message)}}
