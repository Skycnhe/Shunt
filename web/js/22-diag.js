// 网络诊断
async function runDiag(){const b=$('#diag-btn');b.disabled=true;b.textContent='诊断中…';$('#diag').innerHTML='<span class="mut small">正在检查，约需 10 秒…</span>';
  try{const r=await api('/api/diag');const bad=r.filter(x=>x.ok!==true).length;
    $('#diag').innerHTML=`<div class="small ${bad?'warn':'ok'}" style="margin:4px 0">${bad?bad+' 项需要注意':'全部正常'}</div>`+r.map(x=>{const c=x.ok===true?'ok':x.ok==='warn'?'warn':'bad';
      return `<div class="diag"><span class="ic ${c}">${c==='ok'?'✓':c==='warn'?'!':'✕'}</span><div class="sp"><div class="row"><b class="sp" style="font-weight:600">${esc(x.name)}</b><span class="mut small w" style="text-align:right">${esc(x.detail)}</span></div>${x.fix?`<div class="small ${c}" style="margin-top:2px">${esc(x.fix)}</div>`:''}</div></div>`}).join('')}
  catch(e){$('#diag').innerHTML=`<span class="bad">${esc(e.message)}</span>`}b.disabled=false;b.textContent='一键诊断';balanceSG()}

