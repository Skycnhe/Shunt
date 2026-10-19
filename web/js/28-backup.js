// 版本备份/恢复（设置 → 备份与更新）
function fmtSize(b){if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";return (b/1048576).toFixed(1)+" MB"}
function fmtTime(ts){var d=new Date(ts*1000);return d.getFullYear()+"/"+String(d.getMonth()+1).padStart(2,"0")+"/"+String(d.getDate()).padStart(2,"0")+" "+String(d.getHours()).padStart(2,"0")+":"+String(d.getMinutes()).padStart(2,"0")}

async function loadBackups(){
  var el=$("#verbak-list");if(!el)return;
  el.innerHTML='<span class="mut">加载中…</span>';
  try{
    var j=await api("/api/backup/list");
    var arr=j.backups||[];
    if(!arr.length){el.innerHTML='<span class="mut">暂无备份（更新面板时会自动备份当前版本）</span>';return}
    el.innerHTML=arr.map(function(b){
      return '<div class="row" style="padding:6px 0;border-bottom:1px solid var(--line)">'+
        '<span class="sp"><b>v'+esc(b.version)+'</b> <span class="mut small">'+esc(b.name)+'</span><br>'+
        '<span class="mut small">'+fmtTime(b.mtime)+' · '+fmtSize(b.size)+'</span></span>'+
        '<button class="btn g sm" onclick="restoreBackup('+jsq(b.name)+')">恢复</button>'+
        '<button class="btn r sm" onclick="delBackup('+jsq(b.name)+')">删除</button></div>';
    }).join("");
  }catch(e){el.innerHTML='<span class="mut">加载失败</span>'}
}

async function createBackup(btn){
  if(btn)btn.disabled=true;
  try{
    var j=await api("/api/backup/create","POST");
    toast(j.message||(j.ok?"已备份："+j.name:"备份失败"));
    loadBackups();
  }catch(e){toast("备份失败")}finally{if(btn)btn.disabled=false}
}

async function restoreBackup(name){
  if(!confirm("恢复到 "+name+"？\n\n会先自动备份当前版本，恢复后需重启面板生效。"))return;
  try{
    var j=await api("/api/backup/restore","POST",{name:name});
    toast(j.message||"");
    if(j.ok&&confirm("已恢复。是否现在重启面板？"))location.reload();
  }catch(e){toast("恢复失败")}
}

async function delBackup(name){
  if(!confirm("删除备份 "+name+"？"))return;
  try{
    var j=await api("/api/backup/delete","POST",{name:name});
    toast(j.message||"");
    loadBackups();
  }catch(e){toast("删除失败")}
}
