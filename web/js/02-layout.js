// 手机上把导航移到页面底部（header 带 backdrop-filter，fixed 子元素无法相对视口定位，所以要移出 header）
const MQ=matchMedia('(max-width:720px)');
function placeNav(){const n=$('#nav');if(MQ.matches){if(n.parentNode!==document.body)document.body.appendChild(n);n.classList.add('bottom');document.body.classList.add('hasbn')}
  else{if(n.parentNode===document.body)$('header').appendChild(n);n.classList.remove('bottom');document.body.classList.remove('hasbn')}}
MQ.addEventListener?MQ.addEventListener('change',placeNav):MQ.addListener(placeNav);
function go(t){if(TAB==='日志'&&t!=='日志')stopLive();if(TAB==='WARP'&&t!=='WARP')warpPoll(false);TAB=t;nav();scrollTo({top:0});
  ({节点:loadProxies,策略组:loadGroupsPage,订阅:loadSubs,规则:loadRules,DNS:loadDNSPage,广告拦截:loadAB,统计:loadStats,日志:openLogs,WARP:loadWarp,设置:renderSettings,概览:renderOverview,连接:loadDevs})[t]?.()}

