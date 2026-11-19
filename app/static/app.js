'use strict';
const ui={tab:'sessions',sessionView:'current',state:'all',nas:'all',search:'',includePortal:false,offset:0,pageSize:50,
          userCategory:'all',userSearch:'',userOffset:0,userSize:50,portalSearch:'',portalOffset:0,portalSize:50};
const $=id=>document.getElementById(id);
const CATEGORY={wifi_device:'Устройство · RADIUS',guest_wifi:'Гостевой Wi-Fi',portal_user:'Captive Portal',
 infrastructure:'Инфраструктура · защищено',other_local:'Требует проверки',unknown:'Источник неизвестен'};
const ACTIONS={enable:'Включить',disable:'Выключить',set_vlan:'Изменить VLAN',
 disconnect_session:'Disconnect сессии',disconnect_portal:'Disconnect портала',disconnect_all_guests:'Disconnect всех гостей'};
const STATES={fresh:'Fresh · вероятно активно',stale:'Stale',ended:'Ended'};

function setDisconnectResult(message,kind='info'){
 const el=$('disconnect-result');
 el.textContent=message;
 el.className='disconnect-result '+kind+(message?'':' hidden');
}
let disconnectBusy=false;
function confirmUnifiDisconnect(s){
 const dialog=$('disconnect-dialog');
 const offline=s.state!=='fresh';
 $('disconnect-dialog-title').textContent=offline?'Проверить и очистить PMKSA?':'Disconnect / проверка PMKSA?';
 $('disconnect-dialog-description').textContent=offline?
  'Проверим обе UniFi и при необходимости удалим остаточную PMKSA этого MAC. Активную Wi-Fi-сессию не разрываем.':
  'При подтверждённом Online отправим RADIUS Disconnect и проверим PMKSA. Если клиент уже Offline — только проверим/очистим PMKSA. Повторное подключение возможно.';
 dialog.querySelector('button[value="confirm"]').textContent=offline?'Проверить PMKSA':'Выполнить Disconnect / PMKSA';
 $('disconnect-dialog-user').textContent=s.username||'-';
 $('disconnect-dialog-nas').textContent=s.nas_name||s.nas_ip;
 $('disconnect-dialog-mac').textContent=s.mac||'-';
 $('disconnect-dialog-hint').textContent=offline?
  'Запись завершена или устарела. Перед очисткой проверим обе UniFi. Если MAC снова Online, операция будет заблокирована.':
  'RADIUS Disconnect не гарантирует постоянного отключения. Повторная EAP-авторизация и новое подключение клиента возможны.';
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});
  dialog.showModal();
 });
}
function pmksaResultText(result){
 const details=(result.cache||[]).map(x=>
  (x.nas_ip==='192.0.2.4'?'UniFi1':'UniFi2')+' '+x.bss+': '+
  ({removed:'PMKSA удалена',already_gone:'запись уже отсутствует',not_verified:'результат не подтверждён'}[x.status]||x.status)
 );
 return details.length?details.join(' · '):'PMKSA: '+(result.reason||'нет данных');
}
async function executeUnifiDisconnect(s,button){
 if(disconnectBusy)return;
 if(!await confirmUnifiDisconnect(s))return;
 if(disconnectBusy)return;
 disconnectBusy=true;
 const offline=s.state!=='fresh';
 button.disabled=true;button.textContent='Выполняется…';
 setDisconnectResult((offline?'Проверяем PMKSA на обеих UniFi для ':'Проверяем сессию на UniFi для ')+(s.username||s.mac)+'.','pending');
 try{
  const response=await fetch("/api/unifi/disconnect",{
   method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({nas_ip:s.nas_ip,session_id:s.session_id,mac:s.mac,offline})
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok)throw new Error(answer.detail||('HTTP '+response.status));
  await refresh();
  const message=(answer.disconnect_ack?'RADIUS Disconnect-ACK. ':'Offline — разрыв сессии не требовался. ')+
    pmksaResultText(answer.pmksa||{});
  if(answer.result==='partial'){
   setDisconnectResult('Частичный результат. '+message+'. Причина: '+(answer.pmksa?.reason||'-'),'error');
  }else{
   setDisconnectResult('Завершено: '+message,'success');
  }
 }catch(error){setDisconnectResult((offline?'Проверка PMKSA не завершена: ':'RADIUS Disconnect не завершён: ')+error.message,'error');}
 finally{disconnectBusy=false;button.disabled=false;button.textContent=offline?'Проверить PMKSA':'Disconnect / PMKSA';}
}
function confirmOmadaWired(s){
 const dialog=$('disconnect-dialog');
 const labels={
  ru:{
   title:'Wired Disconnect — Omada?',
   description:'Отправить один RADIUS Disconnect для выбранной проводной 802.1X-сессии Omada. После разрыва клиент может автоматически повторно подключиться через EAP-TLS.',
   hint:'Сессия {sid}. Команда без повторов. Только проверенный Disconnect-ACK подтверждает результат. При неизвестном результате сначала проверьте Accounting.',
   confirm:'Выполнить Wired Disconnect'
  },
  en:{
   title:'Wired Disconnect — Omada?',
   description:'Send one RADIUS Disconnect for the selected Omada wired 802.1X session. The client may reconnect automatically via EAP-TLS.',
   hint:'Session {sid}. No retries. Only a verified Disconnect-ACK confirms success. If the result is unknown, check Accounting first.',
   confirm:'Run Wired Disconnect'
  },
  de:{
   title:'Wired Disconnect — Omada?',
   description:'Eine RADIUS-Disconnect-Anfrage für die ausgewählte kabelgebundene Omada-802.1X-Sitzung senden. Der Client kann sich über EAP-TLS automatisch erneut verbinden.',
   hint:'Sitzung {sid}. Keine Wiederholungen. Nur ein geprüfter Disconnect-ACK bestätigt den Erfolg. Bei unklarem Ergebnis zuerst Accounting prüfen.',
   confirm:'Wired Disconnect ausführen'
  },
  uk:{
   title:'Wired Disconnect — Omada?',
   description:'Надіслати один RADIUS Disconnect для вибраної дротової сесії Omada 802.1X. Клієнт може автоматично підключитися повторно через EAP-TLS.',
   hint:'Сесія {sid}. Без повторних спроб. Лише перевірений Disconnect-ACK підтверджує успіх. Якщо результат невідомий, спочатку перевірте Accounting.',
   confirm:'Виконати Wired Disconnect'
  }
 };
 const locale=window.BiXUI?.locale||'ru';
 const t=labels[locale]||labels.ru;
 $('disconnect-dialog-title').textContent=t.title;
 $('disconnect-dialog-description').textContent=t.description;
 $('disconnect-dialog-user').textContent=s.username||'-';
 $('disconnect-dialog-nas').textContent='Omada '+(s.nas_ip||'-');
 $('disconnect-dialog-mac').textContent=s.mac||'-';
 $('disconnect-dialog-hint').textContent=t.hint.replace('{sid}',s.session_id);
 dialog.querySelector('button[value="confirm"]').textContent=t.confirm;
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});
  dialog.showModal();
 });
}
async function executeOmadaWiredDisconnect(s,button){
 if(disconnectBusy)return;
 if(!await confirmOmadaWired(s))return;
 if(disconnectBusy)return;
 disconnectBusy=true;button.disabled=true;button.textContent='\u041f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u043c \u0441\u0435\u0441\u0441\u0438\u044e\u2026';
 setDisconnectResult('\u041f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u043c \u0441\u0435\u0441\u0441\u0438\u044e \u0438 \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u0435\u043c \u043e\u0434\u0438\u043d Disconnect \u043d\u0430 Omada.','pending');
 try{
  const response=await fetch('/api/omada/disconnect',{
   method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({nas_ip:s.nas_ip,session_id:s.session_id,mac:s.mac})
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(response.status===202){
   setDisconnectResult('\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 Disconnect \u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043d. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 Accounting Stop/Start. \u041d\u0435 \u043f\u043e\u0432\u0442\u043e\u0440\u044f\u0439\u0442\u0435 \u0437\u0430\u043f\u0440\u043e\u0441 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438.','error');
   return;
  }
  if(!response.ok)throw new Error(answer.detail||('HTTP '+response.status));
  if(answer.result!=='ack')throw new Error('\u041e\u0442\u0432\u0435\u0442 \u043a\u043e\u043c\u043c\u0443\u0442\u0430\u0442\u043e\u0440\u0430 \u043d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d');
  setDisconnectResult(answer.message || 'Disconnect-ACK verified; Accounting status unavailable.', 'success');
  await refresh();
 }catch(error){setDisconnectResult('Omada Wired Disconnect: '+error.message,'error');}
 finally{disconnectBusy=false;button.disabled=false;button.textContent='Wired Disconnect';}
}
function confirmUnifiReauth(s){
 const dlg=$('reauth-dialog');
 $('reauth-dialog-user').textContent=s.username||'-';
 $('reauth-dialog-nas').textContent=s.nas_name||s.nas_ip;
 dlg.returnValue='';
 return new Promise(resolve=>{
  dlg.addEventListener('close',()=>resolve(dlg.returnValue==='confirm'),{once:true});
  dlg.showModal();
 });
}
async function executeUnifiReauth(s,button){
 if(disconnectBusy)return;
 if(!await confirmUnifiReauth(s))return;
 if(disconnectBusy)return;
 disconnectBusy=true;
 button.disabled=true;button.textContent='Запрос…';
 setDisconnectResult('Запрашиваем адресную EAPOL_REAUTH для '+s.username+'.','pending');
 try{
  const response=await fetch('/api/unifi/reauth',{
   method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({nas_ip:s.nas_ip,session_id:s.session_id,mac:s.mac})
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok)throw new Error(answer.detail||('HTTP '+response.status));
  setDisconnectResult('Команда EAPOL_REAUTH принята на '+s.nas_name+' / '+answer.bss+
   '. Соединение не разрывали. Для подтверждения результата EAP смотри FreeRADIUS Login OK.','success');
  await refresh();
 }catch(error){setDisconnectResult('Переавторизация не выполнена: '+error.message,'error');}
 finally{disconnectBusy=false;button.disabled=false;button.textContent='Запросить EAP-проверку';}
}
let staleCloseBusy=false;
function confirmStaleClose(s){
 const dialog=$('stale-close-dialog');
 $('stale-close-dialog-user').textContent=s.username||'-';
 $('stale-close-dialog-nas').textContent=s.nas_name||s.nas_ip;
 $('stale-close-dialog-session').textContent=s.session_id||'-';
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});
  dialog.showModal();
 });
}
async function closeStaleAccounting(s,button){
 if(staleCloseBusy)return;
 if(!await confirmStaleClose(s))return;
 if(staleCloseBusy)return;
 staleCloseBusy=true;
 button.disabled=true;
 button.textContent='Закрываем…';
 setDisconnectResult('Закрываем старую запись Accounting. Активное Wi-Fi-подключение не затрагивается.','pending');
 try{
  const response=await fetch('/api/accounting/close-stale',{
   method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({
    nas_ip:s.nas_ip,session_id:s.session_id,mac:s.mac,username:s.username,
    started_at:s.started_at,updated_at:s.updated_at
   })
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok)throw new Error(answer.detail||('HTTP '+response.status));
  if(lastManualRefreshAvailable){
   const refreshed=await fetch('/api/snapshot/refresh',{method:'POST',cache:'no-store'});
   if(refreshed.ok){
    await refresh();
    setDisconnectResult('Старая запись закрыта. Снимок обновлён; текущие подключения не отключались.','success');
   }else{
    await refresh();
    setDisconnectResult('Запись закрыта. Автоматический снимок обновится в течение минуты.','success');
   }
  }else{
   await refresh();
   setDisconnectResult('Запись закрыта. Обновление снимка произойдёт автоматически в течение минуты.','success');
  }
 }catch(error){setDisconnectResult('Не удалось закрыть старую запись: '+error.message,'error');}
 finally{staleCloseBusy=false;button.disabled=false;button.textContent='Закрыть Accounting';}
}

const formatTime=s=>s?new Intl.DateTimeFormat(({ru:'ru-RU',en:'en-GB',de:'de-DE',uk:'uk-UA'})[window.BiXUI?.locale||'ru']||'ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false,timeZone:'Europe/Berlin'}).format(new Date(s)):'—';
const add=(parent,tag,text,cls)=>{const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);parent.append(node);return node;};
const addRaw=(parent,tag,text,cls)=>{const node=add(parent,tag,text,cls);node.setAttribute('data-i18n-ignore','');return node;};
const cell=(tr,label)=>{const td=add(tr,'td');td.dataset.label=label;return td;};
const tag=(parent,text)=>add(parent,'span',text,'small-tag');
async function fetchData(path){const resp=await fetch(path,{cache:'no-store'});if(resp.status===401){window.location.replace('/login');throw new Error('Сессия входа завершилась')}if(!resp.ok){let detail='';try{detail=(await resp.json()).detail||'';}catch{}throw new Error(String(resp.status)+' '+detail);}return await resp.json();}
function setError(message){$('error-box').classList.toggle('hidden',!message);$('error-box').textContent=message||'';}
function setMode(meta){
 $('manual-refresh').disabled=manualRefreshBusy||!meta.manual_refresh_enabled;
 const demo=meta.mode==='demo';
 $('mode-title').textContent=demo?'ДЕМОНСТРАЦИЯ · НЕ LIVE':meta.snapshot_stale?'СНИМОК УСТАРЕЛ · НЕ LIVE':'ИМПОРТ RADIUS · НЕ LIVE';
 const source=demo?'Все записи здесь вымышлены. ':`Снимок получен ${formatTime(meta.as_of)}, возраст ${Math.ceil(meta.snapshot_age_seconds/60)} мин. `;
 $('snapshot-notice').textContent=source+(meta.snapshot_stale?'Источник старше 15 мин. ':'')+
   (meta.users_available?'Users загружены. ':'Users не подключены. ')+
   (meta.portal_available?'Captive Portal загружен.':'Сессии портала не подключены.');
}
function renderSessions(items,total,meta){
 $('session-count').textContent=window.BiXUI.count(ui.sessionView==='history'?'history':'current',total);
 $('page-info').textContent=total?`Показано ${ui.offset+1}–${Math.min(ui.offset+items.length,total)} из ${total}`:'Нет результатов';
 $('prev-page').disabled=ui.offset===0;$('next-page').disabled=ui.offset+items.length>=total;
 const body=$('session-rows');body.replaceChildren();$('sessions-empty').classList.toggle('hidden',items.length>0);
 for(const s of items){
  const tr=add(body,'tr');
  let td=cell(tr,'Идентичность');addRaw(td,'div',s.username||'—','principal');add(td,'span',CATEGORY[s.identity_kind]||'Не определено','secondary secondline');
  td=cell(tr,'NAS');add(td,'div',s.nas_name);add(td,'span',s.nas_ip+' · '+s.network_kind,'secondary secondline');
  td=cell(tr,'MAC');addRaw(td,'span',s.mac||'—','mono');
  td=cell(tr,'Начало');add(td,'span',formatTime(s.started_at));
  td=cell(tr,ui.sessionView==='history'?'Accounting Stop':'Последний Update');
  add(td,'span',formatTime(ui.sessionView==='history'?(s.stopped_at||s.updated_at):s.updated_at));
  if(ui.sessionView==='current'&&s.age_minutes!==null)add(td,'span',s.clock_skew?'Время требует проверки':'Возраст: '+s.age_minutes+' мин','secondary secondline');
  td=cell(tr,'Состояние');add(td,'span',STATES[s.state]||s.state,'state '+s.state);
  const detail=add(td,'details',undefined,'cell-details');add(detail,'summary','Подробнее');add(detail,'p','Acct-Session-Id: '+(s.session_id||'—'));
  if(s.stopped_at)add(detail,'p','Accounting Stop: '+formatTime(s.stopped_at));
  td=cell(tr,'Управление');
  const unifiActions=meta.unifi_maintenance_enabled && meta.management_enabled &&
    s.nas_family==='unifi' && s.identity_kind!=='infrastructure';
  if(unifiActions && ui.sessionView==='current' && s.state==='fresh'
     && s.age_minutes!==null && s.age_minutes>=-1 && s.age_minutes<=10.9){
   const group=add(td,'div',undefined,'unifi-session-actions');
   const reauth=add(group,'button','Запросить EAP-проверку','disconnect-now reauth-now');
   reauth.type='button';
   reauth.title='Адресная EAPOL_REAUTH без намеренного разрыва Wi-Fi';
   reauth.addEventListener('click',()=>executeUnifiReauth(s,reauth));
   const disc=add(group,'button','Disconnect / PMKSA','disconnect-now');
   disc.type='button';
   disc.title='Если MAC Online — отправить RADIUS Disconnect и проверить PMKSA; если Offline — только проверить/очистить PMKSA';
   disc.addEventListener('click',()=>executeUnifiDisconnect(s,disc));
  }else if(meta.omada_wired_enabled && ui.sessionView==='current'
     && s.omada_wired_latest===true
     && s.nas_ip==='192.0.2.6' && s.nas_family==='omada'
     && !!s.username
     && /^[0-9a-f]{12}$/i.test(String(s.mac||'').replace(/[^0-9a-f]/gi,''))
     && /^[0-9a-f]{8}$/i.test(s.session_id||'')
     && s.state==='fresh' && s.age_minutes!==null
     && s.age_minutes>=-1 && s.age_minutes<=10.9){
    const disc=add(td,'button','Wired Disconnect','disconnect-now');
    disc.type='button';
    disc.title='Omada: \u043e\u0434\u043d\u0430 \u0442\u0435\u043a\u0443\u0449\u0430\u044f 802.1X-\u0441\u0435\u0441\u0441\u0438\u044f. \u041e\u0434\u0438\u043d \u0430\u0434\u0440\u0435\u0441\u043d\u044b\u0439 Disconnect; \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043e\u0442\u0432\u0435\u0442\u0430 ACK \u0438 Accounting \u043d\u0430 RadiusGateway.';
    disc.addEventListener('click',()=>executeOmadaWiredDisconnect(s,disc));
   }else if(unifiActions && ui.sessionView==='history' && s.state==='ended' && s.offline_disconnect_eligible){
   const disc=add(td,'button','Проверить PMKSA','disconnect-now');
   disc.type='button';
   disc.title='Проверить обе UniFi и при наличии очистить остаточную PMKSA этого MAC без разрыва активной сессии';
   disc.addEventListener('click',()=>executeUnifiDisconnect(s,disc));
  }else if(ui.sessionView==='current' && s.state==='stale'
   && meta.stale_close_enabled && s.started_at && s.updated_at
   && ['192.0.2.4','192.0.2.5','192.0.2.6'].includes(s.nas_ip)){
   const group=add(td,'div',undefined,'unifi-session-actions');
   if(unifiActions && s.offline_disconnect_eligible){
    const disc=add(group,'button','Проверить PMKSA','disconnect-now');
    disc.type='button';disc.title='Проверить обе UniFi и при наличии очистить остаточную PMKSA этого MAC без разрыва активной сессии';
    disc.addEventListener('click',()=>executeUnifiDisconnect(s,disc));
   }
   const b=add(group,'button','Закрыть Accounting','disconnect-now stale-close-now');b.type='button';
   b.title='Закрыть только устаревшую запись RADIUS Accounting. Не отключает Wi-Fi.';
   b.addEventListener('click',()=>closeStaleAccounting(s,b));
  }else add(td,'span','-','secondary');
 }
}
let userToggleBusy=false;
function setUserToggleResult(message,kind='info'){
 const el=$('user-toggle-result');
 el.textContent=message;
 el.className='disconnect-result '+kind+(message?'':' hidden');
}
function confirmUserToggle(user,wanted){
 const dialog=$('user-toggle-dialog');
 $('user-toggle-dialog-name').textContent=user.username;
 $('user-toggle-dialog-vlan').textContent='VLAN '+user.configured_vlan;
 $('user-toggle-dialog-action').textContent=wanted?'Включить':'Выключить';
 $('user-toggle-dialog-action').className=wanted?'state fresh':'state ended';
 $('user-toggle-dialog-warning').textContent=wanted?
  'Запись будет переведена в Enabled на RadiusGateway. Это влияет на следующие авторизации, но не подключает устройство автоматически.':
  'Запись будет переведена в Disabled на RadiusGateway. Уже активные сессии не разрываются; решение о новых авторизациях принимает FreeRADIUS.';
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});
  dialog.showModal();
 });
}
async function executeUserToggle(user,button){
 if(userToggleBusy||!user.editable||user.protected||user.kind!=='wifi_device')return;
 const wanted=!user.enabled;
 if(!await confirmUserToggle(user,wanted))return;
 if(userToggleBusy)return;
 userToggleBusy=true;
 button.disabled=true;button.textContent='Применяем…';
 setUserToggleResult('Применяем '+(wanted?'Enabled':'Disabled')+' для '+user.username+' на RadiusGateway…','pending');
 try{
  const response=await fetch('/api/users/set-enabled',{
   method:'POST',cache:'no-store',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({uuid:user.uuid,username:user.username,expected_enabled:user.enabled,enabled:wanted})
  });
  const answer=await response.json();
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok){
   if(response.status===409)await refresh();
   throw new Error(answer.detail||('Ошибка '+response.status));
  }
  setUserToggleResult('RadiusGateway подтвердил: '+user.username+' '+(wanted?'включён':'выключен')+
   '. Состояние в таблице обновится после следующего импорта (около минуты).','success');
  await refresh();
 }catch(e){
  setUserToggleResult('Изменение не выполнено: '+e.message,'error');
 }finally{
  userToggleBusy=false;
  button.disabled=false;
  button.textContent=wanted?'Включить':'Выключить';
 }
}
function confirmUserVlan(user){
 const dialog=$('user-vlan-dialog');
 $('user-vlan-name').textContent=user.username;
 $('user-vlan-current').textContent='VLAN '+user.configured_vlan;
 const input=$('user-vlan-new');
 input.value=String(user.configured_vlan);
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>{
   const value=dialog.returnValue==='confirm'?Number(input.value):null;
   resolve(value);
  },{once:true});
  dialog.showModal();
  input.focus();
  input.select();
 });
}
async function executeUserVlan(user,button){
 if(userToggleBusy||!user.editable||user.protected||user.kind!=='wifi_device')return;
 const newVlan=await confirmUserVlan(user);
 if(newVlan===null)return;
 if(!Number.isInteger(newVlan)||newVlan<1||newVlan>4094){
  setUserToggleResult('VLAN должен быть целым числом от 1 до 4094.','error');return;
 }
 if(newVlan===user.configured_vlan){
  setUserToggleResult('VLAN не изменён: указано текущее значение.','info');return;
 }
 if(userToggleBusy)return;
 userToggleBusy=true;
 button.disabled=true;button.textContent='Сохраняем…';
 setUserToggleResult('Изменяем VLAN '+user.username+': '+user.configured_vlan+' → '+newVlan+'…','pending');
 try{
  const response=await fetch('/api/users/set-vlan',{
   method:'POST',cache:'no-store',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({uuid:user.uuid,username:user.username,
    expected_vlan:user.configured_vlan,vlan:newVlan,expected_enabled:user.enabled})
  });
  let answer={};
  try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok){
   if(response.status===409)await refresh();
   throw new Error(answer.detail||'Ошибка '+response.status);
  }
  setUserToggleResult('RadiusGateway подтвердил: VLAN для '+user.username+' изменён с '+
   user.configured_vlan+' на '+newVlan+'. Это постоянная настройка. '+
   'Новая VLAN начнёт действовать после следующей полной аутентификации устройства. '+
   'Никаких Disconnect автоматически не отправлено.','success');
  await refresh();
 }catch(e){
  setUserToggleResult('VLAN не изменён: '+e.message,'error');
 }finally{
  userToggleBusy=false;
  button.disabled=false;
  button.textContent='Изменить VLAN';
 }
}
function renderUsers(items,total,meta){
 $('user-count').textContent=window.BiXUI.count('records',total);
 $('user-page-info').textContent=total?`Показано ${ui.userOffset+1}–${Math.min(total,ui.userOffset+items.length)} из ${total}`:'Нет результатов';
 $('user-prev-page').disabled=ui.userOffset===0;$('user-next-page').disabled=ui.userOffset+items.length>=total;
 const body=$('user-rows');body.replaceChildren();$('users-empty').classList.toggle('hidden',items.length>0);
 if(!meta.users_available)$('users-empty').textContent='Источник Local Users ещё не подключён. Это не означает, что пользователей на OPNsense нет.';
 else $('users-empty').textContent='Нет записей по выбранному фильтру.';
 for(const u of items){
  const tr=add(body,'tr');
  let td=cell(tr,'Пользователь');addRaw(td,'div',u.username,'principal');addRaw(td,'span',u.uuid,'mono secondary secondline');
  td=cell(tr,'Назначение');tag(td,CATEGORY[u.kind]||'Не определено');
  td=cell(tr,'Enabled');add(td,'span',u.enabled?'Включено':'Выключено','state '+(u.enabled?'fresh':'ended'));
  td=cell(tr,'VLAN');add(td,'strong',u.configured_vlan===null?'—':u.configured_vlan);
  td=cell(tr,'Операции');
  const actions=add(td,'div',undefined,'actions-inline');
  if(u.editable&&u.kind==='wifi_device'&&!u.protected&&meta.user_management_enabled){
   const wanted=!u.enabled;
   const b=add(actions,'button',wanted?'Включить':'Выключить','user-toggle-now'+(wanted?'':' warn'));
   b.type='button';
   b.addEventListener('click',()=>executeUserToggle(u,b));
   b.title='Меняет доступ только для следующих RADIUS-авторизаций; существующие сессии не разрывает';
    const vlanButton=add(actions,'button','Изменить VLAN','user-vlan-button');
   vlanButton.type='button';
   vlanButton.addEventListener('click',()=>executeUserVlan(u,vlanButton));
  }else{
   if(u.protected)tag(actions,'Защищено · без изменений');
   else if(u.kind==='wifi_device')tag(actions,'Управление недоступно');
   else if(u.kind==='guest_wifi')tag(actions,'Управление в блоке Guest Wi-Fi');
    else if(u.kind==='portal_user')tag(actions,'Управление в Captive Portal');
   else tag(actions,'Только просмотр');
  }
 }
}
// v0.9.0: portal user and individual portal-session actions.
const portalDisconnected=new Set();
const portalPendingUsers=new Map();
let portalBusy=false;
function portalKey(session){return session.zone_id+'|'+session.session_id;}
function portalResult(message,kind='info'){
 const box=$('portal-action-result');
 box.textContent=message;
 box.className='disconnect-result '+kind+(message?'':' hidden');
}
function confirmPortalAction(user,action,session){
 const dialog=$('portal-action-dialog');
 $('portal-dialog-name').textContent=user.username;
 $('portal-dialog-action').textContent=action;
 $('portal-dialog-target').textContent=session?
  'зона '+session.zone_id+' · '+(session.ip||session.mac||session.session_id):
  'локальная запись без VLAN';
 $('portal-action-title').textContent=action+'?';
 $('portal-action-warning').textContent=session?
  'Будет удалена только эта авторизованная сессия портала. Wi-Fi и VLAN не меняются.':
  action==='Выключить'?
  'Следующая авторизация по этой учётной записи станет недоступна. Уже открытые сессии сохранятся до отдельного Disconnect.':
  'Новая авторизация будет вновь разрешена. Уже активные сессии не затрагиваются.';
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});
  dialog.showModal();
 });
}
async function executePortalEnabled(user,button){
 if(portalBusy||!user.editable||portalPendingUsers.has(user.uuid))return;
 const enable=!user.enabled;
 if(!await confirmPortalAction(user,enable?'Включить':'Выключить',null))return;
 if(portalBusy)return;
 portalBusy=true;button.disabled=true;button.textContent='Применяем…';
 portalResult('Изменяем Enabled для '+user.username+'…','pending');
 try{
  const response=await fetch('/api/portal-users/set-enabled',{
   method:'POST',cache:'no-store',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({uuid:user.uuid,username:user.username,
     expected_enabled:user.enabled,enabled:enable})
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok){if(response.status===409)await refresh();throw new Error(answer.detail||'HTTP '+response.status);}
  portalPendingUsers.set(user.uuid,enable);
  portalResult(user.username+': '+(enable?'включён':'выключен')+
   '. Изменение подтверждено RadiusGateway. Текущие сессии не разорваны; список обновится после синхронизации.','success');
  await refresh();
 }catch(e){portalResult('Enabled не изменён: '+e.message,'error');}
 finally{portalBusy=false;button.disabled=false;button.textContent=enable?'Включить':'Выключить';}
}
async function executePortalDisconnect(user,session,button){
 if(portalBusy||!user.disconnect_available||portalDisconnected.has(portalKey(session)))return;
 if(!await confirmPortalAction(user,'Завершить сессию портала',session))return;
 if(portalBusy)return;
 portalBusy=true;button.disabled=true;button.textContent='Отключаем…';
 portalResult('Отправляем Disconnect сессии '+user.username+'…','pending');
 try{
  const response=await fetch('/api/portal-sessions/disconnect',{
   method:'POST',cache:'no-store',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({uuid:user.uuid,username:user.username,
    expected_enabled:user.enabled,zone_id:session.zone_id,
    session_id:session.session_id,ip:session.ip,mac:session.mac})
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok){if(response.status===409)await refresh();throw new Error(answer.detail||'HTTP '+response.status);}
  portalDisconnected.add(portalKey(session));
  portalResult('OPNsense подтвердил разрыв сессии '+user.username+
   '. Обновление списка — после следующего снимка. Учётная запись Enabled не менялась.','success');
  await refresh();
 }catch(e){portalResult('Disconnect не подтверждён: '+e.message,'error');}
 finally{portalBusy=false;button.disabled=false;button.textContent='Завершить сессию портала';}
}

function renderPortal(data){
 const {items,total,meta,unmatched_sessions:unmatched,unmatched_count:unmatchedCount}=data;
 $('portal-count').textContent=window.BiXUI.count('accounts',total);
 $('portal-active-count').textContent=data.active_session_count===null?'Сессии недоступны':window.BiXUI.count('sessions',data.active_session_count)+' по снимку';
 $('portal-page-info').textContent=total?('Показано '+(ui.portalOffset+1)+'–'+Math.min(total,ui.portalOffset+items.length)+' из '+total):'Нет записей';
 $('portal-prev-page').disabled=ui.portalOffset===0;
 $('portal-next-page').disabled=ui.portalOffset+items.length>=total;
 $('portal-missing').classList.toggle('hidden',meta.portal_available);
 if(meta.portal_available && !meta.snapshot_stale){
  const actual=new Set(items.flatMap(u=>u.sessions.map(portalKey)));
  for(const key of portalDisconnected){if(!actual.has(key))portalDisconnected.delete(key);}
 }
 const body=$('portal-rows');body.replaceChildren();$('portal-empty').classList.toggle('hidden',items.length>0);
 const AUTH={authorized:['Авторизован · снимок','fresh'],not_authorized:['Не авторизован · снимок','ended'],
   previously_authorized:['Был авторизован · снимок устарел','stale'],not_confirmed:['Не подтверждено · снимок устарел','stale'],
   unknown:['Неизвестно · нет данных','stale']};
 for(const u of items){
  const tr=add(body,'tr');
  let td=cell(tr,'Пользователь');addRaw(td,'div',u.username,'principal');addRaw(td,'span',u.uuid,'mono secondary secondline');
  td=cell(tr,'Enabled');add(td,'span',u.enabled?'Включено':'Выключено','state '+(u.enabled?'fresh':'ended'));
  td=cell(tr,'Авторизация');const a=AUTH[u.authorization_status]||AUTH.unknown;add(td,'span',a[0],'state '+a[1]);
  td=cell(tr,'Сессии');add(td,'strong',u.session_count?window.BiXUI.count('sessions',u.session_count)+' по снимку':'—');
  if(portalPendingUsers.has(u.uuid) && u.enabled===portalPendingUsers.get(u.uuid)){
   portalPendingUsers.delete(u.uuid);
  }
  if(u.sessions.length){
   const details=add(td,'details',undefined,'cell-details');add(details,'summary','Показать подключение');
   for(const session of u.sessions){
    const item=add(details,'div',undefined,'portal-session-detail');
    add(item,'p','IP: '+(session.ip||'—')+' · MAC: '+(session.mac||'—')+' · зона: '+session.zone_id);
    add(item,'p','Вход: '+formatTime(session.started_at)+' · Session ID: '+session.session_id);
    if(portalDisconnected.has(portalKey(session))){
     add(item,'span','Disconnect подтверждён · ожидаем новый снимок','state ended');
    }else if(u.disconnect_available){
     const button=add(item,'button','Завершить сессию портала','user-toggle-now warn portal-session-button');
     button.type='button';
     button.addEventListener('click',()=>executePortalDisconnect(u,session,button));
    }
   }
  }
  td=cell(tr,'Управление');const actions=add(td,'div',undefined,'actions-inline');
  if(u.editable){
   const pending=portalPendingUsers.has(u.uuid);
   const desired=pending?portalPendingUsers.get(u.uuid):!u.enabled;
   const button=add(actions,'button',pending?'Ожидаем обновления':desired?'Включить':'Выключить',
                    'user-toggle-now'+(desired?'':' warn'));
   button.type='button';button.disabled=pending;
    button.title='Изменяет доступ к новым авторизациям Captive Portal; существующие сессии не отключает';
   if(!pending)button.addEventListener('click',()=>executePortalEnabled(u,button));
  }else tag(actions,'Только просмотр');
 }
 const orphan=$('portal-unmatched'),list=$('portal-unmatched-list');list.replaceChildren();
 orphan.classList.toggle('hidden',!unmatchedCount);
 for(const s of unmatched){
  add(list,'li',(s.username||'Имя неизвестно')+' · '+(s.ip||'IP неизвестен')+' · зона '+s.zone_id+' · Session ID '+s.session_id);
 }
}
// v0.10.0 — only the SHARED Wi-Fi identity guestwlan (VLAN30).
// Portal accounts and their authorization sessions are never included.
let guestUser=null;
let guestBusy=false;
let guestPendingEnabled=null;

function guestFeedback(message,kind='info'){
 const el=$('guest-control-result');
 el.textContent=message;
 el.className='disconnect-result '+kind+(message?'':' hidden');
}
function confirmGuestAction(label,explanation){
 const dialog=$('guest-action-dialog');
 $('guest-dialog-title').textContent=label+'?';
 $('guest-dialog-action').textContent=label;
 $('guest-dialog-warning').textContent=explanation;
 dialog.returnValue='';
 return new Promise(resolve=>{
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true});
  dialog.showModal();
 });
}
async function changeGuestEnabled(enabled){
 if(guestBusy||!guestUser||!guestUser.editable||guestUser.enabled===enabled)return;
 const uuid=guestUser.uuid,expected=guestUser.enabled;
 const choice=enabled?'Включить guestwlan':'Выключить guestwlan';
 const warning=enabled?
  'Перевести guestwlan в Enabled на RadiusGateway. Это влияет на будущие RADIUS-авторизации; Captive Portal не изменяется.':
  'Перевести guestwlan в Disabled на RadiusGateway. Новые авторизации определяются FreeRADIUS; действующие Wi-Fi-сессии и Captive Portal не разрываются.';
 if(!await confirmGuestAction(choice,warning))return;
 if(guestBusy)return;
 guestBusy=true;
 guestFeedback('Применяем '+choice+' на RadiusGateway…','pending');
 try{
  const response=await fetch('/api/guest-wifi/set-enabled',{
   method:'POST',credentials:'same-origin',cache:'no-store',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({uuid,expected_enabled:expected,enabled})
  });
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok){
   if(response.status===409)await refresh();
   throw new Error(answer.detail||'Ошибка '+response.status);
  }
  guestPendingEnabled=enabled;
  guestFeedback('RadiusGateway подтвердил: guestwlan '+(enabled?'включена':'выключена')+
    '. Уже открытые сессии Wi-Fi и Captive Portal не разрывались.','success');
  await refresh();
 }catch(e){guestFeedback('Команда не выполнена: '+e.message,'error');}
 finally{guestBusy=false;updateGuestButtons();}
}
function updateGuestButtons(){
 const ready=!!guestUser&&guestUser.editable&&!guestBusy&&guestPendingEnabled===null;
 $('guest-enable').title='Разрешить новые RADIUS-авторизации guestwlan; активные подключения останутся без изменений';
  $('guest-disable').title='Запретить новые RADIUS-авторизации guestwlan; активные подключения останутся без изменений';
  $('guest-preview').title='Сначала показать список подходящих гостевых сессий UniFi — без выполнения Disconnect';
  $('guest-enable').disabled=!ready||guestUser.enabled;
 $('guest-disable').disabled=!ready||!guestUser.enabled;
 // Disconnect can be requested regardless of Enabled; only UniFi guest sessions.
 $('guest-preview').disabled=guestBusy||!guestUser||!guestUser.guest_disconnect_available;
}
async function runGuestBatch(preview){
 if(guestBusy||!guestUser||!guestUser.guest_disconnect_available||!preview)return;
 if(!preview.plan.count||!preview.plan.within_limit)return;
 const count=preview.plan.count;
 const warning='RADIUS Disconnect-Request: '+window.BiXUI.count('guestSessions',count)+'. '+
  'Подключённые устройства могут повторно войти в Wi-Fi. '+
  'Индивидуальные учётные записи и авторизации Captive Portal НЕ изменятся. '+
  'Omada и устаревшие сессии не входят в список.';
 if(!await confirmGuestAction(window.BiXUI.actionCount('guestDisconnect',count),warning))return;
 if(guestBusy)return;
 guestBusy=true;
 updateGuestButtons();
 guestFeedback('Выполняем '+count+' адресных UniFi Disconnect…','pending');
 try{
  const res=await fetch('/api/guest-wifi/disconnect-all',{
   method:'POST',credentials:'same-origin',cache:'no-store',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({
    uuid:preview.guest.uuid,expected_enabled:preview.guest.enabled,
    fingerprint:preview.plan.fingerprint,expected_count:count,
    confirmation:'disconnect_guest_wifi'
   })
  });
  let answer={};try{answer=await res.json();}catch{}
  if(res.status===401){window.location.replace('/login');return;}
  if(!res.ok){
   if(res.status===409)await refresh();
   throw new Error(answer.detail||'Ошибка '+res.status);
  }
  guestFeedback('UniFi: Disconnect-ACK '+answer.ack+' из '+answer.requested+
    ', NAK '+answer.nak+', ошибки '+answer.error+'. '+
    (answer.ok?'Для всех выбранных сессий получен Disconnect-ACK. ':'Для части сессий Disconnect-ACK не получен. ')+
    'Captive Portal не затрагивался. Устройства могут переподключиться.',
    answer.ok?'success':'error');
  $('plan-panel').classList.add('hidden');
  await refresh();
 }catch(e){guestFeedback('Массовый Disconnect не подтверждён: '+e.message,'error');}
 finally{guestBusy=false;updateGuestButtons();}
}
async function previewGuestBatch(){
 if(guestBusy)return;
 $('guest-preview').disabled=true;
 try{
  const data=await fetchData('/api/guest-wifi/preview');
  const plan=data.plan;
  const panel=$('plan-panel'),area=$('plan-details');
  area.replaceChildren();panel.classList.remove('hidden');
  add(area,'p','RADIUS Disconnect-Request: '+window.BiXUI.count('guestSessions',plan.count)+'. '+
     'Только гостевая учётная запись guestwlan (VLAN 30). '+
    'Индивидуальные Captive Portal учётные записи и авторизованные сессии не затрагиваются.','plan-note');
  add(area,'p','Пропущены: устаревшие '+plan.skipped_stale+
    ', после roaming '+plan.skipped_roaming+', некорректные '+plan.skipped_invalid+
    '. Сессии Omada без поддержки Disconnect: '+plan.omada_unsupported+'.','secondary');
  if(!plan.within_limit){
   add(area,'p','Подтверждённых сессий больше безопасного лимита '+plan.limit+
    '. Операция не выполняется.','warning-inline');
  }else if(!plan.count){
   add(area,'p','Подтверждённых текущих гостевых сессий UniFi нет.','secondary');
  }
  const list=add(area,'ul');
  for(const target of plan.targets){
   add(list,'li',target.nas_ip+' · '+target.mac+' · '+target.session_id);
  }
  const b=add(area,'button',window.BiXUI.actionCount('guestDisconnect',plan.count),'action-button warn guest-execute');
  b.type='button';
  b.disabled=!plan.count||!plan.within_limit;
  b.addEventListener('click',()=>runGuestBatch(data));
  panel.scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){guestFeedback('Не удалось построить план Disconnect: '+e.message,'error');}
 finally{updateGuestButtons();}
}

let manualRefreshBusy=false;
function manualRefreshMessage(message,kind='info'){
 const el=$('manual-refresh-result');
 el.textContent=message;
 el.className='disconnect-result '+kind+(message?'':' hidden');
}
async function refreshFromRadiusGateway(){
 if(manualRefreshBusy)return;
 manualRefreshBusy=true;
 $('manual-refresh').disabled=true;
 $('manual-refresh').textContent='Экспортируем…';
 manualRefreshMessage('Запрашиваем новый экспорт данных с RadiusGateway…','pending');
 try{
  const response=await fetch('/api/snapshot/refresh',{method:'POST',cache:'no-store'});
  let answer={};try{answer=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok)throw new Error(answer.detail||('HTTP '+response.status));
  await refresh();
  manualRefreshMessage('Новый экспорт с RadiusGateway получен: '+formatTime(answer.as_of)+'. Таблицы обновлены.','success');
 }catch(error){
  manualRefreshMessage('Новый экспорт не выполнен: '+error.message+'. Старые данные сохранены.','error');
 }finally{
  manualRefreshBusy=false;
  $('manual-refresh').textContent='Обновить данные сейчас';
  // Do not incorrectly enable the button in demo/offline mode.
  $('manual-refresh').disabled=!lastManualRefreshAvailable;
 }
}
let lastManualRefreshAvailable=false;

// v0.10.6: persistent, read-only administrative audit display.
const AUDIT_ACTION_LABELS={
 ADMIN_LOGIN:'Вход администратора',ADMIN_LOGOUT:'Выход администратора',
 ADMIN_PASSWORD_CHANGE:'Смена пароля администратора',
 SNAPSHOT_REFRESH:'Новый экспорт снимка',UNIFI_EAP_REAUTH:'Запрос EAP-проверки',
 UNIFI_DISCONNECT_PMKSA:'UniFi Disconnect / PMKSA',ACCOUNTING_CLOSE:'Закрытие Accounting',
 RADIUS_USER_ENABLED:'Изменение Enabled RADIUS',RADIUS_USER_VLAN:'Изменение VLAN',
 PORTAL_USER_ENABLED:'Изменение Enabled портала',PORTAL_SESSION_END:'Завершение сессии портала',
 GUEST_WIFI_ENABLED:'Изменение guestwlan',GUEST_WIFI_DISCONNECT_BATCH:'Гостевой UniFi Disconnect',
 OMADA_DISCONNECT:'Omada Disconnect'
};
const AUDIT_STATES={started:'Начато · нет результата',success:'Успешно',
 partial:'Частично',rejected:'Отклонено',error:'Ошибка'};
let auditOffset=0;
let auditTotal=0;
function auditClean(value){
 if(value===null||value===undefined)return '—';
 if(typeof value==='boolean')return value?'true':'false';
 return String(value);
}
function renderAudit(a){
 auditTotal=a.total;
 $('audit-count').textContent=window.BiXUI.count('records',a.total);
 const rows=$('audit-rows');rows.replaceChildren();
 for(const item of a.items){
  const tr=add(rows,'tr');
  let td=cell(tr,'Время');add(td,'span',formatTime(item.started_at));
  td=cell(tr,'Администратор');addRaw(td,'span',item.actor,'principal');
  td=cell(tr,'Операция');add(td,'span',AUDIT_ACTION_LABELS[item.action]||item.action,'principal');
  td=cell(tr,'Цель');
  const target=Object.entries(item.target).map(([k,v])=>k+': '+auditClean(v)).join(' · ');
  addRaw(td,'span',target||'—','secondary mono');
  td=cell(tr,'Результат');
  const state=add(td,'span',AUDIT_STATES[item.state]||item.state,'state');
  const stateClass=item.state==='success'?'fresh':item.state==='partial'?'stale':null;
  if(stateClass)state.classList.add(stateClass);
  td=cell(tr,'Подробности');
  const outcome=Object.entries(item.outcome).map(([k,v])=>k+': '+auditClean(v)).join(' · ');
  addRaw(td,'span','HTTP '+(item.http_status??'—')+(outcome?' · '+outcome:''),'secondary');
 }
 $('audit-empty').classList.toggle('hidden',a.items.length>0);
 $('audit-page-info').textContent=(a.items.length?auditOffset+1:0)+'–'+(a.items.length?Math.min(a.total,auditOffset+a.items.length):0)+' из '+a.total;
 $('audit-prev').disabled=auditOffset===0;
 $('audit-next').disabled=auditOffset+50>=a.total;
}
async function refreshAudit(){
 if(ui.tab!=='audit')return;
 const q=new URLSearchParams({limit:'50',offset:String(auditOffset)});
 if($('audit-action').value)q.set('action',$('audit-action').value);
 if($('audit-state').value)q.set('state',$('audit-state').value);
 const el=$('audit-error');el.textContent='';el.classList.add('hidden');
 try{
  const a=await fetchData('/api/audit?'+q);
  if(a.total>0 && auditOffset>=a.total){
   auditOffset=Math.floor((a.total-1)/50)*50;
   return refreshAudit();
  }
  if(!a.total)auditOffset=0;
  renderAudit(a);
 }catch(e){el.textContent='Не удалось прочитать журнал аудита: '+e.message;el.classList.remove('hidden');}
}
for(const [action,name] of Object.entries(AUDIT_ACTION_LABELS)){
 const opt=document.createElement('option');opt.value=action;opt.textContent=name;
 $('audit-action').append(opt);
}
for(const id of ['audit-action','audit-state'])$(id).addEventListener('change',()=>{auditOffset=0;refreshAudit();});
$('audit-prev').addEventListener('click',()=>{if(auditOffset===0)return;auditOffset=Math.max(0,auditOffset-50);refreshAudit();});
$('audit-next').addEventListener('click',()=>{if(auditOffset+50>=auditTotal)return;auditOffset+=50;refreshAudit();});
$('audit-reload').addEventListener('click',refreshAudit);


async function refresh(){
 if(ui.tab==='audit')return refreshAudit();
 $('refresh').disabled=true;setError('');
 try{
  const o=await fetchData('/api/overview');lastManualRefreshAvailable=Boolean(o.meta.manual_refresh_enabled);setMode(o.meta);
  for(const key of ['total','fresh','stale','ended'])$('stat-'+key).textContent=o.sessions[key];
  const sp=new URLSearchParams({state:ui.sessionView==='history'?'ended':ui.state,nas:ui.nas,query:ui.search,include_portal:String(ui.includePortal),limit:String(ui.pageSize),offset:String(ui.offset)});
  const up=new URLSearchParams({category:ui.userCategory,query:ui.userSearch,limit:String(ui.userSize),offset:String(ui.userOffset)});
  const pp=new URLSearchParams({query:ui.portalSearch,limit:String(ui.portalSize),offset:String(ui.portalOffset)});
  const [s,u,p,guest]=await Promise.all([fetchData('/api/sessions?'+sp),fetchData('/api/users?'+up),
   fetchData('/api/portal-users?'+pp),fetchData('/api/users?category=guest_wifi')]);
  renderSessions(s.items,s.total,o.meta);renderUsers(u.items,u.total,o.meta);renderPortal(p);
  const gw=guest.items.find(x=>x.username==='guestwlan'&&x.kind==='guest_wifi');
  guestUser=gw||null;
  if(guestUser){
   guestUser.guest_disconnect_available=Boolean(o.meta.guest_disconnect_enabled);
  }
  if(guestUser&&guestPendingEnabled!==null && guestUser.enabled===guestPendingEnabled){
   guestPendingEnabled=null;
  }
  $('guest-status').textContent=!guestUser?'Нет подтверждённых данных':
    guestPendingEnabled!==null?'Ожидаем синхронизации':
    guestUser.enabled?'Включено':'Выключено';
  $('guest-status').className='state '+(guestUser&&guestPendingEnabled===null&&guestUser.enabled?'fresh':'stale');
  updateGuestButtons();
 }catch(e){setError('Не удалось прочитать данные: '+e.message);}
 finally{$('refresh').disabled=false;}
}
window.addEventListener('bix:localechange',()=>refresh());
const VALID_TABS=new Set(['sessions','users','portal','audit']);
function tabFromHash(){
 const name=window.location.hash.slice(1);
 return VALID_TABS.has(name)?name:'sessions';
}
function setTab(tab,updateUrl=true){
 if(!VALID_TABS.has(tab))tab='sessions';
 ui.tab=tab;
 if(updateUrl && window.location.hash!=='#'+tab){
  window.history.replaceState(null,'',window.location.pathname+
   window.location.search+'#'+tab);
 }
 for(const b of document.querySelectorAll('[data-tab]'))b.classList.toggle('is-active',b.dataset.tab===tab);
 for(const view of ['sessions','users','portal','audit'])$(view+'-view').classList.toggle('hidden',tab!==view);
 $('summary-cards').classList.toggle('hidden',tab!=='sessions');
 $('plan-panel').classList.add('hidden');
 const meta={sessions:['RADIUS-сессии','Учёт всех клиентов UniFi и Omada. Статус по Accounting — оценка, а не проверка AP.'],
 users:['Пользователи RADIUS','Локальные записи с VLAN; без VLAN — в Captive Portal.'],
 portal:['Captive Portal','Локальные записи без VLAN, Enabled и состояние авторизации.'],
 audit:['Журнал аудита','Постоянная история административных операций и результатов.']}[tab];
 $('page-title').textContent=meta[0];$('page-description').textContent=meta[1];$('crumb').textContent=meta[0];
 if(tab==='audit')refreshAudit();
}
let debounce;function scheduleSearchRefresh(){clearTimeout(debounce);debounce=setTimeout(refresh,220);}
for(const b of document.querySelectorAll('[data-tab]'))b.addEventListener('click',()=>setTab(b.dataset.tab));
window.addEventListener('hashchange',()=>setTab(tabFromHash(),false));
for(const b of document.querySelectorAll('[data-session-view]'))b.addEventListener('click',()=>{
 ui.sessionView=b.dataset.sessionView;ui.offset=0;
 for(const x of document.querySelectorAll('[data-session-view]')){
  const selected=x===b;x.classList.toggle('is-selected',selected);x.setAttribute('aria-selected',String(selected));
 }
 $('session-state-filters').classList.toggle('hidden',ui.sessionView==='history');
 $('session-heading').textContent=ui.sessionView==='history'?'История завершённых сессий':'Текущие RADIUS-сессии';
 $('session-subtitle').textContent=ui.sessionView==='history'?'Не более двух последних Accounting Stop на устройство':'Fresh и Stale; все UniFi, Omada и гостевые Wi-Fi-клиенты';
 $('session-time-heading').textContent=ui.sessionView==='history'?'Accounting Stop':'Последний Update';
 refresh();
});
for(const b of document.querySelectorAll('[data-state]'))b.addEventListener('click',()=>{
 ui.state=b.dataset.state;ui.offset=0;for(const f of document.querySelectorAll('[data-state]'))f.classList.toggle('is-selected',b===f);refresh();
});
$('nas-filter').addEventListener('change',e=>{ui.nas=e.target.value;ui.offset=0;refresh();});
$('session-search').addEventListener('input',e=>{ui.search=e.target.value;ui.offset=0;scheduleSearchRefresh();});
$('portal-toggle').addEventListener('change',e=>{ui.includePortal=e.target.checked;ui.offset=0;refresh();});
$('user-category').addEventListener('change',e=>{ui.userCategory=e.target.value;ui.userOffset=0;refresh();});
$('user-search').addEventListener('input',e=>{ui.userSearch=e.target.value;ui.userOffset=0;scheduleSearchRefresh();});
$('portal-search').addEventListener('input',e=>{ui.portalSearch=e.target.value;ui.portalOffset=0;scheduleSearchRefresh();});
$('portal-prev-page').addEventListener('click',()=>{ui.portalOffset=Math.max(0,ui.portalOffset-ui.portalSize);refresh();});
$('portal-next-page').addEventListener('click',()=>{ui.portalOffset+=ui.portalSize;refresh();});
$('refresh').addEventListener('click',refresh);
$('manual-refresh').addEventListener('click',refreshFromRadiusGateway);
const passwordDialog=$('password-change-dialog');
const passwordForm=$('password-change-form');
const passwordError=$('password-change-error');
const passwordSubmit=$('password-change-submit');
let passwordSaving=false;

function passwordChangeError(message){
 passwordError.textContent=message||'';
 passwordError.classList.toggle('hidden',!message);
}
$('password-change-open').addEventListener('click',()=>{
 if(passwordSaving||passwordDialog.open)return;
 passwordChangeError('');
 passwordForm.reset();
 passwordDialog.showModal();
 $('password-current').focus();
});
$('password-change-cancel').addEventListener('click',()=>{
 if(!passwordSaving)passwordDialog.close();
});
passwordDialog.addEventListener('cancel',event=>{
 if(passwordSaving)event.preventDefault();
});
passwordDialog.addEventListener('close',()=>{
 passwordForm.reset();
 passwordChangeError('');
});
passwordForm.addEventListener('submit',async event=>{
 event.preventDefault();
 if(passwordSaving)return;
 const current=$('password-current').value;
 const next=$('password-new').value;
 const confirm=$('password-confirm').value;
 if(next.length<16||next.length>256){passwordChangeError('Новый пароль должен содержать от 16 до 256 символов');return;}
 if(next!==confirm){passwordChangeError('Подтверждение нового пароля не совпадает');return;}
 if(next===current){passwordChangeError('Новый пароль должен отличаться от текущего');return;}
 passwordSaving=true;
 passwordSubmit.disabled=true;
 $('password-change-cancel').disabled=true;
 passwordSubmit.textContent='Сохраняем…';
 passwordChangeError('');
 try{
  const response=await fetch('/api/auth/change-password',{
   method:'POST',cache:'no-store',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({current_password:current,new_password:next,confirm_password:confirm})
  });
  let data={};
  try{data=await response.json();}catch{}
  if(response.status===401){window.location.replace('/login');return;}
  if(!response.ok)throw new Error(data.detail||('Ошибка сохранения: '+response.status));
  passwordForm.reset();
  window.location.replace('/login?changed=1');
 }catch(e){
  passwordChangeError(e.message||'Не удалось сменить пароль');
  passwordSaving=false;
  passwordSubmit.disabled=false;
  $('password-change-cancel').disabled=false;
  passwordSubmit.textContent='Сохранить пароль';
 }
});

$('logout-button').addEventListener('click',async()=>{
 const b=$('logout-button');b.disabled=true;
 try{
  const r=await fetch('/api/auth/logout',{method:'POST',credentials:'same-origin'});
  if(!r.ok)throw new Error('Не удалось завершить сеанс');
  window.location.replace('/login');
 }catch(e){setError(e.message);b.disabled=false;}
});
$('prev-page').addEventListener('click',()=>{ui.offset=Math.max(0,ui.offset-ui.pageSize);refresh();});
$('next-page').addEventListener('click',()=>{ui.offset+=ui.pageSize;refresh();});
$('user-prev-page').addEventListener('click',()=>{ui.userOffset=Math.max(0,ui.userOffset-ui.userSize);refresh();});
$('user-next-page').addEventListener('click',()=>{ui.userOffset+=ui.userSize;refresh();});
$('close-plan').addEventListener('click',()=>$('plan-panel').classList.add('hidden'));
$('guest-enable').addEventListener('click',()=>changeGuestEnabled(true));
$('guest-disable').addEventListener('click',()=>changeGuestEnabled(false));
$('guest-preview').addEventListener('click',previewGuestBatch);
setTab(tabFromHash(),false);
refresh();setInterval(()=>{if(!document.hidden)refresh();},30000);
