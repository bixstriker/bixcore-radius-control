'use strict';
const form=document.getElementById('login-form');
const button=document.getElementById('login-submit');
const error=document.getElementById('login-error');
form.addEventListener('submit',async event=>{
 event.preventDefault();
 if(button.disabled)return;
 button.disabled=true;
 button.textContent='Проверяем…';
 error.classList.add('hidden');
 error.textContent='';
 try{
  const username=document.getElementById('login-username').value.trim();
  const password=document.getElementById('login-password').value;
  const response=await fetch('/api/auth/login',{
   method:'POST',cache:'no-store',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({username,password})
  });
  let data={};
  try{data=await response.json();}catch{}
  if(!response.ok)throw new Error(data.detail||('Ошибка входа '+response.status));
  window.location.replace('/');
 }catch(e){
  error.textContent=e.message||'Не удалось выполнить вход';
  error.classList.remove('hidden');
  button.disabled=false;
  button.textContent='Войти';
 }
});

if(new URLSearchParams(window.location.search).get('changed')==='1'){
 const success=document.getElementById('login-success');
 success.textContent='Пароль изменён. Войди с новым паролем.';
 success.classList.remove('hidden');
}
