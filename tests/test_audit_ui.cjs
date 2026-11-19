'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const app=fs.readFileSync(path.join(__dirname,'../app/static/app.js'),'utf8');
const begin=app.indexOf('const AUDIT_ACTION_LABELS=');
const end=app.indexOf('async function refresh(){',begin);
assert(begin>0 && end>begin,'Audit UI fragment exists');

function harness(fetchImpl){
  const els=new Map();
  const makeNode=()=>({
    textContent:'', value:'', disabled:false, children:[], handlers:{},
    classList:{
      classes:new Set(),
      add(s){if(!s)throw new SyntaxError("Failed to execute 'add' on 'DOMTokenList': The token provided must not be empty.");this.classes.add(s);},
      remove(s){this.classes.delete(s);},
      toggle(s,forced){if(!s)throw new SyntaxError('Empty token');if(forced===true){this.classes.add(s);return true;}if(forced===false){this.classes.delete(s);return false;}if(this.classes.has(s)){this.classes.delete(s);return false;}this.classes.add(s);return true;}
    },
    append(n){this.children.push(n);},
    replaceChildren(){this.children=[];},
    addEventListener(type,callback){this.handlers[type]=callback;}
  });
  const $=(id)=>{if(!els.has(id))els.set(id,makeNode());return els.get(id);};
  const add=(parent,tag,text='',klass='')=>{const el=makeNode();el.textContent=String(text);el.tag=tag;el.className=klass;parent.append(el);return el;};
  const ctx={
    $,document:{createElement:makeNode},
    window:{BiXUI:{count:(_,n)=>n+' записей'}},
    add,cell:(parent,name)=>add(parent,'td'),addRaw:add,
    formatTime:(t)=>t,
    URLSearchParams,
    ui:{tab:'audit'},
    fetchData:fetchImpl
  };
  vm.createContext(ctx);vm.runInContext(app.slice(begin,end),ctx);
  return {ctx,$,makeNode,setOffset:(v)=>vm.runInContext('auditOffset='+v,ctx)};
}
const event=(state,i=1)=>({state,action:'SNAPSHOT_REFRESH',actor:'admin',started_at:'2026-11-19T00:00:00Z',target:{id:i},outcome:{},http_status:state==='rejected'?422:200});

test('all audit states render without DOMTokenList empty-token exception',()=>{
  const h=harness(async()=>{throw Error('not called')});
  const items=['rejected','error','started','partial','success'].map(event);
  h.ctx.renderAudit({total:items.length,items});
  assert.equal(h.$('audit-rows').children.length,5);
  assert.equal(h.$('audit-page-info').textContent,'1–5 из 5');
  assert(h.$('audit-empty').classList.classes.has('hidden'));
  assert.equal(h.$('audit-next').disabled,true);
  const r=h.$('audit-rows').children;
  assert(r[3].children[4].children[0].classList.classes.has('stale'));
  assert(r[4].children[4].children[0].classList.classes.has('fresh'));
});
test('stale offset 50 is automatically clamped to first page of 8',async()=>{
  const called=[];
  const h=harness(async url=>{const o=Number(new URLSearchParams(url.split('?')[1]).get('offset'));called.push(o);return {total:8,items:o?[]:Array.from({length:8},(_,i)=>event('success',i))}});
  h.setOffset(50);
  await h.ctx.refreshAudit();
  assert.deepEqual(called,[50,0]);
  assert.equal(h.$('audit-page-info').textContent,'1–8 из 8');
  assert.equal(h.$('audit-rows').children.length,8);
  assert.equal(h.$('audit-prev').disabled,true);
  assert.equal(h.$('audit-next').disabled,true);
  assert(h.$('audit-error').classList.classes.has('hidden'));
});
test('next-page button is guarded and page boundaries remain valid',async()=>{
  const h=harness(async url=>{
    const o=Number(new URLSearchParams(url.split('?')[1]).get('offset'));
    return {total:52,items:Array.from({length:Math.max(0,Math.min(50,52-o))},(_,i)=>event('success',i+o))};
  });
  await h.ctx.refreshAudit();
  assert.equal(h.$('audit-next').disabled,false);
  h.$('audit-next').handlers.click();
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.$('audit-page-info').textContent,'51–52 из 52');
  assert.equal(h.$('audit-next').disabled,true);
});
test('zero records show sensible pagination and empty state',()=>{
  const h=harness(async()=>{});
  h.ctx.renderAudit({total:0,items:[]});
  assert.equal(h.$('audit-page-info').textContent,'0–0 из 0');
  assert.equal(h.$('audit-prev').disabled,true);
  assert.equal(h.$('audit-next').disabled,true);
});
