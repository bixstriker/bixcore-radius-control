"""v0.9.1: the selected BiXCore section survives a browser reload."""
import shutil
import subprocess
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
JS=(ROOT/"app/static/app.js").read_text(encoding="utf8")


class TabPersistenceTests(unittest.TestCase):
    def test_current_tab_restored_before_initial_refresh(self):
        self.assertIn("setTab(tabFromHash(),false);\nrefresh();",JS)
        self.assertIn("window.addEventListener('hashchange',()=>setTab(tabFromHash(),false));",JS)
        self.assertIn("window.history.replaceState",JS)
        self.assertIn("window.location.search+'#'+tab",JS)

    def test_tab_navigation_updates_address_without_server_mutations(self):
        self.assertIn("['sessions','users','portal','audit']",JS)
        self.assertIn("VALID_TABS.has(name)?name:'sessions'",JS)
        self.assertIn("if(!VALID_TABS.has(tab))tab='sessions'",JS)
        self.assertIn("window.location.hash!=='#'+tab",JS)
        self.assertNotIn("localStorage.setItem",JS)
        self.assertNotIn("sessionStorage.setItem",JS)

    @unittest.skipUnless(shutil.which("node"),"Node is required for JavaScript runtime tests")
    def test_actual_tab_functions_with_fake_browser(self):
        start=JS.index("const VALID_TABS=")
        end=JS.index("let debounce;",start)
        source=JS[start:end]
        harness=r"""
const vm=require("node:vm"), assert=require("node:assert/strict");
const source=process.argv[1];
const nodes=new Map();
function node(id){if(!nodes.has(id)){nodes.set(id,{
  textContent:'',classList:{values:new Set(),
   toggle(name,on){if(on)this.values.add(name);else this.values.delete(name);},
   add(name){this.values.add(name);}}
});}return nodes.get(id);}
const navigation=['sessions','users','portal'].map(tab=>({dataset:{tab},classList:node('nav-'+tab).classList}));
const win={
 location:{pathname:'/',search:'?source=test',hash:''},
 history:{replaceState(_a,_b,url){this.lastUrl=url;win.location.hash=url.substring(url.indexOf('#'));}},
 addEventListener(){}};
const ctx=vm.createContext({ui:{tab:'sessions'},window:win,
 document:{querySelectorAll(selector){if(selector==='[data-tab]')return navigation;throw Error(selector);}},
 $:node});
vm.runInContext(source,ctx);
function evalJs(code){return vm.runInContext(code,ctx);}
win.location.hash='#portal';
evalJs('setTab(tabFromHash(),false)');
assert.equal(ctx.ui.tab,'portal');
assert.equal(node('portal-view').classList.values.has('hidden'),false);
assert.equal(node('sessions-view').classList.values.has('hidden'),true);
assert.equal(node('page-title').textContent,'Captive Portal');
evalJs("setTab('users')");
assert.equal(ctx.ui.tab,'users');
assert.equal(win.location.hash,'#users');
assert.equal(win.history.lastUrl,'/?source=test#users');
assert.equal(node('users-view').classList.values.has('hidden'),false);
win.location.hash='#portal';
evalJs('setTab(tabFromHash(),false)');
assert.equal(ctx.ui.tab,'portal');
win.location.hash='#invalid';
evalJs('setTab(tabFromHash(),false)');
assert.equal(ctx.ui.tab,'sessions');
assert.equal(node('sessions-view').classList.values.has('hidden'),false);
win.location.hash='';
evalJs('setTab(tabFromHash(),false)');
assert.equal(ctx.ui.tab,'sessions');
console.log('TAB_RUNTIME_OK');
"""
        result=subprocess.run(["node","-e",harness,source],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("TAB_RUNTIME_OK",result.stdout)


if __name__=="__main__":
    unittest.main()
