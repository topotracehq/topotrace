const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
// Minimal DOM adapter: test renderer output without introducing a browser dependency.
class Node {
  constructor(tag,text=''){this.tag=tag;this.value=text;this.children=[];this.attrs={};}
  append(...nodes){for(const n of nodes){if(n.tag==='#fragment')this.children.push(...n.children);else this.children.push(n);}}
  get textContent(){return this.value+this.children.map(n=>n.textContent).join('');}
}
const el=(tag,attrs={},...children)=>{const n=new Node(tag,attrs.text||'');n.attrs=attrs;n.append(...children);return n;};
const document={createDocumentFragment:()=>new Node('#fragment'),createTextNode:t=>new Node('#text',t)};
const context={window:{},document};vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/docs.js'),'utf8'),context);
const render=context.window.MusterDocs({el}).render;
const all=nodes=>nodes.flatMap(n=>[n,...all(n.children)]);
test('source line wrapping becomes one paragraph',()=>{
  const nodes=render('# Guide\n\nA paragraph that wraps\nacross source lines.\n\nNext paragraph.');
  assert.equal(nodes.length,3);assert.equal(nodes[1].textContent,'A paragraph that wraps across source lines.');
});
test('numbered procedures preserve step boundaries and continuation lines',()=>{
  const nodes=render('3. Capture a backup\n   and check it.\n4. Restore separately.\n\n## Verify');
  assert.equal(nodes[0].tag,'ol');assert.equal(nodes[0].attrs.start,'3');assert.equal(nodes[0].children.length,2);
  assert.equal(nodes[0].children[0].textContent,'Capture a backup and check it.');assert.equal(nodes[1].tag,'h3');
});
test('tables and code retain their contents',()=>{
  const nodes=render('| Name | Value |\n|---|---|\n| OS | `linux` |\n\n```sh\necho "<hello>"\n```');
  assert.equal(nodes[0].attrs.class,'docs-table-wrap');assert.equal(all(nodes).filter(n=>n.tag==='td').length,2);
  assert.equal(nodes[1].textContent,'echo "<hello>"');
});
test('untrusted markup and unsafe links never become executable nodes',()=>{
  const nodes=render('<img src=x onerror=alert(1)>\n\n[unsafe](javascript:alert) [network](//evil.test) [guide](recovery.md) [web](https://example.com)');
  const links=all(nodes).filter(n=>n.tag==='a');assert.equal(links.length,2);
  assert.equal(links[0].attrs.href,'#/docs/recovery');assert.equal(links[1].attrs.rel,'noopener noreferrer');
  assert.equal(all(nodes).filter(n=>n.tag==='img'||n.tag==='script').length,0);assert.ok(nodes[0].textContent.includes('<img'));
});
