const {test} = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {Guard} = require('../dist/index.js');

async function sidecar(run) {
  let response = {decision:'ALLOW',reason_code:'synthetic',requires_human:false,explanation:'synthetic'};
  const captured=[];
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;
    captured.push(JSON.parse(body));
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify(response));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const guard=new Guard({baseUrl:`http://127.0.0.1:${server.address().port}`,
      token:'synthetic-test-only',mode:'enforce',timeoutMs:500});
    await run(guard,captured,value=>{response={...response,...value};});
  } finally {await new Promise(resolve=>server.close(resolve));}
}

test('BLOCK prevents wrapped tool execution',async()=>sidecar(async(guard,captured,set)=>{
  set({decision:'BLOCK'});let calls=0;
  const tool=guard.tool('navigate',()=>{calls++;},{sessionId:'synthetic',arguments:{url:'http://orders.lab.test/'}});
  await assert.rejects(()=>tool('http://external.invalid/'),{name:'GuardBlockedError'});
  assert.equal(calls,0);assert.equal(captured[0].arguments.url,'http://external.invalid/');
}));

test('checked explicit and default arguments are the executed arguments',async()=>sidecar(async(guard,captured)=>{
  const executed=[];
  const tool=guard.tool('navigate',(url='http://external.invalid/')=>executed.push(url),
    {sessionId:'synthetic',arguments:{url:'http://orders.lab.test/'}});
  await tool();await tool('http://orders.lab.test/notes');
  assert.deepEqual(executed,captured.map(r=>r.arguments.url));
  assert.equal(executed[0],'http://orders.lab.test/');
}));

test('unknown or malformed decisions fail closed',async()=>sidecar(async(guard,captured,set)=>{
  let calls=0;const tool=guard.tool('read_page',()=>calls++,{sessionId:'synthetic'});
  set({decision:'SURPRISE'});await assert.rejects(()=>tool());
  set({decision:'ALLOW',requires_human:'no'});await assert.rejects(()=>tool());
  assert.equal(calls,0);
}));

test('CONFIRM without an approver never executes',async()=>sidecar(async(guard,captured,set)=>{
  set({decision:'CONFIRM',requires_human:true});let calls=0;
  await assert.rejects(()=>guard.tool('submit',()=>calls++,{sessionId:'synthetic'})());
  assert.equal(calls,0);
}));

test('monitor records BLOCK but executes',async()=>{
  const original=global.fetch;let calls=0;
  global.fetch=async()=>new Response(JSON.stringify({decision:'BLOCK',reason_code:'synthetic',
    requires_human:false,explanation:'synthetic'}),{status:200});
  try {
    const guard=new Guard({baseUrl:'http://127.0.0.1:1',token:'synthetic',mode:'monitor'});
    await guard.tool('read_page',()=>calls++,{sessionId:'synthetic'})();assert.equal(calls,1);
  } finally {global.fetch=original;}
});

test('external sidecars are rejected before network access',()=>{
  assert.throws(()=>new Guard({baseUrl:'https://external.invalid',token:'synthetic',mode:'enforce'}));
});
