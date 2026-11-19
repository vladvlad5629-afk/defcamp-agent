import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { run } from '../harness/agent.mjs';
import { decode, valid, notebook } from '../harness/analysis.mjs';

const flag = 'flag{' + randomBytes(16).toString('hex') + '}';
test('decoders and strict flag validation', () => {
  assert.equal(decode(Buffer.from(Buffer.from(flag).toString('hex')), ['hex']),flag);
  assert.equal(valid(flag),true);
  assert.equal(valid('flag{'+'f'.repeat(32)+'}'),false);
  assert.throws(() => decode(Buffer.from('123'),['hex']));
});

async function scenario(t, { replies = [], cents = 5, seconds = 100, correct = true, plain = false }) {
  const dir = await mkdtemp(join(tmpdir(),'encoding-'));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const data = plain ? flag : Buffer.from(Buffer.from(flag).toString('base64')).reverse();
  await writeFile(join(dir,'message'),data);
  await writeFile(join(dir,'notes'),'h'.repeat(200));
  const events = [];
  const server = createServer(async(req,res) => {
    assert.equal(req.headers['x-run-token'],'fixture');
    const path = req.url;
    assert.ok(path.startsWith('/nested/gateway/'));
    let body = '';
    for await (const chunk of req) body += chunk;
    const parsed = JSON.parse(body || '{}');
    events.push([path.split('/').pop(),parsed]);
    let answer = {};
    if (path.endsWith('/health')) answer = {secondsLeft:seconds,centsLeft:cents};
    if (path.endsWith('/flag')) { assert.equal(parsed.flag,flag); answer = {correct}; }
    if (path.endsWith('/completions')) {
      const reply = replies.shift();
      assert.ok(reply);
      res.statusCode = reply.status || 200;
      res.setHeader('Retry-After','0');
      const id = JSON.parse(parsed.messages[1].content).files.find(f => f.name === 'message').id;
      const args = reply.args === 'message' ? {id,steps:['reverse','base64']} : reply.args;
      const message = reply.tool ? {content:null,tool_calls:[{id:'call-'+events.length,type:'function',function:{name:reply.tool,arguments:JSON.stringify(args)}}]} : {content:reply.content};
      answer = {choices:[{message}],usage:{total_tokens:12}};
    }
    res.end(JSON.stringify(answer));
  });
  await new Promise(r => server.listen(0,'127.0.0.1',r));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const status = await run(dir,{RUN_TOKEN:'fixture',GATEWAY_URL:'http://127.0.0.1:'+server.address().port+'/nested/gateway'});
  return {status,events};
}
const solution = {tool:'derive',args:'message'};
test('recover after busy, oversize context, idle model and bad tool, then verify bytes',async t => {
  const {status,events} = await scenario(t,{replies:[{status:429},{status:400},{content:'{}'},{tool:'inspect',args:{id:999,offset:0,length:8}},solution,{tool:'verify',args:{id:2}}]});
  assert.equal(status,0);
  const calls = events.filter(([p]) => p === 'completions');
  assert.equal(calls.length,6);
  assert.ok(calls[2][1].messages[1].content.length < calls[1][1].messages[1].content.length);
  assert.ok(calls[4][1].messages.some(m=>m.role==='tool' && m.content.includes('Unknown artifact id')));
  assert.equal(JSON.parse(calls[5][1].messages[1].content).tokensUsed,36);
  assert.equal(events.filter(([p])=>p==='flag').length,1);
});
for (const [name,opts,note] of [
  ['exhausted budget',{cents:0},'Model budget exhausted'],
  ['near deadline',{seconds:2},'Time reserve'],
  ['rejected result',{plain:true,correct:false,cents:0},'Model budget exhausted'],
  ['model declines',{replies:Array(3).fill({content:'{}'})},'Model repeatedly idle'],
  ['gateway spending limit',{replies:[{status:402}]},'Model budget exhausted']
]) test(name,async t => {
  const {status,events} = await scenario(t,opts);
  assert.equal(status,1);
  assert.deepEqual(events.at(-1),['give-up',{message:note}]);
});
test('closed run makes no further requests',async t => {
  const {events} = await scenario(t,{replies:[{status:409}]});
  assert.equal(events.at(-1)[0],'completions');
});

test('inspect, locate and reconstruct a split artifact from exact byte ranges', () => {
  const local = notebook([{data:Buffer.from('prefix ' + flag.slice(0,18))},{data:Buffer.from(flag.slice(18))}]);
  assert.deepEqual(local('find_text',{id:0,text:'flag{'}).offsets,[7]);
  assert.equal(local('inspect',{id:0,offset:7,length:5}).text,'flag{');
  const part = local('derive',{id:0,offset:7,length:18,steps:[]});
  const whole = local('join_parts',{ids:[part.id,1]});
  assert.equal(local('verify',{id:whole.id}).candidate,flag);
  assert.throws(()=>local('inspect',{id:0,offset:-1,length:2}));
});
test('keyed hypothesis uses original bytes including whitespace', () => {
  const data = Buffer.from([32,0,10,255]);
  const local = notebook([{data:Buffer.from(data.toString('base64'))}]);
  const a=local('derive',{id:0,steps:['base64','xor'],keyHex:'ff'});
  assert.equal(local('inspect',{id:a.id,offset:0,length:4}).hex,'dffff500');
});
