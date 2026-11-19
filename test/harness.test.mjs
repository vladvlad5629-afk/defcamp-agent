import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { run } from '../harness/agent.mjs';
import { decode, valid } from '../harness/analysis.mjs';

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
      const content = reply === solution ? JSON.stringify({id, steps:['reverse','base64']}) : reply.content;
      answer = {choices:[{message:{content}}]};
    }
    res.end(JSON.stringify(answer));
  });
  await new Promise(r => server.listen(0,'127.0.0.1',r));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const status = await run(dir,{RUN_TOKEN:'fixture',GATEWAY_URL:'http://127.0.0.1:'+server.address().port+'/nested/gateway'});
  return {status,events};
}
const solution = {content:JSON.stringify({id:0,steps:['reverse','base64']})};
test('busy gateway, smaller context, invalid proposals, verified capture',async t => {
  const {status,events} = await scenario(t,{replies:[{status:429},{status:400},{content:'?'},{content:'{"id":99,"steps":[]}'},solution]});
  assert.equal(status,0);
  const calls = events.filter(([p]) => p === 'completions');
  assert.equal(calls.length,5);
  assert.ok(calls[2][1].messages[1].content.length < calls[1][1].messages[1].content.length);
});
for (const [name,opts,note] of [
  ['exhausted budget',{cents:0},'Model budget exhausted'],
  ['near deadline',{seconds:2},'Time reserve'],
  ['rejected result',{plain:true,correct:false},'Candidate rejected'],
  ['model declines',{replies:[{content:'{}'}]},'No supported decoding'],
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
