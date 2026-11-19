import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { run } from '../harness/agent.mjs';

test('official local gateway accepts a fresh split practice fixture', {timeout:10000}, async t => {
  const dir = await mkdtemp(join(tmpdir(),'practice-'));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const middle = randomBytes(16).toString('hex');
  const script = await readFile(new URL('../local/practice/entrypoint.sh',import.meta.url),'utf8');
  const note = script.match(/^echo "(The flag is split[^"]+)" > \/code\/README.txt$/m)[1];
  await writeFile(join(dir,'flag.txt'),'flag{\n');
  await writeFile(join(dir,'README.txt'),note);
  const target = http.createServer((req,res) => {
    assert.equal(req.headers['x-run-token'],undefined);
    assert.ok(['/flag.txt','/brace.txt'].includes(req.url));
    res.end(req.url === '/flag.txt' ? middle : '}');
  });
  await new Promise(r => target.listen(0,'127.0.0.1',r));
  t.after(() => { target.closeAllConnections(); target.close(); });
  const env = {RUN_TOKEN:randomBytes(12).toString('hex'),FLAG:'flag{'+middle+'}',LLM_BASE_URL:''};
  const gateway = spawn(process.execPath,['local/gateway.mjs'],{env,stdio:['ignore','pipe','pipe']});
  t.after(async () => {
    if (gateway.exitCode !== null || gateway.signalCode !== null) return;
    const stopped = once(gateway,'close');
    gateway.kill();
    await stopped;
  });
  await Promise.race([once(gateway.stdout,'data'),once(gateway,'exit').then(() => { throw Error('Local port 8080 unavailable'); })]);
  assert.equal(await run(dir,{RUN_TOKEN:env.RUN_TOKEN,GATEWAY_URL:'http://127.0.0.1:8080/gateway',TARGETS:'127.0.0.1:'+target.address().port}),0);
});
