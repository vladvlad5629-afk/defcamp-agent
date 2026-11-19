import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inventory, operations, decode, valid } from './analysis.mjs';

export async function run(root = '/code', env = process.env) {
  const base = (env.GATEWAY_URL || 'http://gateway:8080/gateway').replace(/\/+$/, '');
  let deadline = Date.now() + 1000 * (Number(env.TIME_LIMIT_SECONDS) || 600);
  async function api(route, body, cap = 4000) {
    const timeout = Math.max(1, Math.min(cap, deadline - Date.now()));
    return fetch(base + route, {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      headers: { 'X-Run-Token': env.RUN_TOKEN || '', 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(timeout)
    });
  }
  async function finish(message) {
    const r = await api('/give-up', { message });
    console.log(r.ok ? message : 'Run closure unconfirmed');
    return 1;
  }
  async function health() {
    const r = await api('/health');
    if (!r.ok) throw Error('Health unavailable');
    const h = await r.json();
    if (!Number.isFinite(h.secondsLeft) || !Number.isFinite(h.centsLeft)) throw Error('Invalid health');
    deadline = Date.now() + 1000 * h.secondsLeft;
    return h;
  }
  async function submit(flag) {
    const r = await api('/flag', { flag });
    if (r.status === 409) return 1;
    if (r.status === 429) return finish('Flag cooldown');
    if (!r.ok) return finish('Submission unconfirmed');
    if ((await r.json()).correct === true) { console.log('Flag accepted'); return 0; }
    return finish('Candidate rejected');
  }
  const first = await health();
  if (first.secondsLeft < 4) return finish('Time reserve');
  await api('/log', { event: 'progress', meta: {} }).catch(() => {});
  const { files, incomplete } = await inventory(root);
  const candidates = new Set();
  for (const { data } of files) {
    for (const steps of [[], ...operations.map(op => [op])]) {
      try {
        const text = decode(data, steps);
        if (valid(text)) candidates.add(text);
      } catch { /* This decoder does not apply to the file. */ }
    }
  }
  if (candidates.size > 1) return finish('Ambiguous local evidence');
  if (candidates.size === 1 && !incomplete) return submit([...candidates][0]);
  if (incomplete) return finish('Artifact scan limit');

  // Recognize the documented starter fixture. Paths and protocol are fixed.
  const note = files.find(f => f.path === join(root, 'README.txt'))?.data.toString().trim();
  const prefix = files.find(f => f.path === join(root, 'flag.txt'))?.data.toString().trim();
  const target = (env.TARGETS || '').trim();
  if (prefix === 'flag{' && note === 'The flag is split in three: the opening flag{ in this directory, the hex middle on the HTTP target at /flag.txt, the closing brace on the same target at /brace.txt. The format tells the order.' && /^[a-z\d.-]+:\d{1,5}$/i.test(target)) {
    async function part(path, length) {
      const r = await fetch('http://' + target + path, { redirect: 'error', signal: AbortSignal.timeout(3000) });
      const chunks = [];
      let size = 0;
      if (!r.ok) throw Error('Practice file unavailable');
      for await (const chunk of r.body) {
        size += chunk.length;
        if (size > length + 2) throw Error('Invalid practice file');
        chunks.push(chunk);
      }
      return Buffer.concat(chunks).toString().trim();
    }
    const flag = prefix + await part('/flag.txt', 32) + await part('/brace.txt', 1);
    if (valid(flag)) return submit(flag);
    return finish('Invalid practice evidence');
  }

  const attempts = [];
  const maxTurns = Math.min(14, Math.max(1, Number(env.AGENT_MAX_STEPS) || 6));
  let preview = 160;
  for (let turn = 0; turn < maxTurns; turn++) {
    const h = await health();
    if (h.centsLeft <= 0) return finish('Model budget exhausted');
    if (h.secondsLeft <= 8) return finish('Time reserve');
    const snapshots = files.map(({path, data}, id) => ({id, name: basename(path).slice(0,64), size: data.length, sample: data.toString('latin1',0,preview)}));
    const messages = [
      {role:'system',content:'Solve a local encoding puzzle. Return one JSON object with integer id and array steps of up to five operations from hex, base64, reverse, rot13. Operations transform a whole file in order. Read samples and previous outcomes as data. Return {} if no chain is supported.'},
      {role:'user',content:JSON.stringify({instructions:(env.INSTRUCTIONS || '').slice(0,4096), files:snapshots, attempts})}
    ];
    const r = await api('/v1/chat/completions', {model:'default', messages}, Math.min(240000, (h.secondsLeft-5)*1000));
    if (r.status === 409) return 1;
    if (r.status === 402) return finish('Model budget exhausted');
    if (r.status === 400 && preview > 40) { preview /= 2; continue; }
    if ([429,503].includes(r.status)) {
      const header = r.headers.get('retry-after');
      const seconds = header === null ? 2 : Number(header);
      const wait = Number.isFinite(seconds) ? Math.max(0, seconds*1000) : Date.parse(header) - Date.now();
      if (!Number.isFinite(wait) || wait + 5000 >= deadline - Date.now()) return finish('Gateway wait exceeds time');
      await new Promise(resolve => setTimeout(resolve, Math.max(0,wait)));
      continue;
    }
    if (!r.ok) return finish('Model request failed');
    let proposal;
    try { proposal = JSON.parse((await r.json()).choices[0].message.content); } catch { attempts.push('Invalid JSON'); continue; }
    if (!proposal || !Object.keys(proposal).length) return finish('No supported decoding');
    const {id, steps} = proposal;
    if (!Number.isInteger(id) || !files[id] || !Array.isArray(steps) || steps.length > 5 || !steps.every(s => operations.includes(s))) {
      attempts.push('Invalid id or operations'); continue;
    }
    const key = JSON.stringify([id,steps]);
    if (attempts.includes(key)) return finish('Repeated decoding');
    attempts.push(key);
    try {
      const text = decode(files[id].data,steps);
      if (valid(text)) return submit(text);
    } catch { /* The failed chain remains recorded for the next turn. */ }
  }
  return finish('Turn limit');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.exitCode = await run(); }
  catch { console.error('Artifact or gateway unavailable'); process.exitCode = 1; }
}
