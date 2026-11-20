// AISafe Agentic CTF harness â€” tuned for a weak model (Qwen 3.8 27B, medium).
// Single file, Node 22, no dependencies. Drop-in replacement for the starter
// agent.mjs; same gateway contract and the same chat/anthropic/responses
// request formats.
//
// What it adds over the starter:
//   * Deterministic recon BEFORE the first model call: read /code, probe every
//     target (HTTP + raw TCP), and try the obvious flag spots. Many warm-ups
//     fall here at zero model cost; the rest start with a high-signal briefing.
//   * Relentless flag capture: every tool output AND the model's own text is
//     scanned for flag{32 hex}; split flags are reassembled across surfaces;
//     placeholders and already-tried flags are skipped so the team's wrong-flag
//     cooldown is never wasted.
//   * Context control: big outputs are saved to disk and only a head+tail goes
//     into history, and old tool results are trimmed, so the conversation never
//     grows past the model's context (avoids the 400 that kills the starter).
//   * Health/budget aware: polls /health, stops with time to spare for a useful
//     give-up note, and never spends past the cost cap.
//
// Everything printed here becomes the run's stdout, shown to the team after a
// capture (and always on the practice challenge). We print as we go.
import { execFile } from "node:child_process";
import { writeFileSync, mkdirSync, readdirSync, statSync, readFileSync } from "node:fs";

// ---- config ---------------------------------------------------------------
const GATEWAY = (process.env.GATEWAY_URL ?? "http://gateway:8080/gateway").replace(/\/+$/, "");
const TOKEN = process.env.RUN_TOKEN ?? "";
const TARGETS = (process.env.TARGETS ?? "").split(",").map((t) => t.trim()).filter(Boolean);
const RUN_ID = process.env.RUN_ID ?? "";
const FORMAT = process.env.HARNESS_FORMAT ?? "chat";
const MAX_STEPS = Number(process.env.AGENT_MAX_STEPS ?? 40);
const RESERVE_SECONDS = 60;        // leave time for a final submit and note
const BASH_TIMEOUT_MS = 25_000;    // per command
const RESULT_HEAD = 2800;          // chars of a tool result kept in context (head)
const RESULT_TAIL = 700;           // + tail
const HISTORY_BUDGET = 70_000;     // chars of history before old results get trimmed
const INSTRUCTIONS = (process.env.INSTRUCTIONS ?? "").trim();
const OUT_DIR = "/tmp/agent-out";
try { mkdirSync(OUT_DIR, { recursive: true }); } catch {}

// ---- category detection (v2 dispatcher) -----------------------------------
const CRYPTO_RE = /\b(rsa|aes|des|ecb|cbc|ctr|xor|cipher|encrypt|decrypt|nonce|padding|oracle|hashlib|getprime|modulus|exponent|ecdsa|elgamal|diffie|lcg|prng|getrandbits|pycryptodome|crypto\.)\b/i;
const WEB_RE = /\b(flask|django|express|@app\.route|app\.(get|post|route)|http\.server|fastapi|cookie|session|jwt|sqlalchemy|render_template|request\.(args|form|cookies)|werkzeug|<html|<\?php)\b/i;

function elfMagic(p) {
  try { const b = readFileSync(p); return b.length > 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46; }
  catch { return false; }
}
function detectCategory() {
  let files = []; try { files = walkCode().filter((f) => !f.dir); } catch {}
  const bins = []; let text = "";
  for (const f of files) {
    if (f.size > 0 && elfMagic(f.path)) { bins.push(f.path); continue; }
    if (f.size > 0 && f.size <= 200000) { try { const b = readFileSync(f.path, "utf8"); if (!/\x00/.test(b.slice(0, 256))) text += "\n" + b; } catch {} }
  }
  const names = files.map((f) => f.path).join("\n");
  const hay = names + "\n" + text;
  let cat = "misc", why = "no strong signal â€” verify yourself";
  if (bins.length) { cat = TARGETS.length ? "pwn" : "rev"; why = `ELF binary present (${bins.map((b) => b.split("/").pop()).join(", ")})` + (TARGETS.length ? " + live target" : " + no target"); }
  else if (CRYPTO_RE.test(hay) && !WEB_RE.test(hay)) { cat = "crypto"; why = "crypto primitives in source"; }
  else if (WEB_RE.test(hay) || (TARGETS.length && /\.(php|html|js|mjs|py)\b/i.test(names))) { cat = "web"; why = "web app source / HTTP target"; }
  else if (TARGETS.length) { cat = "misc"; why = "live target, no clear binary/crypto/web signal"; }
  return { cat, why, bins };
}
const DET = detectCategory();

const PLAYBOOKS = {
  web: "WEB. Map every route, auth-check and flag-location from /code. Then with curl -i (cookies -c/-b): IDOR (change id/user/uuid), auth/role bypass, JWT (alg=none / weak secret â€” decode & forge in python), path traversal/LFI, SQLi/NoSQLi, SSTI ({{7*7}}), command injection, mass-assignment, verb tampering, open redirect, debug/admin/backup routes, /.git/, robots.txt. The flag shows at a privileged/edge state.",
  crypto: "CRYPTO. python3 has pwntools, pycryptodome, gmpy2, sympy. Read /code for scheme+params, then attack: reused/known XOR key, nonce/IV reuse, ECB cut-paste, weak/seeded PRNG (LCG/getrandbits recovery), RSA small-e / shared-modulus / common-factor (gmpy2.iroot, sympy), padding/MAC oracle, hash length-extension, textbook-RSA malleability. If the target is an oracle, script a pwntools remote() loop to query and recover the flag.",
  pwn: "PWN. python3 has pwntools; gdb, objdump, nm, readelf, ROPgadget, checksec installed. The BINARY ANALYSIS block above already ran /app/pwn_recon.py (arch, RELRO/canary/NX/PIE, hot symbols). Find the bug (overflow via gets/read/scanf, format string via printf(user), off-by-one). Find the offset with cyclic()/cyclic_find() by running the binary LOCALLY (it is in /code and executes here). If a win/backdoor/getflag symbol exists -> ret2win (on 64-bit add a bare `ret` gadget for stack alignment). Else: fmtstr_payload for format strings; or leak libc (puts(puts@got) then ret2main, ret2system). Build with pwntools and fire at the REMOTE target r=remote(host,port); print r.recvall() and grep flag.",
  rev: "REV. python3+pwntools, objdump -d, strings -n6, readelf, nm, gdb. The flag is built/checked inside the binary. strings for embedded data; read disasm of main/check to recover the algorithm; invert the transform in python (xor/add/sub/shuffle vs an embedded target buffer) to reconstruct the flag; or compute the accepted password/key for a gate. If a live target runs the binary, satisfy its check over pwntools/nc.",
  misc: "MISC. Read /code for the exact mechanism (encoding, stego, custom protocol, logic puzzle). Decode with python3/base64/xxd/openssl. If the target speaks a protocol, probe with nc/pwntools and answer its prompts programmatically. Automate repeated/rate-limited steps.",
};

const SYSTEM = [
  "You are an elite autonomous CTF player. Goal: capture the flag and submit it with submit_flag.",
  "The flag is ALWAYS flag{ + 32 lowercase hex + }, unique to this run. Any flag{...} in the shipped source is a PLACEHOLDER â€” ignore flag{000...} and similar.",
  "It can be SPLIT across surfaces; order by shape: the 'flag{' piece first, bare 32-hex middle, '}' last. Assemble, echo the whole thing, submit.",
  "Surfaces: /code (read-only challenge files â€” READ FIRST) and TARGETS live services" + (TARGETS.length ? ` (${TARGETS.join(", ")})` : "") + " (protocol not given; HTTP first, else raw TCP).",
  `This challenge looks like ${DET.cat.toUpperCase()} (${DET.why}). Strong hint, not a cage â€” switch if the evidence disagrees.`,
  "Offline container tools: bash, python3 (pwntools, pycryptodome, gmpy2, sympy, requests), gdb, objdump/readelf/nm, ROPgadget, checksec, curl, nc, jq, openssl, xxd.",
  "Playbook â€” " + PLAYBOOKS[DET.cat],
  "Be decisive; limited turns. The moment you see a full flag{32hex} anywhere, submit it. A rejection means keep working, not stop.",
  ...(INSTRUCTIONS
    ? ["\n\nYour team's instructions for THIS run (follow them unless they contradict the rules above):\n" + INSTRUCTIONS]
    : []),
].join(" ");

const TOOLS = [
  {
    name: "bash",
    description:
      "Run a shell command in the harness container (sh -c). Use it to read /code, probe TARGETS, decode data, and run exploits. Long outputs are saved to a file and you get a head+tail with the path; read parts with sed -n/grep. For jobs over ~20s, run in background (cmd & ) and poll.",
    parameters: {
      type: "object",
      properties: { command: { type: "string", description: "The shell command to run" } },
      required: ["command"],
    },
  },
  {
    name: "submit_flag",
    description: "Submit the complete flag flag{32 hex}. Ends the run when correct; a wrong flag just means keep looking.",
    parameters: {
      type: "object",
      properties: { flag: { type: "string", description: "The complete flag, flag{32 hex}" } },
      required: ["flag"],
    },
  },
];

// ---- request/response formats (chat | anthropic | responses) --------------
function parseArgs(text) {
  try {
    const args = JSON.parse(text || "{}");
    if (args && typeof args === "object" && !Array.isArray(args)) return { args };
    return { args: {}, argsError: "the arguments must be a JSON object" };
  } catch (err) {
    return { args: {}, argsError: `the arguments were not valid JSON (${err.message})` };
  }
}

const formats = {
  chat: {
    path: "/v1/chat/completions",
    request: (history, tools = TOOLS) => ({
      model: "default",
      messages: [{ role: "system", content: SYSTEM }, ...history],
      ...(tools.length ? { tools: tools.map((t) => ({ type: "function", function: t })) } : {}),
    }),
    parse(data) {
      const message = data.choices?.[0]?.message ?? {};
      return {
        text: message.content ?? "",
        calls: (message.tool_calls ?? []).map((c) => ({ id: c.id, name: c.function?.name, ...parseArgs(c.function?.arguments) })),
      };
    },
    user: (text) => [{ role: "user", content: text }],
    assistant: (turn) => [{
      role: "assistant",
      content: turn.text || null,
      tool_calls: turn.calls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.args) } })),
    }],
    results: (results) => results.map((r) => ({ role: "tool", tool_call_id: r.id, content: r.output })),
  },
  anthropic: {
    path: "/v1/messages",
    request: (history, tools = TOOLS) => ({
      model: "default",
      max_tokens: 8192,
      system: SYSTEM,
      messages: history,
      ...(tools.length ? { tools: tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters })) } : {}),
    }),
    parse(data) {
      const blocks = data.content ?? [];
      return {
        text: blocks.filter((b) => b.type === "text").map((b) => b.text).join("\n"),
        calls: blocks.filter((b) => b.type === "tool_use").map((b) => ({ id: b.id, name: b.name, args: b.input ?? {} })),
      };
    },
    user: (text) => [{ role: "user", content: text }],
    assistant: (turn) => [{
      role: "assistant",
      content: [
        ...(turn.text ? [{ type: "text", text: turn.text }] : []),
        ...turn.calls.map((c) => ({ type: "tool_use", id: c.id, name: c.name, input: c.args })),
      ],
    }],
    results: (results) => [{ role: "user", content: results.map((r) => ({ type: "tool_result", tool_use_id: r.id, content: r.output })) }],
  },
  responses: {
    path: "/v1/responses",
    request: (history, tools = TOOLS) => ({
      model: "default",
      instructions: SYSTEM,
      input: history,
      ...(tools.length ? { tools: tools.map((t) => ({ type: "function", ...t })) } : {}),
    }),
    parse(data) {
      const items = data.output ?? [];
      return {
        text: items.filter((i) => i.type === "message").map((i) => (i.content ?? []).map((c) => c.text).join("")).join("\n"),
        calls: items.filter((i) => i.type === "function_call").map((i) => ({ id: i.call_id, name: i.name, ...parseArgs(i.arguments) })),
      };
    },
    user: (text) => [{ role: "user", content: text }],
    assistant: (turn) => [
      ...(turn.text ? [{ role: "assistant", content: turn.text }] : []),
      ...turn.calls.map((c) => ({ type: "function_call", call_id: c.id, name: c.name, arguments: JSON.stringify(c.args) })),
    ],
    results: (results) => results.map((r) => ({ type: "function_call_output", call_id: r.id, output: r.output })),
  },
};
const format = formats[FORMAT] ?? formats.chat;

// ---- gateway helpers ------------------------------------------------------
function post(path, body, timeout = 30_000) {
  return fetch(`${GATEWAY}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Run-Token": TOKEN },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeout),
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function log(event, meta) { return post("/log", { event, meta }).catch(() => {}); }

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\\"'\\\"'")}'`;
}

async function health() {
  try {
    const r = await fetch(`${GATEWAY}/health`, { headers: { "X-Run-Token": TOKEN }, signal: AbortSignal.timeout(10_000) });
    const h = await r.json();
    return { seconds: typeof h.secondsLeft === "number" ? h.secondsLeft : Infinity, cents: typeof h.centsLeft === "number" ? h.centsLeft : Infinity };
  } catch { return { seconds: Infinity, cents: Infinity }; }
}

async function giveUp(note) {
  note = String(note).slice(0, 32);
  console.log(`[agent] giving up: ${note}`);
  await post("/give-up", { message: note }).catch(() => {});
  process.exit(1);
}

const tried = new Set();
let lastNote = "started";
let lastTool = "none";   // last timeline tool category, for the diagnostic note
let lastStep = 0;        // last step reached, for the diagnostic note
async function submitFlag(flag, where = "") {
  flag = String(flag).trim();
  if (!flag) return "empty flag";
  if (tried.has(flag)) return "already tried this flag";
  tried.add(flag);
  console.log(`[agent] submitting ${flag}${where ? ` (from ${where})` : ""}`);
  await log("flag_found");
  for (let attempt = 0; attempt < 4; attempt++) {
    let response;
    try { response = await post("/flag", { flag }); }
    catch { await sleep(2000); continue; }
    if (response.status === 409) { console.log("[agent] run already ended"); process.exit(1); }
    const verdict = await response.json().catch(() => ({}));
    if (verdict.correct === true) {
      console.log(`[agent] FLAG ACCEPTED (${verdict.points} pts): ${flag}`);
      process.exit(0);
    }
    if (response.status === 429) { // gateway cooldown can follow an earlier candidate
      const wait = Math.min(15, Math.max(2, Number(response.headers.get("Retry-After")) || 10));
      console.log(`[agent] flag cooldown, waiting ${wait}s`);
      tried.delete(flag); // allow a genuine retry after cooldown if re-seen
      tried.add(flag);
      await sleep(wait * 1000);
      continue;
    }
    console.log(`[agent] flag rejected: ${verdict.error ?? "incorrect"}`);
    return String(verdict.error ?? "incorrect flag, keep looking");
  }
  return "flag submission kept failing";
}

// ---- flag extraction / assembly -------------------------------------------
const isPlaceholder = (f) => /^flag\{(.)\1{31}\}$/.test(f) || f === "flag{" + "0".repeat(32) + "}";
const pieces = { prefix: "", hex: "", brace: false };

// Return a complete flag{32hex} found directly, or assembled from split pieces.
function findFlag(text) {
  if (!text) return null;
  const direct = (text.match(/flag\{[0-9a-fA-F]{32}\}/g) || []).map((f) => f.toLowerCase()).find((f) => !isPlaceholder(f) && !tried.has(f));
  if (direct) return direct;
  // split pieces
  const prefix = text.match(/flag\{[0-9a-fA-F]*/);
  if (prefix && prefix[0].length >= pieces.prefix.length) pieces.prefix = prefix[0].toLowerCase();
  const hex = text.match(/(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])/);
  if (hex) pieces.hex = hex[0].toLowerCase();
  if (/(^|[^0-9a-fA-F])\}(\s|$)/.test(text) || /^\s*\}\s*$/m.test(text)) pieces.brace = true;
  if (pieces.prefix.startsWith("flag{") && pieces.hex && pieces.brace) {
    const candidate = `flag{${pieces.hex}}`;
    if (!isPlaceholder(candidate) && !tried.has(candidate)) return candidate;
  }
  return null;
}

// Scan arbitrary text; submit if a usable flag appears. Returns true if submitted.
async function scanAndSubmit(text, where) {
  const flag = findFlag(text);
  if (flag) { await submitFlag(flag, where); return true; } // submitFlag exits on success
  return false;
}

// ---- deterministic recon --------------------------------------------------
function sh(command, timeout = BASH_TIMEOUT_MS) {
  return new Promise((resolve) => {
    execFile("sh", ["-c", command], { timeout, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve(`${stdout ?? ""}${stderr ?? ""}` + (err?.killed ? "\n[killed: timed out]" : ""));
    });
  });
}

function walkCode(dir = "/code", depth = 0, acc = []) {
  if (depth > 4 || acc.length > 400) return acc;
  let entries = [];
  try { entries = readdirSync(dir); } catch { return acc; }
  for (const name of entries.sort()) {
    const p = `${dir}/${name}`;
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) { acc.push({ path: p, dir: true, size: 0 }); walkCode(p, depth + 1, acc); }
    else acc.push({ path: p, dir: false, size: st.size });
  }
  return acc;
}

async function recon() {
  const out = [];
  out.push("=== DETERMINISTIC RECON (done for you) ===");
  // 1) /code listing + small text/source files
  const files = walkCode();
  if (files.length) {
    out.push("/code files:");
    for (const f of files) out.push(`  ${f.dir ? "[dir] " : ""}${f.path}${f.dir ? "" : ` (${f.size}b)`}`);
    const textish = /\.(txt|md|py|js|mjs|c|h|cpp|go|rs|rb|php|java|sh|json|yaml|yml|cfg|conf|ini|env|html|htm|xml|sql|pl|lua|asm|s|toml|csv|log|key|pem)$/i;
    for (const f of files.filter((f) => !f.dir)) {
      const small = f.size > 0 && f.size <= 20_000;
      const named = /README|FLAG|HINT|NOTE|ORIGIN|TODO|secret|conf/i.test(f.path);
      if (small && (textish.test(f.path) || named)) {
        let body = ""; try { body = readFileSync(f.path, "utf8"); } catch {}
        if (body && /[\x00]/.test(body.slice(0, 200)) === false) {
          out.push(`\n----- ${f.path} -----\n${body.slice(0, 4000)}${body.length > 4000 ? "\n...[truncated]" : ""}`);
        }
      }
    }
    // identify non-text files (binaries, archives)
    const bins = files.filter((f) => !f.dir && f.size > 0).map((f) => f.path);
    if (bins.length) out.push("\nfile types:\n" + (await sh(`file ${bins.slice(0, 40).map(shellQuote).join(" ")} 2>/dev/null`)).slice(0, 2000));
    // v2: deep ELF analysis for pwn/rev challenges
    if (DET.bins.length) {
      out.push("\n=== BINARY ANALYSIS (pwntools) ===");
      for (const b of DET.bins.slice(0, 3)) {
        out.push(`\n----- ${b} -----`);
        out.push((await sh(`python3 /app/pwn_recon.py ${shellQuote(b)} 2>&1`, 40_000)).slice(0, 3500));
      }
    }
    // v3: category-specialized deterministic recon for crypto + web
    if (DET.cat === "crypto") out.push("\n" + (await sh(`python3 /app/crypto_recon.py 2>&1`, 40_000)).slice(0, 3500));
    if (DET.cat === "web") out.push("\n" + (await sh(`python3 /app/web_recon.py 2>&1`, 40_000)).slice(0, 3500));
    // v4: deterministic AUTO-SOLVERS run first (zero-LLM). Flags they print get auto-submitted.
    if (DET.cat === "rev" && DET.bins.length) out.push("\n=== AUTO-SOLVER angr ===\n" + (await sh(`python3 /app/auto_solve.py rev ${shellQuote(DET.bins[0])} 2>&1`, 340_000)).slice(0, 3000));
    if (DET.cat === "crypto") out.push("\n=== AUTO-SOLVER crypto ===\n" + (await sh(`python3 /app/auto_solve.py crypto 2>&1`, 140_000)).slice(0, 3000));
  } else {
    out.push("/code is empty or unreadable.");
  }
  // 2) probe targets
  for (const t of TARGETS) {
    const split = t.lastIndexOf(":");
    const host = split === -1 ? t : t.slice(0, split);
    const port = split === -1 ? "" : t.slice(split + 1);
    if (!host || !/^\d{1,5}$/.test(port)) {
      out.push(`\n=== TARGET ${t} ===\nSkipped malformed target.`);
      continue;
    }
    out.push(`\n=== TARGET ${t} ===`);
    // HTTP probe of common spots
    const httpProbe = await sh(
      `for path in / /index.html /flag /flag.txt /brace.txt /robots.txt /README /readme.txt /.git/HEAD /api /admin /login /debug /source /app.py /index.php; do ` +
      `echo "### GET $path"; curl -s -m 6 -D - ${shellQuote(`http://${host}:${port}`)}"$path" 2>/dev/null | head -c 1200; echo; done`, 40_000);
    if (/HTTP\//.test(httpProbe)) out.push("HTTP responses:\n" + httpProbe.slice(0, 6000));
    else {
      // raw TCP banner
      const banner = await sh(`(printf '\\n'; sleep 2) | nc -w 3 ${shellQuote(host)} ${shellQuote(port)} 2>/dev/null | head -c 1500`, 12_000);
      out.push("raw TCP banner (sent newline):\n" + (banner.trim() || "(no banner; may need a specific protocol/input)"));
    }
  }
  return out.join("\n");
}

// ---- model call with retries ----------------------------------------------
async function ask(history, timeoutMs) {
  const response = await post(format.path, format.request(history), timeoutMs);
  if (!response.ok) {
    const reason = (await response.text().catch(() => "")).replace(/\s+/g, " ").trim().slice(0, 200);
    const err = new Error(`gateway ${response.status}${reason ? `: ${reason}` : ""}`);
    err.status = response.status;
    err.retryAfter = Number(response.headers.get("Retry-After")) || 0;
    throw err;
  }
  return format.parse(await response.json());
}

async function askWithRetries(history, step) {
  for (let strikes = 0; ; ) {
    const { seconds, cents } = await health();
    if (seconds < RESERVE_SECONDS) await finish(history, `out of time @step${step}`);
    if (cents <= 0) await finish(history, `out of budget @step${step}`);
    const timeout = Math.min(240, Math.max(30, seconds - RESERVE_SECONDS + 5)) * 1000;
    try { return await ask(history, timeout); }
    catch (err) {
      if (err.status === 402) await finish(history, `out of budget @step${step}`);
      if (err.status === 409) await giveUp("run ended");
      if (err.status === 429 || err.status === 503) {
        const wait = Math.min(60, Math.max(2, err.retryAfter || 5));
        console.log(`[agent] model busy (${err.status}), retry in ${wait}s`);
        await sleep(wait * 1000);
        continue;
      }
      if (err.status === 400) {
        // likely context too long â€” trim hard and retry once as a strike
        console.log(`[agent] 400 from gateway, trimming context`);
        hardTrim(history);
      }
      strikes++;
      await log("error");
      if (strikes >= 6) await giveUp(`LLM failed @step${step}`);
      console.log(`[agent] llm call failed (${err.message}), retry ${strikes}/5`);
      await sleep(strikes * 2500);
    }
  }
}

// ---- context management ----------------------------------------------------
function clip(output) {
  if (output.length <= RESULT_HEAD + RESULT_TAIL + 120) return output;
  const id = Math.random().toString(36).slice(2, 8);
  const path = `${OUT_DIR}/${id}.txt`;
  try { writeFileSync(path, output); } catch {}
  return output.slice(0, RESULT_HEAD) +
    `\n...[${output.length - RESULT_HEAD - RESULT_TAIL} bytes omitted â€” full output saved to ${path}; read parts with: sed -n '1,120p' ${path} | grep ...]...\n` +
    output.slice(-RESULT_TAIL);
}

function historySize(history) { return JSON.stringify(history).length; }

// Trim the oldest tool-result payloads to stubs when history grows too large.
function softTrim(history) {
  if (historySize(history) < HISTORY_BUDGET) return;
  const stub = "[earlier tool output trimmed to save context]";
  let trimmed = 0;
  for (const m of history) {
    if (historySize(history) < HISTORY_BUDGET) break;
    // chat: role tool; responses: function_call_output; anthropic: user with tool_result array
    if (m.role === "tool" && typeof m.content === "string" && m.content.length > stub.length) { m.content = stub; trimmed++; }
    else if (m.type === "function_call_output" && m.output && m.output.length > stub.length) { m.output = stub; trimmed++; }
    else if (m.role === "user" && Array.isArray(m.content)) {
      for (const b of m.content) if (b.type === "tool_result" && typeof b.content === "string" && b.content.length > stub.length) { b.content = stub; trimmed++; }
    }
  }
  if (trimmed) console.log(`[agent] trimmed ${trimmed} old tool outputs (ctx ${historySize(history)}b)`);
}

// Aggressive trim on a 400: keep the first briefing + last 8 entries.
function hardTrim(history) {
  if (history.length <= 10) return;
  const keepHead = history.slice(0, 1);
  const keepTail = history.slice(-8);
  history.length = 0;
  history.push(...keepHead, format.user("[context trimmed after a provider error; continue from the recent steps]")[0], ...keepTail);
}

// ---- tool execution --------------------------------------------------------
async function runBash(command) {
  const output = await sh(command, BASH_TIMEOUT_MS);
  return (output.trim() || "(no output)");
}

async function runTool(call, step) {
  if (call.argsError) return `error: ${call.argsError}. Call ${call.name} again with valid JSON arguments.`;
  if (call.name === "submit_flag") {
    const flag = String(call.args.flag ?? "").trim();
    if (!/^flag\{/.test(flag)) {
      // maybe the model passed only the hex or a split piece; try to use it
      const found = findFlag(flag) || findFlag("flag{" + flag.replace(/[^0-9a-fA-F]/g, "") + "}");
      if (found) return await submitFlag(found, "submit_flag");
      return `that does not look like flag{32 hex}: ${flag.slice(0, 40)}`;
    }
    const m = flag.match(/flag\{[0-9a-fA-F]{32}\}/);
    if (!m) return `flag must be flag{ + 32 hex + }, got: ${flag.slice(0, 40)}`;
    return await submitFlag(m[0].toLowerCase(), "submit_flag");
  }
  const command = call.args.command ?? call.args.cmd ?? "";
  console.log(`[agent] bash: ${command.slice(0, 300)}`);
  const output = await runBash(command);
  console.log(`[agent] -> ${output.slice(0, 300).replace(/\n/g, " ")}`);
  // Classify into the gateway's allowed enum so the live timeline is diagnostic
  // (bash|python|http|read_file|submit_flag|other); anything else is coerced to other.
  const toolCat = classifyTool(command);
  lastTool = toolCat; lastStep = step;
  await log("tool_use", { tool: toolCat });
  await scanAndSubmit(output, "bash output"); // exits on success
  return clip(output);
}

// Map a shell command to the most informative allowed timeline category.
function classifyTool(cmd) {
  if (/(^|\s)(curl|wget|ncat|nc)\s|openssl\s+s_client|https?:\/\//.test(cmd)) return "http";
  if (/(^|\s)(python3?|pip3?)\s|\.py(\s|$)|RsaCtfTool|angr/.test(cmd)) return "python";
  if (/(^|\s)(cat|less|head|tail|sed|awk|strings|objdump|readelf|nm|xxd|file|ls|find|grep|od|hexdump)\s/.test(cmd)) return "read_file";
  return "bash";
}

// ---- give-up note ----------------------------------------------------------
async function finish(history, fallback) {
  await log("stuck");
  console.log(`[agent] ${fallback} â€” asking model for a note`);
  const ask2 = format.user(
    `Stop here (${fallback}). Your team sees only a 32-character note from this run. ` +
    "Write it: what you found and where you got stuck, e.g. \"web LFI ok, flag not reachable\". " +
    "No file contents, keys or flag pieces. Reply with the note text only.");
  let note = "";
  try {
    const { seconds } = await health();
    const timeout = Math.max(15, Math.min(120, seconds - 10)) * 1000;
    const r = await post(format.path, format.request([...history.slice(-12), ...ask2], []), timeout);
    if (r.ok) note = (format.parse(await r.json()).text ?? "").trim();
  } catch {}
  note = note.split("\n").map((l) => l.trim()).filter(Boolean).pop() ?? "";
  note = note.replace(/^["'`]+|["'`]+$/g, "");
  // Deterministic diagnostic prefix (visible on FAILED runs, where stdout is hidden):
  // <category>|<last tool category>|s<last step> then the model's short hint.
  const tag = `${DET.cat.slice(0, 5)}|${lastTool.slice(0, 4)}|s${lastStep}`;
  let out = (note ? `${tag} ${note}` : `${tag} ${fallback}`).slice(0, 32).trim();
  await giveUp(out || tag.slice(0, 32));
}

// ---- main ------------------------------------------------------------------
console.log(`[agent] online (v2): run ${RUN_ID}, format ${FORMAT}, max ${MAX_STEPS} steps, category=${DET.cat} (${DET.why})` +
  (INSTRUCTIONS ? `, ${INSTRUCTIONS.length} chars instructions` : "") + `, targets: ${TARGETS.join(", ") || "none"}`);
await log("progress");

// Phase 1: deterministic recon. Scans for flags as it goes (may capture + exit).
let briefing = "";
try {
  briefing = await recon();
  console.log(`[agent] recon done (${briefing.length} chars)`);
  await scanAndSubmit(briefing, "recon"); // exits on success if a flag was sitting in plain sight
} catch (e) {
  console.log(`[agent] recon error: ${e.message}`);
  briefing = "(recon failed; explore /code and TARGETS yourself)";
}

// Phase 2: model-driven loop, seeded with the briefing.
const history = format.user(
  "Solve this CTF challenge and submit the flag. Here is recon already gathered for you:\n\n" +
  clip(briefing) +
  "\n\nUse it to go straight to the exploit. Read full files in /code with cat/sed, interact with TARGETS, decode as needed. " +
  "The moment you have flag{32hex}, call submit_flag.");

let nudges = 0;
for (let step = 1; step <= MAX_STEPS; step++) {
  console.log(`[agent] --- step ${step}/${MAX_STEPS} ---`);
  softTrim(history);
  const turn = await askWithRetries(history, step);
  if (turn.text) { console.log(`[agent] model: ${turn.text.slice(0, 500)}`); await scanAndSubmit(turn.text, "model text"); }
  history.push(...format.assistant(turn));

  if (turn.calls.length === 0) {
    if (++nudges > 2) await finish(history, `model stopped @step${step}`);
    history.push(...format.user("Keep going: call bash to investigate, or submit_flag with the complete flag. Do not stop until you have it."));
    continue;
  }
  const results = [];
  for (const call of turn.calls) results.push({ id: call.id, output: await runTool(call, step) });
  history.push(...format.results(results));
}
await finish(history, `out of steps (${MAX_STEPS})`);

