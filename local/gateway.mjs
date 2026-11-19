// A local stand-in for the event gateway, with the same routes, token check,
// request formats and status codes.
//
// Routes answer under /gateway (GATEWAY_URL in compose.yaml ends in it, as it
// does at the event) and at the root.
//
// With LLM_BASE_URL set, the model routes go to that OpenAI-compatible
// endpoint with your own key and model. Without it, a scripted mock answers:
// it runs one command and then stops.
//
// Differences from the event: flags are checked against FLAG, every model
// call counts as one cent of COST_LIMIT_CENTS, there is no shared queue, and
// log events are printed here instead of going to your team's timeline.
import http from "node:http";

const PORT = 8080;
const TOKEN = process.env.RUN_TOKEN ?? "local";
const FLAG = process.env.FLAG ?? "";
const INSTRUCTIONS = process.env.INSTRUCTIONS ?? "";
const TIME_LIMIT = Number(process.env.TIME_LIMIT_SECONDS ?? 600);
const COST_LIMIT = Number(process.env.COST_LIMIT_CENTS ?? 100);
const BASE_URL = (process.env.LLM_BASE_URL ?? "").replace(/\/+$/, "");
const API_KEY = process.env.LLM_API_KEY ?? "";
const MODEL = process.env.LLM_MODEL ?? "";
// The event runs the model at reasoning effort "medium". Sent to the provider
// as OpenRouter's reasoning setting; leave it empty for providers that do not
// take one.
const REASONING_EFFORT = process.env.LLM_REASONING_EFFORT ?? "";

const LOG_EVENTS = new Set(["progress", "tool_use", "stuck", "flag_found", "error"]);
const LOG_TOOLS = new Set(["bash", "python", "http", "read_file", "submit_flag", "other"]);
// The path decides the answer's format; /llm works it out from the body.
const LLM_PATHS = new Map([
  ["/llm", null],
  ["/v1/chat/completions", "chat"],
  ["/v1/messages", "anthropic"],
  ["/v1/responses", "responses"],
]);
const PREFIX = "/gateway";
// Wrong flags: one per 10 seconds for the whole team, as at the event.
const FLAG_COOLDOWN_SECONDS = 10;
const MAX_OUTPUT_TOKENS = 8192;
const MAX_IN_FLIGHT = 4;

const startedAt = Date.now();
let spent = 0;
let inFlight = 0;
let logEvents = 0;
let ended = "";
let lastWrongFlagAt = 0;

const secondsLeft = () => Math.max(0, TIME_LIMIT - Math.floor((Date.now() - startedAt) / 1000));

function end(reason) {
  if (ended) return;
  ended = reason;
  console.log(`run ended: ${reason}`);
}

class HttpError extends Error {
  constructor(status, message, retryAfter) {
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

// --- request formats --------------------------------------------------------
//
// Every request is read into one shape:
//   { system, messages: [{ role, text, calls, results }], tools, params }
// and the answer is written back in the format it came in.

function detectFormat(body) {
  if (Array.isArray(body.input) || typeof body.input === "string") return "responses";
  const messages = body.messages ?? [];
  if (messages.some((m) => Array.isArray(m.tool_calls))) return "chat";
  if (body.system !== undefined) return "anthropic";
  const blocks = new Set(messages.flatMap((m) => (Array.isArray(m.content) ? m.content.map((b) => b.type) : [])));
  if (blocks.has("tool_use") || blocks.has("tool_result") || blocks.has("thinking")) return "anthropic";
  if (blocks.has("image_url")) return "chat";
  if ((body.tools ?? []).some((t) => t.input_schema !== undefined)) return "anthropic";
  if ((body.tools ?? []).some((t) => t.function !== undefined)) return "chat";
  if (messages.some((m) => Array.isArray(m.content))) return "anthropic";
  return "chat";
}

function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b) => (typeof b === "string" ? b : b.text ?? "")).filter(Boolean).join("\n");
}

// tool results sit on a user entry; consecutive results share one
function addResult(messages, id, text) {
  const last = messages.at(-1);
  if (last?.role === "user" && last.results) last.results.push({ id, text });
  else messages.push({ role: "user", results: [{ id, text }] });
}

function readChat(body) {
  const messages = [];
  let system;
  for (const m of body.messages ?? []) {
    if (m.role === "system" || m.role === "developer") system ??= textOf(m.content);
    else if (m.role === "tool") addResult(messages, m.tool_call_id, textOf(m.content));
    else {
      messages.push({
        role: m.role,
        text: textOf(m.content),
        calls: (m.tool_calls ?? []).map((c) => ({ id: c.id, name: c.function?.name, args: c.function?.arguments })),
      });
    }
  }
  const tools = (body.tools ?? []).map((t) => ({
    name: t.function?.name,
    description: t.function?.description ?? "",
    parameters: t.function?.parameters ?? { type: "object", properties: {} },
  }));
  return { system, messages, tools };
}

function readAnthropic(body) {
  const messages = [];
  for (const m of body.messages ?? []) {
    const blocks = Array.isArray(m.content) ? m.content : [{ type: "text", text: String(m.content ?? "") }];
    const text = blocks.filter((b) => b.type === "text").map((b) => b.text).join("\n");
    if (m.role === "user") {
      for (const b of blocks.filter((b) => b.type === "tool_result")) addResult(messages, b.tool_use_id, textOf(b.content));
      if (text) messages.push({ role: "user", text });
    } else {
      const calls = blocks
        .filter((b) => b.type === "tool_use")
        .map((b) => ({ id: b.id, name: b.name, args: JSON.stringify(b.input ?? {}) }));
      messages.push({ role: "assistant", text, calls });
    }
  }
  const tools = (body.tools ?? []).map((t) => ({
    name: t.name,
    description: t.description ?? "",
    parameters: t.input_schema ?? { type: "object", properties: {} },
  }));
  return { system: textOf(body.system), messages, tools };
}

function readResponses(body) {
  const messages = [];
  const input = typeof body.input === "string" ? [{ role: "user", content: body.input }] : body.input ?? [];
  for (const item of input) {
    if (item.role && item.role !== "system" && (item.type ?? "message") === "message") {
      messages.push({ role: item.role, text: textOf(item.content) });
    } else if (item.type === "function_call") {
      // parallel calls arrive as separate items but belong to one turn
      const call = { id: item.call_id, name: item.name, args: item.arguments };
      const last = messages.at(-1);
      if (last?.role === "assistant") (last.calls ??= []).push(call);
      else messages.push({ role: "assistant", calls: [call] });
    } else if (item.type === "function_call_output") {
      addResult(messages, item.call_id, String(item.output ?? ""));
    }
  }
  const tools = (body.tools ?? [])
    .filter((t) => t.type === "function")
    .map((t) => ({ name: t.name, description: t.description ?? "", parameters: t.parameters ?? { type: "object", properties: {} } }));
  return { system: body.instructions, messages, tools };
}

function read(body, format) {
  const conversation =
    format === "anthropic" ? readAnthropic(body) : format === "responses" ? readResponses(body) : readChat(body);
  const requested = Number(body.max_tokens ?? body.max_completion_tokens ?? body.max_output_tokens);
  // Sampling settings (temperature, top_p, seed, stop, ...) are ignored, as
  // at the event; only the output cap is passed on.
  conversation.params = {
    max_tokens: requested > 0 ? Math.min(Math.floor(requested), MAX_OUTPUT_TOKENS) : MAX_OUTPUT_TOKENS,
  };
  return conversation;
}

// The upstream is always OpenAI chat completions, which OpenRouter, Ollama
// and most providers speak.
function toChat({ system, messages, tools, params }) {
  const out = system ? [{ role: "system", content: system }] : [];
  for (const m of messages) {
    for (const r of m.results ?? []) out.push({ role: "tool", tool_call_id: r.id, content: r.text });
    if (m.calls?.length) {
      out.push({
        role: "assistant",
        content: m.text || null,
        tool_calls: m.calls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: c.args || "{}" } })),
      });
    } else if (m.text) {
      out.push({ role: m.role, content: m.text });
    }
  }
  return {
    model: MODEL,
    messages: out,
    ...(tools.length ? { tools: tools.map((t) => ({ type: "function", function: t })) } : {}),
    ...(REASONING_EFFORT ? { reasoning: { effort: REASONING_EFFORT } } : {}),
    ...params,
  };
}

async function upstream(conversation) {
  let response;
  try {
    response = await fetch(`${BASE_URL}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify(toChat(conversation)),
      signal: AbortSignal.timeout(180_000),
    });
  } catch (err) {
    // the event gateway gives a call 3 minutes too, then answers 503
    if (err.name === "TimeoutError") throw new HttpError(503, "the provider did not answer within 180 s", 5);
    // A wrong LLM_BASE_URL, no network, a proxy or a TLS problem. Waiting
    // will not fix it, so this is not a "busy" answer.
    throw new HttpError(502, `could not reach ${BASE_URL}: ${err.cause?.message ?? err.message}`);
  }
  const data = await response.json().catch(() => null);
  const message = data?.choices?.[0]?.message;
  if (response.ok && message) {
    return {
      text: message.content || null,
      calls: (message.tool_calls ?? []).map((c) => ({ id: c.id, name: c.function?.name, args: c.function?.arguments || "{}" })),
      tokensIn: data.usage?.prompt_tokens ?? 0,
      tokensOut: data.usage?.completion_tokens ?? 0,
    };
  }
  const said = data?.error?.message ?? (data ? JSON.stringify(data) : "(no JSON body)");
  const detail = `provider answered ${response.status}: ${String(said).slice(0, 300)}`;
  // OpenRouter's daily allowance for free models: nothing to wait for today.
  // The hint goes first, so it survives when a harness prints only the start.
  if (response.status === 429 && /per-day|per day/i.test(said)) {
    throw new HttpError(502, `free daily allowance used up for this key; try tomorrow, another key or a paid model. ${detail}`);
  }
  if (/data policy/i.test(said)) {
    throw new HttpError(502, `refused for your data policy; on openrouter.ai, Settings, Privacy, allow free endpoints. ${detail}`);
  }
  // Same mapping as the event gateway: busy -> 429/503 with Retry-After,
  // a request the model rejects -> 400, a key, model or account problem -> 502.
  if (response.status === 429) throw new HttpError(429, detail, Number(response.headers.get("retry-after")) || 10);
  if (response.status >= 500) throw new HttpError(503, detail, 5);
  if ([400, 413, 422].includes(response.status)) throw new HttpError(400, detail);
  throw new HttpError(502, detail);
}

// No key: one scripted command, then a stop. This shows that the harness
// reaches the gateway and the challenge.
function mock({ messages, tools }) {
  const ranCommand = messages.some((m) => m.results?.length);
  if (!ranCommand && tools.length) {
    const tool = tools.find((t) => /bash|shell|exec|command/i.test(t.name)) ?? tools[0];
    const command = [
      "ls -la /code; cat /code/*.txt",
      "for t in $(echo \"$TARGETS\" | tr ',' ' '); do",
      "  for f in flag.txt brace.txt; do curl -s \"http://$t/$f\" || wget -qO- \"http://$t/$f\"; done",
      "done",
    ].join("\n");
    return { text: null, calls: [{ id: "mock-1", name: tool.name, args: JSON.stringify({ command }) }], tokensIn: 40, tokensOut: 30 };
  }
  return {
    // a request without tools is the starter agent asking for its note
    text: !tools.length
      ? "mock model, no LLM_BASE_URL set"
      : "Mock model: that was the only scripted step. Set LLM_BASE_URL in .env to try a real model.",
    calls: [],
    tokensIn: 80,
    tokensOut: 20,
  };
}

function render(turn, format, model) {
  if (format === "anthropic") {
    const content = [
      ...(turn.text ? [{ type: "text", text: turn.text }] : []),
      ...turn.calls.map((c) => ({ type: "tool_use", id: c.id, name: c.name, input: JSON.parse(c.args || "{}") })),
    ];
    return {
      id: "msg_local", type: "message", role: "assistant", model, content,
      stop_reason: turn.calls.length ? "tool_use" : "end_turn", stop_sequence: null,
      usage: { input_tokens: turn.tokensIn, output_tokens: turn.tokensOut },
    };
  }
  if (format === "responses") {
    const output = [
      ...(turn.text
        ? [{ type: "message", id: "msg_local", role: "assistant", status: "completed",
            content: [{ type: "output_text", text: turn.text, annotations: [] }] }]
        : []),
      ...turn.calls.map((c) => ({
        type: "function_call", id: `fc_${c.id}`, call_id: c.id, name: c.name, arguments: c.args || "{}", status: "completed",
      })),
    ];
    return {
      id: "resp_local", object: "response", status: "completed", model, output,
      usage: { input_tokens: turn.tokensIn, output_tokens: turn.tokensOut, total_tokens: turn.tokensIn + turn.tokensOut },
    };
  }
  return {
    id: "chat_local", object: "chat.completion", model,
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: turn.text,
        ...(turn.calls.length
          ? { tool_calls: turn.calls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: c.args || "{}" } })) }
          : {}),
      },
      finish_reason: turn.calls.length ? "tool_calls" : "stop",
    }],
    usage: { prompt_tokens: turn.tokensIn, completion_tokens: turn.tokensOut, total_tokens: turn.tokensIn + turn.tokensOut },
  };
}

// stream: true gets the whole turn as server-sent events in its own format,
// like the event gateway: one text delta, one delta per tool call, no
// token-by-token streaming.
function renderStream(turn, format, model) {
  const full = render(turn, format, model);
  const out = [];
  const sse = (event, data) => out.push(`${event ? `event: ${event}\n` : ""}data: ${JSON.stringify(data)}\n\n`);

  if (format === "anthropic") {
    sse("message_start", { type: "message_start", message: { ...full, content: [], stop_reason: null, usage: { input_tokens: turn.tokensIn, output_tokens: 0 } } });
    full.content.forEach((block, index) => {
      const text = block.type === "text";
      sse("content_block_start", { type: "content_block_start", index, content_block: text ? { type: "text", text: "" } : { ...block, input: {} } });
      sse("content_block_delta", {
        type: "content_block_delta", index,
        delta: text ? { type: "text_delta", text: block.text } : { type: "input_json_delta", partial_json: JSON.stringify(block.input) },
      });
      sse("content_block_stop", { type: "content_block_stop", index });
    });
    sse("message_delta", { type: "message_delta", delta: { stop_reason: full.stop_reason, stop_sequence: null }, usage: { output_tokens: turn.tokensOut } });
    sse("message_stop", { type: "message_stop" });
  } else if (format === "responses") {
    let seq = 0;
    const ev = (type, data) => sse(type, { type, sequence_number: seq++, ...data });
    ev("response.created", { response: { ...full, status: "in_progress", output: [], usage: null } });
    full.output.forEach((item, output_index) => {
      const at = { item_id: item.id, output_index };
      if (item.type === "message") {
        const text = item.content[0].text;
        const part = { type: "output_text", text: "", annotations: [] };
        ev("response.output_item.added", { output_index, item: { ...item, status: "in_progress", content: [] } });
        ev("response.content_part.added", { ...at, content_index: 0, part });
        ev("response.output_text.delta", { ...at, content_index: 0, delta: text });
        ev("response.output_text.done", { ...at, content_index: 0, text });
        ev("response.content_part.done", { ...at, content_index: 0, part: { ...part, text } });
      } else {
        ev("response.output_item.added", { output_index, item: { ...item, status: "in_progress", arguments: "" } });
        ev("response.function_call_arguments.delta", { ...at, delta: item.arguments });
        ev("response.function_call_arguments.done", { ...at, arguments: item.arguments });
      }
      ev("response.output_item.done", { output_index, item });
    });
    ev("response.completed", { response: full });
  } else {
    const created = Math.floor(Date.now() / 1000);
    const chunk = (choices, extra) => sse(null, { id: full.id, object: "chat.completion.chunk", created, model, choices, ...extra });
    const { message, finish_reason } = full.choices[0];
    chunk([{ index: 0, delta: { role: "assistant", content: message.content ?? "" }, finish_reason: null }]);
    (message.tool_calls ?? []).forEach((call, index) => {
      chunk([{ index: 0, delta: { tool_calls: [{ index, ...call }] }, finish_reason: null }]);
    });
    chunk([{ index: 0, delta: {}, finish_reason }]);
    chunk([], { usage: full.usage });
    out.push("data: [DONE]\n\n");
  }
  return out.join("");
}

// --- routes -----------------------------------------------------------------

async function llm(body, res, pathFormat) {
  if (!ended && secondsLeft() === 0) end("time limit");
  if (ended) throw new HttpError(409, "run ended");
  if (spent + 1 > COST_LIMIT) throw new HttpError(402, "cost limit reached");
  if (inFlight >= MAX_IN_FLIGHT) throw new HttpError(429, `at most ${MAX_IN_FLIGHT} LLM requests in flight per run`, 2);

  const format = pathFormat ?? detectFormat(body);
  const conversation = read(body, format);
  inFlight++;
  let turn;
  try {
    turn = BASE_URL ? await upstream(conversation) : mock(conversation);
  } finally {
    inFlight--;
  }
  spent += 1;
  console.log(`llm ${format}: ${turn.tokensIn} in, ${turn.tokensOut} out, ` +
    `${turn.calls.length} tool call(s)${turn.calls.length ? "" : `, text: ${String(turn.text).slice(0, 120)}`}`);

  // the model you name is ignored; the answer names the one that answered
  const model = MODEL || "mock";
  if (body.stream === true) {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" }).end(renderStream(turn, format, model));
  } else {
    send(res, 200, render(turn, format, model));
  }
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers }).end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

async function handle(req, res) {
  let { pathname } = new URL(req.url, "http://gateway");
  if (pathname === PREFIX || pathname.startsWith(`${PREFIX}/`)) pathname = pathname.slice(PREFIX.length) || "/";
  if (req.headers["x-run-token"] !== TOKEN) return send(res, 401, { error: "bad or missing X-Run-Token" });

  if (req.method === "GET" && pathname === "/health") {
    return send(res, 200, { ok: true, run: process.env.RUN_ID ?? "local", secondsLeft: secondsLeft(), centsLeft: Math.max(0, COST_LIMIT - spent) });
  }
  if (req.method === "GET" && pathname === "/instructions") {
    return res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" }).end(INSTRUCTIONS);
  }
  if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });

  const body = await readJson(req);

  if (LLM_PATHS.has(pathname)) return llm(body, res, LLM_PATHS.get(pathname));

  if (pathname === "/flag") {
    if (ended) return send(res, 409, { error: "run ended" });
    const flag = String(body.flag ?? "");
    // a correct flag is never held back by the cooldown
    if (flag === FLAG) {
      console.log(`flag ACCEPTED: ${flag}`);
      end("flag captured");
      return send(res, 200, { correct: true, points: 0 });
    }
    const wait = Math.ceil(FLAG_COOLDOWN_SECONDS - (Date.now() - lastWrongFlagAt) / 1000);
    if (wait > 0) {
      console.log(`flag refused, cooldown ${wait}s: ${flag}`);
      return send(res, 429, { error: `wrong-flag cooldown: wait ${wait}s` }, { "Retry-After": String(wait) });
    }
    lastWrongFlagAt = Date.now();
    console.log(`flag rejected: ${flag}`);
    return send(res, 200, { correct: false, error: "incorrect flag" });
  }

  if (pathname === "/log") {
    const event = String(body.event ?? "progress");
    if (!LOG_EVENTS.has(event)) return send(res, 400, { error: `unknown event; use one of ${[...LOG_EVENTS].join(", ")}` });
    if (++logEvents > 300) return send(res, 429, { error: "log limit (300 events per run) reached" });
    const tool = event === "tool_use" ? String(body.meta?.tool ?? "other") : "";
    console.log(`log ${event}${tool ? ` ${LOG_TOOLS.has(tool) ? tool : "other"}` : ""}`);
    return send(res, 200, { ok: true });
  }

  if (pathname === "/give-up") {
    const note = String(body.message ?? "").slice(0, 32);
    console.log(`give up: ${JSON.stringify(note)}`);
    end("gave up");
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: "not found" });
}

http
  .createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.log(`${req.method} ${req.url}: ${err.message}`);
      const status = err instanceof HttpError ? err.status : err instanceof SyntaxError ? 400 : 500;
      send(res, status, { error: err.message }, err.retryAfter ? { "Retry-After": String(err.retryAfter) } : {});
    });
  })
  .listen(PORT, () => {
    console.log(`gateway on :${PORT}, ${BASE_URL ? `model ${MODEL || "(LLM_MODEL not set)"} at ${BASE_URL}${REASONING_EFFORT ? `, reasoning ${REASONING_EFFORT}` : ""}` : "mock LLM (no LLM_BASE_URL)"}`);
  });
