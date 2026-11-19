# AISafe starter kit

Use this kit to build a harness, try it on your own machine, and package
it for upload. You only need Docker (Docker Desktop on Windows and macOS,
Docker Engine with the compose plugin on Linux).

```
harness/agent.mjs      the starter agent: Node 22, one file, no dependencies
harness/Dockerfile     the image you upload, with the agent's settings
build.sh, build.ps1    build the image and save it as my-harness.tar
compose.yaml           a local run: your harness, a practice challenge, a gateway
.env.example           settings for the local run (copy to .env)
local/gateway.mjs      the local gateway, a stand-in for the event's
local/practice/        the practice challenge (the same one as smoke-test on the site)
```

## Quick start

Before anything else:

1. Start Docker Desktop and wait until it says "Engine running". On Linux,
   make sure the Docker service is up.
2. Unzip the kit and open the inner `aisafe-starter-kit` folder, the one
   that holds `compose.yaml`. Windows "Extract All" puts it one level down,
   in a folder of the same name.
3. Open a terminal in that folder. On Windows: right-click the empty space
   inside the folder, then "Open in Terminal".

Do step 1 below once at home, before the event. It downloads the base
images, which is slow on a shared venue connection. If Docker answers
`toomanyrequests`, sign in with a free Docker account (`docker login`) and
try again: Docker Hub limits anonymous downloads per IP address, and the
venue shares one.

All commands run from this folder and are the same on every OS, except
where noted.

### 1. Try it locally, no key needed

```
docker compose up --build --exit-code-from harness
```

This builds your harness and starts it with the practice challenge and the
local gateway. With no model configured, the gateway answers with a scripted
mock: one command, then a stop. That only shows that your harness reaches
the gateway and the challenge. The starter agent finds the flag in the
output and submits it, so you should see:

```
gateway-1  | flag ACCEPTED: flag{0123456789abcdef0123456789abcdef}
harness-1  | [agent] FLAG ACCEPTED, 0 points at step 1
```

Clean up afterwards with `docker compose down -v`.

### 2. Try it with a real model

Copy the settings file and edit it:

```
cp .env.example .env              # macOS, Linux
Copy-Item .env.example .env       # Windows PowerShell
```

Set `LLM_BASE_URL`, `LLM_API_KEY` and `LLM_MODEL` to any OpenAI-compatible
endpoint, with your own key. You pay for those calls.

- OpenRouter, with the event's model (Qwen 3.8 27B at reasoning effort
  medium):

  ```
  LLM_BASE_URL=https://openrouter.ai/api/v1
  LLM_API_KEY=sk-or-...
  LLM_MODEL=qwen/qwen3.8-27b
  LLM_REASONING_EFFORT=medium
  ```

  Other OpenRouter models work too; pick one that supports tool calling. Free
  models (ids ending in `:free`) have a daily request limit, and you have to
  allow free endpoints in your openrouter.ai privacy settings, or every call
  fails with a "data policy" error (404).
- Ollama on your machine: `LLM_BASE_URL=http://host.docker.internal:11434/v1`,
  any key, and a model you have pulled. On Linux, Ollama has to listen on
  more than localhost (`OLLAMA_HOST=0.0.0.0`).

Then run step 1 again. Only the gateway gets internet access; your harness
stays offline, as at the event. At the event every call goes to Qwen 3.8
27B, whatever model your requests name, and you spend none of your own
money.

`.env` also takes `INSTRUCTIONS` and the budgets. Wrap `INSTRUCTIONS` in
single quotes (`INSTRUCTIONS='...'`): without them a `#` starts a comment
and `$NAME` is replaced by a variable. Locally every model call counts as
one cent, so a small `COST_LIMIT_CENTS` lets you watch your harness handle
running out.

### 3. Build the file you upload

macOS, Linux:

```
sh build.sh
```

Windows PowerShell:

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

Both write `my-harness.tar`. If you would rather type the commands
yourself, they are the same everywhere:

```
docker build --platform linux/amd64 -t my-harness harness
docker save -o my-harness.tar my-harness
```

### 4. Upload

Upload `my-harness.tar` on the Harnesses page. The name is only a label.
You have one live harness; a new upload replaces your earlier one.
Anyone on your team can queue runs with any teammate's upload, so one
person with Docker is enough. Then queue a run on the practice challenge,
Sanity Check (smoke-test). Its stdout is shown after every run, so debug
there.

## How a run works

A harness is a Docker image. For each run the platform starts it next to
the challenge and a gateway, on a private network with no internet. Your
agent reads the challenge's files in `/code`, talks to the live targets in
`TARGETS`, and reaches the model through the gateway. The run ends when it
submits the right flag, gives up, exits, or runs out of time or budget.
The clock starts once your image has loaded.

The model is Qwen 3.8 27B (`qwen3.8-27b`) at reasoning effort medium, for
every run and every team.

The starter agent is a plain loop: ask the model for a command, run it,
repeat. It gives the model two tools, `bash` and `submit_flag`, and adds
your team's instructions to its prompt. It stops after 14 steps, or when
`GET /health` says fewer than 100 seconds are left. Then it asks the model
for a note of up to 32 characters on where it got to, and sends that with
`/give-up`. That note is what your team sees on the run page of a failed
run. The platform's basic harness is this same agent.

### Environment

The platform sets these:

| Variable | |
| --- | --- |
| `GATEWAY_URL` | base URL of the gateway. It includes a path (at the event `http://gateway.internal/gateway`), so append routes to it: `$GATEWAY_URL/flag` |
| `RUN_TOKEN` | send it as the `X-Run-Token` header on every gateway call |
| `TARGETS` | live targets, `host:port`, comma separated, any protocol |
| `INSTRUCTIONS` | your team's notes for this run, up to 4096 characters, may be empty |
| `RUN_ID` | the run's id |
| `TIME_LIMIT_SECONDS`, `COST_LIMIT_CENTS` | the run's budgets |
| `/code` | the challenge's files, a read-only snapshot |

`HARNESS_FORMAT` (chat, anthropic or responses) and `AGENT_MAX_STEPS` are
the starter agent's own settings, not the platform's. They are set with
`ENV` in `harness/Dockerfile`; change them there and rebuild, so the
image you test locally is the one that runs at the event.

### Gateway routes

Every route is relative to `GATEWAY_URL`. The routes also answer at the
host root.

| Route | |
| --- | --- |
| `POST /v1/chat/completions` | the model, OpenAI chat completions format |
| `POST /v1/messages` | the model, Anthropic messages format |
| `POST /v1/responses` | the model, OpenAI Responses format |
| `POST /llm` | the model, any of the three; the gateway works out the format from the body |
| `POST /flag {flag}` | submit a flag: `{"correct": true, ...}` ends the run, `{"correct": false, ...}` means keep looking |
| `POST /log {event, meta}` | a timeline event your team sees live: `progress`, `tool_use` (with `meta.tool`: bash, python, http, read_file, submit_flag or other), `stuck`, `flag_found`, `error`. Up to 300 per run. |
| `POST /give-up {message}` | end the run with a note of up to 32 characters |
| `GET /health` | seconds and cents left |
| `GET /instructions` | the instructions, as plain text |

About the model routes:

- The answer comes back in the format of the path you called. With an SDK,
  set its base URL to `$GATEWAY_URL/v1` (OpenAI) or `$GATEWAY_URL`
  (Anthropic), any API key, and `X-Run-Token` as a default header.
- The `model` field you send is ignored: every call goes to Qwen 3.8 27B.
  So are sampling settings (`temperature`, `top_p`, `n`, `seed`,
  `stop`, `tool_choice`, `response_format`); reasoning effort is fixed by
  the organizers.
- The Responses route keeps no state (`previous_response_id` is ignored):
  send the whole history every time.
- `stream: true` works in all three formats.
- At most 4 model calls in flight per run.

### Status codes

How the gateway answers, and what the starter agent does:

| Status | Meaning | Starter agent |
| --- | --- | --- |
| 200 | ok | carries on |
| 400 | bad request, for example the conversation is longer than the model's context. Fix the request; sending it again as it is will fail again | counts a failure |
| 402 | the run's budget is used up | stops |
| 409 | the run has ended | stops |
| 429 | busy: the shared model rate limit, your run's in-flight cap, or the wrong-flag cooldown | waits `Retry-After`, then retries; not a failure |
| 503 | an upstream error, or the model took longer than 3 minutes on this call | waits `Retry-After`, then retries; not a failure |

Anything else counts as a failure; the starter agent gives up after 5
failed tries on one step. When a call fails it prints the gateway's reason,
so read its output.

A single model call can take a while. In testing, half took under 15
seconds and 1 in 10 over a minute. About 1 in 25 ran past 3 minutes,
usually because the model kept reasoning, and came back as 503; sending it
again usually works. Give calls a long timeout (the starter agent waits up
to 240 s, less when the run is nearly out of time). A streaming call sends
keepalive comments while it waits, which SSE clients ignore.

Time a run spends waiting for the shared model, or on model calls that
fail (a 503 after 3 minutes included), is added back to its time limit, up
to 10 minutes. `GET /health` shows the extended time.

Wrong flags have a cooldown for the whole team: a second wrong flag soon
after another gets 429 with `Retry-After`. The cooldown does not apply
to a correct flag.

### What your team sees

On the run page, live:

- the timeline: every model call (tokens in and out, cost), the tools your
  harness reports with `/log`, flag submissions, and how the run ended;
- the note from `/give-up`, up to 32 characters;
- the instructions the run was queued with.

Your harness's stdout and stderr are both captured, and the last 128 KiB is
kept. Your team sees it after you capture the challenge, and after every
run on the practice challenge. Until a capture, the timeline and the note
are all you get back from a run, so make the note useful.

When the run ends, the platform stops your container (3 seconds' grace) and
then reads the output, so anything still sitting in a buffer is lost. Flush
as you go: in Python run `python -u` or set `PYTHONUNBUFFERED=1`. Nothing
printed after the run ends is kept.

### Network

- `TARGETS` lists `host:port` entries. Reach them by the names given.
- Only TCP to the listed ports. No UDP, no internet.
- Nothing can connect in to your harness, so reverse shells and callback
  listeners do not work. Do not bind listeners on the target ports.

## Limits

- linux/amd64 images only. The build commands above take care of it, also
  on Apple Silicon and Windows on ARM (builds there run under emulation and
  are slower).
- The upload is at most 1 GiB: the plain `.tar` from `docker save`, or the
  same file gzipped (on macOS or Linux, `gzip my-harness.tar`). Once
  loaded, the image must fit in about 6 GB of disk. A smaller base image
  helps with both.
- At the event a run gets about half a CPU and about 3 GB of memory. The
  local run uses the same limits.
- No internet during a run, so nothing can be installed then. Put every
  tool your agent needs into the image. The starter image has curl,
  python3, nc, jq, openssl, xxd and bsdtar.
- No model weights and no API keys in the image: Qwen 3.8 27B, through the
  gateway, is the only model you may use during a run. Your own key is for
  testing at home only.
- Each run has a cost cap and your team has a total budget. Cost is
  charged per token at the organizers' prices; fractions of a cent add up.

## Writing your own harness

- Any language works. The image only has to start your agent (its
  `ENTRYPOINT` or `CMD`), read the environment above, and exit when done.
- Keep your code in `harness/` (or point `build:` in `compose.yaml` and
  the build commands at another folder) and the local run tests it.
- Settings your agent needs go into the image as `ENV` lines in the
  Dockerfile. The platform passes only the variables listed above.
- `INSTRUCTIONS` is how your team steers a run without uploading a new
  image: up to 4096 characters, written when you queue the run. Make your
  agent read it.
- The local mock calls the first tool whose name looks like a shell
  (`bash`, `shell`, `exec`, `command`) with `{"command": "..."}`. If your
  tools look different, test with a real model.
- Print what your agent does. After a capture, stdout is your record of
  how it got there.

## Troubleshooting

- **The agent prints "model busy" over and over, or "llm call failed".**
  Read the `gateway-1 |` lines just above: they show what your model
  provider answered. A wrong key, a model id that does not exist, a model
  without tool calling, a used-up daily free allowance or a "data policy"
  error all show up there.
- **`error during connect`, `Cannot connect to the Docker daemon`, or
  `The system cannot find the file specified` with `dockerDesktopLinuxEngine`.**
  Docker is not running. Start Docker Desktop and wait for "Engine running".
- **`no configuration file provided: not found`.** The terminal is in the
  wrong folder. Go to the folder that holds `compose.yaml` (see Quick
  start).
- **`toomanyrequests`.** Run `docker login` with a free Docker account, then
  try again.
- **A shell script fails with `$'\r': command not found` or `not found` on
  a file that exists.** It was saved with Windows line endings. Save
  scripts with LF line endings (in VS Code: the "CRLF" button in the status
  bar).
- **The build is slow on a Mac with Apple Silicon or on Windows on ARM.**
  Builds use `--platform linux/amd64` and run under emulation there, which
  is slower but works.
