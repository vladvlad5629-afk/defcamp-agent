# AISafe offline investigation harness

## Investigation strategy

The agent does a bounded, offline inventory first and produces a compact manifest with file type, entropy, encoding hints and a few printable strings. The model sees this manifest—not complete file previews on every turn—and must select focused byte windows after static triage. A persistent evidence ledger records tool outcomes, read ranges and model notes; only the latest tool round is replayed, so prompt growth is bounded across a ten-minute run.

The no-model fast path scans raw, hex, base64, reversed and URL-encoded artifacts before spending a model call. The bounded toolkit supports byte-window inspection, string extraction, frequency checks, range derivation, hex/base64/URL/ROT13/reversal, gzip/zlib decompression, repeating-key XOR and exact-byte joins. It never executes challenge artifacts or probes targets. A candidate is submitted only after exact format validation and explicit artifact verification.

`test/harness.test.mjs` includes offline regression coverage for the compact-memory recovery flow, static triage, nested decoding, compression, byte-range coverage and invalid tool recovery. The same tests run in the GitHub Actions build before the linux/amd64 image is saved and reloaded.

Sanity Check keeps its documented two-file HTTP reader and zero-model path. For local files the agent first tries inexpensive whole-file checks. It then uses structured Chat Completions tool calls. Qwen can inspect text and hex at byte offsets, locate literal strings, extract byte ranges, test encoding and repeating-key XOR hypotheses, and join derived artifacts. Intermediate artifacts retain IDs across turns. Verification operates on the reconstructed bytes. The gateway decides acceptance.

Every model request refreshes time and spend from /health. The agent accumulates usage.total_tokens when reported. The kit exposes remaining cents and seconds; it has no documented remaining-token counter. Recent tool exchanges and a bounded record of observations carry across turns. An idle reply gets two chances to recover. Failed tool arguments and repeated actions produce feedback. The default ceiling is 24 model requests, adjustable with AGENT_MAX_STEPS (maximum 50). The inventory covers regular files of up to 64 KiB each, 2 MiB total; omitted entries are flagged in the prompt. The model can analyze only the indexed data and available operations. It cannot execute arbitrary programs or interact with live services. The documented practice reader is the single exception for static HTTP files.

## Rulare de pe calculator

Extrage ZIP-ul și deschide un terminal în directorul care conține compose.yaml. Cu Node instalat, testele rulează fără pachete npm. Testul cu gateway-ul oficial necesită portul local 8080 liber.

```sh
node --test test/harness.test.mjs test/practice.test.mjs
```

Cu Docker Desktop pornit pe Windows, sau Docker Engine și Compose pe Linux, pornește proba locală. Configurația implicită folosește gateway-ul local fără cheie API. Proba publică se rezolvă prin citirea fragmentelor, cu zero cereri către model.

```sh
docker compose up --build --exit-code-from harness
docker compose down -v
```

Așteaptă mesajul „Flag accepted” și codul de ieșire 0. A doua comandă elimină volumele temporare ale acestei probe.

## Construirea imaginii și încărcarea

Windows PowerShell, din același director:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Linux sau macOS:

```sh
sh build.sh
```

Scripturile construiesc pentru linux/amd64 și produc my-harness.tar. Pe platformă, secțiunea Harnesses primește fișierul TAR. Încărcarea înlocuiește harness-ul live al echipei. Verifică întâi rezultatul local și dimensiunea TAR (maximum 1 GiB), apoi rulează Sanity Check pe platformă.

## Validation

The test suite covers scripted model iteration, failed tools, exact-byte reconstruction, budget handling, gateway submission, and the official local practice gateway. GitHub Actions builds on Ubuntu using Node 22, runs Docker Compose, saves the image, reloads the TAR, and checks identity, linux/amd64, and size. A successful practice run verifies packaging and gateway integration. Competition performance requires separate live evaluation.
