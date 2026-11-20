#!/usr/bin/env python3
# Deterministic CTF auto-solvers. Run BEFORE the LLM; if a flag or a key input
# is recovered, print it so the harness can submit / replay to the target.
#   auto_solve.py rev <binary>     -> angr symbolic execution (crackme/keygen)
#   auto_solve.py crypto           -> RsaCtfTool + classic attacks over /code
# Best-effort and time-boxed; failures are swallowed so the LLM still runs.
import sys, os, re, glob, signal, subprocess, socket, time

FLAG_RE = re.compile(rb'flag\{[0-9a-fA-F]{32}\}')

class Timeout(Exception): pass
def _alarm(sig, frm): raise Timeout()
signal.signal(signal.SIGALRM, _alarm)

def say(*a): print(*a, flush=True)

def targets():
    return [t.strip() for t in os.environ.get("TARGETS", "").split(",") if t.strip()]

def send_to_target(payload, deadline=12):
    """Send payload (bytes) to each target over TCP, return combined response."""
    out = b""
    for t in targets():
        try:
            host, port = t.split(":"); port = int(port)
            s = socket.create_connection((host, port), timeout=6)
            s.settimeout(4)
            try:
                # read any banner/prompt first
                s.sendall(payload if payload.endswith(b"\n") else payload + b"\n")
                end = time.time() + deadline
                while time.time() < end:
                    try:
                        d = s.recv(4096)
                        if not d: break
                        out += d
                    except socket.timeout:
                        break
            finally:
                s.close()
        except Exception as e:
            say(f"[auto] target {t} send failed: {e}")
    return out

# ---------------- REV: angr (isolated venv) ----------------
def solve_rev(binary):
    # angr lives in its own Python 3.12 venv (/opt/angr) to avoid dep clashes.
    venv = "/opt/angr/bin/python"
    runner = venv if os.path.exists(venv) else sys.executable
    try:
        signal.alarm(320)
        r = subprocess.run([runner, "-I", "/app/angr_solve.py", binary, "--targets", os.environ.get("TARGETS", "")],
                           capture_output=True, timeout=320)
        signal.alarm(0)
        say((r.stdout + r.stderr).decode("latin1")[-3000:])
    except Exception as e:
        signal.alarm(0); say("[auto] angr runner error:", e)
    return

def _solve_rev_inproc(binary):
    try:
        import angr, claripy
    except Exception as e:
        say("[auto] angr unavailable:", e); return
    import logging
    logging.getLogger("angr").setLevel("ERROR"); logging.getLogger("cle").setLevel("ERROR")
    SUCC = [b"flag{", b"Correct", b"correct", b"Congrat", b"congrat", b"Well done",
            b"Access granted", b"Good job", b"Nice", b"You win", b"Right", b"unlocked", b"Success"]
    FAIL = [b"Wrong", b"wrong", b"Incorrect", b"incorrect", b"Denied", b"denied",
            b"Invalid", b"invalid", b"Nope", b"try again", b"Try again", b"Bad", b"fail", b"Fail"]
    say(f"[auto] angr loading {binary}")
    deadline = time.time() + 130   # global budget across all lengths
    for L in (8, 11, 16, 20, 24, 32, 40):
        remaining = int(deadline - time.time())
        if remaining < 15:
            say("[auto] angr global budget exhausted"); break
        try:
            signal.alarm(min(60, remaining))
            proj = angr.Project(binary, auto_load_libs=False)
            chars = [claripy.BVS(f"c{i}", 8) for i in range(L)]
            stdin = claripy.Concat(*chars, claripy.BVV(b"\n"))
            st = proj.factory.full_init_state(stdin=stdin)
            for c in chars:
                st.solver.add(c >= 0x20, c <= 0x7e)
            sm = proj.factory.simulation_manager(st)
            def good(s):
                o = s.posix.dumps(1)
                return any(x in o for x in SUCC)
            def bad(s):
                o = s.posix.dumps(1)
                return any(x in o for x in FAIL)
            sm.explore(find=good, avoid=bad, num_find=1)
            signal.alarm(0)
            if sm.found:
                f = sm.found[0]
                inp = f.posix.dumps(0)
                out = f.posix.dumps(1)
                say(f"[auto] angr SOLVED at len {L}")
                say("[auto] recovered input:", repr(inp))
                say("[auto] program stdout:", repr(out))
                m = FLAG_RE.search(out)
                if m:
                    say("[auto] FLAG-IN-OUTPUT:", m.group(0).decode()); return
                # No flag in local stdout: the real binary runs on the target.
                # Replay the recovered input to the target and scan the response.
                key = inp.split(b"\n")[0]
                if targets() and key:
                    say("[auto] replaying recovered input to target...")
                    resp = send_to_target(key)
                    say("[auto] target response:", repr(resp[:400]))
                    m2 = FLAG_RE.search(resp)
                    if m2: say("[auto] FLAG-FROM-TARGET:", m2.group(0).decode())
                return
        except Timeout:
            signal.alarm(0); say(f"[auto] angr len {L} timed out")
        except Exception as e:
            signal.alarm(0); say(f"[auto] angr len {L} error: {e}")
    say("[auto] angr found no solution (fall back to manual rev)")

# ---------------- CRYPTO: RsaCtfTool + classics ----------------
def read_code():
    src = ""
    for f in sorted(glob.glob("/code/**/*", recursive=True)):
        if os.path.isfile(f) and os.path.getsize(f) < 400000:
            try: src += "\n" + open(f, encoding="latin1").read()
            except Exception: pass
    return src

def bigint(name, src):
    m = re.search(r"\b" + name + r"\s*[:=]\s*([0-9]{3,})", src)
    return int(m.group(1)) if m else None

def solve_crypto():
    src = read_code()
    n = bigint("n", src) or bigint("N", src) or bigint("modulus", src)
    em = re.search(r"\be\s*[:=]\s*([0-9]{1,8})\b", src); e = int(em.group(1)) if em else None
    c = bigint("c", src) or bigint("ct", src) or bigint("C", src) or bigint("ciphertext", src)
    pem = [f for f in glob.glob("/code/**/*", recursive=True) if os.path.isfile(f) and open(f, 'rb').read(40).lstrip().startswith(b"-----BEGIN")]
    if not (n or pem):
        say("[auto] no RSA params/keys found in /code for RsaCtfTool");
    else:
        say(f"[auto] RSA params: n_bits={n.bit_length() if n else '?'} e={e} c={'yes' if c else 'no'} pem={pem}")
        cmd = ["python3", "/opt/RsaCtfTool/RsaCtfTool.py", "--private", "--attack", "all"]
        if n: cmd += ["-n", str(n)]
        if e: cmd += ["-e", str(e)]
        if pem: cmd = ["python3", "/opt/RsaCtfTool/RsaCtfTool.py", "--publickey", pem[0], "--private"]
        if c: cmd += ["--uncipher", str(c)]
        try:
            signal.alarm(120)
            r = subprocess.run(cmd, capture_output=True, timeout=120)
            signal.alarm(0)
            out = (r.stdout + r.stderr).decode("latin1")
            say("[auto] RsaCtfTool output:\n" + out[-1500:])
            m = FLAG_RE.search(out.encode());
            if m: say("[auto] FLAG:", m.group(0).decode())
        except Exception as ex:
            signal.alarm(0); say("[auto] RsaCtfTool error:", ex)
    # quick classics independent of RsaCtfTool
    try:
        if n and e and c and e <= 7 and n.bit_length() > 256:
            import gmpy2
            r, exact = gmpy2.iroot(c, e)
            if exact:
                b = int(r).to_bytes((int(r).bit_length() + 7) // 8, "big")
                say("[auto] small-e root plaintext:", b)
    except Exception:
        pass

def main():
    if len(sys.argv) < 2: return
    mode = sys.argv[1]
    try:
        if mode == "rev" and len(sys.argv) > 2:
            solve_rev(sys.argv[2])
        elif mode == "crypto":
            solve_crypto()
    except Exception as e:
        say("[auto] solver crashed:", e)

if __name__ == "__main__":
    main()

