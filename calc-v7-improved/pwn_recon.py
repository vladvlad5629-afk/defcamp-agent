#!/usr/bin/env python3
# Deterministic ELF briefing for the agent: arch, mitigations, hot symbols,
# dangerous imports, and notable strings. Keeps the weak model oriented.
import sys, subprocess
try:
    from pwn import ELF, context
    context.log_level = "error"
except Exception as e:
    print("pwntools unavailable:", e); sys.exit(0)

path = sys.argv[1]
try:
    e = ELF(path, checksec=False)
except Exception as ex:
    print("ELF parse failed:", ex); sys.exit(0)

print(f"arch={e.arch} bits={e.bits} endian={e.endian} static={e.statically_linked}")
try:
    print(f"PIE={e.pie} RELRO={e.relro} NX={e.nx} Canary={e.canary}")
except Exception:
    pass

WANT = ("win", "backdoor", "flag", "secret", "admin", "system", "shell", "give",
        "getflag", "print_flag", "read_flag", "target", "vuln", "unlock", "debug")
hot = {}
try:
    for k, v in e.symbols.items():
        if any(w in k.lower() for w in WANT):
            hot[k] = hex(v)
except Exception:
    pass
print("HOT symbols (ret2win candidates / interesting):", hot if hot else "(none obvious)")

try:
    print("PLT (library calls):", sorted(e.plt.keys()))
except Exception:
    pass
try:
    funcs = sorted(e.functions.keys())
    print("functions:", funcs[:50])
except Exception:
    pass
try:
    got = {k: hex(v) for k, v in e.got.items()}
    print("GOT:", got)
except Exception:
    pass

DANGER = ("gets", "system", "execve", "strcpy", "sprintf", "scanf", "read",
          "printf", "memcpy", "fgets", "puts", "fscanf", "vprintf")
try:
    used = [k for k in e.plt.keys() if k in DANGER] + [k for k in e.symbols if k in DANGER]
    print("dangerous funcs present:", sorted(set(used)))
except Exception:
    pass

try:
    out = subprocess.check_output(["strings", "-n", "6", path], timeout=20).decode("latin1").splitlines()
    tokens = ("flag", "/bin/sh", "secret", "password", "passwd", "key", "http", "%s", "%p", "%n", "format", "nc ", "token")
    notable = [s for s in out if any(t in s.lower() for t in tokens)]
    print("notable strings:", notable[:30])
except Exception as ex:
    print("strings error:", ex)

