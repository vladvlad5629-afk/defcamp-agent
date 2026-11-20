#!/usr/bin/env python3
# Generic angr crackme/keygen solver for angr 10.0.7 (run by /opt/angr py3.12 venv).
# CRITICAL: use angr's OWN vendored claripy (angr.claripy), never `import claripy`
# (angr 10 checks isinstance against its internal rustylib claripy). Symbolic stdin
# must be content=sym (NO newline) + has_end=True, or the solve silently fails.
import sys, re, socket, os, time, argparse, logging
import angr
cp = angr.claripy
logging.getLogger('angr').setLevel('ERROR')

FLAG = re.compile(rb'flag\{[0-9a-f]{32}\}')
WIN  = [b'Correct', b'correct', b'Well done', b'Access granted', b'access granted', b'Congratulat',
        b'You win', b'Good job', b'Success', b'flag{', b'FLAG', b'Right', b'unlocked', b'accepted', b'granted']
LOSE = [b'Wrong', b'wrong', b'Invalid', b'invalid', b'Denied', b'denied',
        b'Nope', b'Try again', b'Incorrect', b'fail', b'Fail', b'Bad']
_OPTS = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
         angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}

def harvest(binpath):
    win, lose = list(WIN), list(LOSE)
    try:
        data = open(binpath, 'rb').read()
        for s in re.findall(rb'[ -~]{4,}', data):
            ls = s.lower()
            if any(w.lower() in ls for w in WIN): win.append(s)
            if any(l.lower() in ls for l in LOSE): lose.append(s)
    except Exception: pass
    return win, lose

def _outmatch(state, needles):
    try: o = state.posix.dumps(1)
    except Exception: return False
    return any(n in o for n in needles)

def try_solve(binpath, nbytes, vector, win, lose, budget=90):
    proj = angr.Project(binpath, auto_load_libs=False)
    sym = cp.BVS('inp', nbytes * 8)
    if vector == 'stdin':
        stdin = angr.SimFileStream(name='stdin', content=sym, has_end=True)  # NO newline; has_end REQUIRED
        st = proj.factory.full_init_state(stdin=stdin, add_options=_OPTS)
    else:
        st = proj.factory.full_init_state(args=[binpath, sym], add_options=_OPTS)
    for i in range(nbytes):
        b = sym.get_byte(i); st.solver.add(b >= 0x20); st.solver.add(b <= 0x7e)
    sm = proj.factory.simulation_manager(st)
    t0 = time.time()
    sm.explore(find=lambda s: _outmatch(s, win),
               avoid=lambda s: _outmatch(s, lose),
               step_func=lambda lsm: lsm.move('active', 'deadended') if time.time() - t0 > budget else lsm)
    if not sm.found:
        return None, None
    f = sm.found[0]
    rec = f.posix.dumps(0) if vector == 'stdin' else f.solver.eval(sym, cast_to=bytes)
    out = b''
    try: out = f.posix.dumps(1)
    except Exception: pass
    return rec.split(b'\x00')[0].rstrip(b'\x20'), out

def try_exit(binpath, nbytes, vector, lose, budget=90):
    """Fallback: find an input that drives the program to a clean exit WITHOUT
    hitting a failure string. Catches accept-paths whose success message isn't a
    known crib (common for network services / flag injected on the target)."""
    proj = angr.Project(binpath, auto_load_libs=False)
    sym = cp.BVS('inp', nbytes * 8)
    if vector == 'stdin':
        stdin = angr.SimFileStream(name='stdin', content=sym, has_end=True)
        st = proj.factory.full_init_state(stdin=stdin, add_options=_OPTS)
    else:
        st = proj.factory.full_init_state(args=[binpath, sym], add_options=_OPTS)
    for i in range(nbytes):
        b = sym.get_byte(i); st.solver.add(b >= 0x20); st.solver.add(b <= 0x7e)
    sm = proj.factory.simulation_manager(st)
    t0 = time.time()
    sm.run(until=lambda lsm: time.time() - t0 > budget)
    cands = []
    for s in list(sm.deadended) + list(sm.active):
        try: o = s.posix.dumps(1)
        except Exception: o = b''
        if any(l in o for l in lose): continue
        rec = s.posix.dumps(0) if vector == 'stdin' else s.solver.eval(sym, cast_to=bytes)
        rec = rec.split(b'\x00')[0].rstrip(b'\x20')
        if rec and len(rec) >= 3: cands.append((rec, o))
    cands.sort(key=lambda c: -len(c[1]))   # prefer the path that printed the most (likely the accept/flag path)
    return cands[0] if cands else (None, None)

def solve(binpath, win, lose, deadline):
    # pass 1: match known success strings (fast, precise)
    for vector in ('stdin', 'argv'):
        for n in (8, 9, 12, 16, 20, 24, 32, 6, 5, 4, 40, 48, 64):
            if time.time() > deadline: return None, None, None
            try:
                rec, out = try_solve(binpath, n, vector, win, lose, budget=min(90, int(deadline - time.time())))
            except Exception as e:
                print(f'[angr] p1 vec={vector} n={n} err: {e}', file=sys.stderr); continue
            if rec:
                print(f'[+] solved(win) vector={vector} len={n} input={rec!r}', file=sys.stderr)
                return vector, rec, out
    # (clean-exit fallback removed: tested unreliable â€” recovers spurious paths
    #  when the accept branch has no success signal.)
    return None, None, None

def replay(targets, payload):
    found = set()
    for t in targets:
        try:
            host, port = t.rsplit(':', 1); port = int(port)
            s = socket.create_connection((host, port), timeout=10); s.settimeout(8)
            try: pre = s.recv(4096)
            except Exception: pre = b''
            s.sendall(payload if payload.endswith(b'\n') else payload + b'\n')   # real service wants a line
            time.sleep(0.5); buf = pre
            try:
                while True:
                    d = s.recv(4096)
                    if not d: break
                    buf += d
                    if FLAG.search(buf): break
            except Exception: pass
            s.close()
            for m in FLAG.findall(buf): found.add(m.decode())
        except Exception as e:
            print(f'[angr] replay {t} failed: {e}', file=sys.stderr)
    return found

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('binary')
    ap.add_argument('--targets', default=os.environ.get('TARGETS', ''))
    a = ap.parse_args()
    win, lose = harvest(a.binary)
    deadline = time.time() + 280
    vector, rec, out = solve(a.binary, win, lose, deadline)
    if not rec:
        print('NO_SOLUTION', file=sys.stderr); sys.exit(2)
    print('RECOVERED_INPUT=' + rec.decode('latin1', 'replace'))
    if out:
        m = FLAG.search(out)
        if m: print('FLAG=' + m.group(0).decode())
    tg = [t for t in a.targets.split(',') if t.strip()]
    if tg:
        for fl in replay(tg, rec): print('FLAG=' + fl)

