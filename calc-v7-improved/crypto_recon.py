#!/usr/bin/env python3
# Deterministic crypto briefing from /code: detect scheme, extract params,
# name the most likely attack. Orients the model before it reasons.
import os, re, glob

src = ""
for f in sorted(glob.glob('/code/**/*', recursive=True)):
    if os.path.isfile(f) and os.path.getsize(f) < 300000:
        try: src += "\n# FILE " + f + "\n" + open(f, encoding='latin1').read()
        except Exception: pass

rep = []
def num(name):
    m = re.search(r'\b' + name + r'\s*[:=]\s*([0-9]{3,})', src)
    return int(m.group(1)) if m else None

N = num('n') or num('N') or num('modulus')
_em = re.search(r'\be\s*[:=]\s*([0-9]{1,8})\b', src)
e = int(_em.group(1)) if _em else (num('e') or num('E'))
c = num('c') or num('ct') or num('C') or num('cipher')
if N:
    rep.append(f"RSA: N={N.bit_length()} bits" + (f", e={e}" if e else "") + (", ciphertext present" if c else ""))
    if e and e <= 7:
        rep.append(f"  -> SMALL e={e}: if message unpadded, flag = integer e-th root of c (gmpy2.iroot(c,{e})).")
    if N.bit_length() <= 256:
        rep.append("  -> SMALL N: factor it. try sympy.factorint(N) or known factordb values, then d=inverse(e,(p-1)(q-1)); m=pow(c,d,N).")
        if N.bit_length() <= 170:
            try:
                from sympy import factorint
                fac = factorint(N)
                if len(fac) > 1 or list(fac.values())[0] > 1:
                    rep.append(f"  -> FACTORED: N = {fac}  (compute d and decrypt c now)")
            except Exception:
                pass
    rep.append("  -> also check: common-modulus (two c with different e), Wiener (small d), Hastad (same m, many N).")

if re.search(r'MODE_ECB|\bECB\b', src): rep.append("AES-ECB: byte-at-a-time decryption, or cut-and-paste block reordering if you control plaintext prefix.")
if re.search(r'MODE_CBC|\bCBC\b', src): rep.append("AES-CBC: try PADDING ORACLE (if it reports padding errors) or bit-flipping in IV/prev block.")
if re.search(r'MODE_CTR|MODE_OFB|MODE_CFB|keystream|\bCTR\b', src): rep.append("Stream/CTR: KEYSTREAM/NONCE REUSE -> xor two ciphertexts, crib-drag; or recover keystream if a known plaintext exists.")
if re.search(r'(?<![a-z])xor(?![a-z])|\^\s*key|single.?byte', src, re.I): rep.append("XOR: reused/known-key -> ct ^ known, crib-dragging, single-byte brute (freq analysis).")
if re.search(r'getrandbits|random\.(get|rand|seed)|MT19937|mersenne', src, re.I): rep.append("PRNG Mersenne: collect 624 32-bit outputs -> untemper -> clone state -> predict the value it wants.")
if re.search(r'lcg|\b[a-z]\s*=\s*\(\s*[a-z]\s*\*', src, re.I): rep.append("Possible LCG: recover a,c,m from consecutive outputs, then predict.")
if re.search(r'time\(\)|time\.time|seed\(\s*\d', src, re.I): rep.append("Seeded by time/constant: brute the seed window and reproduce the stream.")
if re.search(r'md5|sha1|sha256|hashlib|hmac', src, re.I): rep.append("Hash/MAC: if tag=hash(secret||msg) with known len -> LENGTH EXTENSION (hashpumpy) to forge; if HMAC, look for key leak/timing.")
if re.search(r'ecdsa|secp|\bnonce\b|\bk\b\s*=', src, re.I): rep.append("ECDSA/DSA: reused or biased nonce k -> recover private key from two signatures.")
if re.search(r'getPrime|is_prime|pow\(', src) and not N: rep.append("Custom number-theory scheme: read the math and invert it (sympy for discrete log / CRT / roots).")

print("=== CRYPTO BRIEF (auto) ===")
print("\n".join(rep) if rep else "no standard scheme auto-detected â€” read the source and identify the primitive manually.")

