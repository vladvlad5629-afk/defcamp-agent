import os,re,glob,base64,binascii,hashlib
D=[f for f in glob.glob("/code/*") if os.path.isfile(f)]
raw={f:open(f,"rb").read() for f in D}
keys=set()
for b in raw.values():
    for m in re.findall(rb'[\x20-\x7e]{4,40}',b): keys.add(m)
for k in list(keys):
    keys.add(hashlib.md5(k).digest()); keys.add(hashlib.sha256(k).digest())
keys=[k for k in keys if k]
def forms(b):
    out=[("raw",b)]; s=b.strip()
    try:
        h=binascii.unhexlify(re.sub(rb'[^0-9a-fA-F]',b'',s))
        if h: out.append(("hex",h))
    except: pass
    try:
        d=base64.b64decode(s,validate=False)
        if d and d!=b: out.append(("b64",d))
    except: pass
    return out
def hit(tag,d):
    m=re.search(rb'flag\{[0-9a-f]{32}\}',d)
    if m: print("FLAG",m.group().decode(),flush=True); return True
    return False
try:
    from Crypto.Cipher import AES,ARC4; HAVE=True
except: HAVE=False
for f,b in raw.items():
    for fn,ct in forms(b):
        for k in range(256):
            if hit("x1",bytes(c^k for c in ct)): raise SystemExit
        for key in keys:
            if hit("xk",bytes(c^key[i%len(key)] for i,c in enumerate(ct))): raise SystemExit
        if HAVE:
            for key in keys:
                try:
                    if hit("rc4",ARC4.new(key).decrypt(ct)): raise SystemExit
                except SystemExit: raise
                except: pass
                for kl in (16,24,32):
                    kk=(key+b"\0"*kl)[:kl]; body=ct[:len(ct)//16*16]
                    if not body: continue
                    for mode,args in (("ecb",()),("cbc0",(b"\0"*16,))):
                        try:
                            c=AES.new(kk,AES.MODE_ECB) if mode=="ecb" else AES.new(kk,AES.MODE_CBC,*args)
                            if hit(mode,c.decrypt(body)): raise SystemExit
                        except SystemExit: raise
                        except: pass
print("NO_FLAG",flush=True)

