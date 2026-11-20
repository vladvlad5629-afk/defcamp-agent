import os,re,glob,base64
FLAG=re.compile(rb'flag\{[0-9a-f]{32}\}')
def val(b):
    m=FLAG.search(b); return m.group(0).decode() if m else None
def decs(c):
    n=len(c); yield c; yield c[::-1]
    for k in range(256):
        yield bytes(x^k for x in c); yield bytes((x+k)&255 for x in c); yield bytes((x-k)&255 for x in c)
    yield bytes(x^(i&255) for i,x in enumerate(c))
    yield bytes(x^((i*7+13)&255) for i,x in enumerate(c))
    if n>=6:
        kp={0:102,1:108,2:97,3:103,4:123,n-1:125}
        for L in range(1,17):
            key={}
            for pos,p in kp.items(): key[pos%L]=c[pos]^p
            if len(key)>=L: yield bytes(c[i]^key[i%L] for i in range(n))
def forms(d):
    yield d
    s=re.sub(rb'[^0-9a-fA-F]',b'',d)
    if len(s)>=76 and len(s)%2==0:
        try: yield bytes.fromhex(s.decode())
        except: pass
    s2=re.sub(rb'[^A-Za-z0-9+/]',b'',d)
    try: yield base64.b64decode(s2+b'='*(-len(s2)%4))
    except: pass
def engine(blobs):
    for b in blobs:
        for f in forms(b):
            for c in decs(f):
                v=val(c)
                if v: return v
    for b in blobs:
        for k in range(256):
            for mk in (0,1,2):
                nd=bytes((x^k) if mk==0 else ((x+k)&255) if mk==1 else ((x-k)&255) for x in b'flag{')
                i=b.find(nd)
                while i!=-1:
                    w=b[i:i+40]
                    d=bytes((x^k) if mk==0 else ((x-k)&255) if mk==1 else ((x+k)&255) for x in w)
                    v=val(d)
                    if v: return v
                    i=b.find(nd,i+1)
    return None
blobs=[]
for f in glob.glob('/code/**/*',recursive=True):
    if os.path.isfile(f):
        try: blobs.append(open(f,'rb').read())
        except: pass
r=engine(blobs); print(r if r else "NO_FLAG")

