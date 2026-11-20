import os,re,socket,time,sys
def hostport():
    t=os.environ.get("TARGETS","").strip(); t=re.sub(r'^\w+://','',t)
    m=re.search(r'([\w.\-]+)[:\s]+(\d+)',t)
    return (m.group(1),int(m.group(2))) if m else (t,0)
HOST,PORT=hostport(); WIDTH=32
def harvest(min_n=624,budget=40):
    buf=b""; nums=[]; start=time.time()
    s=socket.create_connection((HOST,PORT),timeout=10); s.settimeout(4)
    while time.time()-start<budget:
        try: d=s.recv(65536)
        except socket.timeout: d=b""
        if d: buf+=d
        nums=[int(x) for x in re.findall(rb'\d+',buf)]
        low=buf.lower(); prompt=any(k in low for k in (b'next',b'guess',b'predict',b'?'))
        if prompt and len(nums)>=min_n: break
        if not d and (prompt or len(nums)>=min_n): break
    return s,buf,nums
def untemper(y):
    y^=y>>18; y^=(y<<15)&0xefc60000; t=y
    for _ in range(5): t=y^((t<<7)&0x9d2c5680)
    y=t; t=y
    for _ in range(3): t=y^(t>>11)
    return t&0xffffffff
def mt_predict(vals):
    try:
        from randcrack import RandCrack
        rc=RandCrack()
        for v in vals[:624]: rc.submit(v&0xffffffff)
        return rc.predict_getrandbits(32)
    except Exception:
        from random import Random
        st=[untemper(v&0xffffffff) for v in vals[:624]]
        r=Random(); r.setstate((3,tuple(st)+(624,),None)); return r.getrandbits(32)
def lcg_solve(x):
    from math import gcd
    t=[x[i+1]-x[i] for i in range(len(x)-1)]
    z=[abs(t[i+2]*t[i]-t[i+1]*t[i+1]) for i in range(len(t)-2)]
    m=0
    for v in z: m=gcd(m,v)
    if m==0: return None
    try:
        a=((x[2]-x[1])*pow(x[1]-x[0],-1,m))%m; c=(x[1]-a*x[0])%m; return (a*x[-1]+c)%m
    except: return None
s,buf,nums=harvest()
sys.stderr.write("got %d ints\n"%len(nums))
if WIDTH==64:
    sub=[]
    for v in nums: sub+=[v&0xffffffff,(v>>32)&0xffffffff]
    nums=sub
nxt=None
if len(nums)>=624:
    try: nxt=mt_predict(nums)
    except Exception as e: sys.stderr.write("mt fail %s\n"%e)
if nxt is None and len(nums)>=6: nxt=lcg_solve(nums)
if nxt is not None:
    for payload in (str(nxt).encode()+b"\n",str(nxt).encode()):
        try: s.sendall(payload)
        except: break
        s.settimeout(4); out=b""
        try:
            while True:
                d=s.recv(65536)
                if not d: break
                out+=d
        except: pass
        buf+=out
        mo=re.search(rb'flag\{[0-9a-f]{32}\}',buf)
        if mo: print(mo.group().decode()); break
        if out: break
mo=re.search(rb'flag\{[0-9a-f]{32}\}',buf)
print(mo.group().decode() if mo else "NO_FLAG")

