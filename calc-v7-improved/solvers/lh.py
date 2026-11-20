import socket,re,os,zlib
T=os.environ.get("TARGETS","").split(",")[0].replace("tcp://","").strip()
host,port=T.split(":");port=int(port)
M32=2**32;M16=2**16
def xall(n):
    r=0
    for v in n:r^=v
    return r
def prod(n):
    p=1
    for v in n:p=(p*v)%M32
    return p
def F():
    return [("sum",lambda n:sum(n)),("sum32",lambda n:sum(n)%M32),
    ("sum16",lambda n:sum(n)%M16),("sum256",lambda n:sum(n)%256),
    ("xor",xall),("prod32",prod),("min",min),("max",max),
    ("count",len),("sumsq",lambda n:sum(v*v for v in n)),
    ("sumsq32",lambda n:sum(v*v for v in n)%M32),
    ("mean",lambda n:sum(n)//len(n)),
    ("sumabs",lambda n:sum(abs(v) for v in n)),
    ("idxw",lambda n:sum(i*v for i,v in enumerate(n))),
    ("crc",lambda n:zlib.crc32(" ".join(map(str,n)).encode())),
    ("crccat",lambda n:zlib.crc32("".join(map(str,n)).encode())),
    ("sortcat",lambda n:"".join(map(str,sorted(n)))),
    ("cat",lambda n:"".join(map(str,n)))]
def drain(s):
    s.settimeout(2.0);buf=b""
    try:
        while True:
            d=s.recv(65535)
            if not d:break
            buf+=d
    except socket.timeout:
        pass
    return buf
def run(fn):
    s=socket.socket();s.settimeout(8);s.connect((host,port))
    try:
        for _ in range(30):
            buf=drain(s)
            if not buf:break
            m=re.search(rb'flag\{[0-9a-f]{32}\}',buf.lower())
            if m:return m.group().decode()
            ns=[int(x) for x in re.findall(rb'-?\d+',buf)]
            if not ns:break
            s.sendall(str(fn(ns)).encode()+b"\n")
    finally:
        s.close()
    return None
for name,fn in F():
    try:r=run(fn)
    except Exception as e:r=None
    if r and "flag{" in r:
        print("FLAG",name,r);break
    print("try",name,"-> no flag",flush=True)

