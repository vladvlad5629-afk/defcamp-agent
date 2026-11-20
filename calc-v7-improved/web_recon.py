#!/usr/bin/env python3
# Deterministic web briefing from /code: framework, routes, user-controlled
# params, dangerous sinks, and where the flag is referenced.
import os, re, glob

src = {}
for f in sorted(glob.glob('/code/**/*', recursive=True)):
    if os.path.isfile(f) and os.path.getsize(f) < 400000:
        try: src[f] = open(f, encoding='latin1').read()
        except Exception: pass
allsrc = "\n".join(src.values())

fw = []
if re.search(r'from flask|Flask\(', allsrc): fw.append('Flask')
if re.search(r"require\(['\"]express|express\(\)", allsrc): fw.append('Express/Node')
if re.search(r'<\?php|\$_(GET|POST|REQUEST|COOKIE|SERVER)', allsrc): fw.append('PHP')
if re.search(r'fastapi|FastAPI|APIRouter', allsrc): fw.append('FastAPI')
if re.search(r'django|urls\.py|path\(', allsrc): fw.append('Django')

routes = set(re.findall(r'@(?:app|bp|router)\.route\(\s*[\'"]([^\'"]+)', allsrc))
routes |= set(re.findall(r'(?:app|router)\.(?:get|post|put|delete|all)\(\s*[\'"]([^\'"]+)', allsrc))
routes |= set(re.findall(r'@(?:app|router)\.(?:get|post|put|delete)\(\s*[\'"]([^\'"]+)', allsrc))
routes |= set(re.findall(r'path\(\s*[\'"]([^\'"]+)', allsrc))

params = set(re.findall(r'request\.(?:args|form|values|json|cookies|headers)(?:\.get)?\(?\s*[\'"]?(\w+)', allsrc))
params |= set(re.findall(r'\$_(?:GET|POST|REQUEST|COOKIE)\[\s*[\'"]?(\w+)', allsrc))
params |= set(re.findall(r'req\.(?:query|body|params|cookies)\.(\w+)', allsrc))

print("=== WEB BRIEF (auto) ===")
print("framework:", fw or "unknown")
print("routes:", sorted(routes)[:40] or "(none parsed; read source)")
print("user-controlled params:", sorted(params)[:40] or "(none parsed)")

SINKS = {
    'SQL injection': r'execute\(|cursor\.|SELECT\s|FROM\s|WHERE\s|query\(|mysqli|sqlite3|db\.',
    'SSTI/template': r'render_template_string|Template\(|jinja|{{',
    'eval/exec RCE': r'\beval\(|\bexec\(|pickle\.loads|yaml\.load\b|unserialize|Function\(',
    'command injection': r'os\.system|subprocess|popen|shell_exec|child_process|`.*\$',
    'file/LFI': r'open\(|file_get_contents|include\(|require\(|send_file|sendFile|readFile',
    'deserialize': r'pickle\.loads|yaml\.load\b|unserialize|marshal|Marshal',
    'JWT/crypto': r'jwt\.|jsonwebtoken|HS256|verify\(|sign\(',
    'redirect': r'redirect\(|Location:|res\.redirect',
}
for name, rx in SINKS.items():
    if re.search(rx, allsrc, re.I): print(f"SINK {name}: present -> test it")

if 'PHP' in fw and re.search(r'[^=!]==[^=]', allsrc):
    print("PHP loose '==' present -> TYPE JUGGLING (0e magic hashes, strcmp(array) NULL bypass, '0'==false).")
if re.search(r'===|strcmp|hash_equals', allsrc) is None and re.search(r'password|token|otp|secret', allsrc, re.I):
    print("auth compare may be loose -> check == vs === on secret/password/otp.")

for f, s in src.items():
    m = re.search(r'.{0,50}flag.{0,70}', s, re.I)
    if m:
        print(f"flag ref in {os.path.basename(f)}: ...{re.sub(chr(10),' ',m.group(0)).strip()[:130]}...")

