import { opendir, readFile, stat } from 'node:fs/promises';
import { join, extname, basename } from 'node:path';
import { gunzipSync, inflateSync } from 'node:zlib';

const MAX_FILES = 64, MAX_FILE_BYTES = 65536, MAX_TOTAL_BYTES = 2097152;
const FLAG_RE = /flag\{[\da-fA-F]{32}\}/g;

export async function inventory(root) {
  const files = []; let entries = 0, bytes = 0, incomplete = false;
  async function walk(dir) {
    let handle; try { handle = await opendir(dir); } catch { incomplete = true; return; }
    for await (const item of handle) {
      if (++entries > 512) { incomplete = true; break; }
      const path = join(dir, item.name);
      if (item.isSymbolicLink()) { incomplete = true; continue; }
      if (item.isDirectory()) { await walk(path); continue; }
      if (!item.isFile()) continue;
      const size = (await stat(path)).size;
      if (size > MAX_FILE_BYTES || bytes + size > MAX_TOTAL_BYTES || files.length >= MAX_FILES) { incomplete = true; continue; }
      const data = await readFile(path); bytes += data.length; files.push({ path, data, info: describe(data, path) });
    }
  }
  await walk(root); return { files, incomplete };
}

function printableRatio(data) { if (!data.length) return 1; let n = 0; for (const b of data) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) n++; return n / data.length; }
function entropy(data) { if (!data.length) return 0; const c = new Uint32Array(256); for (const b of data) c[b]++; let v = 0; for (const n of c) if (n) { const p = n/data.length; v -= p*Math.log2(p); } return Number(v.toFixed(2)); }
function magic(data) {
  if (data.subarray(0,4).equals(Buffer.from([127,69,76,70]))) return 'ELF executable';
  if (data.subarray(0,2).equals(Buffer.from('MZ'))) return 'PE executable';
  if (data.subarray(0,4).equals(Buffer.from('PK\x03\x04'))) return 'ZIP archive';
  if (data.subarray(0,2).equals(Buffer.from([31,139]))) return 'gzip stream';
  if (data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return 'PNG image';
  if (data.subarray(0,6).toString('ascii').match(/^GIF8[79]a$/)) return 'GIF image';
  if (data.subarray(0,2).equals(Buffer.from([255,216]))) return 'JPEG image';
  if (data.subarray(0,4).toString('ascii') === '%PDF') return 'PDF document';
  if (data.subarray(0,4).toString('ascii') === 'RIFF') return 'RIFF container'; return '';
}
function encodingHint(data) { const text = data.toString('latin1').trim().replace(/\s/g,''); if (/^(?:[\da-f]{2})+$/i.test(text)) return 'hex-looking text'; if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length > 8 && text.length % 4 === 0) return 'base64-looking text'; return ''; }
function strings(data, min = 5, limit = 12) { const out = [], re = new RegExp(`[ -~]{${min},}`, 'g'); for (const match of data.toString('latin1').matchAll(re)) { out.push({offset:match.index,text:match[0].slice(0,160)}); if (out.length >= limit) break; } return out; }
export function describe(data, path = '') { const ratio = printableRatio(data); return { name:basename(path), ext:extname(path).slice(0,12).toLowerCase(), size:data.length, kind:magic(data) || (ratio > .92 ? 'text' : 'binary'), entropy:entropy(data), printable:Number(ratio.toFixed(2)), encoding:encodingHint(data) || undefined, strings:strings(data,8,3) }; }

export const operations = ['hex','base64','reverse','rot13','url','gzip','zlib'];
function rot13(text) { return text.replace(/[a-z]/gi, c => { const start = c <= 'Z' ? 65 : 97; return String.fromCharCode(start+(c.charCodeAt(0)-start+13)%26); }); }
function decodeBytes(data, steps) {
  if (!Array.isArray(steps) || steps.length > 5) throw Error('invalid steps');
  for (const step of steps) {
    const text = data.toString('latin1').trim();
    if (step === 'reverse') data = Buffer.from(data).reverse();
    else if (step === 'rot13') data = Buffer.from(rot13(text),'latin1');
    else if (step === 'url') { try { data = Buffer.from(decodeURIComponent(text.replace(/\+/g,'%20')),'utf8'); } catch { throw Error('invalid URL encoding'); } }
    else if (step === 'gzip') { try { data = gunzipSync(data); } catch { throw Error('invalid gzip stream'); } }
    else if (step === 'zlib') { try { data = inflateSync(data); } catch { throw Error('invalid zlib stream'); } }
    else { const flat = text.replace(/\s/g,''); if (step === 'hex' && /^(?:[a-f\d]{2})+$/i.test(flat)) data = Buffer.from(flat,'hex'); else if (step === 'base64' && /^[A-Za-z0-9+/]+={0,2}$/.test(flat) && flat.length%4 === 0) data = Buffer.from(flat,'base64'); else throw Error('invalid encoding'); }
  }
  return data;
}
export function decode(data, steps) { return decodeBytes(data,steps).toString('latin1').trim(); }
export function valid(text) { return /^flag\{[\da-fA-F]{32}\}$/.test(text) && !/^flag\{(.)\1{31}\}$/i.test(text); }
export function candidates(data) { const found = new Set(), visit = bytes => { for (const m of bytes.toString('latin1').matchAll(FLAG_RE)) if (valid(m[0])) found.add(m[0]); }; visit(data); for (const steps of [[],['hex'],['base64'],['reverse'],['reverse','hex'],['reverse','base64'],['hex','base64'],['base64','hex'],['url']]) try { visit(decodeBytes(data,steps)); } catch {} return [...found]; }

const uint = {type:'integer',minimum:0};
function tool(name, description, properties, required) { return {type:'function',function:{name,description,parameters:{type:'object',properties,required,additionalProperties:false}}}; }
export const tools = [
  tool('math','Perform bounded exact integer math for crypto hypotheses. Operations: gcd(a,b), modpow(base,exponent,modulus), modinv(a,modulus), xor(a,b). All values are unsigned decimal strings.',{operation:{enum:['gcd','modpow','modinv','xor']},a:{type:'string'},b:{type:'string'},base:{type:'string'},exponent:{type:'string'},modulus:{type:'string'}},['operation']),
  tool('overview','Static, cached triage: type, entropy, encoding clues, and selected printable strings. Use before reading unknown binaries.',{id:uint},['id']),
  tool('inspect','Read a bounded byte window. Returns text, hex, and exact offsets.',{id:uint,offset:uint,length:uint},['id','offset','length']),
  tool('find_text','Locate literal UTF-8 text in an artifact. Returns byte offsets only.',{id:uint,text:{type:'string'}},['id','text']),
  tool('extract_strings','Extract printable strings and their byte offsets from an artifact.',{id:uint,minLength:{type:'integer',minimum:3,maximum:64}},['id']),
  tool('frequency','Return frequent byte values; useful for deciding whether XOR or binary parsing is plausible.',{id:uint,top:{type:'integer',minimum:1,maximum:32}},['id']),
  tool('derive','Create an artifact from a byte range. transforms: hex, base64, reverse, rot13, url, gzip, zlib, xor. xor uses repeating keyHex.',{id:uint,offset:uint,length:uint,steps:{type:'array',items:{enum:[...operations,'xor']}},keyHex:{type:'string'}},['id','steps']),
  tool('join_parts','Join 2–8 artifact IDs in order.',{ids:{type:'array',items:uint}},['ids']),
  tool('verify','Check a complete artifact as a candidate. Submit only exact valid flag bytes.',{id:uint},['id']),
  tool('note','Persist a concise evidence-backed hypothesis or failed approach for later turns. No flag guesses.',{summary:{type:'string',minLength:1,maxLength:360}},['summary'])
];

export function notebook(files) {
  const artifacts = files.map(f=>f.data), names = files.map(f=>f.path), coverage = new Map();
  function get(id) { if (!Number.isInteger(id) || id < 0 || id >= artifacts.length) throw Error('Unknown artifact id'); return artifacts[id]; }
  function mark(id,start,end) { const r = coverage.get(id) ?? []; r.push([start,end]); coverage.set(id,r); }
  function range(data,offset,length,max,id) { if (!Number.isInteger(offset)||offset<0||offset>data.length||!Number.isInteger(length)||length<1||length>max) throw Error('Invalid byte range'); const end=Math.min(data.length,offset+length); mark(id,offset,end); return data.subarray(offset,end); }
  function save(data,label='derived') { if (!data.length || data.length > MAX_FILE_BYTES || artifacts.length >= files.length+64) throw Error('Derived artifact limit'); const id=artifacts.push(data)-1; names[id]=label; return {id,size:data.length,overview:describe(data,label),preview:data.toString('latin1',0,120)}; }
  function integer(value, name) { if (typeof value !== 'string' || !/^\d{1,512}$/.test(value)) throw Error(`Invalid ${name}`); return BigInt(value); }
  function inverse(a, modulus) { let [oldR,r]=[a,modulus], [oldS,s]=[1n,0n]; while(r) { const q=oldR/r; [oldR,r]=[r,oldR-q*r]; [oldS,s]=[s,oldS-q*s]; } if(oldR!==1n) throw Error('No modular inverse'); return (oldS%modulus+modulus)%modulus; }
  const execute = (name,args) => {
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw Error('Expected argument object');
    if (name === 'note') throw Error('Notes are handled by investigation memory');
    if (name === 'math') {
      let value;
      if (args.operation === 'gcd') { let a=integer(args.a,'a'), b=integer(args.b,'b'); while(b) [a,b]=[b,a%b]; value=a; }
      else if (args.operation === 'xor') value=integer(args.a,'a')^integer(args.b,'b');
      else if (args.operation === 'modinv') { const m=integer(args.modulus,'modulus'); if(m<2n) throw Error('Invalid modulus'); value=inverse(integer(args.a,'a')%m,m); }
      else if (args.operation === 'modpow') { const modulus=integer(args.modulus,'modulus'); if(modulus<2n) throw Error('Invalid modulus'); let base=integer(args.base,'base')%modulus, exponent=integer(args.exponent,'exponent'), result=1n; while(exponent) { if(exponent&1n) result=result*base%modulus; base=base*base%modulus; exponent>>=1n; } value=result; }
      else throw Error('Unknown math operation');
      return {decimal:value.toString(),hex:value.toString(16)};
    }
    if (name === 'join_parts') { if (!Array.isArray(args.ids)||args.ids.length<2||args.ids.length>8) throw Error('Expected 2–8 ids'); return save(Buffer.concat(args.ids.map(get)),'joined'); }
    const data=get(args.id);
    if (name === 'overview') return {id:args.id,name:basename(names[args.id]??''),...describe(data,names[args.id])};
    if (name === 'inspect') { const part=range(data,args.offset,args.length,1024,args.id); return {size:data.length,offset:args.offset,end:args.offset+part.length,text:part.toString('utf8'),hex:part.toString('hex')}; }
    if (name === 'find_text') { if (typeof args.text !== 'string'||!args.text.length||args.text.length>128) throw Error('Invalid search text'); const offsets=[]; for (let i=data.indexOf(args.text);i>=0&&offsets.length<32;i=data.indexOf(args.text,i+1)) offsets.push(i); return {offsets}; }
    if (name === 'extract_strings') return {strings:strings(data,args.minLength??5,32)};
    if (name === 'frequency') { const counts=new Uint32Array(256); for (const b of data) counts[b]++; return {entropy:entropy(data),bytes:[...counts].map((count,value)=>({value,hex:value.toString(16).padStart(2,'0'),count})).filter(x=>x.count).sort((a,b)=>b.count-a.count).slice(0,args.top??8)}; }
    if (name === 'derive') { if (!Array.isArray(args.steps)||args.steps.length>5) throw Error('Expected up to five steps'); let bytes=range(data,args.offset??0,args.length??data.length,MAX_FILE_BYTES,args.id); for (const op of args.steps) { if (op === 'xor') { if (typeof args.keyHex !== 'string'||!/^(?:[a-f\d]{2}){1,128}$/i.test(args.keyHex)) throw Error('Invalid hex key'); const key=Buffer.from(args.keyHex,'hex'); bytes=bytes.map((b,i)=>b^key[i%key.length]); } else { if (!operations.includes(op)) throw Error('Unknown operation'); bytes=decodeBytes(bytes,[op]); } if (bytes.length>MAX_FILE_BYTES) throw Error('Derived artifact limit'); } return save(bytes,`derive:${args.id}`); }
    if (name === 'verify') { const value=data.toString('latin1').trim(); return valid(value)?{candidate:value}:{verified:false,reason:'Expected complete flag bytes'}; }
    throw Error('Unknown tool');
  };
  execute.coverage=()=>[...coverage.entries()].map(([id,ranges])=>({id,ranges:ranges.slice(-8)})); return execute;
}
