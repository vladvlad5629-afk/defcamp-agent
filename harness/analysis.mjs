import { opendir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

export async function inventory(root) {
  const files = [];
  let entries = 0;
  let bytes = 0;
  let incomplete = false;
  async function walk(dir) {
    for await (const item of await opendir(dir)) {
      if (++entries > 512) { incomplete = true; break; }
      const path = join(dir, item.name);
      if (item.isDirectory()) await walk(path);
      if (!item.isFile()) continue;
      const size = (await stat(path)).size;
      if (size > 65536 || bytes + size > 2097152 || files.length >= 64) {
        incomplete = true;
        continue;
      }
      bytes += size;
      files.push({ path, data: await readFile(path) });
    }
  }
  await walk(root);
  return { files, incomplete };
}

export const operations = ['hex', 'base64', 'reverse', 'rot13'];
function decodeBytes(data, steps) {
  if (!Array.isArray(steps) || steps.length > 5) throw Error('invalid steps');
  for (const step of steps) {
    const text = data.toString('latin1').trim();
    if (step === 'reverse') data = Buffer.from(data).reverse();
    else if (step === 'rot13') data = Buffer.from(text.replace(/[a-z]/gi, c => {
      const start = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(start + (c.charCodeAt(0) - start + 13) % 26);
    }), 'latin1');
    else {
      const flat = text.replace(/\s/g, '');
      if (step === 'hex' && /^(?:[a-f\d]{2})+$/i.test(flat)) data = Buffer.from(flat, 'hex');
      else if (step === 'base64' && /^[A-Za-z0-9+/]+={0,2}$/.test(flat) && flat.length % 4 === 0) data = Buffer.from(flat, 'base64');
      else throw Error('invalid encoding');
    }
  }
  return data;
}

export function decode(data, steps) {
  return decodeBytes(data, steps).toString('latin1').trim();
}

export function valid(text) {
  return /^flag\{[\da-fA-F]{32}\}$/.test(text) && !/^flag\{(.)\1{31}\}$/i.test(text);
}

const uint = {type:'integer', minimum:0};
function tool(name, description, properties, required) {
  return {type:'function',function:{name,description,parameters:{
    type:'object',properties,required,additionalProperties:false
  }}};
}
export const tools = [
  tool('inspect','Read a window from an artifact. Returns text, hex, and byte offsets.',
    {id:uint,offset:uint,length:uint},['id','offset','length']),
  tool('find_text','Locate literal UTF-8 text in an artifact. Returns byte offsets.',
    {id:uint,text:{type:'string'}},['id','text']),
  tool('derive','Create an artifact from a byte range. Optional transforms are applied in order. xor uses repeating keyHex.',
    {id:uint,offset:uint,length:uint,steps:{type:'array',items:{enum:[...operations,'xor']}},keyHex:{type:'string'}},['id','steps']),
  tool('join_parts','Join 2–8 artifact IDs in order and record a new artifact.',
    {ids:{type:'array',items:uint}},['ids']),
  tool('verify','Check a whole artifact as a candidate. Submit only if the bytes give a complete valid flag.',
    {id:uint},['id'])
];

export function notebook(files) {
  const artifacts = files.map(f => f.data);
  function get(id) {
    if (!Number.isInteger(id) || id < 0 || id >= artifacts.length) throw Error('Unknown artifact id');
    return artifacts[id];
  }
  function range(data,offset,length,max) {
    if (!Number.isInteger(offset) || offset < 0 || offset > data.length ||
        !Number.isInteger(length) || length < 1 || length > max) throw Error('Invalid byte range');
    return data.subarray(offset,offset+length);
  }
  function save(data) {
    if (!data.length || data.length > 65536 || artifacts.length >= files.length+64) throw Error('Derived artifact limit');
    const id = artifacts.push(data)-1;
    return {id,size:data.length,preview:data.toString('latin1',0,160)};
  }
  return (name,args) => {
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw Error('Expected argument object');
    if (name === 'join_parts') {
      if (!Array.isArray(args.ids) || args.ids.length < 2 || args.ids.length > 8) throw Error('Expected 2–8 ids');
      return save(Buffer.concat(args.ids.map(get)));
    }
    const data = get(args.id);
    if (name === 'inspect') {
      const part = range(data,args.offset,args.length,1024);
      return {size:data.length,offset:args.offset,text:part.toString('utf8'),hex:part.toString('hex')};
    }
    if (name === 'find_text') {
      if (typeof args.text !== 'string' || !args.text.length || args.text.length > 128) throw Error('Invalid search text');
      const offsets = [];
      for (let i=data.indexOf(args.text); i>=0 && offsets.length<32; i=data.indexOf(args.text,i+1)) offsets.push(i);
      return {offsets};
    }
    if (name === 'derive') {
      if (!Array.isArray(args.steps) || args.steps.length>5) throw Error('Expected up to five steps');
      let bytes = range(data,args.offset ?? 0,args.length ?? data.length,65536);
      for (const op of args.steps) {
        if (op === 'xor') {
          if (typeof args.keyHex !== 'string' || !/^(?:[a-f\d]{2}){1,128}$/i.test(args.keyHex)) throw Error('Invalid hex key');
          const key = Buffer.from(args.keyHex,'hex');
          bytes = bytes.map((b,i)=>b^key[i%key.length]);
        } else {
          if (!operations.includes(op)) throw Error('Unknown operation');
          // Preserve decoded binary bytes, including leading and trailing whitespace.
          bytes = decodeBytes(bytes,[op]);
        }
      }
      return save(bytes);
    }
    if (name === 'verify') {
      const value = data.toString('latin1').trim();
      return valid(value) ? {candidate:value} : {verified:false,reason:'Expected complete flag bytes'};
    }
    throw Error('Unknown tool');
  };
}
