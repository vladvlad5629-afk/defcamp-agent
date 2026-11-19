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
export function decode(data, steps) {
  if (!Array.isArray(steps) || steps.length > 5) throw Error('invalid steps');
  for (const step of steps) {
    const text = data.toString('latin1').trim();
    if (step === 'reverse') data = Buffer.from(text, 'latin1').reverse();
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
  return data.toString('latin1').trim();
}

export function valid(text) {
  return /^flag\{[\da-fA-F]{32}\}$/.test(text) && !/^flag\{(.)\1{31}\}$/i.test(text);
}
