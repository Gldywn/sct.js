export class BufferReader {
  private offset = 0;

  constructor(private buffer: Buffer) {}

  readUInt8(): number {
    const value = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return value;
  }

  readUInt16BE(): number {
    const value = this.buffer.readUInt16BE(this.offset);
    this.offset += 2;
    return value;
  }

  readUInt24BE(): number {
    const value = this.buffer.readUIntBE(this.offset, 3);
    this.offset += 3;
    return value;
  }

  readBigUInt64BE(): bigint {
    const value = this.buffer.readBigUInt64BE(this.offset);
    this.offset += 8;
    return value;
  }

  readBytes(length: number): Buffer {
    const value = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  hasBytes(length: number): boolean {
    return this.offset + length <= this.buffer.length;
  }

  remaining(): number {
    return this.buffer.length - this.offset;
  }
}

import * as pvtsutils from 'pvtsutils';

export function decodePEM(pem: string, tag = '[A-Z0-9 ]+'): ArrayBuffer[] {
  const pattern = new RegExp(`-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`, 'g');

  const res: ArrayBuffer[] = [];
  let matches: RegExpExecArray | null = null;
  // eslint-disable-next-line no-cond-assign
  while ((matches = pattern.exec(pem))) {
    const base64 = matches[1].replace(/\r/g, '').replace(/\n/g, '');
    res.push(pvtsutils.Convert.FromBase64(base64));
  }

  return res;
}
