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
