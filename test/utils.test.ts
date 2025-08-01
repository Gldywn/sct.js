import { describe, it } from 'node:test';
import assert from 'node:assert';
import { BufferReader, decodePEM } from '../src/utils';

describe('BufferReader', () => {
  const data = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);

  it('creates a new BufferReader', () => {
    const reader = new BufferReader(data);
    assert.ok(reader instanceof BufferReader);
  });

  it('readUInt8', () => {
    const reader = new BufferReader(data);
    assert.strictEqual(reader.readUInt8(), 0x01);
    assert.strictEqual(reader.readUInt8(), 0x02);
  });

  it('readUInt16BE', () => {
    const reader = new BufferReader(data);
    assert.strictEqual(reader.readUInt16BE(), 0x0102);
  });

  it('readUInt24BE', () => {
    const reader = new BufferReader(data);
    assert.strictEqual(reader.readUInt24BE(), 0x010203);
  });

  it('readBigUInt64BE', () => {
    const reader = new BufferReader(data);
    assert.strictEqual(reader.readBigUInt64BE(), 0x0102030405060708n);
  });

  it('readBytes', () => {
    const reader = new BufferReader(data);
    assert.deepStrictEqual(reader.readBytes(4), Buffer.from([0x01, 0x02, 0x03, 0x04]));
  });

  it('hasBytes', () => {
    const reader = new BufferReader(data);
    assert.ok(reader.hasBytes(10));
    reader.readBytes(5);
    assert.ok(reader.hasBytes(5));
  });

  it('hasBytes returns false if there are not enough bytes remaining', () => {
    const reader = new BufferReader(data);
    assert.ok(!reader.hasBytes(11));
    reader.readBytes(5);
    assert.ok(!reader.hasBytes(6));
  });

  it('remaining returns the number of remaining bytes', () => {
    const reader = new BufferReader(data);
    assert.strictEqual(reader.remaining(), 10);
    reader.readBytes(5);
    assert.strictEqual(reader.remaining(), 5);
    reader.readBytes(5);
    assert.strictEqual(reader.remaining(), 0);
  });

  it('throws when reading past the end of the buffer', () => {
    const reader = new BufferReader(Buffer.from([0x01]));
    reader.readUInt8();
    assert.throws(() => reader.readUInt8());
  });
});

describe('decodePEM', () => {
  const cert = '-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----';
  const certWithCR = '-----BEGIN CERTIFICATE-----\r\nQQ==\r\n-----END CERTIFICATE-----';
  const custom = '-----BEGIN FOO BAR-----\nQQ==\n-----END FOO BAR-----';
  const multiple = `${cert}\n${custom}`;
  const noPem = 'not a pem';
  const base64 = 'QQ==';

  it('decodes a single PEM', () => {
    const result = decodePEM(cert);
    assert.strictEqual(result.length, 1);
    assert.strictEqual(Buffer.from(result[0]).toString('base64'), base64);
  });

  it('decodes a single PEM with carriage returns', () => {
    const result = decodePEM(certWithCR);
    assert.strictEqual(result.length, 1);
    assert.strictEqual(Buffer.from(result[0]).toString('base64'), base64);
  });

  it('decodes multiple PEMs', () => {
    const result = decodePEM(multiple);
    assert.strictEqual(result.length, 2);
    assert.strictEqual(Buffer.from(result[0]).toString('base64'), base64);
    assert.strictEqual(Buffer.from(result[1]).toString('base64'), base64);
  });

  it('returns an empty array if no PEM is found', () => {
    const result = decodePEM(noPem);
    assert.strictEqual(result.length, 0);
  });

  it('decodes a PEM with a custom tag', () => {
    const result = decodePEM(custom, 'FOO BAR');
    assert.strictEqual(result.length, 1);
    assert.strictEqual(Buffer.from(result[0]).toString('base64'), base64);
  });
});
