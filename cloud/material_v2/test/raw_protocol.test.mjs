import assert from 'node:assert/strict';

const header = Buffer.alloc(44);
header.writeUInt32BE(0x4d564f58, 0);
header.writeUInt16BE(1, 4);
header.writeUInt16BE(3, 6);
header.writeUInt32BE(0, 8);
header.writeBigUInt64BE(7n, 28);
header.writeUInt32BE(5, 36);
header.writeUInt32BE(0, 40);

assert.equal(header.length, 44);
assert.equal(header.readUInt32BE(0), 0x4d564f58);
assert.equal(header.readUInt16BE(4), 1);
assert.equal(header.readUInt16BE(6), 3);
assert.equal(header.readBigUInt64BE(28), 7n);
assert.equal(header.readUInt32BE(36), 5);
assert.equal(header.readUInt32BE(40), 0);

console.log(JSON.stringify({ ok: true, vector: header.toString('hex') }));
