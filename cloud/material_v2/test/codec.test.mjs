import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decodeCanonical, encodeCanonical, readU64} from '../codec.mjs';
import {parseExecutionPackage, frame, packageHash} from '../../../tools/cloud-material/format.mjs';

// 该入口让 Python 将相同原始字节交给真实 Node/C++ 进程。
if (process.argv[2] === '--case') {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 11250348 + 2049) process.exit(2);
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks);
  const split = input.indexOf(10);
  try {
    const expected = decodeCanonical(input.subarray(0, split));
    const bytes = input.subarray(split + 1);
    if (process.argv[3] === 'canonical' || process.argv[3] === 'canonical-noalloc') {
      decodeCanonical(bytes);
      console.log(JSON.stringify({ok: true}));
    } else {
      const p = parseExecutionPackage(bytes, expected);
      console.log(JSON.stringify({ok: true, bytecode_size: p.bytecode.length,
        generation: p.binding.generation, package_hash: p.binding.package_hash,
        bytecode_hash: createHash('sha256').update(p.bytecode).digest('hex')}));
    }
  } catch (error) {
    console.log(JSON.stringify({ok: false, code: error.code ?? 'unexpected_error'}));
  }
} else {
  test('canonical golden bytes, ASCII escapes and u64 strings', () => {
    const value = {z: '18446744073709551615', a: 1};
    assert.equal(encodeCanonical(value).toString('hex'),
      '7b2261223a312c227a223a223138343436373434303733373039353531363135227d');
    assert.deepEqual(decodeCanonical(encodeCanonical(value)), value);
    assert.equal(encodeCanonical({a: '/"\\'}).toString(), '{"a":"/\\"\\\\"}');
    assert.equal(readU64(value.z), 18446744073709551615n);
    assert.equal(readU64('0'), 0n);
  });

  test('duplicate keys, numeric aliases, invalid UTF-8 and noncanonical bytes rejected', () => {
    for (const text of ['{"a":1,"a":2}', '{"a":{"x":1,"x":2}}',
      '{"generation":9007199254740993}', '{"a":1.0}', '{"a":1e0}', '{"a":-0}',
      '{ "a":1}', '{"a":"\\u0031"}', '{"a":"\\/"}', '{"z":0,"a":1}',
      '{"a":null}', '{"A":1}', '{"a":1}\n', '{"a":"é"}', '{"a":"\\n"}']) {
      assert.throws(() => decodeCanonical(Buffer.from(text)), undefined, text);
    }
    assert.throws(() => decodeCanonical(Buffer.from([34, 0xc0, 0xaf, 34])));
    for (const value of [1, '01', '-1', '', '18446744073709551616', '0'.repeat(21)]) {
      assert.throws(() => readU64(value));
    }
  });

  test('encoder refuses lossy values rather than JSON normalizing them', () => {
    for (const value of [null, -0, -1, 1.5, NaN, Infinity, 4294967296, 1n,
      {a: undefined}, new Date(), Array(1), {a: '\n'}, {'bad-key': 1}]) {
      assert.throws(() => encodeCanonical(value));
    }
    const cycle = {}; cycle.a = cycle;
    assert.throws(() => encodeCanonical(cycle));
  });

  test('resource ceilings enforced by preflight before JSON.parse', () => {
    const original = JSON.parse;
    JSON.parse = () => { throw new Error('DOM must not be reached'); };
    try {
      for (const [text, code] of [
        ['['.repeat(9), 'depth_limit'],
        ['{"a":"' + 'x'.repeat(257), 'string_limit'],
        ['{"a":' + '1'.repeat(11), 'number_limit'],
        ['[' + '0,'.repeat(256) + '0]', 'array_limit'],
        ['{' + Array.from({length: 41}, (_, i) => `"k${String(i).padStart(2, '0')}":0`).join(',') + '}', 'object_limit'],
        [' '.repeat(11250349), 'size_limit'],
      ]) assert.throws(() => decodeCanonical(Buffer.from(text)), {code});
    } finally { JSON.parse = original; }
  });

  test('framing fixed golden vector and domain separation', () => {
    assert.equal(frame('XOVM2/aad', Buffer.from('{}')).toString('hex'),
      '584f564d322f61616400000000027b7d');
    assert.notDeepEqual(frame('x', Buffer.from('ab'), Buffer.from('c')),
      frame('x', Buffer.from('a'), Buffer.from('bc')));
    assert.throws(() => frame('x\0', Buffer.alloc(0)));
  });

  test('package hash removes only binding.package_hash', () => {
    const core = {binding: {a: 1}, x: 2};
    // 使用独立前像；长度由字节定义校对。
    const preimage = Buffer.from('{"binding":{"a":1},"x":2}');
    const length = Buffer.alloc(4); length.writeUInt32BE(preimage.length);
    const digest = createHash('sha256').update(Buffer.concat([
      Buffer.from('XOVM2/package\0'), length, preimage])).digest('hex');
    assert.equal(packageHash({...core, binding: {...core.binding, package_hash: 'f'.repeat(64)}}), digest);
    assert.notEqual(packageHash({...core, x: 3}), digest);
  });
}
