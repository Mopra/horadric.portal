'use strict';
const test = require('node:test');
const assert = require('node:assert');
const R = require('../relay');

test('pc id is the first 32 hex of sha256 of the secret', () => {
  assert.strictEqual(R.pcId('abc'), 'ba7816bf8f01cfea414140de5dae2223');
  assert.ok(R.isId(R.pcId('anything at all')));
});

test('frame and unframe round trip, big endian', () => {
  const f = R.frame(0x01020304, Buffer.from([9, 8]));
  assert.deepStrictEqual([...f], [1, 2, 3, 4, 9, 8]);
  const u = R.unframe(f);
  assert.strictEqual(u.ch, 0x01020304);
  assert.deepStrictEqual([...u.payload], [9, 8]);
  assert.strictEqual(R.frame(R.BROADCAST, Buffer.alloc(0)).readUInt32BE(0), 0xffffffff);
  assert.strictEqual(R.unframe(Buffer.from([1, 2])), null);
});

test('channels skip 0, broadcast and taken ones', () => {
  assert.strictEqual(R.nextChannel(0, new Map()), 1);
  assert.strictEqual(R.nextChannel(0xfffffffe, new Map()), 1);
  assert.strictEqual(R.nextChannel(0, new Map([[1, 0], [2, 0]])), 3);
});

test('ids and secrets are checked', () => {
  assert.ok(!R.isId('ABC'));
  assert.ok(!R.isId('0'.repeat(31)));
  assert.ok(!R.isSecret('short'));
  assert.ok(R.isSecret('x'.repeat(43)));
});

test('pings are recognised, nothing else is', () => {
  assert.ok(R.isPing(Buffer.from('{"ping":1}')));
  assert.ok(!R.isPing(Buffer.from('{"ping":2}')));
  assert.ok(!R.isPing(Buffer.from('{"open":1}')));
  assert.ok(!R.isPing(Buffer.from('not json')));
  assert.ok(!R.isPing(Buffer.from('x'.repeat(100))));
});
