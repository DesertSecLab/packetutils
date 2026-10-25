import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCidr, containsIp, ipToInt, intToIp } from '../tools/cidr.js';

test('parseCidr /24', () => {
  const c = parseCidr('192.168.1.77/24');
  assert.equal(c.network, '192.168.1.0');
  assert.equal(c.broadcast, '192.168.1.255');
  assert.equal(c.firstHost, '192.168.1.1');
  assert.equal(c.lastHost, '192.168.1.254');
  assert.equal(c.mask, '255.255.255.0');
  assert.equal(c.wildcard, '0.0.0.255');
  assert.equal(c.usable, 254);
});
test('edge prefixes', () => {
  assert.equal(parseCidr('10.0.0.0/31').usable, 2);
  assert.equal(parseCidr('10.0.0.5/32').usable, 1);
  assert.equal(parseCidr('0.0.0.0/0').total, 4294967296);
});
test('containsIp', () => {
  assert.equal(containsIp('10.0.0.0/24', '10.0.0.200'), true);
  assert.equal(containsIp('10.0.0.0/24', '10.0.1.1'), false);
});
test('rejects bad input', () => {
  for (const bad of ['10.0.0.0/33', '010.0.0.0/24', '10.0.0/24', '10.0.0.0', '10.0.0.0/24/1']) {
    assert.throws(() => parseCidr(bad), bad);
  }
  assert.throws(() => ipToInt('256.1.1.1'));
});
test('int round trip', () => assert.equal(intToIp(ipToInt('172.16.0.9')), '172.16.0.9'));
