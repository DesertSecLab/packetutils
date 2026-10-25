import test from 'node:test';
import assert from 'node:assert/strict';
import { allowPort, portForward } from '../tools/iptables.js';

test('allowPort', () => {
  assert.equal(allowPort({ port: 80 }), 'sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT');
  assert.equal(
    allowPort({ action: 'DROP', protocol: 'udp', port: 53, source: '203.0.113.0/24' }),
    'sudo iptables -I INPUT 1 -p udp -s 203.0.113.0/24 --dport 53 -j DROP'
  );
  assert.throws(() => allowPort({ port: 70000 }));
  assert.throws(() => allowPort({ port: 22, source: '300.1.1.1' }));
});
test('portForward add and undo match', () => {
  const r = portForward({ publicPort: 8080, destination: '10.0.0.5', destinationPort: 80, iface: 'eth0', masquerade: true });
  assert.equal(r.add.length, 4);
  assert.equal(r.undo.length, 4);
  assert.equal(r.add[0], 'sudo iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 8080 -j DNAT --to-destination 10.0.0.5:80');
  assert.equal(r.undo[3], 'sudo iptables -t nat -D PREROUTING -p tcp -i eth0 --dport 8080 -j DNAT --to-destination 10.0.0.5:80');
  assert.throws(() => portForward({ publicPort: 8080, destination: '010.0.0.5', destinationPort: 80 }));
});
