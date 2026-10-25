# PacketUtils

**Practical network and firewall tools**

[PacketUtils](https://packetutils.com/) provides free online tools and practical guides for networking, firewall configuration and server administration. The tools run in your browser.

This repository holds the small, dependency-free JavaScript helpers behind some of them, so you can use the same logic in your own scripts.

## Modules

Plain ES modules for browsers and Node.js 18 or newer.

### `tools/cidr.js`

```js
import { parseCidr, containsIp } from './tools/cidr.js';

parseCidr('10.0.0.0/26');
// { prefix: 26, network: '10.0.0.0', broadcast: '10.0.0.63', firstHost: '10.0.0.1',
//   lastHost: '10.0.0.62', mask: '255.255.255.192', wildcard: '0.0.0.63', total: 64, usable: 62 }

containsIp('192.168.1.0/24', '192.168.1.42'); // true
```

### `tools/iptables.js`

```js
import { allowPort, portForward } from './tools/iptables.js';

allowPort({ port: 3306, source: '203.0.113.5' });
// sudo iptables -I INPUT 1 -p tcp -s 203.0.113.5 --dport 3306 -j ACCEPT

portForward({ publicPort: 8080, destination: '10.0.0.5', destinationPort: 80 });
// { add: [...], undo: [...] }  the undo list removes exactly the rules that were added
```

The functions only build command strings. Review every command before you run it on a server.

## Tests

```
npm test
```

## Online tools and guides

- [CIDR to IP range](https://packetutils.com/cidr-to-ip-range)
- [iptables command generator](https://packetutils.com/iptables-generator)
- [iptables tables and chains explained](https://packetutils.com/iptables-tables-and-chains)
- [iptables port forwarding](https://packetutils.com/iptables-port-forwarding)
- [MASQUERADE vs SNAT](https://packetutils.com/iptables-masquerade-vs-snat)
- [Common ports](https://packetutils.com/common-ports)

## License

MIT, see [LICENSE](LICENSE).
