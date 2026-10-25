import { parseCidr, containsIp } from '../tools/cidr.js';
import { allowPort, portForward } from '../tools/iptables.js';

console.log(parseCidr('10.0.0.0/26'));
console.log(containsIp('192.168.1.0/24', '192.168.1.42'));
console.log(allowPort({ port: 3306, source: '203.0.113.5' }));
console.log(portForward({ publicPort: 8080, destination: '10.0.0.5', destinationPort: 80 }));
