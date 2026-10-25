// IPv4 and CIDR helpers. No dependencies. Works in browsers and Node.js 18+.

const OCT = '(0|[1-9]\\d{0,2})';
const IPV4 = new RegExp('^' + OCT + '\\.' + OCT + '\\.' + OCT + '\\.' + OCT + '$');

/** "192.168.1.10" -> 3232235786. Rejects leading zeros and values above 255. */
export function ipToInt(ip) {
  const m = IPV4.exec(String(ip).trim());
  if (!m || m.slice(1).some((n) => Number(n) > 255)) throw new Error('Invalid IPv4 address: ' + ip);
  return ((Number(m[1]) << 24) | (Number(m[2]) << 16) | (Number(m[3]) << 8) | Number(m[4])) >>> 0;
}

/** 3232235786 -> "192.168.1.10" */
export function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** Parse "10.0.0.0/24" and return network, broadcast, first/last host, masks and host counts. */
export function parseCidr(cidr) {
  const parts = String(cidr).trim().split('/');
  if (parts.length !== 2 || !/^(0|[1-9]\d?)$/.test(parts[1]) || Number(parts[1]) > 32) {
    throw new Error('Invalid CIDR block: ' + cidr);
  }
  const prefix = Number(parts[1]);
  const addr = ipToInt(parts[0]);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (addr & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = 2 ** (32 - prefix);
  return {
    prefix,
    network: intToIp(network),
    broadcast: intToIp(broadcast),
    firstHost: intToIp(prefix >= 31 ? network : network + 1),
    lastHost: intToIp(prefix >= 31 ? broadcast : broadcast - 1),
    mask: intToIp(mask),
    wildcard: intToIp((~mask) >>> 0),
    total,
    usable: prefix === 32 ? 1 : prefix === 31 ? 2 : total - 2,
  };
}

/** True when the address lies inside the CIDR block. */
export function containsIp(cidr, ip) {
  const c = parseCidr(cidr);
  const n = ipToInt(ip);
  return n >= ipToInt(c.network) && n <= ipToInt(c.broadcast);
}
