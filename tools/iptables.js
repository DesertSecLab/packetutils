// iptables command builders. They return strings, nothing is executed.
// Review every command before running it on a production server.
import { ipToInt, parseCidr } from './cidr.js';

const PORT = /^[1-9]\d{0,4}$/;
const IFACE = /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,13}\+?$/;

function port(p, label) {
  const s = String(p);
  if (!PORT.test(s) || Number(s) > 65535) throw new Error('Invalid ' + label + ': ' + p);
  return s;
}
function host(ip) {
  ipToInt(ip);
  if (ip === '0.0.0.0') throw new Error('Invalid destination: ' + ip);
  return ip;
}
function source(s) {
  if (s.includes('/')) parseCidr(s);
  else ipToInt(s);
  return s;
}
function oneOf(v, list, label) {
  if (!list.includes(v)) throw new Error('Invalid ' + label + ': ' + v);
  return v;
}

/** Allow or block a port, optionally for one source address or subnet. Inserted at the top of INPUT. */
export function allowPort({ action = 'ACCEPT', protocol = 'tcp', port: p, source: src } = {}) {
  oneOf(action, ['ACCEPT', 'DROP', 'REJECT'], 'action');
  oneOf(protocol, ['tcp', 'udp'], 'protocol');
  const s = src ? ' -s ' + source(src) : '';
  return 'sudo iptables -I INPUT 1 -p ' + protocol + s + ' --dport ' + port(p, 'port') + ' -j ' + action;
}

/**
 * Forward a public port to another host (DNAT). Returns the commands to add and to undo.
 * Set masquerade only when replies would not return through this server.
 */
export function portForward({ protocol = 'tcp', publicPort, destination, destinationPort, iface, masquerade = false } = {}) {
  oneOf(protocol, ['tcp', 'udp'], 'protocol');
  const pp = port(publicPort, 'public port');
  const dp = port(destinationPort, 'destination port');
  const ip = host(destination);
  if (iface && !IFACE.test(iface)) throw new Error('Invalid interface: ' + iface);
  const ix = iface ? ' -i ' + iface : '';
  const add = [];
  const del = [];
  const rule = (table, chain, spec, insert) => {
    const head = 'sudo iptables' + (table ? ' -t ' + table : '');
    add.push(head + (insert ? ' -I ' + chain + ' 1 ' : ' -A ' + chain + ' ') + spec);
    del.unshift(head + ' -D ' + chain + ' ' + spec);
  };
  rule('nat', 'PREROUTING', '-p ' + protocol + ix + ' --dport ' + pp + ' -j DNAT --to-destination ' + ip + ':' + dp);
  rule('', 'FORWARD', '-p ' + protocol + ' -d ' + ip + ' --dport ' + dp + ' -j ACCEPT', true);
  rule('', 'FORWARD', '-p ' + protocol + ' -s ' + ip + ' --sport ' + dp + ' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', true);
  if (masquerade) {
    rule('nat', 'POSTROUTING', '-p ' + protocol + ' -d ' + ip + ' --dport ' + dp + ' -m conntrack --ctstate DNAT -j MASQUERADE');
  }
  return { add, undo: del };
}
