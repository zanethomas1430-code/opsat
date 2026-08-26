#!/usr/bin/env python
# OPSAT server. Static files with HTTP range support (pmtiles needs it),
# plus small local endpoints. No accounts, no cloud, no content logging.
#
# Run from ~/opsat:  python server.py
#
# Endpoints:
#   /drop     GET returns last dropped text, POST stores text (LAN paste bridge)
#   /battery  GET -> termux-battery-status JSON
#   /vibrate  GET -> buzz the phone (termux-vibrate), returns OK
#   /scan     GET -> { wifi: [...], ble: [...] } from termux-api scanners
#
# The termux-api endpoints just wrap the termux-* CLIs; if a scan is
# unavailable (Android throttling, permission off) the JSON carries an
# "error" field instead of crashing the page.

import os
import json
import subprocess
from http.server import ThreadingHTTPServer
from RangeHTTPServer import RangeRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))
DROP_FILE = os.path.join(BASE, 'drop.txt')
PORT = 8080


def run(cmd, timeout=15):
    """Run a termux-api command, return (ok, stdout_or_error)."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return True, out.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        return False, 'timeout'
    except subprocess.CalledProcessError as e:
        return False, e.output.decode('utf-8', 'replace') if e.output else 'command failed'
    except FileNotFoundError:
        return False, 'command not found (termux-api installed?)'
    except Exception as e:
        return False, str(e)



import socket
import ipaddress
import re as _re

def own_subnet():
    """Return the /24 the phone's primary interface sits on, or None.
    We derive it from the outbound-route source IP; we never accept a
    target from the client, so scans can only ever hit our own LAN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.168.0.1', 1))   # no packet sent; just picks the iface
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            return None, None
    # refuse anything that isn't RFC1918 private space -> hard scope lock
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    if not addr.is_private:
        return None, ip
    net = ipaddress.ip_network(ip + '/24', strict=False)
    return net, ip


def netscan():
    net, ip = own_subnet()
    if net is None:
        return {'error': 'no private LAN detected (scope lock: private /24 only)', 'self': ip}
    # conservative discovery: ping sweep + a few common ports, no aggressive probes.
    # -sn would be ping-only; we do a light port check on a small, safe set.
    ports = '22,80,443,8080,8022,9100,53,139,445,3389,5353'
    ok, out = run(['nmap', '-T3', '--max-retries', '1', '--host-timeout', '20s',
                   '-p', ports, '--open', '-oG', '-', str(net)], timeout=120)
    if not ok:
        return {'error': out, 'subnet': str(net), 'self': ip}
    hosts = []
    for line in out.splitlines():
        if not line.startswith('Host:'):
            continue
        m = _re.search(r'Host:\s+(\S+)\s+\(([^)]*)\)', line)
        if not m:
            continue
        host_ip = m.group(1)
        hostname = m.group(2)
        openp = []
        pm = _re.search(r'Ports:\s+(.*?)(?:\tIgnored|$)', line)
        if pm:
            for chunk in pm.group(1).split(','):
                parts = chunk.strip().split('/')
                if len(parts) >= 5 and parts[1] == 'open':
                    svc = parts[4] or parts[2]
                    openp.append(parts[0] + ('/' + svc if svc else ''))
        hosts.append({'ip': host_ip, 'host': hostname, 'ports': openp,
                      'self': (host_ip == ip)})
    hosts.sort(key=lambda h: tuple(int(x) for x in h['ip'].split('.')))
    return {'subnet': str(net), 'self': ip, 'count': len(hosts), 'hosts': hosts}


class OpsatHandler(RangeRequestHandler):

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/drop':
            try:
                with open(DROP_FILE, 'rb') as f:
                    body = f.read()
            except FileNotFoundError:
                body = b''
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == '/battery':
            ok, out = run(['termux-battery-status'])
            if ok:
                try:
                    self._json(json.loads(out)); return
                except ValueError:
                    pass
            self._json({'error': out})
            return

        if self.path.startswith('/vibrate'):
            ok, out = run(['termux-vibrate', '-d', '200'])
            self._json({'ok': ok, 'detail': out if not ok else 'buzzed'})
            return

        if self.path == '/scan':
            result = {}
            ok, out = run(['termux-wifi-scaninfo'])
            if ok:
                try:
                    result['wifi'] = json.loads(out)
                except ValueError:
                    result['wifi'] = []
                    result['wifi_error'] = 'unparseable'
            else:
                result['wifi'] = []
                result['wifi_error'] = out
            ok, out = run(['termux-bluetooth-scaninfo'], timeout=8)
            if ok:
                try:
                    result['ble'] = json.loads(out)
                except ValueError:
                    result['ble'] = []
                    result['ble_error'] = 'unparseable'
            else:
                result['ble'] = []
                result['ble_error'] = out
            self._json(result)
            return


        if self.path == '/netscan':
            self._json(netscan())
            return

        super().do_GET()

    def do_POST(self):
        if self.path == '/drop':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length) if length else b''
            with open(DROP_FILE, 'wb') as f:
                f.write(body)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')
            return
        self.send_response(404)
        self.end_headers()


if __name__ == '__main__':
    os.chdir(BASE)
    print('OPSAT server on port %d (static + range + drop + battery/vibrate/scan)' % PORT)
    ThreadingHTTPServer(('', PORT), OpsatHandler).serve_forever()
