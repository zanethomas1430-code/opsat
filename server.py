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
