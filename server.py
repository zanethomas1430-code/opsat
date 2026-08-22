#!/usr/bin/env python
# OPSAT server: static files with HTTP range support (pmtiles needs it)
# plus a tiny text-drop endpoint at /drop for moving pasteboards
# between devices on the LAN. No accounts, no cloud, no logging of content.
#
# Run from ~/opsat:  python server.py
# Replaces:          python -m RangeHTTPServer 8080

import os
from http.server import HTTPServer
from RangeHTTPServer import RangeRequestHandler

DROP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drop.txt')
PORT = 8080


class OpsatHandler(RangeRequestHandler):

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
        # everything else: normal static serving with range support
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
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print('OPSAT server on port %d (static + range + /drop)' % PORT)
    HTTPServer(('', PORT), OpsatHandler).serve_forever()
