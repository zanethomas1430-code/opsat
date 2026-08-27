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
import time
import urllib.request as _urlreq
import urllib.error as _urlerr
import urllib.parse as _urlparse
import threading
from http.server import ThreadingHTTPServer
from RangeHTTPServer import RangeRequestHandler

try:
    import dungeon_weather
    _HAS_DW = True
except Exception:
    _HAS_DW = False

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



def nfc_read():
    """Read one tag now (blocking until a tag is present or timeout).
    termux-nfc returns JSON describing the tapped tag. Own tags only:
    this reports UID/type, it does not authenticate or crack sectors."""
    ok, out = run(['termux-nfc', '-r', 'short'], timeout=25)
    if not ok:
        return {'error': out}
    try:
        data = json.loads(out)
    except ValueError:
        return {'error': 'unparseable', 'raw': out[:400]}
    # normalize the fields we care about
    tag = {}
    # termux-nfc shapes vary by version; pull common keys defensively
    def dig(d, *keys):
        for k in keys:
            if isinstance(d, dict) and k in d:
                return d[k]
        return None
    tag['id'] = dig(data, 'id', 'uid', 'serial')
    tag['type'] = dig(data, 'type', 'techlist', 'tech')
    tag['raw'] = data
    return {'tag': tag}


def nfc_write(text):
    """Write a text/URL record to a writable tag you own (NTAG etc.).
    Refuses empty payloads. Does not format or lock."""
    text = (text or '').strip()
    if not text:
        return {'ok': False, 'error': 'empty payload'}
    # -w write mode, -t link/text record
    ok, out = run(['termux-nfc', '-w', '-t', 'link', '-p', text], timeout=25)
    if not ok:
        # some builds use different flags; report so we can adapt
        return {'ok': False, 'error': out}
    return {'ok': True, 'wrote': text}



# ---- combined sensor stream: ONE termux-sensor process, both dials ----
# Android typically allows only one termux-sensor at a time, so we read
# light AND magnetic in a single stream and fan the values out.
import math as _math
_light_lock = threading.Lock()
_light_latest = {"lux": None, "ts": None, "note": "starting"}
_mag_lock = threading.Lock()
_mag_latest = {"uT": None, "baseline": None, "ts": None, "note": "starting"}
_mag_baseline_ema = None

def _sensor_stream_loop():
    global _mag_baseline_ema
    cmd = ["termux-sensor", "-s", "light,magnetic", "-d", "200"]
    while True:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, bufsize=1,
                                    universal_newlines=True)
            buf = ""; depth = 0; started = False
            for ch in iter(lambda: proc.stdout.read(1), ""):
                if ch == "{":
                    depth += 1; started = True
                if started:
                    buf += ch
                if ch == "}":
                    depth -= 1
                    if depth == 0 and started:
                        try:
                            data = json.loads(buf)
                            # light: any key containing 'light'
                            # magnetic: any key containing 'magnet'
                            for name, v in data.items():
                                if not isinstance(v, dict):
                                    continue
                                vals = v.get("values")
                                if not vals:
                                    continue
                                lname = name.lower()
                                if "light" in lname:
                                    with _light_lock:
                                        _light_latest["lux"] = round(float(vals[0]), 1)
                                        _light_latest["ts"] = time.time()
                                        _light_latest["note"] = ""
                                elif "magnet" in lname and len(vals) >= 3:
                                    mag = _math.sqrt(sum(float(x) ** 2 for x in vals[:3]))
                                    if _mag_baseline_ema is None:
                                        _mag_baseline_ema = mag
                                    else:
                                        _mag_baseline_ema = 0.02 * mag + 0.98 * _mag_baseline_ema
                                    with _mag_lock:
                                        _mag_latest["uT"] = round(mag, 1)
                                        _mag_latest["baseline"] = round(_mag_baseline_ema, 1)
                                        _mag_latest["ts"] = time.time()
                                        _mag_latest["note"] = ""
                        except (ValueError, TypeError):
                            pass
                        buf = ""; started = False
        except FileNotFoundError:
            with _light_lock:
                _light_latest["note"] = "termux-sensor not found"
            with _mag_lock:
                _mag_latest["note"] = "termux-sensor not found"
            return
        except Exception as e:
            with _light_lock:
                _light_latest["note"] = "stream error: " + str(e)
        time.sleep(1)

def start_sensor_stream():
    threading.Thread(target=_sensor_stream_loop, name="sensor-stream", daemon=True).start()
AI_UPSTREAM = "http://127.0.0.1:8081/completion"

OPSAT_SYSTEM = (
    "You are OPSAT, a terse tactical field computer worn on the wrist. "
    "You speak in short, clipped, mission-log sentences. You never invent "
    "capabilities you do not have. When given sensor readings, you interpret "
    "them plainly and flag only real anomalies. Stay in character; be useful, "
    "not chatty."
)

def _ai_complete(user_text, context_text):
    # build a single prompt string (llama.cpp /completion is prompt-in/text-out)
    prompt = "<|system|>\n" + OPSAT_SYSTEM + "\n"
    if context_text:
        prompt += "<|context|>\n" + context_text + "\n"
    prompt += "<|user|>\n" + user_text + "\n<|assistant|>\n"
    payload = json.dumps({
        "prompt": prompt,
        "n_predict": 200,
        "temperature": 0.7,
        "stop": ["<|user|>", "<|system|>"]
    }).encode("utf-8")
    req = _urlreq.Request(AI_UPSTREAM, data=payload,
                          headers={"Content-Type": "application/json"})
    try:
        with _urlreq.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode("utf-8"))
        return {"ok": True, "text": (data.get("content") or "").strip()}
    except _urlerr.URLError as e:
        return {"ok": False, "error": "AI offline (start ~/opsat-ai/start-ai.sh): " + str(e.reason)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _live_sensor_context():
    """Gather current sensor readings to feed the model, in plain text."""
    parts = []
    try:
        with _light_lock:
            if _light_latest.get("lux") is not None:
                parts.append("light %.0f lux" % _light_latest["lux"])
    except Exception:
        pass
    try:
        with _mag_lock:
            if _mag_latest.get("uT") is not None:
                parts.append("EMI %.0f uT (baseline %.0f)" % (
                    _mag_latest["uT"], _mag_latest.get("baseline") or _mag_latest["uT"]))
    except Exception:
        pass
    return "; ".join(parts)



# ---- ALPR / Flock camera awareness: fetch-once, cache-to-disk, serve local --
CAM_CACHE = os.path.join(BASE, "cameras.json")
# Portland metro bbox (S,W,N,E) -- same area as the offline map
CAM_BBOX = "45.448,-122.815,45.662,-122.473"
OVERPASS = "https://overpass-api.de/api/interpreter"

def _fetch_cameras():
    """One-time pull of ALPR nodes from OpenStreetMap via Overpass.
    This is the ONLY outbound call; after caching, /cameras is fully local."""
    q = ('[out:json][timeout:25];node["surveillance:type"="ALPR"](%s);out body;'
         % CAM_BBOX)
    data = _urlparse.urlencode({"data": q}).encode()
    req = _urlreq.Request(OVERPASS, data=data,
                          headers={"User-Agent": "opsat/1.0 (personal)"})
    with _urlreq.urlopen(req, timeout=45) as r:
        j = json.loads(r.read().decode("utf-8"))
    pts = []
    for e in j.get("elements", []):
        if "lat" not in e or "lon" not in e:
            continue
        t = e.get("tags", {})
        pts.append({
            "lat": e["lat"], "lon": e["lon"],
            "mfr": t.get("manufacturer", ""),
            "dir": t.get("camera:direction", ""),
            "type": t.get("surveillance:type", "ALPR"),
        })
    with open(CAM_CACHE, "w") as f:
        json.dump({"count": len(pts), "cameras": pts}, f)
    return pts


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


        if self.path == '/nfc':
            self._json(nfc_read())
            return


        if self.path == '/sense/status':
            if _HAS_DW:
                self._json(dungeon_weather.get_state())
            else:
                self._json({'error': 'dungeon_weather module not found'})
            return


        if self.path == '/light/live':
            with _light_lock:
                snap = dict(_light_latest)
            self._json(snap)
            return


        if self.path == '/emi/live':
            with _mag_lock:
                snap = dict(_mag_latest)
            self._json(snap)
            return


        if self.path == '/cameras':
            try:
                with open(CAM_CACHE) as f:
                    self._json(json.load(f)); return
            except FileNotFoundError:
                # no cache yet -> try one fetch, fall back to empty+hint
                try:
                    pts = _fetch_cameras()
                    self._json({"count": len(pts), "cameras": pts})
                except Exception as e:
                    self._json({"count": 0, "cameras": [],
                                "note": "no cache; fetch failed (need internet once): " + str(e)})
            return

        if self.path == '/cameras/refresh':
            try:
                pts = _fetch_cameras()
                self._json({"ok": True, "count": len(pts)})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})
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
        if self.path == '/nfcwrite':
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length else b''
            try:
                payload = json.loads(raw.decode('utf-8'))
            except Exception:
                payload = {}
            self._json(nfc_write(payload.get('text', '')))
            return

        if self.path == '/ai':
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length else b''
            try:
                body = json.loads(raw.decode('utf-8'))
            except Exception:
                body = {}
            user_text = (body.get('text') or '').strip()
            ctx = _live_sensor_context() if body.get('use_sensors') else ''
            if not user_text and ctx:
                user_text = 'Give a one-line read on the room from these sensors.'
            self._json(_ai_complete(user_text, ctx))
            return

        self.send_response(404)
        self.end_headers()


if __name__ == '__main__':
    os.chdir(BASE)
    # dungeon_weather.start() disabled: it spawned its own termux-sensor
    # calls that collided with the combined sensor stream. Re-enable only
    # after refactoring it to read the shared _light_latest/_mag_latest.
    # if _HAS_DW:
    #     dungeon_weather.start()
    start_sensor_stream()
    print('OPSAT server on port %d (static + range + drop + battery/vibrate/scan/nfc/sense/light/emi)' % PORT)
    ThreadingHTTPServer(('', PORT), OpsatHandler).serve_forever()
