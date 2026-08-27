"""
dungeon_weather.py  --  the OPSAT's opinion about the room.

A small, always-on, rules-based "environment brain". Every SAMPLE_INTERVAL
seconds it reads three dials -- SOUND, DEVICES, LIGHT -- classifies each, and
rolls them into one DUNGEON STATE verdict: NORMAL / RISING / COMPROMISED.

Design principles (match the OPSAT ethics rig):
  - LOCAL ONLY. No cloud, no analytics, no network calls of any kind.
  - PRIVACY. Never persist raw audio. Never log MAC addresses or SSIDs.
    We compute aggregate stats (levels, spike counts, device counts) and
    throw the raw material away in the same tick.
  - TRANSPARENT. Plain if/else rules with named thresholds you can edit,
    all gathered in the CONFIG block below. No ML, no magic.

Usage from your server process:
    import dungeon_weather
    dungeon_weather.start()              # spins up the background sampler
    ...
    state = dungeon_weather.get_state()  # small JSON-serializable dict
    ...
    dungeon_weather.stop()               # clean shutdown

Everything the sampler touches on the device goes through termux-api CLIs.
If a command is missing or a sensor is unavailable, that dial degrades to a
safe default ('quiet' / 'sparse' / 'dim') and records why in .note rather
than crashing the whole brain.
"""

import json
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone

# ======================================================================
# CONFIG  --  everything you might tune lives here.
# ======================================================================

SAMPLE_INTERVAL = 10          # seconds between full samples (spec default)

# --- SOUND -----------------------------------------------------------
# We take a very short mic clip, compute an RMS-ish level, and track
# sudden jumps (transients) rather than absolute loudness -- so YOU
# turning your own music up does not read as "hostile".
SOUND_CLIP_SECONDS   = 1      # length of the peek clip; keep tiny
SOUND_SPIKE_DELTA    = 0.18   # rise vs. rolling baseline that counts as a spike
                              #   (0..1 scale; lower = more sensitive)
SOUND_SPIKES_WINDOW  = 60     # seconds over which we count spikes
SOUND_SPIKES_HOSTILE = 3      # >= this many spikes in the window => 'hostile'
SOUND_SOCIAL_LEVEL   = 0.06   # sustained level above this (but not spiky) => 'social'
SOUND_BASELINE_ALPHA = 0.3    # EMA smoothing for the baseline (0..1)

# --- DEVICES ---------------------------------------------------------
# Counts of WiFi APs + BLE devices in range. We care about "packed" and
# especially "churn" (a sharp jump in count = new devices arriving fast).
DEV_SPARSE_MAX   = 6          # <= this total => 'sparse'
DEV_PACKED_MIN   = 20         # >= this total => 'packed'
DEV_CHURN_DELTA  = 6          # +this many since last sample => treat as packed/churn
DEV_HISTORY_LEN  = 6          # samples kept to compute recent delta

# --- LIGHT -----------------------------------------------------------
# Comfort dial, not a threat dial. Dark is fine/preferred.
LIGHT_DARK_MAX   = 10         # lux <= this => 'dark'
LIGHT_BRIGHT_MIN = 400        # lux >= this => 'bright'  (else 'dim')

# --- DUNGEON STATE verdict -------------------------------------------
# How the three dials combine. Kept deliberately simple and commented.
# You can add "fuck this floor" rules in classify_state() below.
COMPROMISED_NEEDS_WINDOWS = 2   # sustained hostile+packed for >= this many
                                # consecutive samples before COMPROMISED

# --- termux-api command names (edit here if your build differs) ------
CMD_MIC     = ["termux-microphone-record"]      # + args added below
CMD_WIFI    = ["termux-wifi-scaninfo"]
CMD_BLE     = ["termux-bluetooth-scaninfo"]
CMD_LIGHT   = ["termux-sensor", "-s", "light", "-n", "1"]

# ======================================================================
# internal state
# ======================================================================

_lock = threading.Lock()
_thread = None
_stop_evt = threading.Event()

_spike_times = deque()                     # timestamps of recent sound spikes
_sound_baseline = 0.0                       # EMA of recent sound level
_dev_history = deque(maxlen=DEV_HISTORY_LEN)
_compromised_streak = 0

_state = {
    "sound":   {"label": "quiet",  "spikes_per_min": 0.0, "raw_level": None, "note": ""},
    "devices": {"label": "sparse", "count": 0, "recent_delta": 0, "note": ""},
    "light":   {"label": "dim",    "raw_level": None, "note": ""},
    "dungeon_state": "NORMAL",
    "should_recommend_extraction": False,
    "last_updated": None,
}

# rolling verdict-change log the UI can show (labels + timestamps only)
_verdict_log = deque(maxlen=20)
_last_logged_state = None


def _now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _run(cmd, timeout=15):
    """Run a command, return (ok, stdout_text). Never raises."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return True, out.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except subprocess.CalledProcessError as e:
        return False, (e.output.decode("utf-8", "replace") if e.output else "failed")
    except FileNotFoundError:
        return False, "command not found"
    except Exception as e:  # noqa
        return False, str(e)


# ----------------------------------------------------------------------
# SOUND
# ----------------------------------------------------------------------
def sample_sound():
    """
    Peek at ambient sound. We record a tiny clip to a temp file, measure a
    crude level from its size/content, then DELETE the file immediately.
    Raw audio is never persisted or returned.

    NOTE: termux-microphone-record writes a file; there is no clean
    "give me the RMS" API, so we use file byte-size of a fixed-length clip
    as a coarse proxy for loudness. It is crude but transient-sensitive
    enough for spike detection, and it keeps us from parsing audio.
    Swap in a real RMS (e.g. via a tiny wav read) here if you want more
    fidelity -- this function is the ONE place sound sensing lives.
    """
    global _sound_baseline

    import os, tempfile
    path = os.path.join(tempfile.gettempdir(), "opsat_sound_peek.wav")
    rec = CMD_MIC + ["-l", str(SOUND_CLIP_SECONDS), "-f", path]
    ok, msg = _run(rec, timeout=SOUND_CLIP_SECONDS + 8)

    level = 0.0
    note = ""
    try:
        if ok and os.path.exists(path):
            size = os.path.getsize(path)
            # normalize: a ~1s clip is tens of KB; map to a rough 0..1.
            # tune divisor if your device's clips are bigger/smaller.
            level = min(1.0, size / 120000.0)
        else:
            note = "mic unavailable: " + msg
    finally:
        # PRIVACY: destroy the audio immediately, always.
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    # spike = level jumped well above the rolling baseline (a transient),
    # NOT just "level is high" (that would flag your own music).
    is_spike = (level - _sound_baseline) >= SOUND_SPIKE_DELTA
    _sound_baseline = (SOUND_BASELINE_ALPHA * level
                       + (1 - SOUND_BASELINE_ALPHA) * _sound_baseline)

    now = time.time()
    if is_spike:
        _spike_times.append(now)
    # drop spikes older than the window
    while _spike_times and (now - _spike_times[0]) > SOUND_SPIKES_WINDOW:
        _spike_times.popleft()

    spikes = len(_spike_times)
    spikes_per_min = spikes * (60.0 / SOUND_SPIKES_WINDOW)

    if spikes >= SOUND_SPIKES_HOSTILE:
        label = "hostile"
    elif level >= SOUND_SOCIAL_LEVEL:
        label = "social"
    else:
        label = "quiet"

    return {
        "label": label,
        "spikes_per_min": round(spikes_per_min, 1),
        "raw_level": round(level, 3),
        "note": note,
    }


# ----------------------------------------------------------------------
# DEVICES
# ----------------------------------------------------------------------
def _count_json_array(cmd):
    ok, out = _run(cmd)
    if not ok:
        return None, out
    try:
        data = json.loads(out)
        if isinstance(data, list):
            return len(data), ""
        # some builds wrap results; be forgiving
        if isinstance(data, dict) and "devices" in data:
            return len(data["devices"]), ""
        return 0, "unexpected shape"
    except ValueError:
        return None, "unparseable"


def sample_devices():
    """
    Count WiFi APs + BLE devices in range. We store ONLY counts -- never
    MACs or SSIDs. 'packed' triggers on absolute count or on churn (a fast
    rise since the last sample), because new devices arriving quickly is the
    interesting warning sign.
    """
    notes = []
    wifi, wnote = _count_json_array(CMD_WIFI)
    ble,  bnote = _count_json_array(CMD_BLE)
    if wifi is None:
        notes.append("wifi:" + wnote); wifi = 0
    if ble is None:
        notes.append("ble:" + bnote); ble = 0

    total = wifi + ble
    prev = _dev_history[-1] if _dev_history else total
    delta = total - prev
    _dev_history.append(total)

    if total >= DEV_PACKED_MIN or delta >= DEV_CHURN_DELTA:
        label = "packed"
    elif total <= DEV_SPARSE_MAX:
        label = "sparse"
    else:
        label = "normal"

    return {
        "label": label,
        "count": total,
        "recent_delta": delta,
        "note": "; ".join(notes),
    }


# ----------------------------------------------------------------------
# LIGHT
# ----------------------------------------------------------------------
def sample_light():
    """
    Read the ambient light sensor (lux) via termux-sensor. Comfort dial:
    dark is fine. If the sensor is missing, degrade to 'dim' with a note.
    """
    ok, out = _run(CMD_LIGHT, timeout=12)
    lux = None
    note = ""
    if ok:
        try:
            data = json.loads(out)
            # termux-sensor returns {"<sensor name>": {"values": [lux, ...]}}
            for _, v in data.items():
                vals = v.get("values") if isinstance(v, dict) else None
                if vals:
                    lux = float(vals[0])
                    break
        except (ValueError, KeyError, TypeError):
            note = "unparseable"
    else:
        note = "light sensor unavailable: " + out

    if lux is None:
        return {"label": "dim", "raw_level": None, "note": note or "no reading"}

    if lux <= LIGHT_DARK_MAX:
        label = "dark"
    elif lux >= LIGHT_BRIGHT_MIN:
        label = "bright"
    else:
        label = "dim"
    return {"label": label, "raw_level": round(lux, 1), "note": note}


# ----------------------------------------------------------------------
# VERDICT
# ----------------------------------------------------------------------
def classify_state(sound, devices, light):
    """
    Combine the three dials into NORMAL / RISING / COMPROMISED.
    Simple, commented, editable. Returns (state_str, recommend_extraction).

    Add your own "fuck this floor" rules where marked.
    """
    global _compromised_streak

    hostile = sound["label"] == "hostile"
    packed  = devices["label"] == "packed"
    dark    = light["label"] == "dark"

    # --- COMPROMISED: strong sustained combo -------------------------
    # hostile sound AND packed/churning devices, held for >= N windows.
    if hostile and packed:
        _compromised_streak += 1
    else:
        _compromised_streak = 0

    if _compromised_streak >= COMPROMISED_NEEDS_WINDOWS:
        # We only change the label + set a boolean. Nothing irreversible.
        return "COMPROMISED", True

    # --- RISING: any single strong signal ----------------------------
    # - hostile sound alone, or
    # - packed/churning devices alone, or
    # - dark + hostile (jump-scare combo is worse), nudged in via 'hostile'
    if hostile or packed:
        return "RISING", False

    # (example extra rule you could enable:)
    # if dark and devices["recent_delta"] >= DEV_CHURN_DELTA:
    #     return "RISING", False

    # --- NORMAL ------------------------------------------------------
    return "NORMAL", False


# ----------------------------------------------------------------------
# sampler loop
# ----------------------------------------------------------------------
def _sample_once():
    global _last_logged_state
    sound = sample_sound()
    devices = sample_devices()
    light = sample_light()
    state_str, recommend = classify_state(sound, devices, light)

    with _lock:
        _state["sound"] = sound
        _state["devices"] = devices
        _state["light"] = light
        _state["dungeon_state"] = state_str
        _state["should_recommend_extraction"] = recommend
        _state["last_updated"] = _now_iso()

        # log only when the verdict CHANGES, labels + time only
        if state_str != _last_logged_state:
            _verdict_log.appendleft({
                "t": _now_iso(),
                "sound": sound["label"],
                "devices": devices["label"],
                "light": light["label"],
                "state": state_str,
            })
            _last_logged_state = state_str


def _loop():
    while not _stop_evt.is_set():
        try:
            _sample_once()
        except Exception:
            # never let one bad sample kill the brain
            pass
        _stop_evt.wait(SAMPLE_INTERVAL)


# ----------------------------------------------------------------------
# public API
# ----------------------------------------------------------------------
def start():
    """Spin up the background sampler (idempotent)."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_evt.clear()
    _thread = threading.Thread(target=_loop, name="dungeon-weather", daemon=True)
    _thread.start()


def stop():
    """Signal the sampler to finish its current tick and exit."""
    _stop_evt.set()


def get_state():
    """Return a small JSON-serializable snapshot for the UI."""
    with _lock:
        snap = json.loads(json.dumps(_state))  # cheap deep copy
        snap["log"] = list(_verdict_log)
    return snap


# ----------------------------------------------------------------------
# run standalone for testing:  python dungeon_weather.py
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Dungeon Weather: sampling every %ss. Ctrl-C to stop.\n" % SAMPLE_INTERVAL)
    start()
    try:
        while True:
            time.sleep(SAMPLE_INTERVAL)
            print(json.dumps(get_state(), indent=2))
    except KeyboardInterrupt:
        stop()
        print("\nstopped.")
