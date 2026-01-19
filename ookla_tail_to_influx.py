#!/usr/bin/env python3
import os, re, sys, json, gzip, base64, socket, time, ipaddress
from datetime import datetime, timezone
from glob import glob

ACCESS_LOG = os.environ.get("OOKLA_ACCESS_LOG", "/opt/ookla/ooklaserver-access.log")
ARCHIVE_GLOB = os.environ.get("OOKLA_ARCHIVE_GLOB", "/opt/ookla/ooklaserver-access.log.*.gz")
STATE_FILE = os.environ.get("OOKLA_STATE_FILE", "/var/lib/ookla-logtail/state.json")

SERVER_TAG = os.environ.get("SERVER_TAG", os.uname().nodename.split(".")[0])

MEASUREMENT_TOTAL = os.environ.get("MEASUREMENT_TOTAL", "ookla_speedtest_minutely")
MEASUREMENT_ASN = os.environ.get("MEASUREMENT_ASN", "ookla_speedtest_asn_minutely")
MEASUREMENT_DEVICE = os.environ.get("MEASUREMENT_DEVICE", "ookla_speedtest_device_minutely")
MEASUREMENT_APP = os.environ.get("MEASUREMENT_APP", "ookla_speedtest_app_minutely")
MEASUREMENT_ASN_MAP = os.environ.get("MEASUREMENT_ASN_MAP", "asn_map")

start_re = re.compile(r'^[0-9a-f]{40} ')
line_re = re.compile(
    r'^(?P<client>[0-9a-f]{40})\s+-\s+(?P<session>[0-9a-f-]+|-)\s+'
    r'\[(?P<ts>[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\s+[+-][0-9]{4})?)\s+GMT\]\s+'
    r'\"(?P<req>[^\"]+)\"\s+(?P<status>[0-9]{3})\s+(?P<size>[0-9]+)\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\"'
)

guid_from_req = re.compile(r'\bguid(?:%3D|=)([0-9a-f-]{36})\b', re.IGNORECASE)
hi_req = re.compile(r'^HI\s+([0-9a-f-]{36})\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s+WS/1\.0$')

def b64url_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

def parse_ts(ts: str) -> datetime:
    ts = ts.strip()
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)

def minute_bucket(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            s = json.load(f)
            s.setdefault("inode", None)
            s.setdefault("offset", 0)
            s.setdefault("processed_archives", [])
            s.setdefault("pending_record", "")
            s.setdefault("prefix_cache", {})  # "<prefix>": {asn, asname}
            s.setdefault("asn_cache", {})     # legacy (kept, not used for new entries)
            s.setdefault("asn_mapped", [])
            return s
    except FileNotFoundError:
        return {
            "inode": None,
            "offset": 0,
            "processed_archives": [],
            "pending_record": "",
            "prefix_cache": {},
            "asn_cache": {},
            "asn_mapped": [],
        }

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)

def iter_records_from_lines(lines, pending=""):
    records = []
    cur = pending or ""
    for ln in lines:
        if start_re.match(ln):
            if cur:
                records.append(cur)
            cur = ln
        else:
            cur += ln.strip()
    return records, cur

def escape_tag(v: str) -> str:
    return str(v).replace("\\","\\\\").replace(" ","\\ ").replace(",","\\,").replace("=","\\=")

def escape_field_string(v: str) -> str:
    v = "" if v is None else str(v)
    v = v.replace("\\", "\\\\").replace('"', '\"')
    return f'"{v}"'

def build_prefix_nets(prefix_cache: dict):
    nets = {}
    for pfx in prefix_cache.keys():
        try:
            nets[pfx] = ipaddress.ip_network(pfx, strict=False)
        except Exception:
            pass
    return nets

def find_cached_prefix(ip: str, prefix_nets: dict):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return None
    for pfx, net in prefix_nets.items():
        try:
            if ip_obj in net:
                return pfx
        except Exception:
            pass
    return None

def cymru_lookup_verbose(ip: str):
    # Returns (asn, prefix, asname)
    q = f" -v {ip}\n".encode("utf-8")
    asn, prefix, asname = "unknown", None, "unknown"
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=2.5) as s:
            s.sendall(q)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        text = data.decode("utf-8", "replace").splitlines()
        for line in text:
            if "|" in line and "ASN" not in line and "AS Name" not in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 7:
                    asn = parts[0] or "unknown"
                    prefix = parts[2] or None
                    asname = parts[6] or "unknown"
                break
    except Exception:
        pass
    return asn, prefix, asname

def asn_lookup_cymru_prefix(ip: str, prefix_cache: dict, prefix_nets: dict):
    # Prefix-based caching with CIDR membership checks.
    if not ip:
        return ("unknown", None, "unknown")
    ip = ip.strip()

    cached_prefix = find_cached_prefix(ip, prefix_nets)
    if cached_prefix and cached_prefix in prefix_cache:
        v = prefix_cache[cached_prefix]
        return (v.get("asn", "unknown"), cached_prefix, v.get("asname", "unknown"))

    asn, prefix, asname = cymru_lookup_verbose(ip)

    if prefix:
        prefix_cache[prefix] = {"asn": asn, "asname": asname}
        try:
            prefix_nets[prefix] = ipaddress.ip_network(prefix, strict=False)
        except Exception:
            pass

    return (asn, prefix, asname)

def update_agg_from_record(agg, record, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s: int):
    m = line_re.match(record)
    if not m:
        return

    ts = parse_ts(m.group("ts"))
    minute = minute_bucket(ts)
    req = m.group("req")
    status = int(m.group("status"))
    ua = m.group("ua")
    client = m.group("client")

    d = agg.setdefault(minute, {
        "guids": set(),
        "users": set(),
        "uploads": 0,
        "downloads": 0,
        "errors5xx": 0,
        "asn_guids": {},
        "asn_users": {},
        "model_guids": {},
        "model_users": {},
        "app_guids": {},
        "app_users": {},
    })

    if 500 <= status <= 599:
        d["errors5xx"] += 1

    g = guid_from_req.search(req)
    if g:
        guid = g.group(1)
        d["guids"].add(guid)
        if req.startswith("POST /upload") or " /upload" in req:
            d["uploads"] += 1
        if req.startswith("GET /download") or " /download" in req:
            d["downloads"] += 1

    h = hi_req.match(req)
    if not h:
        return

    guid_from_hi = h.group(1)
    token = h.group(2)

    parts = token.split(".")
    user_key = None
    ip = None
    model = "unknown"
    app = "unknown"
    version = "unknown"
    guid_from_jwt = None

    if len(parts) >= 2:
        try:
            payload = json.loads(b64url_decode(parts[1]).decode("utf-8", "replace"))
            data = payload.get("data", {}) if isinstance(payload, dict) else {}
            if isinstance(data, dict):
                user_key = data.get("deviceId")
                ip = data.get("ip")
                model = data.get("model") or "unknown"
                app = data.get("app") or "unknown"
                version = data.get("version") or "unknown"
                guid_from_jwt = data.get("guid")
        except Exception:
            pass

    guid = guid_from_jwt or guid_from_hi
    d["guids"].add(guid)

    if user_key:
        d["users"].add(str(user_key))
    else:
        d["users"].add(f"{client}|{ua}")

    asn, _prefix, asname = asn_lookup_cymru_prefix(ip, prefix_cache, prefix_nets)
    d["asn_guids"].setdefault(asn, set()).add(guid)
    d["asn_users"].setdefault(asn, set()).add(str(user_key) if user_key else "unknown")

    if asn not in asn_mapped_set and asn != "unknown":
        asn_map_out.append(
            f"{MEASUREMENT_ASN_MAP},asn={escape_tag(asn)} asname={escape_field_string(asname)} {map_ts_s}"
        )
        asn_mapped_set.add(asn)

    model = str(model)
    d["model_guids"].setdefault(model, set()).add(guid)
    d["model_users"].setdefault(model, set()).add(str(user_key) if user_key else "unknown")

    appver = f"{app}|{version}"
    d["app_guids"].setdefault(appver, set()).add(guid)
    d["app_users"].setdefault(appver, set()).add(str(user_key) if user_key else "unknown")

def finalize_agg(agg):
    for _minute, d in agg.items():
        if d["guids"] and not d["users"]:
            d["users"].add("unknown")

def emit_total(agg):
    out = []
    for minute in sorted(agg.keys()):
        d = agg[minute]
        ts_s = int(minute.timestamp())
        out.append(
            f"{MEASUREMENT_TOTAL},server={escape_tag(SERVER_TAG)} "
            f"tests={len(d['guids'])}i,users={len(d['users'])}i,uploads={d['uploads']}i,downloads={d['downloads']}i,errors5xx={d['errors5xx']}i {ts_s}"
        )
    return "\n".join(out) + ("\n" if out else "")

def emit_asn(agg):
    out = []
    for minute in sorted(agg.keys()):
        d = agg[minute]
        ts_s = int(minute.timestamp())
        for asn, guidset in d.get("asn_guids", {}).items():
            out.append(
                f"{MEASUREMENT_ASN},server={escape_tag(SERVER_TAG)},asn={escape_tag(asn)} "
                f"tests={len(guidset)}i,users={len(d.get('asn_users', {}).get(asn, set()))}i {ts_s}"
            )
    return "\n".join(out) + ("\n" if out else "")

def emit_device(agg):
    out = []
    for minute in sorted(agg.keys()):
        d = agg[minute]
        ts_s = int(minute.timestamp())
        for model, guidset in d.get("model_guids", {}).items():
            out.append(
                f"{MEASUREMENT_DEVICE},server={escape_tag(SERVER_TAG)},model={escape_tag(model)} "
                f"tests={len(guidset)}i,users={len(d.get('model_users', {}).get(model, set()))}i {ts_s}"
            )
    return "\n".join(out) + ("\n" if out else "")

def emit_app(agg):
    out = []
    for minute in sorted(agg.keys()):
        d = agg[minute]
        ts_s = int(minute.timestamp())
        for appver, guidset in d.get("app_guids", {}).items():
            if "|" in appver:
                app, ver = appver.split("|", 1)
            else:
                app, ver = appver, "unknown"
            out.append(
                f"{MEASUREMENT_APP},server={escape_tag(SERVER_TAG)},app={escape_tag(app)},version={escape_tag(ver)} "
                f"tests={len(guidset)}i,users={len(d.get('app_users', {}).get(appver, set()))}i {ts_s}"
            )
    return "\n".join(out) + ("\n" if out else "")

def process_gz_file(path, agg, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s: int):
    with gzip.open(path, "rt", errors="replace") as f:
        lines = [ln.rstrip("\n") for ln in f]
    records, _ = iter_records_from_lines(lines, pending="")
    for rec in records:
        update_agg_from_record(agg, rec, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s)

def process_active_file_incremental(path, start_offset, agg, pending, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s: int):
    with open(path, "rb") as f:
        f.seek(start_offset)
        data = f.read()
        new_offset = f.tell()
    if not data:
        return new_offset, pending
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    records, new_pending = iter_records_from_lines(lines, pending=pending)
    for rec in records:
        update_agg_from_record(agg, rec, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s)
    return new_offset, new_pending

def main():
    state = load_state()
    prefix_cache = state.get("prefix_cache", {})
    prefix_nets = build_prefix_nets(prefix_cache)
    asn_mapped_set = set(state.get("asn_mapped", []))

    try:
        st = os.stat(ACCESS_LOG)
    except FileNotFoundError:
        return 0

    inode = st.st_ino
    size = st.st_size
    offset = int(state.get("offset", 0))
    prev_inode = state.get("inode")
    pending = state.get("pending_record", "")
    processed_archives = set(state.get("processed_archives", []))

    rotated_or_truncated = False
    if prev_inode is not None and (inode != prev_inode or size < offset):
        rotated_or_truncated = True

    agg = {}
    asn_map_out = []
    map_ts_s = int(time.time())

    if rotated_or_truncated:
        archives = sorted(glob(ARCHIVE_GLOB), key=lambda p: os.stat(p).st_mtime)
        for ap in archives:
            if ap not in processed_archives:
                process_gz_file(ap, agg, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s)
                processed_archives.add(ap)
        offset = 0
        pending = ""

    new_offset, new_pending = process_active_file_incremental(
        ACCESS_LOG, offset, agg, pending, prefix_cache, prefix_nets, asn_map_out, asn_mapped_set, map_ts_s
    )

    finalize_agg(agg)

    if asn_map_out:
        sys.stdout.write("\n".join(asn_map_out) + "\n")
    sys.stdout.write(emit_total(agg))
    sys.stdout.write(emit_asn(agg))
    sys.stdout.write(emit_device(agg))
    sys.stdout.write(emit_app(agg))

    state["inode"] = inode
    state["offset"] = new_offset
    state["processed_archives"] = sorted(processed_archives)
    state["pending_record"] = new_pending
    state["prefix_cache"] = prefix_cache
    state["asn_mapped"] = sorted(asn_mapped_set)
    save_state(state)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
