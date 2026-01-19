# Ookla Speedtest Server → InfluxDB v2 (Stateful Tail Parser) + Grafana
Ookla Speedtest Server Logfiles to InfluxDB v2 (Stateful Tail Parser) Bash and Python and Grafana Visualisation

Dieses Projekt liest **OoklaServer Access Logs** (`ooklaserver-access.log`) inkrementell (stateful tail parsing),
erkennt Log-Rotation (10 MB) inkl. `.gz`-Archive und schreibt aggregierte Metriken in **InfluxDB v2**.

Zusätzlich werden aus dem WebSocket `HI ... <JWT> ... WS/1.0` Request die JWT-Payload-Daten extrahiert:

- `deviceId` (eindeutiger User-Key)
- `guid` (Test-ID)
- `ip` (für ASN Lookup)
- `model` (Geräte-Modell)
- `app` / `version` (Client/SDK Version)

Damit kannst du in **Grafana** sehr sauber auswerten:

✅ Tests pro Minute  
✅ Unique Users pro Minute  
✅ Top ASNs / Provider (Telekom, Vodafone, …)  
✅ Top Geräte-Modelle  
✅ Top App-/SDK-Versionen  
✅ Fehlerpeaks (5xx)  

---

## Features

### ✅ Stateful Tail Parsing
- liest **nur neue Zeilen**, kein kompletter Re-Parse
- merkt sich `inode` + `offset`
- erkennt **Rotation/Truncate**

### ✅ Rotation / Archivierung
- verarbeitet rotierte Logs:  
  `/opt/ookla/ooklaserver-access.log.<timestamp>.gz`
- jedes `.gz` wird **genau einmal** verarbeitet

### ✅ Multi-line Log Records
- `HI ... JWT ...` kann im Log über mehrere Zeilen umbrechen
- wird wieder korrekt zusammengefügt

### ✅ ASN Lookup (Team Cymru) + Prefix Cache
- ASN Lookup per `whois.cymru.com`
- Cache basiert auf dem BGP Prefix (z.B. `83.215.0.0/16`) → deutlich weniger Lookups

### ✅ ASN Mapping Measurement (Option 2)
Es wird zusätzlich zur Statistik pro Minute ein kleines “Dimension-Mapping” geschrieben:

- Measurement: `asn_map`
- Tag: `asn`
- Field: `asname`

Damit kannst du in Grafana/Flux sauber `join()` machen und Provider-Namen anzeigen.

---

## Metriken / Measurements

### 1) Gesamt pro Minute
Measurement: `ookla_speedtest_minutely`  
Tags:
- `server`

Fields:
- `tests` (distinct guid)
- `users` (distinct deviceId)
- `uploads` (legacy HTTP endpoint detection, häufig 0 bei WS-only)
- `downloads` (legacy HTTP endpoint detection)
- `errors5xx`

---

### 2) ASN pro Minute
Measurement: `ookla_speedtest_asn_minutely`  
Tags:
- `server`
- `asn`

Fields:
- `tests`
- `users`

---

### 3) ASN Mapping (“Dimension Table”)
Measurement: `asn_map`  
Tags:
- `asn`

Fields:
- `asname` (Provider-Name, z.B. Vodafone / Telekom)

---

### 4) Device pro Minute
Measurement: `ookla_speedtest_device_minutely`  
Tags:
- `server`
- `model`

Fields:
- `tests`
- `users`

---

### 5) App/SDK Version pro Minute
Measurement: `ookla_speedtest_app_minutely`  
Tags:
- `server`
- `app`
- `version`

Fields:
- `tests`
- `users`

---

## Installation

### Requirements
- Linux Server
- Python 3.x
- Zugriff auf:
  - `/opt/ookla/ooklaserver-access.log`
  - `/opt/ookla/ooklaserver-access.log.*.gz`
- InfluxDB v2 Token mit Write-Rechten
- `curl`

### Dateien
Empfohlenes Zielverzeichnis:
```bash
/opt/ookla-influx-tail/
```

### Copy & Permissions
```bash
sudo mkdir -p /opt/ookla-influx-tail
sudo cp -a ./* /opt/ookla-influx-tail/
sudo chmod +x /opt/ookla-influx-tail/*.py /opt/ookla-influx-tail/*.sh
```

---

## Konfiguration

### InfluxDB v2 Env Vars
Diese Werte müssen gesetzt werden:

```bash
export INFLUX_URL="http://influx.example.com:8086"
export INFLUX_ORG="myorg"
export INFLUX_BUCKET="monitoring"
export INFLUX_TOKEN="xxxxx"
```

Optional:
```bash
export SERVER_TAG="ookla-speedtest-01"
```

---

## Manuell ausführen

### Parser (nur Ausgabe prüfen)
```bash
/opt/ookla-influx-tail/ookla_tail_to_influx.py | head -n 20
```

### Parser → Influx Push
```bash
/opt/ookla-influx-tail/ookla_push_minutely.sh
```

Bei Erfolg antwortet InfluxDB normalerweise mit:
- **HTTP 204 No Content**
- also keine Ausgabe

---

## Cron Job (jede Minute)
```cron
* * * * * INFLUX_URL=... INFLUX_ORG=... INFLUX_BUCKET=... INFLUX_TOKEN=... /opt/ookla-influx-tail/ookla_push_minutely.sh >/dev/null 2>&1
```

---

## State File

Default:
```text
/var/lib/ookla-logtail/state.json
```

Enthält u.a.:

- `inode` / `offset` → tail state
- `processed_archives` → bereits verarbeitete `.gz`
- `prefix_cache` → Prefix → ASN Cache
- `asn_mapped` → Liste ASNs, die bereits in `asn_map` geschrieben wurden

---

# Grafana Dashboard Beispiele (Flux)

> Alle Beispiele gehen von Bucket `monitoring` aus.  
> Passe `bucket`/`server` nach Bedarf an.

---

## Panel 1: Tests/Minute (global)
Time series

```flux
from(bucket: "monitoring")
  |> range(start: -24h)
  |> filter(fn: (r) =>
    r._measurement == "ookla_speedtest_minutely" and
    r._field == "tests"
  )
  |> aggregateWindow(every: 1m, fn: sum, createEmpty: false)
  |> yield(name: "tests_per_min")
```

---

## Panel 2: Users/Minute (global)
Time series

```flux
from(bucket: "monitoring")
  |> range(start: -24h)
  |> filter(fn: (r) =>
    r._measurement == "ookla_speedtest_minutely" and
    r._field == "users"
  )
  |> aggregateWindow(every: 1m, fn: sum, createEmpty: false)
  |> yield(name: "users_per_min")
```

---

## Panel 3: Top 10 ASN (mit Providername) – letzte 24h
Table

### 1) ASN Stats (tests)
```flux
asnStats =
  from(bucket: "monitoring")
    |> range(start: -24h)
    |> filter(fn: (r) =>
      r._measurement == "ookla_speedtest_asn_minutely" and
      r._field == "tests"
    )
    |> group(columns: ["asn"])
    |> sum()
    |> keep(columns: ["asn", "_value"])
    |> rename(columns: {_value: "tests"})
```

### 2) ASN Mapping (Provider name)
```flux
asnMap =
  from(bucket: "monitoring")
    |> range(start: -30d)
    |> filter(fn: (r) =>
      r._measurement == "asn_map" and
      r._field == "asname"
    )
    |> last()
    |> keep(columns: ["asn", "_value"])
    |> rename(columns: {_value: "asname"})
```

### 3) Join + Sort
```flux
join(tables: {s: asnStats, m: asnMap}, on: ["asn"], method: "left")
  |> sort(columns: ["tests"], desc: true)
  |> limit(n: 10)
  |> yield(name: "top_asn")
```

---

## Panel 4: Top Devices (Modelle) – letzte 24h
Table

```flux
from(bucket: "monitoring")
  |> range(start: -24h)
  |> filter(fn: (r) =>
    r._measurement == "ookla_speedtest_device_minutely" and
    r._field == "tests"
  )
  |> group(columns: ["model"])
  |> sum()
  |> keep(columns: ["model", "_value"])
  |> rename(columns: {_value: "tests"})
  |> sort(columns: ["tests"], desc: true)
  |> limit(n: 15)
```

---

## Panel 5: Top App-Versionen – letzte 24h
Table

```flux
from(bucket: "monitoring")
  |> range(start: -24h)
  |> filter(fn: (r) =>
    r._measurement == "ookla_speedtest_app_minutely" and
    r._field == "tests"
  )
  |> group(columns: ["app", "version"])
  |> sum()
  |> keep(columns: ["app", "version", "_value"])
  |> rename(columns: {_value: "tests"})
  |> sort(columns: ["tests"], desc: true)
  |> limit(n: 20)
```

---

## Panel 6: 5xx Errors pro Minute
Time series

```flux
from(bucket: "monitoring")
  |> range(start: -24h)
  |> filter(fn: (r) =>
    r._measurement == "ookla_speedtest_minutely" and
    r._field == "errors5xx"
  )
  |> aggregateWindow(every: 1m, fn: sum, createEmpty: false)
```

---

# Ideen / KPIs (was man noch auswerten kann)

### Traffic / Load
- **tests/min** (Peak / Durchschnitt)
- **users/min** (Unique Clients)
- “Busy hours” / Tagesprofile

### Provider-Qualität
- Tests pro ASN
- Fehlerpeaks pro ASN
- Zeitfenster “Provider X bricht weg”

### Geräte-/App-Verteilung
- Top Devices (z.B. “SM-G990B”)
- App-Versionen (Rollouts erkennen)
- “neue Version erzeugt mehr Tests / mehr Fehler?”

### Debugging / Betrieb
- plötzlicher Rückgang “tests/min” → Service down?
- `errors5xx` steigt → Backend Problem, Storage, CPU, Network
- ASN Mapping hilft beim Einordnen von regionalen Problemen

---

# Troubleshooting

### InfluxDB liefert HTML statt 204
Dann triffst du meist die Influx Web-UI statt den Write API Endpoint.

✅ Verwende `INFLUX_URL` ohne trailing slash:
```bash
export INFLUX_URL="http://influx.example.com:8086"
```

Check:
```bash
curl -i "$INFLUX_URL/health"
curl -i "$INFLUX_URL/api/v2/ready"
```

---

### State JSON prüfen
```bash
jq . /var/lib/ookla-logtail/state.json
```

---

## Security / Privacy
- Es werden keine IP-Adressen nach Influx geschrieben.
- IPs werden nur kurzfristig für ASN Lookup genutzt.
- `deviceId` wird ausschließlich **aggregiert** (nie als Influx Tag gespeichert).
