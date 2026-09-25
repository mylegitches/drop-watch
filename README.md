# drop-watch

Continuous, sub-second network drop monitor for Windows — designed to surface
**intermittent** connectivity issues that a 30-minute-interval speedtest will
miss.

## Why this exists

If you have:

- Calls that randomly drop mid-conversation
- Video meetings and playback that lag for no apparent reason
- A work VPN that "dips out" repeatedly during the day
- ISP that insists "the line is fine"

…then your existing diagnostic cadence is too slow to find the culprit.
`drop-watch` samples every layer of your network path **in parallel at
sub-second resolution** and timestamps every sample, so you can correlate a
reported glitch with the moment it actually happened.

## What it monitors (all in parallel)

| Probe              | Default cadence | Isolates                                                  |
|--------------------|----------------:|-----------------------------------------------------------|
| ICMP to router     | 1/sec           | Your LAN / Wi-Fi / switch / router                        |
| ICMP to internet   | 1/sec (round-robin 8.8.8.8 & 1.1.1.1) | Upstream link past your router         |
| DNS resolution     | every 5s        | DNS path / resolver issues                                |
| HTTP probe         | every 10s       | TCP/HTTP path through full stack                          |
| Wi-Fi association  | every 5s        | Disconnects, roaming (BSSID change), signal drops         |
| NIC throughput     | every 30s       | Bandwidth saturation, errors, discards                    |
| TCP probe (VPN)    | every 10s       | VPN tunnel liveness (optional — set `vpn_probe` in config)|

Every sample is stored in SQLite with millisecond UTC timestamps.

## What counts as a "drop event"

A drop is recorded when **any** of these fire:

- **3+ consecutive failures** of any probe (loss burst)
- **Latency spike** ≥ 5× rolling baseline (e.g. 4ms → 800ms)
- **DNS > 1500ms** (drop) or **> 500ms** (warning)
- **HTTP > 3000ms** (drop) or **> 1500ms** (warning)
- **Wi-Fi disconnect**, **BSSID change** (roam), or **signal drop ≥ 30%**

## Install

### One-time

```powershell
cd C:\Users\adamr\drop-watch
python -m pip install -r requirements.txt        # optional: matplotlib for graphs
copy config.example.json config.local.json       # edit targets to your network
pwsh -ExecutionPolicy Bypass -File .\scripts\install_windows.ps1
```

The installer registers a Task Scheduler job named **`drop-watch`** that runs
30 seconds after every logon, hidden in the background, and restarts itself
on crash.

### Manual run (no scheduler)

```bash
python -m drop_watch run --config config.local.json
# Ctrl+C to stop
```

## Usage

```bash
python -m drop_watch doctor              # one-shot reachability check
python -m drop_watch report --hours 24   # text summary of last 24h
python -m drop_watch report --hours 1    # just the last hour
python -m drop_watch graph --hours 24 --output report.png
python -m drop_watch prune               # run retention immediately
```

## Reading the report

A healthy link over a 24h workday will show:

- Router ICMP avg < 5ms, loss < 0.5%, max < 50ms
- Internet ICMP avg stable, no latency spikes > 5× baseline
- DNS consistently < 100ms
- HTTP probe time stable

If the **router** probes spike but internet probes stay flat → your LAN is the
problem (Wi-Fi interference, switch, NIC driver, cable).

If **router** is fine but **internet** spikes → upstream ISP (or modem).

If **both** spike together → likely Wi-Fi or power (router rebooting,
association dropping).

If **only DNS** is slow → ISP DNS or resolver; try changing `dns_resolvers`.

If **HTTP probes** fail while ICMP works → MTU/blackhole/router filtering
somewhere on path.

If **VPN** drops while everything else is fine → VPN tunnel/server problem,
not your link.

## Privacy

This tool captures network data that may include your BSSIDs, internal IPs,
SSID, and DNS lookups. **Everything captured lives only on this machine** in
`drop_watch.db` and `logs/`.

- `config.example.json` ships with generic placeholders only.
- `config.local.json` is **gitignored** — your real targets never leave this
  machine.
- `*.db`, `logs/`, `reports/`, and `*.log` are all gitignored.
- The repo on GitHub contains **no** sample data, no IPs, no hostnames.

## Files

```
drop-watch/
├── drop_watch/
│   ├── __init__.py
│   ├── __main__.py        # `python -m drop_watch …`
│   ├── cli.py             # argparse entry points
│   ├── config.py          # config loader (no hardcoded targets)
│   ├── storage.py         # SQLite + retention/downsampling
│   ├── samplers.py        # ICMP, DNS, HTTP, Wi-Fi, NIC
│   ├── detector.py        # loss-burst / spike / roam detection
│   ├── monitor.py         # thread orchestrator
│   └── graph.py           # matplotlib render
├── config.example.json    # copy -> config.local.json, then edit
├── requirements.txt       # matplotlib (only for `graph`)
├── scripts/
│   ├── drop-watch.xml     # Task Scheduler template (placeholders)
│   ├── install_windows.ps1
│   └── uninstall_windows.ps1
└── README.md
```

## License

MIT.
