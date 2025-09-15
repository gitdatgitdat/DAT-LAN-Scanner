# DAT LAN Scanner

Lightweight LAN scanner for Windows/macOS/Linux.  
Discovers live hosts in a CIDR range and does a quick TCP probe to spot a few common services.  
Outputs results to the console, JSON, or CSV.  

---

## Features

ICMP and/or TCP discovery (--discovery icmp|tcp|both)  

Concurrent scanning with a tunable worker pool  

Per-host open port list with friendly service names (e.g., 80(http), 443(https))  

Optional reverse DNS lookups (--rdns)  

Structured output: JSON with _meta + items, or CSV  

Output controls: --show-all, --quiet, --summary-only  

Bind source IP for multi-homed hosts (--bind)  

Clear summary and CI-friendly exit codes  

---

## Requirements

Python 3.11+

Run from a host that can route to the target subnet(s)

Some networks block ICMP or drop unknown TCP — see Troubleshooting below

---

## Installation
Clone the DAT-LAN-Scanner repo

cd DAT-LAN-Scanner

Create a virtual environment in python (optional):
```python -m venv .venv && .\.venv\Scripts\activate  # Windows```
```python3 -m venv .venv && source .venv/bin/activate # macOS/Linux```

---

## Usage

Basic sweep of a /24:

```python scanner.py 192.168.1.0/24```

Use both ICMP and TCP for discovery and print per-host open ports:

```python scanner.py 192.168.1.0/24 --discovery both --probe-ports 80,443,22,445```

Enable reverse DNS and write machine-readable reports:

```python scanner.py 192.168.1.0/24 --rdns --json scan.json --csv scan.csv```

Turn up concurrency and tune TCP wait time:

```python scanner.py 10.0.0.0/24 --workers 512 --port-timeout 0.4```

Keep the console minimal:

```python scanner.py 192.168.1.0/24 --summary-only```

The scanner prints a brief summary at the end:

```=== Summary ===```  
```Hosts up: 3```  
```Total open ports found: 5```  
```=================```  

---

## Command-line Options

Positional arguments:

CIDR  
Target subnet/range (e.g., 192.168.1.0/24)  

Common flags:

--workers N  
Max concurrent probes (default: 256; clamped 1–1024)  

--port-timeout S  
TCP connect timeout per probe in seconds (default: 0.6; min 0.05)  

--rdns  
Reverse-DNS live hosts  

--json PATH  
Write results to a JSON file (includes _meta + items)  

--csv PATH  
Write results to a CSV file (one row per host)  

Discovery controls:  

--discovery icmp|tcp|both  
How to find live hosts (default: both)  

--probe-ports LIST  
Ports to try for TCP discovery (default: 80,443,22,3389,445)  

Scan controls:

--ports LIST  
Ports to check on each live host (default: 22,80,135,139,443,445,3389,8080)  

--bind IP  
Source IP to bind outgoing TCP connects (default: auto per target)  

Output controls:

--show-all  
Print every live host, even if no open ports were found  

--summary-only  
Per-host lines + final summary; suppress debug noise  

--quiet  
Only print the final summary (still writes JSON/CSV if requested)  

Misc:

--debug  
Print connection errors (noisy)  

--version  
Show tool version and exit  

Flags above reflect the current script. Run ```python scanner.py --help``` on your machine for the authoritative list and defaults.  

---

## Output Format

JSON (--json scan.json)

Array of host objects. Example:

"_meta": {  
    "scanned_at": "2025-09-10T19:14:25Z",  
    "cidr": "192.168.1.0/24",  
    "discovery": "both",  
    "probe_ports": [80, 443, 22, 3389, 445],  
    "ports": [22, 80, 135, 139, 443, 445, 3389, 8080],  
    "bind": "auto",  
    "workers": 256,    
    "host": "MYPC",  
    "platform": "Windows-10-10.0.22631-SP0",  
    "version": "0.2.0"   

"items": [  
    {  
      "ip": "192.168.1.58",  
      "name": "192.168.1.58",  
      "rtt_ms": 2,  
      "open_ports": [80, 443],  
      "open_services": ["http", "https"]  

---

CSV (--csv scan.csv)

One row per (host,port). Header:

ip,name,rtt_ms,open_ports,open_services

---

## Tips and Troubleshooting

If you see “Hosts up: 0” and empty JSON/CSV:

ICMP blocked or TCP filtered
Many endpoints drop pings and unknown TCP connects. Try targeting a single known host to validate:
python scanner.py 192.168.1.10/32

Validate a single host  
python scanner.py 192.168.1.1/32 --discovery both  

Increase wait time
Some devices respond slowly to TCP connects. Try: --port-timeout 1.5

Adjust concurrency
On noisy or low-power networks, back concurrency off: --workers 128
On fast desktops, you can raise it: --workers 512

Scan the right subnet
Verify the local interface network (e.g., ipconfig / ifconfig) and that routing is in place.

Permissions/firewall
Local host firewalls can block outbound or throttle unusual probes. If you manage the test network, allow temporary egress.

---

## Safety & Etiquette

Only scan networks you own or have explicit permission to test.

Keep timeouts reasonable and avoid aggressive settings on shared networks.

---

## Roadmap

ARP sweep on local /24 for faster host discovery

Configurable named port sets (e.g., --ports web, --ports ms)

NDJSON output (one JSON object per line)

Progress bar and per-host timing stats
