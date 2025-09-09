# DAT LAN Scanner

Lightweight LAN scanner for Windows/macOS/Linux.  
Discovers live hosts in a CIDR range and does a quick TCP probe to spot a few common services.  
Outputs results to the console, JSON, or CSV.  

---

## Features

CIDR sweep of an IPv4 range (e.g., 192.168.1.0/24)

Concurrent scanning with a tunable worker pool

Quick TCP liveness probe with small service check

Optional reverse DNS lookups

Structured output: JSON and/or CSV

End-of-run summary (hosts up, total open ports seen)

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

Enable reverse DNS and write machine-readable reports:

```python scanner.py 192.168.1.0/24 --rdns --json scan.json --csv scan.csv```


Turn up concurrency and tune TCP wait time:

```python scanner.py 10.0.0.0/24 --workers 512 --port-timeout 0.4```

The scanner prints a brief summary at the end:

```=== Summary ===```  
```Hosts up: 3```  
```Total open ports found: 5```  
```=================```  

---

## Command-line options

positional arguments:

CIDR - 
Target subnet/range (e.g., 192.168.1.0/24)

optional arguments:

```--workers N``` -         
Max concurrent probes (default: sensible per system)

```--port-timeout S``` -   
TCP connect timeout per probe in seconds (default: 0.8–1.0)  

```--rdns``` -              
Perform reverse DNS lookups for discovered IPs  

```--json PATH``` -  
Write full results to a JSON file  

```--csv PATH``` -  
Write tabular results to a CSV file  

Flags above reflect the current script. Run python scanner.py --help on your machine for the authoritative list and defaults.  

---

## Output format

JSON (--json scan.json)

Array of host objects. Example:

[
  {
    "ip": "192.168.1.10",
    "hostname": "nas.local",
    "ports": [
      {"port": 22,  "state": "open"},
      {"port": 80,  "state": "open"},
      {"port": 445, "state": "closed"}
    ]
  }
]

---

CSV (--csv scan.csv)

One row per (host,port). Header:

ip,hostname,port,state

---

## Tips and troubleshooting

If you see “Hosts up: 0” and empty JSON/CSV:

ICMP blocked or TCP filtered
Many endpoints drop pings and unknown TCP connects. Try targeting a single known host to validate:
python scanner.py 192.168.1.10/32

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

## Safety & etiquette

Only scan networks you own or have explicit permission to test.

Keep timeouts reasonable and avoid aggressive settings on shared networks.

---

## Roadmap

ARP sweep on local /24 for faster host discovery

Configurable port sets and simple service fingerprinting

Export to NDJSON (one JSON object per line)

Progress bar and per-host timing stats
