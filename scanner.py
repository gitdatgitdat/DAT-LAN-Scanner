import argparse
import ipaddress
import socket
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional
import ctypes
from ctypes import wintypes

# ---- Windows ICMP (no admin, no deps) --------------------------------------

IPHlpAPI = ctypes.WinDLL("iphlpapi")
IcmpCreateFile = IPHlpAPI.IcmpCreateFile
IcmpCloseHandle = IPHlpAPI.IcmpCloseHandle
IcmpSendEcho = IPHlpAPI.IcmpSendEcho

HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
LPVOID = wintypes.LPVOID
LPBYTE = ctypes.POINTER(wintypes.BYTE)
USHORT = ctypes.c_uint16

class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", wintypes.BYTE),
        ("Tos", wintypes.BYTE),
        ("Flags", wintypes.BYTE),
        ("OptionsSize", wintypes.BYTE),
        ("OptionsData", LPBYTE),
    ]

class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", DWORD),
        ("Status", DWORD),
        ("RoundTripTime", DWORD),
        ("DataSize", USHORT),
        ("Reserved", USHORT),
        ("Data", LPVOID),
        ("Options", IP_OPTION_INFORMATION),
    ]

IP_SUCCESS = 0

def pick_source_ip(target_ip: str) -> Optional[str]:
    """
    Return the local source IP the OS would use to reach target_ip.
    Uses a UDP 'connect' (no packets sent) to consult routing table.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 53))   # port doesn't matter; no traffic is sent
        src_ip = s.getsockname()[0]
        s.close()
        return src_ip
    except Exception:
        return None

def icmp_ping(ip: str, timeout_ms: int = 400) -> Optional[int]:
    """Return RTT ms if reachable, else None."""
    handle = IcmpCreateFile()
    if handle == HANDLE(-1).value:
        return None
    try:
        data = b"DAT"
        reply = (ctypes.c_ubyte * 64)()
        reply_ptr = ctypes.byref(reply)
        ip_dword = DWORD(int(ipaddress.IPv4Address(ip)))
        opt = IP_OPTION_INFORMATION(64, 0, 0, 0, None)

        ret = IcmpSendEcho(
            handle,
            ip_dword,
            ctypes.c_char_p(data),
            USHORT(len(data)),
            ctypes.byref(opt),
            reply_ptr,
            DWORD(ctypes.sizeof(reply)),
            DWORD(timeout_ms),
        )
        if ret > 0:
            r = ctypes.cast(reply_ptr, ctypes.POINTER(ICMP_ECHO_REPLY)).contents
            return int(r.RoundTripTime)
        return None
    finally:
        IcmpCloseHandle(handle)

# ---- Port scan -------------------------------------------------------------

def tcp_connect(ip: str, port: int, timeout: float,
                bind_ip: Optional[str] = None,
                debug: bool = False) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if bind_ip:
            s.bind((bind_ip, 0))  # 0 = ephemeral port
        s.connect((ip, port))
        s.close()
        return True
    except Exception as e:
        if debug:
            print(f"[DEBUG] connect {bind_ip or '*'} -> {ip}:{port} failed: {type(e).__name__}: {e}")
        return False

# ---- RDNS ------------------------------------------------------------------

def rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

# ---- Main Workflow ---------------------------------------------------------

def discover_hosts(cidr: str, timeout_ms: int, workers: int):
    net = ipaddress.ip_network(cidr, strict=False)
    addrs = [str(ip) for ip in net.hosts()]
    live = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(icmp_ping, ip, timeout_ms): ip for ip in addrs}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                rtt = fut.result()
                if rtt is not None:
                    live.append((ip, rtt))
            except Exception:
                pass
    return sorted(live, key=lambda t: t[0])

def scan_ports(ip: str, ports: list[int], timeout: float, workers: int,
               bind_ip: Optional[str] = None, debug: bool = False):
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as ex:
        futs = {ex.submit(tcp_connect, ip, p, timeout, bind_ip, debug): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)

def to_json(path: str, rows: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

def to_csv(path: str, rows: list[dict]):
    if not rows:
        open(path, "w").close()
        return
    fields = sorted({k for r in rows for k in r})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def parse_ports_arg(s: str) -> list[int]:
    if not s:
        return []
    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return sorted(out)

def main():
    ap = argparse.ArgumentParser(description="DAT LAN Scanner")
    ap.add_argument("cidr", help="CIDR to scan, e.g. 192.168.1.0/24")
    ap.add_argument("--icmp-timeout", type=int, default=400, help="ICMP timeout (ms).")
    ap.add_argument("--workers", type=int, default=256, help="Max concurrent workers.")
    ap.add_argument("--ports", default="22,80,135,139,443,445,3389,8080",
                    help="Comma/range list of TCP ports to check on live hosts.")
    ap.add_argument("--port-timeout", type=float, default=0.6, help="TCP connect timeout (s).")
    ap.add_argument("--rdns", action="store_true", help="Reverse-DNS live hosts.")
    ap.add_argument("--json", help="Write results to JSON.")
    ap.add_argument("--csv", help="Write results to CSV.")
    ap.add_argument("--bind", help="Source IP to bind outgoing TCP connects (default: auto per target)")
    ap.add_argument("--debug", action="store_true", help="Print connection errors")
    args = ap.parse_args()

    ports = parse_ports_arg(args.ports)

    print(f"[*] Discovering hosts in {args.cidr} …")
    live = discover_hosts(args.cidr, args.icmp_timeout, args.workers)
    print(f"[*] Live hosts: {len(live)}")

    results = []
    for ip, rtt in live:
        src_ip = args.bind or pick_source_ip(ip)
        name = rdns(ip) if args.rdns else ip
        open_ports = scan_ports(
            ip,
            ports,
            args.port_timeout,
            args.workers,
            bind_ip=src_ip,
            debug=args.debug,
        )
        results.append({
            "ip": ip,
            "name": name,
            "rtt_ms": rtt,
            "open_ports": open_ports,
        })
        ports_str = ",".join(map(str, open_ports)) or "-"
        print(f"  {name:<40} rtt={rtt:>3} ms  open=[{ports_str}]")

    if args.json:
        to_json(args.json, results)
        print(f"[*] Wrote JSON: {args.json}")
    if args.csv:
        to_csv(args.csv, results)
        print(f"[*] Wrote CSV : {args.csv}")

    # Summary
    total_open = sum(len(r["open_ports"]) for r in results)
    print("\n=== Summary ===")
    print(f"Hosts up: {len(results)}")
    print(f"Total open ports found: {total_open}")
    print("===============")

if __name__ == "__main__":
    main()
