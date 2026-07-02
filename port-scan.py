from datetime import datetime; import json; import socket; import sys; from concurrent.futures import ThreadPoolExecutor; from concurrent.futures import ThreadPoolExecutor, as_completed; import time; import ssl
timestart = time.perf_counter()
now = datetime.now()
arg = sys.argv
if "--help" in arg[1]:
    print("""──────────────────────────────────────────────────────────────────────────────
                           PYSCAN - TCP Port Scanner
──────────────────────────────────────────────────────────────────────────────

Usage:
    pyscan <target> [OPTIONS]

Examples:
    pyscan localhost -p 80
    pyscan 192.168.1.10 -p 22 80 443
    pyscan github.com -p 22 -b
    pyscan scanme.nmap.org -p c
    pyscan localhost -p 1-1000 -T 100
    pyscan localhost -p 80 443 8080 -b -v
    pyscan localhost -p c -q

──────────────────────────────────────────────────────────────────────────────
Target
──────────────────────────────────────────────────────────────────────────────

<target>
    Target hostname or IPv4 address.

Examples:
    localhost
    192.168.1.100
    github.com

──────────────────────────────────────────────────────────────────────────────
Scan Modes
──────────────────────────────────────────────────────────────────────────────

-p <ports>
    Scan one or more specific ports.

    Examples:
        -p 80
        -p 22 80 443
        -p 21 22 25 80 443

-p <start-end>
    Scan a range of ports.

    Examples:
        -p 1-100
        -p 1-65535

-p c
    Scan common ports only.

──────────────────────────────────────────────────────────────────────────────
Features
──────────────────────────────────────────────────────────────────────────────

-b
    Banner grabbing.

    Attempts to retrieve service banners from open ports.

-v
    Version detection.

    Attempts to identify the running service and version.
    (May use banner information when available.)

-a
    Show all results.
    Displays both open and closed ports.

-q
    Quiet mode.
    Displays only open ports.

──────────────────────────────────────────────────────────────────────────────
Performance
──────────────────────────────────────────────────────────────────────────────

-T <threads>
    Number of worker threads.

    Examples:
        -T 50
        -T 100
        -T 300

-t <seconds>
    Socket timeout.

    Examples:
        -t 1
        -t 0.5
        -t 2

──────────────────────────────────────────────────────────────────────────────
Output
──────────────────────────────────────────────────────────────────────────────

-j
    Output results in JSON format.

-o <file>
    Save scan results to a file.

──────────────────────────────────────────────────────────────────────────────
Advanced
──────────────────────────────────────────────────────────────────────────────

--http-title
    Retrieve HTTP page title.

--headers
    Display HTTP response headers.

--ping
    Perform host discovery before scanning.

--resolve
    Resolve hostname to IP address.

--reverse
    Perform reverse DNS lookup.

-A
    Aggressive scan.

    Enables:
        • Banner grabbing
        • Version detection
        • HTTP title retrieval            print(r)
        • HTTP headers

──────────────────────────────────────────────────────────────────────────────
Examples
──────────────────────────────────────────────────────────────────────────────

Scan common ports
    pyscan localhost -p c

Scan ports 22, 80 and 443
    pyscan github.com -p 22 80 443

Scan an entire range
    pyscan localhost -p 1-1000

Fingerprinting
    pyscan github.com -p 22 -f

Fast scan using 300 threads
    pyscan localhost -p 1-65535 -T 300

Save output
    pyscan localhost -p c -o results.txt

JSON output
    pyscan localhost -p c -j

Quiet mode
    pyscan localhost -p c -q

Aggressive scan
    pyscan localhost -p c -A

──────────────────────────────────────────────────────────────────────────────""")
    exit()
    
SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
}

CONFIG = {
    "target": None,
    "ip": None,
    "socket": {
        "family": socket.AF_INET,
        "type": socket.SOCK_STREAM,
    },
    "timeout" : 1,
    
    "scan": {
        "ports": [],
        "threads": 100,
    },

    "features": {
        "fingerprinting": False,
        "http_title": False,
        "headers": False,
        "verbose": False,
    },

    "output": {
        "json": False,
        "file": False,
        "quiet": False,
    }
}

results = []

CONFIG["target"] = arg[1]
CONFIG["features"]["fingerprinting"] = "-f" in arg
CONFIG["features"]["verbose"] = "-v" in arg
CONFIG["output"]["quiet"] = "-q" in arg
CONFIG["output"]["json"] = "-j" in arg
CONFIG["output"]["file"] = "-o" in arg
CONFIG["ip"] = socket.gethostbyname(CONFIG["target"])

PROBES = {
    "HTTP": f"GET / HTTP/1.1\r\n"f"Host: {CONFIG['target']}\r\nConnection: close\r\n\r\n",
    "Redis": "PING\r\n",
    "SMTP": "EHLO test\r\n",
    "SSH": None,   
}

FINGERPRINTS = {
    "HTTP": "HTTP/",
    "SSH": "SSH-",
    "Redis": "+PONG",
    "SMTP": "220",
}


pindex = arg.index("-p")+1
if "-" in arg[pindex]:
    start, end = arg[pindex].split("-")
    port2scan = range(int(start), int(end) + 1)
elif "c" in arg[pindex]:
    port2scan = []
    for k in SERVICES.keys():
        port2scan.append(k)
else:
    port2scan = []
    i = pindex
    while i < len(arg):
        if arg[i].startswith("-"):
            break
        port2scan.append(int(arg[i]))
        i += 1

default_file = now.strftime(f"output_{CONFIG["target"]}_%Y%m%d_%H%M%S.json")

if "-T" in arg:
    tindex = arg.index("-T")+1
    CONFIG["scan"]["threads"] = int(arg[tindex])

if "-t" in arg:
    timdex = arg.index("-t")+1
    CONFIG["timeout"] = int(arg[timdex])
    
if "-o" in arg:
    fdex = arg.index("-o") + 1
    if fdex < len(arg) and not arg[fdex].startswith("-"):
        default_file = arg[fdex]

def scan_port(port):
    sock = socket.socket(**CONFIG["socket"])
    sock.settimeout(CONFIG["timeout"])
    result = sock.connect_ex((CONFIG["ip"], port))
    sock.close()
    fresult = ""
    if result == 0:
        for p, r in PROBES.items():
            sock = socket.socket(**CONFIG["socket"])
            sock.settimeout(CONFIG["timeout"])
            sock.connect_ex((CONFIG["ip"], port))
            if r is not None:
                try:
                    sock.sendall(r.encode())
                    fresult = sock.recv(1024).decode(errors="ignore")
                    if fresult.startswith(FINGERPRINTS[p]):
                        if "plain HTTP request was sent to HTTPS port" in fresult:
                            sock.close()
                            service = "HTTPS"
                            sock1 = socket.create_connection((CONFIG["ip"], port))
                            ssl_sock = ssl.create_default_context().wrap_socket(
                                sock1,
                                server_hostname=CONFIG["target"]
                                )
                            ssl_sock.sendall(PROBES["HTTP"].encode())
                            print("HTTPS retry", port)
                            fresult = ssl_sock.recv(1024).decode(errors="ignore")
                            ssl_sock.close()
                        
                        break
                except OSError:
                    fresult = ""
            elif r is None:
                try:
                    fresult = sock.recv(1024).decode(errors="ignore")
                except TimeoutError:
                    fresult = ""
                    
    first_line = fresult.split("\r\n")[0]
    sock.close()
    return {
    "port": port,
    "status": result,
    "fingerprint": fresult,
    "NotVerbose": first_line,
}

results = []

try:
    with ThreadPoolExecutor(max_workers=CONFIG["scan"]["threads"]) as pool:
        jobs_done = []
        for port in port2scan:
            jobs_done.append(pool.submit(scan_port, port))
        for job in as_completed(jobs_done):
            results.append(job.result())
            progress = len(results) / len(port2scan)
            bar_length = 40
            filled = int(progress * bar_length)
            bar = "]" * filled + "-" * (bar_length - filled)
            print(f"\r[{bar}] {len(results)}/{len(port2scan)} ({progress*100:.1f}%)",end="",flush=True)
except KeyboardInterrupt:
    print("\nExiting program...")
    exit()

results.sort(key=lambda x: x["port"])
Opened = []
print(f"\nTarget: {CONFIG["ip"]}\n\nPORTS\tSTATUS\tFingerprint")
for info in results:
    if info["status"] == 0:
        Opened.append(info["port"])
        if CONFIG["features"]["verbose"]:
            if len(info["fingerprint"].splitlines()) > 1:
                print(f"{info['port']}\tOpened\n{info['fingerprint']}\n")
            else:
                print(f"{info['port']}\tOpened\t{info['NotVerbose']}")
        else:
            print(f"{info['port']}\tOpened\t{info['NotVerbose']}")
    elif not CONFIG["output"]["quiet"]:
        print(f"{info['port']}\tClosed")
        
if CONFIG["output"]["file"]:
    with open(default_file, "w") as f:
        json.dump(results, f, indent=4)
        print(f"\nFIle saved as: {default_file}\n")

if CONFIG["output"]["quiet"]:
    print(f"Opened ports: {Opened}")
end = time.perf_counter()
print(f"\nProgram took {end - timestart:.2f} seconds")