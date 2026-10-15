# VNC Scanner
# WARNING ⚠️ THIS IS VIBECODED BY GEMINI 3.8 FLASH, PLEASE CHECK THE FORK ⚠️
Automated VNC (RFB) scanner. Give it targets — single IPs, ranges, or subnets —
and it will:

1. **Detect** which hosts run a VNC service (a successful RFB version handshake).
2. **Identify** the security mode: `none` (wide open!), `vncauth`, or unsupported.
3. **Test** the passwords you choose against classic *VNC Authentication*.
4. **Report** live notifications, a results table, a per-hit CSV, and a summary.

> ⚠️ **Authorized use only.** Run this against systems you own or are explicitly
> permitted to test. Credential testing against systems without authorization is
> illegal.

## How it works

VNC speaks the **RFB protocol** on TCP **5900** by default. Classic VNC
Authentication (security type 2) is password-only: the server sends a 16-byte
challenge, the client DES-encrypts it with a key derived from the password
(truncated to 8 bytes, each byte bit-reversed), and the server replies with a
SecurityResult word — `0` means the password is correct.

The scanner uses one connection to fingerprint each host, then one fresh
connection per password (each challenge is single-use). Servers that advertise
the `None` security type require no password at all and are flagged **OPEN**.

## Install

Requires **Python 3.8+** (tested on 3.12).

```powershell
pip install -r requirements.txt
```

Dependencies: [`rich`](https://github.com/Textualize/rich) for the console output
and [`cryptography`](https://github.com/pyca/cryptography) for the VNC-Auth DES.

## Usage

```powershell
# Detect only (no credential testing)
python scan.py targets.txt

# Detect + test passwords from creds/vnc.txt (the default list)
python scan.py targets.txt --check-auth

# Use a custom password list
python scan.py targets.txt --check-auth --creds my_passwords.txt

# Pass passwords inline (overrides the file)
python scan.py targets.txt --check-auth --pass admin --pass password --pass ""

# Scan extra VNC display ports
python scan.py targets.txt --check-auth --ports 5900-5905
```

### Options

| Flag           | Default                       | Description                                   |
|----------------|-------------------------------|-----------------------------------------------|
| `targets`      | —                             | File with one IP / CIDR / range per line      |
| `--check-auth` | off                           | Test passwords against detected services      |
| `--creds`      | `creds/vnc.txt`               | Password list, one per line (`#` = comment)   |
| `--pass`       | —                             | Inline password, repeatable; overrides file   |
| `--ports`      | `5900`                        | `5900`, `5900,5901`, or `5900-5905`           |
| `--workers`    | `30`                          | Parallel connection workers                   |
| `--timeout`    | `6.0`                         | Per-connection timeout in seconds             |
| `--out`        | `results/vnc_<timestamp>.csv` | CSV output path (flushed per hit)             |
| `--only-found` | off                           | Show only detected hosts in the table         |

## Target formats

```
127.0.0.1               # single IP
10.0.0.0/24             # CIDR subnet
10.0.0.1-50             # short range (same /24)
192.168.1.10-192.168.1.20   # full range
```

## Output

- **Live**: `VNC up`, `OPEN`, and `CRACKED` notifications as hosts are scanned.
- **CSV** (`results/vnc_<timestamp>.csv`, flushed per hit so interrupts are safe):
  `timestamp, ip, port, service, url, detected, proto, security, auth, password, error`
- **Tables**: a per-host results table and a final scan summary.

## Files

| File                  | Role                                              |
|-----------------------|---------------------------------------------------|
| `scan.py`             | CLI entry point + results/summary tables          |
| `runner.py`           | Threaded scan engine (`ThreadPoolExecutor`)       |
| `vnc.py`              | RFB protocol: probe + VNC-Auth DES challenge       |
| `targets.py`          | IP / CIDR / range / port expansion                |
| `report.py`           | Live CSV reporting + summary                       |
| `creds/vnc.txt`       | Default password list (edit this)                 |
| `targets.example.txt` | Example targets file                              |
