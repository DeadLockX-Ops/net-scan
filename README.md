# Port Scanner

A simple, modular **Port Scanner** written in Python for discovering open TCP ports on a target host or network. This repository includes an easy-to-use CLI, asynchronous scanning options for speed, and examples showing how to integrate or compare results with Nmap (including the **Nmap Aggressive Scan** `-A`).

> **Warning / Legal:** Scanning networks or hosts without explicit permission is illegal in many jurisdictions and unethical. Only run this tool against systems you own or have written permission to test.

---

## Features

* Fast TCP port scanning (single-host or multiple hosts)
* Optional asynchronous/concurrent mode to speed up large scans
* Basic service banner grabbing (when available)
* Output in human-readable text and optional CSV
* Clear instructions to compare or enhance results using **Nmap** (`-A`) for deeper fingerprinting

---

## Requirements

* Python 3.8+
* `pip` to install Python dependencies
* (Optional) `nmap` binary if you want to run Nmap scans from the README examples

Recommended (example) Python dependencies (add to `requirements.txt` if you ship one):

```text
aiodns==3.0.0         # optional, if doing async DNS
python-nmap==0.7.1    # optional, if you plan to call nmap from Python
```

> The core scanner typically uses only Python's standard library (`socket`, `asyncio`, `concurrent.futures`), so third-party packages are optional.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/port-scanner.git
cd port-scanner
```

2. (Optional) Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate   # Linux / macOS
.\.venv\Scripts\activate  # Windows PowerShell
```

3. Install dependencies (if your repo has `requirements.txt`):

```bash
pip install -r requirements.txt
```

4. (Optional) Install Nmap (if you want to run Nmap scans locally):

* **Ubuntu / Debian:** `sudo apt update && sudo apt install nmap`
* **Fedora / CentOS:** `sudo dnf install nmap` or `sudo yum install nmap`
* **macOS (Homebrew):** `brew install nmap`
* **Windows:** Download from the official Nmap site and install the MSI package. Link  : https://nmap.org/dist/nmap-7.98-setup.exe

---

## Usage — Command-line Examples

> These examples assume the repository contains a script `scanner.py` (adjust names to match your implementation).

### Basic scan (common ports)

```bash
python scanner.py --target 192.168.1.10
```

### Scan a range of ports

```bash
python scanner.py --target 192.168.1.10 --ports 1-1024
```

### Scan a list of ports

```bash
python scanner.py --target 192.168.1.10 --ports 22,80,443,3306
```

### Asynchronous / concurrent scan

```bash
python scanner.py --target 192.168.1.10 --ports 1-65535 --concurrency 200
```

### Scan multiple hosts from a file

```bash
python scanner.py --targets-file targets.txt --ports 1-1024
```

### Save output to CSV

```bash
python scanner.py --target 192.168.1.10 --output results.csv
```

---

## Using Nmap alongside (and Nmap `-A` aggressive scan)

Nmap is a powerful network scanner and can provide much more detailed information (OS detection, version detection, script scanning). You can use it to validate or extend the results of this project.

### What is `-A` (Aggressive Scan)?

The `-A` flag enables several advanced features in Nmap:

* OS detection
* Version detection
* Script scanning (default scripts)
* Traceroute

It is convenient for quick, in-depth inventory and fingerprinting, but note that it increases scan noise and may be intrusive.

### Example Nmap commands

* Aggressive scan all TCP ports on a target (may require elevated privileges):

```bash
sudo nmap -A -p- 192.168.1.10
```

* Aggressive scan specific port set:

```bash
sudo nmap -A -p 22,80,443 192.168.1.10
```

* Aggressive scan multiple targets listed in a file:

```bash
sudo nmap -A -iL targets.txt
```

* Save Nmap results (XML and normal):

```bash
sudo nmap -A -oA nmap_results 192.168.1.10
```

> **Caution:** `-A` will run script scans and OS detection that may be considered intrusive. Only use on networks you are authorized to test.

### Integrating Nmap with this project 

You can call Nmap from Python using `subprocess` or via the `python-nmap` wrapper. Example (subprocess):

```python
import subprocess
cmd = ["sudo", "nmap", "-A", "-p-", "192.168.1.10"]
proc = subprocess.run(cmd, capture_output=True, text=True)
print(proc.stdout)
```

Or using `python-nmap`:

```python
import nmap
nm = nmap.PortScanner()
nm.scan('192.168.1.10', arguments='-A -p-')
print(nm.csv())
```

---

## Output examples

```
$ python scanner.py --target 192.168.1.10 --ports 1-1024
Scanning 192.168.1.10 (1-1024)
22/tcp  open  ssh
80/tcp  open  http
139/tcp closed
445/tcp open  microsoft-ds
Scan completed in 12.3s
```

Nmap aggressive output example (snippet):

```
# nmap -A 192.168.1.10
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41
MAC Address: 00:11:22:33:44:55 (Vendor)
OS details: Linux 4.15 - 5.4
```

---

## Performance & Tuning

* Increase concurrency for faster scans, but watch for false negatives and network load.
* Use smaller port ranges or intelligent port lists for targeted scans.
* Consider rate-limiting or pauses to avoid overloading targets.

---

## Contribution

Contributions, pull requests and issues are welcome. Please follow these rules:

1. Create an issue describing the feature or bug.
2. Fork the repo and work on a branch.
3. Send a pull request with tests and documentation when appropriate.



