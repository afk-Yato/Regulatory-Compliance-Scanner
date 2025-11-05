# Regulatory Compliance Scanner

A lightweight Python-based host/service scanner that checks common security misconfigurations and weak services (FTP anonymous login, outdated SSH versions, HTTP->HTTPS redirection, TLS versions, Telnet exposure). This tool is intended for *authorized* internal scans and quick compliance checks on servers you own or have permission to audit.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [How it works](#how-it-works)
* [Example output](#example-output)
* [Recommended fixes / remediation tips](#recommended-fixes--remediation-tips)

---

## Features

* Scans selected ports (21, 22, 23, 80, 443) using `nmap3`.
* Checks for:

  * Anonymous FTP login.
  * SSH version and warns if `ssh < 7.4`.
  * Telnet exposure (port 23).
  * HTTP (port 80) availability and whether it redirects to HTTPS (port 443).
  * HTTPS cipher/TLS enumeration (uses `ssl-enum-ciphers` script output to detect TLS 1.0/1.1).
* Human-friendly pass/warning messages and simple remediation suggestions.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/afk-Yato/Regulatory-Compliance-Scanner.git
cd Regulatory-Compliance-Scanner
```

2. Install system `nmap` (required for nmap3 to work):

* Debian/Ubuntu:

```bash
sudo apt update && sudo apt install -y nmap
```

* Fedora/CentOS/RHEL:

```bash
sudo dnf install -y nmap
```

* macOS:

```bash
brew install nmap
```

3. Install the Python dependencies:

```bash
pip install requests
```

---

## Usage

Add permission to execute the tool :

```bash
chmod +x Regulatory_Compliance_Scanner 
```

Execute the scanner with :

```bash
./Regulatory_Compliance_Scanner
```

The program will prompt you for a target IP (for example `127.0.0.1`). Enter a valid IPv4/IPv6 address and the scanner will run the checks and print PASS/WARNING messages.

**Important:** Only scan hosts you own or have explicit permission to scan.

---

## How it works (brief)

* Uses `nmap3.NmapHostDiscovery().nmap_portscan_only(target, args)` to run an nmap port/service scan with:

  * `-sV`
  * `-p21,22,23,80,443`
  * `--script ssl-enum-ciphers`
* Parses the nmap results to check each port's state and script output.
* Uses `requests` to test if HTTP redirects to HTTPS.
* Uses `ftplib.FTP` to test anonymous FTP login.

---

## Example output

```
$ python3 scanner.py

=>This tool scans the hosts to detect some popular service protocols
>This program is based on some rules MUST be deployed in every server for security purposes
...
Pls enter a valid host IP to scan(e.g. 127.0.0.1) :
127.0.0.1
||Scanning 127.0.0.1 is in progress - VERBOSE=False - press ctrl-c to stop the scan||
[PASS] Port 23 is closed => No telnet service.
[PASS] ssh service is updated => ssh version >= 7.4
[WARNING] Your http service is available and does not redirect to https !
========> Must close port 80 OR redirect to port 443 -_-
[PASS] Https service support tls ≥ 1.2 ==> No tls 1.0/1.1 ciphers.
[PASS] No ftp anonymous login ==> ftp-anon = 0.

host 127.0.0.1 was scanned successfully :)
```

---

## Recommended fixes / remediation tips

* **FTP anonymous:** edit `/etc/vsftpd.conf` and set `anonymous_enable=NO`.
* **SSH version:** upgrade OpenSSH to a version >= 7.4.
* **HTTP -> HTTPS:** configure redirection or disable port 80.
* **TLS:** disable TLS 1.0 and 1.1.
* **Telnet:** ensure port 23 is closed.
