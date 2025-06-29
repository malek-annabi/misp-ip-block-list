# 🛡️ MISP-to-FortiGate IOC Feed Server

This Python tool bridges your [MISP](https://github.com/MISP/MISP) instance with FortiGate or any platform that supports external threat feeds. It automatically extracts and publishes curated IPs, domains, and malware hashes over HTTP in formats readable by FortiGate's External Block List (EBL).

---

## 🔧 Features

- 🧠 **MISP Integration via PyMISP**
- 🔁 **Auto-refresh every 15 minutes** (customizable)
- 📤 **Exports to 3 feed files**:
  - `misp_ip_blocklist.txt`
  - `misp_domain_blocklist.txt`
  - `misp_hash_blocklist.txt`
- ✅ **Excludes known safe indicators** using [MISP Warning Lists](https://github.com/MISP/misp-warninglists)
- 🧵 **Fully multithreaded**:
  - HTTP server and IOC updater run concurrently
  - Thread-safe, non-blocking
- 🔒 **Memory-safe** with filtering and time scoping to avoid system crashes

---

## 📂 IOC Feed Outputs

| File | Type | Example Entries |
|------|------|-----------------|
| `misp_ip_blocklist.txt` | IP addresses | `8.8.8.8` |
| `misp_domain_blocklist.txt` | Domains | `malicious-site.ru` |
| `misp_hash_blocklist.txt` | MD5, SHA1, SHA256 | `e99a18c428cb38d5f260853678922e03` |

---

## ⚙️ Requirements

- Python 3.6+
- MISP instance which could be installed in a [simple script]((https://misp.github.io/MISP/)) (ubuntu-server 22.04 is recommended for selfhosting)  with [API access](https://www.circl.lu/doc/misp/automation/#automation-api)
- Enabled [warning lists](https://www.circl.lu/doc/misp/warninglists/)
- `pymisp` library

### Install:

```bash
pip install pymisp
```
### 🚀 Usage
1. Clone the repository:
```bash
git clone https://github.com/malek-annabi/misp-to-fortigate-ebl.git
cd misp-to-fortigate-ebl
```
2. Configure your script:
Edit these values at the top of the script:

```python
MISP_URL = 'https://your-misp-instance/'
MISP_KEY = 'your_api_key'
VERIFY_CERT = False
EXPORT_INTERVAL = 900  # 15 minutes
LISTEN_PORT = 8080
```
3. Run the server:
```bash
python3 misp_feed_server.py
```
## It will:

Query MISP for IPs, domains, hashes from the last 7 days

Exclude values matching any active warning list

Export IOC files

Serve them via HTTP at:

```arduino
http://<your-ip>:8080/misp_ip_blocklist.txt
http://<your-ip>:8080/misp_domain_blocklist.txt
http://<your-ip>:8080/misp_hash_blocklist.txt
```
## 🔐 Security Features
✅ Filters by timestamp (last 7 days)

✅ Filters with warning lists (server and client-side)

✅ Optional HTTPS support via reverse proxy (e.g. Nginx)

✅ Thread-isolated HTTP server using ThreadingHTTPServer

✅ RAM-safe: avoids large queries by using filters + deduplication

## 🛠️ FortiGate Integration (FortiOS 6.2+)
Example (for IP feed):
```bash
config firewall threat-feed
    edit "misp_ip_feed"
        set server "http://<your-ip>:8080/misp_ip_blocklist.txt"
        set type ip
    next
end

config firewall address
    edit "misp-ips"
        set type external-ip
        set external-ip-blocklist "misp_ip_feed"
    next
end

config firewall policy
    edit 100
        set name "Block MISP IPs"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "misp-ips"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
```
The domain list could be added in a custom dns filter profile which could be added later in a policy : [reference](https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/195303)
![image](https://github.com/user-attachments/assets/7fbc21db-a241-4362-bcac-556bcd48444d)

The Hashs list could be added to a custom antivirus profile which also could be added later in a policy :
![image](https://github.com/user-attachments/assets/62412471-861d-4f43-b0e5-697a288bcd4b)


## 🧠 Monitor in GUI:
Security Fabric → External Connectors → Threat Feeds
i'm using the fortios version 7.4.2, it will look like this :
![image](https://github.com/user-attachments/assets/5ee568f0-f82d-4c11-acf6-e75bc6dd9ea3)


## 📚 Warning List Support
This project uses the official MISP Warning Lists to eliminate noise and reduce false positives.

It uses both:

`enforce_warninglist=True` on the MISP server

`WarningLists().check_value()` on the client

Domains like google.com, microsoft.com, RFC1918 IPs, and public DNS are automatically excluded.

## 💡 Pro Tips
🛑 Don't remove filters or you'll crash your system

⚠️ Avoid using pythonify=True on unfiltered queries

✅ Always use `timestamp` + `enforce_warninglist` + `check_value`

🪵 Consider adding logging and a /status endpoint

## 📜 License
GPL-3.0 license

## 🤝 Contributions
PRs, bug reports, and feature suggestions are welcome!

## 🧠 Authors & Maintainers
Built by network and security engineer to streamline operational threat intelligence ingestion into enterprise security platforms like FortiGate, WAFs, and SOAR systems.

