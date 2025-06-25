## Documentation will be updated shortly after the last update : malware hash and malicious domains integration have been added.

# 🛡️ MISP-to-FortiGate IOC Feed Server

This Python tool bridges your [MISP](https://github.com/MISP/MISP) instance with FortiGate or any platform that supports external threat feeds. It automatically extracts and publishes curated IPs, domains, and malware hashes over HTTP in formats readable by FortiGate's External Block List (EBL).

---

## 🔧 Features

- 🧠 **MISP Integration via PyMISP**
- 🔁 **Auto-refresh every 15 minutes** (customizable)
- 📤 **Exports to 3 feed files**:
  - `misp_ip_blocklist_v2.txt`
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
| `misp_ip_blocklist_v2.txt` | IP addresses | `8.8.8.8` |
| `misp_domain_blocklist.txt` | Domains | `malicious-site.ru` |
| `misp_hash_blocklist.txt` | MD5, SHA1, SHA256 | `e99a18c428cb38d5f260853678922e03` |

---

## ⚙️ Requirements

- Python 3.6+
- MISP with API access
- Enabled warning lists
- `pymisp` library

### Install:

```bash
pip install pymisp
```
### 🚀 Usage
1. Clone the repository:
```bash
git clone https://github.com/yourusername/misp-to-fortigate-ebl.git
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
It will:

Query MISP for IPs, domains, hashes from the last 7 days

Exclude values matching any active warning list

Export IOC files

Serve them via HTTP at:

```arduino
http://<your-ip>:8080/misp_ip_blocklist_v2.txt
http://<your-ip>:8080/misp_domain_blocklist.txt
http://<your-ip>:8080/misp_hash_blocklist.txt
```
🔐 Security Features
✅ Filters by timestamp (last 7 days)

✅ Filters with warning lists (server and client-side)

✅ Optional HTTPS support via reverse proxy (e.g. Nginx)

✅ Thread-isolated HTTP server using ThreadingHTTPServer

✅ RAM-safe: avoids large queries by using filters + deduplication

🛠️ FortiGate Integration (FortiOS 6.2+)
Example (for IP feed):
```bash
config firewall threat-feed
    edit "misp_ip_feed"
        set server "http://<your-ip>:8080/misp_ip_blocklist_v2.txt"
        set type ip
    next
end

config firewall address
    edit "MISP_IP_List"
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
        set dstaddr "MISP_IP_List"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
```
Repeat for misp_domain_blocklist.txt using type domain.

🧠 Monitor in GUI:
Security Fabric → External Connectors → Threat Feeds

📚 Warning List Support
This project uses the official MISP Warning Lists to eliminate noise and reduce false positives.

It uses both:

`enforce_warninglist=True` on the MISP server

`WarningLists().check_value()` on the client

Domains like google.com, microsoft.com, RFC1918 IPs, and public DNS are automatically excluded.

💡 Pro Tips
🛑 Don't remove filters or you'll crash your system

⚠️ Avoid using pythonify=True on unfiltered queries

✅ Always use `timestamp` + `enforce_warninglist` + `check_value`

🪵 Consider adding logging and a /status endpoint

📜 License
MIT License

🤝 Contributions
PRs, bug reports, and feature suggestions are welcome!

🧠 Authors & Maintainers
Built by offensive and defensive security engineers to streamline operational threat intelligence ingestion into enterprise security platforms like FortiGate, WAFs, and SOAR systems.

