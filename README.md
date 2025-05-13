## 🛡️ MISP-to-FortiGate Dynamic IP Threat Feed
This Python script bridges your [MISP](https://github.com/MISP/MISP) (Malware Information Sharing Platform) instance with [FortiGate](https://www.fortinet.com/products/firewall/fortigate) firewalls by exporting dynamic IP threat intelligence lists and serving them via a local HTTP server in a format compatible with FortiGate’s External Block List (EBL) feature.

---
## 🔧 Features
- 🔁 **Automated IOC Refresh**: Pulls fresh `ip-dst` and `ip-src` attributes from your MISP instance every 15 minutes.

- 📄 **EBL-Compatible Output**: Produces a flat, newline-separated IP list (misp_ip_blocklist.txt) readable by FortiGate firewalls.

- 🌐 **Local Web Server**: Hosts the IP list on a local HTTP server for easy ingestion by FortiGate.

- 🧵 **Multithreaded**: Web server and MISP polling run concurrently in separate threads.
---

## ⚙️ Requirements
- Python 3.6+

[PyMISP](https://github.com/MISP/PyMISP)

PyMISP is distributed under an [open source license](https://github.com/MISP/PyMISP/blob/main/LICENSE)

Install dependencies:

```bash
pip install pymisp
```
---

## 🚀 Usage

Clone this repository:

```bash
git clone https://github.com/malek-annabi/misp-ip-block-list.git
cd misp-ip-block-list
```

Edit the script to configure your MISP instance:

```python
MISP_URL = 'https://your-misp-instance'
MISP_KEY = 'your_misp_api_key'
VERIFY_CERT = False
LISTEN_PORT = 8080
```
Run the script:

```bash
python3 mispv2.py
```

The IOC list will be available at:

```
http://<your-ip>:8080/misp_ip_blocklist.txt
```
---

## 🔐 Security Considerations
⚠️ Production deployments should use HTTPS and restrict access via firewall rules or IP whitelisting.

🧼 Ensure that your MISP filters out test or low-confidence data before exporting to a production firewall.

🔐 Avoid exposing the HTTP service to the public internet without proper access controls.

---

## 🛠️ FortiGate Integration
In FortiOS 6.2+:

```Fortigate CLI
config firewall threat-feed
    edit "misp_ip_feed"
        set server "http://<your-ip>:8080/misp_ip_blocklist.txt"
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
    edit 0
        set name "block_misp_ips"
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
---
## 📚 License
**GNU PUBLIC v3.0 License**

