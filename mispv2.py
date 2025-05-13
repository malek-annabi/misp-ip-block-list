import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pymisp import ExpandedPyMISP
import os

# -----------------------------
# MISP Configuration
MISP_URL = 'https://192.168.122.226/'
MISP_KEY = 'Pc6wE9WMfXqQPAwtP4RbnNEhXvBZbi0btYG9gFuK'
VERIFY_CERT = False
EXPORT_FILENAME = 'misp_ip_blocklist_v2.txt'
EXPORT_PATH = os.path.abspath(EXPORT_FILENAME)
EXPORT_INTERVAL = 900  # 15 minutes
LISTEN_PORT = 8080
# -----------------------------

def fetch_misp_ips():
    print("[*] Fetching IPs from MISP...")
    misp = ExpandedPyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_CERT)
    attributes = misp.search(controller='attributes', type_attribute=['ip-dst', 'ip-src'], pythonify=True)

    ip_list = set()
    for attr in attributes:
        ip_list.add(attr.value.strip())

    print(f"[+] Got {len(ip_list)} unique IPs.")

    with open(EXPORT_PATH, 'w') as f:
        for ip in sorted(ip_list):
            f.write(ip + '\n')
    print(f"[+] Wrote IPs to {EXPORT_PATH}")

def updater_loop():
    while True:
        try:
            fetch_misp_ips()
        except Exception as e:
            print(f"[!] Error updating MISP IPs: {e}")
        time.sleep(EXPORT_INTERVAL)

def start_http_server():
    os.chdir(os.path.dirname(EXPORT_PATH))  # Serve from correct directory
    server = HTTPServer(('0.0.0.0', LISTEN_PORT), SimpleHTTPRequestHandler)
    print(f"[+] Serving IOC list on port {LISTEN_PORT}")
    server.serve_forever()

if __name__ == '__main__':
    # Start updater thread
    updater_thread = threading.Thread(target=updater_loop, daemon=True)
    updater_thread.start()

    # Start HTTP server
    start_http_server()
