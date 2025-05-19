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
DOMAIN_FILE = 'misp_domain_blocklist.txt'
HASH_FILE = 'misp_hash_blocklist.txt'
EXPORT_DIR = os.path.abspath(os.path.dirname(__file__))
EXPORT_PATH = os.path.abspath(EXPORT_FILENAME)
DOMAIN_PATH = os.path.join(DOMAIN_FILE)
HASH_PATH = os.path.join(HASH_FILE)
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
    
def fetch_and_export_misp_data():
    try:
        print("[*] Fetching domains and hashes from MISP...")
        misp = ExpandedPyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_CERT)

        # Domain types
        domain_types = ['domain', 'hostname']
        # Hash types
        hash_types = ['md5', 'sha1', 'sha256']

        domain_set = set()
        hash_set = set()

        # Pull domains
        domain_attrs = misp.search(controller='attributes', type_attribute=domain_types, pythonify=True)
        for attr in domain_attrs:
            domain_set.add(attr.value.strip())

        # Pull hashes
        hash_attrs = misp.search(controller='attributes', type_attribute=hash_types, pythonify=True)
        for attr in hash_attrs:
            hash_set.add(attr.value.strip().lower())

        # Write domains
        with open(DOMAIN_PATH, 'w') as f:
            for domain in sorted(domain_set):
                f.write(domain + '\n')

        # Write hashes
        with open(HASH_PATH, 'w') as f:
            for h in sorted(hash_set):
                f.write(h + '\n')

        print(f"[+] Exported {len(domain_set)} domains and {len(hash_set)} hashes")
    except Exception as e:
        print(f"[!] MISP fetch error: {e}")
    
    

def updater_loop():
    while True:
        try:
            fetch_misp_ips()
            fetch_and_export_misp_data()
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
