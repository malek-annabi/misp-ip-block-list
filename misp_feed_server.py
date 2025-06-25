import time
import threading
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pymisp import ExpandedPyMISP

# -----------------------------
# MISP Configuration
MISP_URL = 'https://192.168.150.128/'
MISP_KEY = 'GlZ4aWljQLsBAMiKSJWGRDYzsSkiFiOgQKh82vtK'
VERIFY_CERT = False

EXPORT_INTERVAL = 900  # 15 minutes
LISTEN_PORT = 8080

EXPORT_DIR = os.path.abspath(os.path.dirname(__file__))
EXPORT_PATH = os.path.join(EXPORT_DIR, 'misp_ip_blocklist_v2.txt')
DOMAIN_PATH = os.path.join(EXPORT_DIR, 'misp_domain_blocklist.txt')
HASH_PATH = os.path.join(EXPORT_DIR, 'misp_hash_blocklist.txt')
# -----------------------------

from datetime import datetime, timedelta

def fetch_misp_ips():
    print("[*] Fetching IPs from MISP...")

    misp = ExpandedPyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_CERT)

    one_week_ago = int((datetime.utcnow() - timedelta(days=7)).timestamp())

    attributes = misp.search(
        controller='attributes',
        type_attribute=['ip-dst', 'ip-src'],
        enforce_warninglist=True,
        limit=150000,
        pythonify=True
    )

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

        domain_types = ['domain', 'hostname']
        hash_types = ['md5', 'sha1', 'sha256']

        domain_set = set()
        hash_set = set()

        # Domains
        domain_attrs = misp.search(controller='attributes', type_attribute=domain_types,limit=150000, enforce_warninglist=True, pythonify=True)
        for attr in domain_attrs:
            domain_set.add(attr.value.strip())
        print(f"[+] Got {len(domain_set)} unique DOMAINs.")

        # Hashes
        hash_attrs = misp.search(controller='attributes', type_attribute=hash_types,limit=150000, enforce_warninglist=True, pythonify=True)
        for attr in hash_attrs:
            hash_set.add(attr.value.strip().lower())
        print(f"[+] Got {len(hash_set)} unique HASHs.")

        # Write domain blocklist
        with open(DOMAIN_PATH, 'w') as f:
            for domain in sorted(domain_set):
                f.write(domain + '\n')

        # Write hash blocklist
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
            print(f"[!] Error updating MISP data: {e}")
        time.sleep(EXPORT_INTERVAL)

def start_http_server():
    os.chdir(EXPORT_DIR)
    server = ThreadingHTTPServer(('0.0.0.0', LISTEN_PORT), SimpleHTTPRequestHandler)
    print(f"[+] HTTP server running at http://0.0.0.0:{LISTEN_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[!] Server interrupted, exiting...")
        server.server_close()

if __name__ == '__main__':
    # IOC updater thread
    updater_thread = threading.Thread(target=updater_loop, daemon=True)
    updater_thread.start()

    # Main thread runs the HTTP server
    start_http_server()
