import os
import time
import random
import requests
import threading
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from tqdm import tqdm
from colorama import init, Fore, Style
from urllib.parse import urlparse

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
]

SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q=",
    "yandex": "https://yandex.com/search/?text=",
    "duckduckgo": "https://duckduckgo.com/?q=",
    "yahoo": "https://search.yahoo.com/search?p=",
    "mozilla": "https://www.startpage.com/do/dsearch?query="
}

FILTER_TLDS = ['.gov', '.ac.id', '.edu']

ASCII_ART = r"""
 __  __ _             _       
|  \/  (_)           (_)      
| \  / |_ _ __  _ __  _  __ _ 
| |\/| | | '_ \| '_ \| |/ _` |
| |  | | | | | | | | | | (_| |
|_|  |_|_|_| |_| |_|_|\__,_|

       Laravel Grabber by Sean
"""

def reverse_ip_lookup(ip):
    try:
        url = f"https://rapiddns.io/sameip/{ip}?full=1"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        domains = set()
        table = soup.find('table')
        if table:
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if cols and cols[0].text.strip():
                    domains.add(cols[0].text.strip())
        return list(domains)
    except Exception as e:
        print(f"[!] Reverse IP failed for {ip}: {e}")
        return []

def get_ip(domain):
    try:
        parsed = urlparse(domain)
        hostname = parsed.hostname if parsed.hostname else domain
        return requests.get(f"https://dns.google/resolve?name={hostname}").json()['Answer'][0]['data']
    except:
        return None

def is_laravel(domain):
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        r = requests.get(domain, headers=headers, timeout=5)
        if 'X-Powered-By' in r.headers and 'Laravel' in r.headers['X-Powered-By']:
            return True
        if "Whoops! There was an error." in r.text:
            return True
        env_url = domain.rstrip("/") + "/.env"
        r_env = requests.get(env_url, headers=headers, timeout=5)
        if "APP_KEY=" in r_env.text:
            return True
    except requests.RequestException:
        return False
    return False

def scan_with_reverse(domains, threads=10):
    valid_urls = []
    lock = threading.Lock()

    def worker(domain):
        domain_full = domain if domain.startswith("http") else f"http://{domain}"
        if is_laravel(domain_full):
            with lock:
                valid_urls.append(domain_full)
                print(Fore.GREEN + f"[Laravel] {domain_full}")
                ip = get_ip(domain_full)
                if ip:
                    neighbors = reverse_ip_lookup(ip)
                    for neighbor in neighbors:
                        if neighbor != domain:
                            neighbor_full = f"http://{neighbor}"
                            if is_laravel(neighbor_full):
                                print(Fore.GREEN + f"  [Reverse IP Laravel] {neighbor_full}")
                                valid_urls.append(neighbor_full)
        else:
            print(Fore.RED + f"[Not Laravel] {domain_full}")

    threads_list = []
    for domain in domains:
        t = threading.Thread(target=worker, args=(domain,))
        threads_list.append(t)
        t.start()
        while threading.active_count() > threads:
            time.sleep(0.1)

    for t in threads_list:
        t.join()

    with open("laravel_found.txt", "w") as f:
        for url in valid_urls:
            f.write(url + "\n")

    # Statistics
    print("\n[+] Scan Summary:")
    print(f"    Total Scanned: {len(domains)}")
    print(f"    Laravel Found: {len(valid_urls)}")
    print(f"    Saved to: laravel_found.txt")

    # Optional TLD filter result
    filtered = [u for u in valid_urls if any(u.endswith(tld) for tld in FILTER_TLDS)]
    if filtered:
        print(f"\n[+] Domains with special TLDs ({', '.join(FILTER_TLDS)}):")
        for u in filtered:
            print("   ", u)

def grab_dork_results(dork, threads=10):
    urls = set()
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)

    for name, base_url in SEARCH_ENGINES.items():
        try:
            query = base_url + dork
            driver.get(query)
            time.sleep(random.uniform(2, 4))
            soup = BeautifulSoup(driver.page_source, "html.parser")
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith("http") and "google" not in href and "yahoo" not in href and not any(x in href for x in ["/search", "/imgres", "/settings"]):
                    urls.add(href.split("?")[0])
        except Exception as e:
            print(f"[!] Error with {name}: {e}")
    driver.quit()

    print("[+] Checking Laravel presence on found sites...")
    scan_with_reverse(list(urls), threads)

def scan_laravel(filename, threads=10):
    try:
        with open(filename, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] File '{filename}' not found.")
        return

    print("[+] Scanning websites with threads...")
    scan_with_reverse(domains, threads)

def main_menu():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(ASCII_ART)
        print("1. Grab Weblist via Dork (Google, Yandex, etc)")
        print("2. Scan Laravel from domain list (.txt)")
        print("3. Exit")
        choice = input("\nSelect an option: ")

        if choice == "1":
            dork = input("Enter dork: ")
            thread_count = input("Thread count (default 10): ")
            try:
                threads = int(thread_count)
            except:
                threads = 10
            grab_dork_results(dork, threads)
            input("\nPress Enter to return to menu...")
        elif choice == "2":
            filename = input("Enter .txt filename (default: weblist.txt): ") or "weblist.txt"
            thread_count = input("Thread count (default 10): ")
            try:
                threads = int(thread_count)
            except:
                threads = 10
            scan_laravel(filename, threads)
            input("\nPress Enter to return to menu...")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option!")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
