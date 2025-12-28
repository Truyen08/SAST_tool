import os
import subprocess
import pickle
import yaml
import requests
import hashlib

# Hardcoded credentials --> dễ bị lộ thông tin nhạy cảm
password = "123456"
api_key = "AKIA_TEST_123"
token = "hardcoded-token"

# eval/exec --> dễ bị RCE
eval("print('hello')")
exec("print('exec running')")

# subprocess --> dễ bị command Injection, chạy lệnh OS, tải malware, xoá dữ liệu.
subprocess.Popen("ls", shell=True)
subprocess.run("whoami", shell=True)

# os.system --> dễ bị command Injection
os.system("id")

#  pickle.load/loads --> dễ bị RCE
data = b"not_trusted"
obj = pickle.loads(data)

# yaml.load without SafeLoader (High) --> dễ bị RCE
cfg = yaml.load("a: 1", Loader=None)   # cố tình unsafe để rule bắt
cfg2 = yaml.load("b: 2")              # cũng sẽ bị bắt theo rule hiện tại

# requests verify=False (Medium) --> dễ bị Bypass SSL
requests.get("https://example.com", verify=False)
requests.post("https://example.com/api", data={"x": 1}, verify=False)

# weak hash md5/sha1 (Medium) --> dễ bị tấn công brute-force
h1 = hashlib.md5(b"hello").hexdigest()
h2 = hashlib.sha1(b"hello").hexdigest()
