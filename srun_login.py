import json
import requests
import time
import re
import hmac
import hashlib
import math
import logging
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

username = ''
password = ''
get_ip_api = ''
init_url = ''
get_challenge_api = ''
srun_portal_api = ''

if username == '':
    username = os.getenv('USERNAME').strip()
if password == '':
    password = os.getenv('PASSWORD').strip()
if init_url == '':
    init_url = os.getenv('init_url').strip()
if get_challenge_api == '':
    get_challenge_api = os.getenv('get_challenge_api').strip()
if srun_portal_api == '':
    srun_portal_api = os.getenv('srun_portal_api').strip()
if get_ip_api == '':
    get_ip_api = os.getenv('get_ip_api').strip()

sleeptime = 300
n = '200'
type = '1'
ac_id = '1'
enc = "srun_bx1"
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

# 设置请求头
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def log(message, level="info"):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)

def ordat(msg, idx):
    return ord(msg[idx]) if len(msg) > idx else 0

def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd

def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    return "".join(msg)[0:ll] if key else "".join(msg)

def get_xencode(msg, key):
    if not msg:
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk.extend([0] * (4 - len(pwdk)))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        for p in range(n):
            y = pwd[p + 1]
            m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
        y = pwd[0]
        m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (pwdk[(n & 3) ^ e] ^ z)
        pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q -= 1
    return lencode(pwd, False)

def get_base64(s):
    r = []
    x = len(s) % 3
    s += '\0' * (3 - x) if x else ''
    for i in range(0, len(s), 3):
        d = ord(s[i]) << 16 | ord(s[i+1]) << 8 | ord(s[i+2])
        r.extend([_ALPHA[d >> 18], _ALPHA[d >> 12 & 63], _ALPHA[d >> 6 & 63], _ALPHA[d & 63]])
    if x == 1:
        r[-1] = r[-2] = '='
    elif x == 2:
        r[-1] = '='
    return ''.join(r)

def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

def get_sha1(msg):
    return hashlib.sha1(msg.encode()).hexdigest()

def get_token(session, ip):
    global token
    get_challenge_params = {
        "callback": f"jQuery112404953340710317169_{int(time.time() * 1000)}",
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    get_challenge_res = session.get(get_challenge_api, params=get_challenge_params, headers=headers)
    token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
    log(f"Token obtained: {token}")

def is_connected():
    try:
        requests.get("https://test.ustc.edu.cn/", timeout=2, headers=headers)
        return True
    except requests.RequestException:
        return False

def do_complex_work(ip, token):
    global i, hmd5, chksum
    i = json.dumps({"username": username, "password": password, "ip": ip, "acid": ac_id, "enc_ver": enc}).replace(" ", "")
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(f"{token}{username}{token}{hmd5}{token}{ac_id}{token}{ip}{token}{n}{token}{type}{token}{i}")
    log("Encryption completed")

def login(session, ip):
    srun_portal_params = {
        'callback': f'jQuery11240645308969735664_{int(time.time() * 1000)}',
        'action': 'login',
        'username': username,
        'password': '{MD5}'+f'{hmd5}',
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': n,
        'type': type,
        '_': int(time.time() * 1000)
    }
    srun_portal_res = session.get(srun_portal_api, params=srun_portal_params, headers=headers)
    log(f"Login response: {srun_portal_res.text}")

def main():
    while True:
        if is_connected():
            log("Already authenticated, no need for re-authentication")
        else:
            log("Not authenticated, proceeding with re-authentication")
            session = requests.Session()
            ip_response = session.get(get_ip_api, headers=headers, verify=False)  # 禁用 SSL 验证
            ip = json.loads(ip_response.text[7:-1]).get('client_ip')
            log(f"IP obtained: {ip}")
            get_token(session, ip)
            do_complex_work(ip, token)
            login(session, ip)
        time.sleep(sleeptime)

if __name__ == '__main__':
    main()
