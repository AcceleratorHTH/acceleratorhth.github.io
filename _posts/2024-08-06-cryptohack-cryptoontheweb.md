---
title: CryptoHack
description: CTF-Crypto
author: Pr0pylTh10ur4C1L
date: 2024-08-06 15:13:00 +0700
categories: [Capture The Flag]
tags: [Cryptography]
math: true
mermaid: true
---

## Block Ciphers
### MODES OF OPERATION STARTER
The previous set of challenges showed how AES performs a keyed permutation on a block of data. In practice, we need to encrypt messages much longer than a single block. A mode of operation describes how to use a cipher like AES on longer messages.

All modes have serious weaknesses when used incorrectly. The challenges in this category take you to a different section of the website where you can interact with APIs and exploit those weaknesses. Get yourself acquainted with the interface and use it to take your next flag!

*source.py*
```python
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/block_cipher_starter/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/block_cipher_starter/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}

## ciphertext = 24e49b0a571db106b3392b0dc7b422b6d284081583603de51865f289806d855a
```
Encrypt => Decrypt => To_bytes

Flag: *crypto{bl0ck_c1ph3r5_4r3_f457_!}*

### PASSWORDS AS KEYS
It is essential that keys in symmetric-key algorithms are random bytes, instead of passwords or other predictable data. The random bytes should be generated using a cryptographically-secure pseudorandom number generator (CSPRNG). If the keys are predictable in any way, then the security level of the cipher is reduced and it may be possible for an attacker who gets access to the ciphertext to decrypt it.

Just because a key looks like it is formed of random bytes, does not mean that it necessarily is. In this case the key has been derived from a simple password using a hashing function, which makes the ciphertext crackable.

For this challenge you may script your HTTP requests to the endpoints, or alternatively attack the ciphertext offline. Good luck!

*source.py*
```python
from Crypto.Cipher import AES
import hashlib
import random


## /usr/share/dict/words from
## https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("/usr/share/dict/words") as f:
    words = [w.strip() for w in f.readlines()]
keyword = random.choice(words)

KEY = hashlib.md5(keyword.encode()).digest()
FLAG = ?


@chal.route('/passwords_as_keys/decrypt/<ciphertext>/<password_hash>/')
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/passwords_as_keys/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}

## ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"
```
Ở đây, key được lấy từ một file words khá dài và được lấy random. Vì vậy, mình sẽ thử với tất cả key trong đó luôn
```python
from Crypto.Cipher import AES
import hashlib

ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"

with open("words") as f:
    words = [w.strip() for w in f.readlines()]
for keyword in words:
    KEY = hashlib.md5(keyword.encode()).digest()

    def decrypt(ciphertext):
        ciphertext = bytes.fromhex(ciphertext)

        cipher = AES.new(KEY, AES.MODE_ECB)
        try:
            decrypted = cipher.decrypt(ciphertext)
        except ValueError as e:
            return {"error": str(e)}

        return decrypted.hex()
    flag = bytes.fromhex(decrypt(ciphertext))
    if(b'crypto{' in flag):
        print(flag)
```

Flag: *crypto{k3y5__r__n07__p455w0rdz?}*

### ECB CBC WTF
Here you can encrypt in CBC but only decrypt in ECB. That shouldn't be a weakness because they're different modes... right?

*source.py*
```python
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

## ciphertext = "8433579e09ad33fa760c8f16a3a26d0ee043bcd3f8e5c1044d65564567624def0cb27dd49ed4688d202e94c3972b39f6"
```

Flag được mã hóa bằng AES_CBC, tuy nhiên giải mã lại là AES_ECB. Nghe có vẻ khá chuối.

Ở đây, mình để ý *ciphertext = iv.hex() + encrypted.hex()*, vì vậy 32 kí tự hex đầu chính là iv. Dựa vào iv đó, mình sẽ giải mã CBC với iv và phương thức decrypt là ECB. Dưới đây là code thực hiện:
```python
from Crypto.Cipher import AES
import requests
from pwn import xor

ciphertext = "8433579e09ad33fa760c8f16a3a26d0ee043bcd3f8e5c1044d65564567624def0cb27dd49ed4688d202e94c3972b39f6"

iv = bytes.fromhex(ciphertext[0:32])

def decrypt(block):
	url = "http://aes.cryptohack.org/ecbcbcwtf/decrypt/"
	url += block.hex() + "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js["plaintext"])

block1 = bytes.fromhex(ciphertext[32:64])
block2 = bytes.fromhex(ciphertext[64:96])

plain1 = xor(decrypt(block1), iv)
plain2 = xor(decrypt(block2), block1)

print(plain1 + plain2)
```
Flag: *crypto{3cb_5uck5_4v01d_17_!!!!!}*

### ECB Oracle
ECB is the most simple mode, with each plaintext block encrypted entirely independently. In this case, your input is prepended to the secret flag and encrypted and that's it. We don't even provide a decrypt function. Perhaps you don't need a padding oracle when you have an "ECB oracle"?

*source.py*
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


KEY = ?
FLAG = ?


@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}

```

Bài này thì đơn giản chỉ là ECB Oracle. Đấm thoi
```python
from Crypto.Cipher import AES
import requests
from tqdm import tqdm

flag = 'crypto{'

def encrypt(string):
	url = "https://aes.cryptohack.org/ecb_oracle/encrypt/"
	url += str(string.encode().hex()) + "/"
	r = requests.get(url)
	js = r.json()
	return js["ciphertext"]

count = 15
for i in range(0,64,32):
    while(True):
        payload= "0" * (count-len(flag))
        res1 = encrypt(payload)
        for j in tqdm("abcdefghijklmnopqrstuvwxyz0123456789_{}"):
            res2 = encrypt(payload + flag + j)
            if(res1[i:i+32] == res2[i:i+32]):
                flag += j
                break
        if(len(flag) in [15, 31, 47]):
            count += 16
            break
        print(flag)

```

Flag: *crypto{p3n6u1n5_h473_3cb}*

### FLIPPING COOKIE
You can get a cookie for my website, but it won't help you read the flag... I think.

*source.py*
```python
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta


KEY = ?
FLAG = ?


@chal.route('/flipping_cookie/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}


@chal.route('/flipping_cookie/get_cookie/')
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}
```

Để ý *ciphertext = iv.hex() + encrypted.hex()* nên ta sẽ tìm ra được iv. VIệc đó tính sau, giờ hãy nhìn vào hàm *check_admin*. Sau khi giải mã, nếu trong cookie có *admin=True* thì mới trả về flag. Vậy phải làm như nào ta.

Do yếu tố liên quan tới admin nằm ở trong block đầu tiên, thứ mà mình có thể kiểm soát thông qua IV. Ở đây mình sẽ có như sau:
```
plaintext_1 = b'admin=False;expi' 
ciphertext_1 = enc(plaintext_1 ^ iv)
```
Nếu sử dụng iv tùy chỉnh, quá trình giải mã sẽ như này:
```
plaintext_1_new = dec(ciphertext_1) ^ iv_new
plaintext_1_new = plaintext_1 ^ iv ^ iv_new
```


chúng ta muốn plaintext_1_new có dạng *b'admin=True;expir'*, vậy phải làm mất đi *plaintext_1* và *iv*. Khi đó, *new_iv* sẽ phải như sau:
```
plaintext_1_new = plaintext_1 ^ iv ^ (plaintext_1 ^ iv ^ b'admin=True;expir')
=> plaintext_1_new = b'admin=True;expir'
```
Code thực thi như sau:
```python
from pwn import *
import requests

plaintext_1 = b'admin=False;expi'
plaintext_1_new = b'admin=True;expir'

def check_admin(cookie, iv):
    url = "http://aes.cryptohack.org/flipping_cookie/check_admin/"
    url += cookie
    url += "/"
    url += iv.hex()
    url += "/"
    r = requests.get(url)
    js = r.json()
    return js['flag']

encrypt = "2fcf378b85cdf04cee54d489b2091b62ae514b08f75bf8f046c6d1faa905a0b866fbe95987ba8b42c4e8f70432c39c5a"

iv = encrypt[0:32]
cookie = encrypt[32:]

iv_new = xor(xor(plaintext_1, plaintext_1_new), bytes.fromhex(iv))

print(check_admin(cookie, iv_new))

```

Flag: *crypto{4u7h3n71c4710n_15_3553n714l}*

### LAZY CBC
I'm just a lazy dev and want my CBC encryption to work. What's all this talk about initialisations vectors? Doesn't sound important.

*source.py*
```python
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/lazy_cbc/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    encrypted = cipher.encrypt(plaintext)

    return {"ciphertext": encrypted.hex()}


@chal.route('/lazy_cbc/get_flag/<key>/')
def get_flag(key):
    key = bytes.fromhex(key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}


@chal.route('/lazy_cbc/receive/<ciphertext>/')
def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode() ## ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}
```
Với bài này, tác giả đã sử dụng chính KEY để làm IV. Điều này vô tình tạo ra lỗ hổng. Ở đây mình sẽ khai thác dựa vào hàm *receive*.

Ở đây, mình sẽ dựa trên bài viết [này](https://crypto.stackexchange.com/questions/16161/problems-with-using-aes-key-as-iv-in-cbc-mode)
![Screenshot 2023-10-03 161556](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/d969519e-e77d-4b30-8456-5b11631240d9)

Code:
```python
from Crypto.Cipher import AES
import requests
from pwn import *

def encrypt(block):
	url = "https://aes.cryptohack.org/lazy_cbc/encrypt/"
	url += str(block.hex()) + "/"
	r = requests.get(url)
	js = r.json()
	return js["ciphertext"]

def get_flag(key):
	url = "https://aes.cryptohack.org/lazy_cbc/get_flag/"
	url += key.hex() + "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js['plaintext'])

def receive(block):
	url = "https://aes.cryptohack.org/lazy_cbc/receive/"
	url += block + "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js["error"][len("Invalid plaintext: "):])

ciphertext = b'A' * 48
ciphertext = encrypt(ciphertext)
ciphertext = ciphertext[:32] + '0'*32 + ciphertext[:32]
recv = receive(ciphertext)
key = xor(recv[:16], recv[32:])
print(get_flag(key))

```
Flag: *crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}*

### Triple DES
Data Encryption Standard was the forerunner to AES, and is still widely used in some slow-moving areas like the Payment Card Industry. This challenge demonstrates a strange weakness of DES which a secure block cipher should not have.

*source.py*
```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad


IV = os.urandom(8)
FLAG = ?


def xor(a, b):
    ## xor 2 bytestrings, repeating the 2nd one if necessary
    return bytes(x ^ y for x,y in zip(a, b * (1 + len(a) // len(b))))



@chal.route('/triple_des/encrypt/<key>/<plaintext>/')
def encrypt(key, plaintext):
    try:
        key = bytes.fromhex(key)
        plaintext = bytes.fromhex(plaintext)
        plaintext = xor(plaintext, IV)

        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = xor(ciphertext, IV)

        return {"ciphertext": ciphertext.hex()}

    except ValueError as e:
        return {"error": str(e)}


@chal.route('/triple_des/encrypt_flag/<key>/')
def encrypt_flag(key):
    return encrypt(key, pad(FLAG.encode(), 8).hex())

```
Khái niệm Weak Key: https://en.wikipedia.org/wiki/Weak_key##Weak_keys_in_DES
![Screenshot 2023-10-04 140906](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/c9d903de-05fd-4bc6-87a1-e3848bf4f5dd)

Khi sử dụng Weak Key, điều này có thể xảy ra:
![Screenshot 2023-10-04 140748](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/42a8c5b2-caf5-427c-9781-51f858c2410b)

Nghĩa là chỉ cần mã hóa message 2 lần bằng Weak Key, ta sẽ nhận lại chính message.

Áp dụng vào bài, mình sẽ thử dùng từng tổ hợp cặp khóa cho tới khi ra flag.
```python
import requests
    
def encrypt(key, plaintext):
    url = "http://aes.cryptohack.org/triple_des/encrypt/"
    url += key
    url += "/"
    url += plaintext
    url += "/"
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']


def encrypt_flag(key):
	url = "https://aes.cryptohack.org/triple_des/encrypt_flag/"
	url += key + "/"
	r = requests.get(url)
	js = r.json()
	return js['ciphertext']

key = b'\xfe'*8 + b'\x01'*8
key = key.hex()

flag = encrypt_flag(key)
flag = encrypt(key, flag)
print(bytes.fromhex(flag))
```
Bonus giải thích kĩ hơn 3DES: [link](https://hackmd.io/@phucrio17/cryptohack-symmetric-ciphers##Triple-DES)

Flag: *crypto{n0t_4ll_k3ys_4r3_g00d_k3ys}*

## Stream Ciphers
### SYMMETRY
Some block cipher modes, such as OFB, CTR, or CFB, turn a block cipher into a stream cipher. The idea behind stream ciphers is to produce a pseudorandom keystream which is then XORed with the plaintext. One advantage of stream ciphers is that they can work of plaintext of arbitrary length, with no padding required.

OFB is an obscure cipher mode, with no real benefits these days over using CTR. This challenge introduces an unusual property of OFB.

*source.py*
```python
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/symmetry/encrypt/<plaintext>/<iv>/')
def encrypt(plaintext, iv):
    plaintext = bytes.fromhex(plaintext)
    iv = bytes.fromhex(iv)
    if len(iv) != 16:
        return {"error": "IV length must be 16"}

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext)
    ciphertext = encrypted.hex()

    return {"ciphertext": ciphertext}


@chal.route('/symmetry/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

```
AES_OFB:
![Screenshot 2023-10-04 160031](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/ebf73e89-dec5-477a-987f-431677f72ccb)


Do *ciphertext = iv.hex() + encrypted.hex()*, mình dễ dàng có được iv và flag encrypted.

Để ý thì ở đây, *key* là không đổi. Vì vậy, mình có thể lấy khối encrypt bằng cách encrypt đoạn text bất kì dài bằng flag và xor nó với chính đoạn text ban đầu. *key* không đổi khiến cho khối encrypt đó giống với khối dùng để encrypt flag. Cuối cùng chỉ cần XOR khối đó với encrypted flag sẽ ra được flag

```python
import requests
from pwn import xor

def encrypt(plaintext, iv):
    url = 'https://aes.cryptohack.org/symmetry/encrypt/'
    url += plaintext.hex() + '/' + iv.hex() + '/'
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']

def encrypt_flag():
    url = 'https://aes.cryptohack.org/symmetry/encrypt_flag/'
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']

flag = bytes.fromhex(encrypt_flag())
iv = flag[:16]
flag = flag[16:]

plain = b'A'*len(flag)
key = xor(bytes.fromhex(encrypt(plain, iv)), plain)
print(xor(key, flag))
```

Flag: *crypto{0fb_15_5ymm37r1c4l_!!!11!}*

### BEAN COUNTER
I've struggled to get PyCrypto's counter mode doing what I want, so I've turned ECB mode into CTR myself. My counter can go both upwards and downwards to throw off cryptanalysts! There's no chance they'll be able to read my picture.

*source.py*
```python
from Crypto.Cipher import AES

KEY = ?

class StepUpCounter(object):
    def __init__(self, step_up=False):
        self.value = os.urandom(16).hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))

    def __repr__(self):
        self.increment()
        return self.value



@chal.route('/bean_counter/encrypt/')
def encrypt():
    cipher = AES.new(KEY, AES.MODE_ECB)
    ctr = StepUpCounter()

    out = []
    with open("challenge_files/bean_flag.png", 'rb') as f:
        block = f.read(16)
        while block:
            keystream = cipher.encrypt(ctr.increment())
            xored = [a^b for a, b in zip(block, keystream)]
            out.append(bytes(xored).hex())
            block = f.read(16)

    return {"encrypted": ''.join(out)}
```
AES_CTR:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/49e5ed7e-7d1c-40db-8542-f3118eff1c65)

Mình nghĩ challenge sẽ cho mình tìm ra được *keystream* đầu tiên bằng cách nào đó. Một block dài 16 bytes, và đây là mã hóa file png. Do không phải một người chơi Forensic nên mình đã phải thử đọc hex của vài file png và nhận ra 16 bytes đầu đều giống nhau.
```
89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
```
Vì vậy mình có thể dễ dàng lấy được keystream đầu. Để ý thêm code class:
```python
class StepUpCounter(object):
    def __init__(self, step_up=False):
        self.value = os.urandom(16).hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))
```
Ở đây, mình thấy `step_up = False`, nên xuống dưới, `self.newIV = hex(int(self.value, 16) - self.stup)`. Tuy nhiên có lỗi chính tả ở đây khi đáng lẽ phải trừ đi `self.step`. Việc trừ đi `self.stup`, thứ có giá trị False đã khiến cho iv không tăng/giảm, và làm keystream luôn không đổi.

Vậy là không còn gì khó, mình chỉ cần xor keystream với từng block của file png bị mã hóa thôi.
```python
import requests
from pwn import *

def encrypt():
    url = "https://aes.cryptohack.org/bean_counter/encrypt/"
    r = requests.get(url)
    js = r.json()
    return js["encrypted"]

png = bytes.fromhex(encrypt())

png_bytes = bytes.fromhex("89504e470d0a1a0a0000000d49484452")
keystream = xor(png_bytes, png[:16])

print(xor(keystream, png).hex())
```
Mình sẽ thu được đoạn hex của file png. Ném vào Cyberchef để render và mình ra được kết quả.
![](https://hackmd.io/_uploads/ByIAYWjg6.png)

Flag: *crypto{hex_bytes_beans}*

### CTRIME
There may be a lot of redundancy in our plaintext, so why not compress it first?

*source.py*
```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import zlib

KEY = ?
FLAG = ?

@chal.route('/ctrime/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    iv = int.from_bytes(os.urandom(16), 'big')
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))
    encrypted = cipher.encrypt(zlib.compress(plaintext + FLAG.encode()))

    return {"ciphertext": encrypted.hex()}
```
AES_CTR:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/a49462a6-6eed-49ca-af87-5a38ae1d48ed)

Mọi thứ trong thuật toán này đều ổn áp. Vì vậy, chúng ta phải nghĩ đến chuyện khai thác hàm `zlib.compress`
`Zlib.compress` trong python sử dụng thuật toán deflate để nén dữ liệu. Thuật toán deflate bao gồm 2 phương pháp chính là LZ77 encoding và Huffman encoding. Về Huffman encoding, đây đơn thuần là phương pháp encode theo từng ký tự một dựa trên cây Huffman, các ký tự xuất hiện nhiều như chữ 'e' sẽ được sub thành một chuỗi các bit ngắn hơn (3-4 bits thay vì 8 bits như bình thường), cách ký tự xuất hiện ít như chữ 'q' thì được encode bằng các bit dài hơn (không quá 7 bits). Default trong python thì cây Huffman được lấy theo quy chuẩn chung (fixed) nên cuối cùng thì đây chỉ là bước thay thế từng byte thành các bits tương ứng, không có tác dụng gì nhiều lắm.
Tiếp theo là LZ77, đây là một thuật toán khá phức tạp, hiểu đơn giản là nó sẽ thay các chuỗi ký tự bị lặp bằng cách tham chiếu đến chuỗi ký tự tương ứng đã được tìm thấy trước đó. Ví dụ minh họa đơn giản:  
AAAAABCDEE => A5BCDE2  
AAAAXBCDEE => A4XBCDE2  
ABABABABXYZT => AB4XYZT  
ABABABACXYZT => AB3ACXYZT  
ABCABCABCABCMNPQ => ABC4MNPQ  
ABCABCABCABXMNPQ => ABC3ABXMNPQ  
Từ các ví dụ trên, ta nhận thấy LZ77 sẽ encode ra các chuỗi có độ dài khác nhau nếu số chuỗi ký tự lặp khác nhau, cụ thể là lặp càng nhiều chuỗi, càng liên tục thì kết quả sau khi LZ77 càng ngắn. Mà CTR là một MODE encrypt giữ nguyên độ dài plaintext. Như vậy ta sẽ brute từng ký tự với một độ lặp nhất định và xem sự thay đổi độ dài của ciphertext, và ta sẽ chọn ký tự nào cho ra ciphertext có độ dài ngắn hơn. Minh họa:  
FLAG = "crypto{thisIsFlag}"  
input = "xxxx"  
=> plaintext = "xxxxcrypto{thisIsFlag}"  
len(zlib(plaintext)) min <=> input = "cccc" => Xác định được byte đầu của FLAG là 'c'  
input2 = 'cxcxcxcx'  
=> plaintext = "cxcxcxcxcrypto{thisIsFlag}"  
len(zlib(plaintext)) min <=> input = "crcrcrcr" => Xác định được phần tiếp theo là 'cr'  

Áp dụng vào code:
```python
import requests
from tqdm import tqdm

def encrypt(plaintext):
    url = "https://aes.cryptohack.org/ctrime/encrypt/"
    url += plaintext.encode().hex() + "/"
    r = requests.get(url)
    js = r.json()
    return js['ciphertext']

flag = ""
len_dict = {}

while True:
    for i in tqdm(range(127,31,-1)):
        payload = flag + chr(i)
        res = encrypt(payload * 5)
        len_dict[chr(i)] = len(res)
    char = min(len_dict, key=lambda x: len_dict[x])
    flag += char
    print(flag)
    len_dict.clear()
```
Flag: *cryto{CRIME_571ll_p4y5}*

### Logon Zero
Before using the network, you must authenticate to Active Directory using our timeworn CFB-8 logon protocol.

Connect at nc socket.cryptohack.org 13399

Attachment: *13399.py*
```python
##!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from os import urandom
from utils import listener

FLAG = "crypto{???????????????????????????????}"


class CFB8:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        IV = urandom(16)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = b''
        state = IV
        for i in range(len(plaintext)):
            b = cipher.encrypt(state)[0]
            c = b ^ plaintext[i]
            ct += bytes([c])
            state = state[1:] + bytes([c])
        return IV + ct

    def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt


class Challenge():
    def __init__(self):
        self.before_input = "Please authenticate to this Domain Controller to proceed\n"
        self.password = urandom(20)
        self.password_length = len(self.password)
        self.cipher = CFB8(urandom(16))

    def challenge(self, your_input):
        if your_input['option'] == 'authenticate':
            if 'password' not in your_input:
                return {'msg': 'No password provided.'}
            your_password = your_input['password']
            if your_password.encode() == self.password:
                self.exit = True
                return {'msg': 'Welcome admin, flag: ' + FLAG}
            else:
                return {'msg': 'Wrong password.'}

        if your_input['option'] == 'reset_connection':
            self.cipher = CFB8(urandom(16))
            return {'msg': 'Connection has been reset.'}

        if your_input['option'] == 'reset_password':
            if 'token' not in your_input:
                return {'msg': 'No token provided.'}
            token_ct = bytes.fromhex(your_input['token'])
            if len(token_ct) < 28:
                return {'msg': 'New password should be at least 8-characters long.'}

            token = self.cipher.decrypt(token_ct)
            new_password = token[:-4]
            self.password_length = bytes_to_long(token[-4:])
            self.password = new_password[:self.password_length]
            return {'msg': 'Password has been correctly reset.'}


listener.start_server(port=13399)

```
AES_CFB:
![Screenshot 2023-10-05 081107](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/1b91527a-2b4c-4aa2-958b-43f0360d2f21)

Bỏ qua sơ đồ trên vì đây là CFB-8.

Ở đây chúng ta sẽ để ý hàm `decrypt` bởi lẽ đọc code, bạn sẽ thấy chúng ta không động được vào hàm `encrypt`:
```python
def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt
```
Hàm này sẽ lấy ra iv và ct từ ciphertext. Khởi tạo giá trị đầu của state là iv. Sau đó, đối với mỗi byte trong ct, ta sẽ thực hiện:
* XOR byte đó với byte đầu tiên của khối mã hóa ECB tạo ra từ state
* Kết quả thu được sẽ là byte đầu của plaintext, ở đây gọi là c
* Cập nhật state bằng cách bỏ đi byte đầu của state và thêm c vào cuối state 


Do `IV = ciphertext[:16]` và `ct = ciphertext[16:]`, chúng ta có thể kiểm soát được 2 thứ này. Đề bài đã gợi ý cho chúng ta về một lỗ hổng trong CFB-8 - ZeroLogon hay CVE-2020-1472. Mục tiêu của lỗ hổng này là làm cho plaintext trả về sẽ toàn là số 0. Vậy ta sẽ làm như nào?

Đầu tiên, ta sẽ truyền vào ciphertext toàn là số 0. Giả sử là 32 số 0. Khi đó:
```
IV = ciphertext[:16] = b'\x00' * 16
ct = ciphertext[16:] = b'\x00' * 16
```
Tiếp theo
```
cipher = AES.new(self.key, AES.MODE_ECB)
pt = b''
state = IV = b'\x00' * 16
```
Vào trong vòng lặp `for i in range(len(ct)):`
```
b = cipher.encrypt(state)[0]
```
Nếu mà bằng một key nào đó, cipher có byte đầu tiên là 0, hay b = 0, ta sẽ có
```
c = b ^ ct[i] = 0 ^ 0 = 0
pt += bytes([c]) hay pt = b'\x00'
state = state[1:] + bytes([ct[i]])
      = b'\x00'*15 + b'\x00'
      = b'\x00'*16 (không đổi)
```
Có thể thấy, state và key đều không đổi trong mỗi vòng lặp, cũng như các bytes của ct đều bằng 0 => ta sẽ thu được `pt = b'\x00' * 16`

Hàm `decrypt` được gọi từ chức năng `reset_password`. Ở đó ta có:
```python
token = self.cipher.decrypt(token_ct)
new_password = token[:-4]
self.password_length = bytes_to_long(token[-4:])
self.password = new_password[:self.password_length]
```
Như trên thì kết quả sẽ trả về `token = b'\x00' * 16`, khi đó
```
new_password = token[:-4] = b'\x00' * 12
self.password_length = bytes_to_long(token[-4:]) = 0
self.password = new_password[:self.password_length]
              = (b'\x00' * 12)[:0]
              = b''
```
Như vậy thì `new_password` sẽ rỗng. Hoàn toàn có thể lấy được flag thông qua option authenticate.

Vậy vấn đề ở đây là làm sao cho `cipher = AES.new(self.key, AES.MODE_ECB)` trả về giá trị có byte đầu là 0. Ở đây ta có option reset_connection:
```python
if your_input['option'] == 'reset_connection':
            self.cipher = CFB8(urandom(16))
            return {'msg': 'Connection has been reset.'}
```

Mỗi khi thực thi nó sẽ trả về một key mới. Vì vậy ta chỉ cần thực hiện option này tới khi nào mà giá trị `cipher = AES.new(self.key, AES.MODE_ECB)`có byte đầu bằng 0.

Áp dụng những lý thuyết trên:
```python
from pwn import *
import json
from tqdm import tqdm

server = "socket.cryptohack.org"
port = 13399
conn = remote(server, port)

payload = b'\x00' * 32

re_conn = json.dumps({"option":"reset_connection"}).encode()
re_pass = json.dumps({"option":"reset_password", "token":payload.hex()}).encode()
au_pass = json.dumps({"option":"authenticate", "password":""}).encode()
conn.recvline()

for _ in tqdm(range(1000)):
    conn.sendline(re_pass)
    conn.recvline()
    conn.sendline(au_pass)
    res = conn.recvline().decode()
    if('flag' in res):
        print(res)
        break
    else:
        conn.sendline(re_conn)
        conn.recvline()
```

Flag: *crypto{Zerologon_Windows_CVE-2020-1472}*

### STREAM OF CONSCIOUSNESS
Talk to me and hear a sentence from my encrypted stream of consciousness.

*source.py*
```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import random


KEY = ?
TEXT = ['???', '???', ..., FLAG]


@chal.route('/stream_consciousness/encrypt/')
def encrypt():
    random_line = random.choice(TEXT)

    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    encrypted = cipher.encrypt(random_line.encode())

    return {"ciphertext": encrypted.hex()}
```

AES_CTR:
![Screenshot 2023-10-04 170632](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/fb5ffb93-b600-4b94-9e39-b7b4e75da436)

Sau khi thử gen ra nhiều kết quả, mình nhận ra có nhiều kết quả trùng nhau. Điều này chứng tỏ, dòng `cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))` tạo ra một khối mã hóa không giống nhau mỗi lần gọi.

Sau khi chạy hẳn mấy trăm request thì mình thấy có tổng cộng 22 đoạn mã. Vì flag bắt đầu bằng `crypto{` nên mình sẽ thử XOR 'crypto{' với từng đoạn mã một để tìm ra 7 bytes đầu của khối mã hóa.
Sau đó, mình sẽ XOR từng khối mã hóa mình có với từng 7 bytes đầu của 22 đoạn mã hóa. Khối mã hóa hợp lệ là khối cho ra nhiều đoạn text có thể `decode()` nhất.

Mình tìm ra nó là `b'\x89d\x82\x04\x1d\xcc\xf4'`

Vấn đề ở đây là tìm ra các kí tự còn lại của flag. Mình sẽ dựa trên 21 đoạn mã còn lại, dựa trên nghĩa của chúng để đoán kí tự tiếp theo, XOR nó với kí tự đã bị mã hóa ở cùng vị trí và thêm vào key. Dần dần, sẽ ra được flag (XOR Crib Attack)


Mình có viết một chương trình để phục vụ điều đó

```python
from pwn import *

global results_list
results_list = ['c044f16c7ca0984105f8b380c1b37b53d802b4b75986d4b5c545a56d625303a9b1cd2d4bcd92a4a5fd3b3812c3e1d606094fe3ece68a', 'de0cfb2479a3d4194dd4edcccafc3753c547e4b3468dd2a5df4aec626b174aade4cc240fc093a6f6f2702012d4e6de435d44efeab2', 'de0bf76879ecbd4d4dd0e2898df17250c202e2b74bc3d2a4d443ec776d121eefd8852b04dc91a5f6e1792d51c8aec8164a45a2ebe8d4da7ac54e71e5c6f15ba9b2852d290a81fd5bd7', 'c043ef2468a29c0c55c1edc08dda3758ce14f1a0598686a5c501ec776d164aa9f0d0241f8e8ee1bbfa72291e80ecce170964a5e2add1c07ad71e6efac6f842a8fb9d2c2d5e9bf3588d39408a0d97ccd8591ebc', 'c80ae62454ec870544ddf8ccc4f47953d902b4bb5bcd', 'c611f03b3d9b9c1405dee19e92', 'dd0cf06178ec96025cc2b49ed8fd7955c500b8f25f8fc7b5d843ab2364074aa7fed73b0edad1e185f66e355ddae6da42', 'd901f06c7cbc874d4dd4b484cce03751c214e7b74bc3d2a4d40db871641a04eff0cb2c4bc08ee1b4f27f2712c2f79b0d465aacafdac5c066960371f183b946b1b68028211f9cfb5a8634', 'de0ce3703dadd40344c2e0958de07a59c70bb4a6478ad5ecc14ca56d715302aef58b', 'ea16fb7469a38f0616c8a1dbdfa02351f415a7a71ad0f9fd8472aa37324706b2', 'c50bf46131ec841f4ad3f58ec1ea281cff0ff1ab0f87c9a29659ec686b1c1deff9ca3f4bcd8fa4b7e1656c5bd4aed210050deae0fa84c667db0772ea87ed47aabcc76a665e9cfa50c8541687068ed9d85515f6cb616bd7c6460452f38a', 'c044f16c7ca0984d49dee7898df66159d91ee0ba468dc1ecd043a8236b1c1eeff6c03c4bc194acf6f17d2f598e', 'cd0bee6864ec830449ddb498c5fa79578b13fcb35bc3efebdc0da066640503a1f685294bda98a2b9fd786c5ad5fdd9024749a2eee3c08e66de0f6aa392f14bb6be8f2b3a1bc8db15856013964888c98a5117ebcb60669ec34c5643f5c1c30c081952e2a9', 'cd16e7776ee1990c4ed8fa8b8df279588b2afdbe438ac8a9c354', 'dd0ce77778ec9c0257c2f19f81b36354c214b4b14e91d4a5d04aa923285302a0e685014bc592a0a2fb796c5fd9fdde0f4f0debe1add0c67bc54e7de294eb47a5bc8c64655e9cfa5091321287489ad0941413fb983923dcdf56567ebdd78b1a161a1cebe2cda0f5998d692f6842d1ce900f4c451d4aa8b2', 'de0ce3703dadd4014ac5b483cbb36354c209f3a10f97ceadc50db86b601d4abcf4c0250ecdddb5b9b3712912d3e19b0e485ff4eae1c8c167c54e7fed82b95baaba9d30291786f35784704cc2009aca9d1419f7886d6edb8a4b1844f4c38d121c1f5fe4e9cfe9a7d890686a3c5edc8b8947444c1b50e6d5a8357198a4b9e3b314748d167b32c60b6b051b147fe64ce7751d3bddba7174611a5f9d13925cb326', 'c817a26d7becbd4d4dd0f0ccccfd6e1cdc0ee7ba0f97c9ecd348ec6a6b531ea7f4853a02ce95b5f7b3556c51c1e09c1708', 'c70bae2454eb980105d6fbccc4fd3748c447d0bd438fdfecd043a823711606a3b1cd2d19898eb5a4f2752b5ad4aed4165d', 'cb11f62454ec830449ddb49fc5fc601cc30ef9fc', 'dd0ce72469a9861f4cd3f8898de77f55c500b4bb5cc3d2a4d059ec776d164abff0d63c4bca9caff1e73c2e5780fad411470dedfaf984cc6b96076af0c6eb41abaf9a6a', 'c010a2677ca2d31905d3f1ccd9fc65528b08e1a603c3c4b9c50da57725100ba1b1c72d4bc09aafb9e179281c', 'c10bf5246dbe9b184191f582c9b37f5ddb17edf2478681a0dd0dae66250402aaff85200e899aa4a2e03c214b80e0d4174c0c']



key = b'\x89d\x82\x04\x1d\xcc\xf4'


def print_xor_results():
    global key
    count = 0
    for j in results_list:
        print(count, xor(key, bytes.fromhex(j)[:len(key)]))
        count += 1

def extend_key():
    global key

    char = input("Nhập vào 1 kí tự: ").strip('\n')
    
    choice = int(input("Chọn một phần tử từ danh sách trên (nhập số): "))
    
    chosen_item = results_list[choice]
    add = xor(char.encode(), bytes.fromhex(chosen_item)[len(key)])
    
    key += add
    print("Key: ", key)

print_xor_results()
while(True):
    extend_key()
    print_xor_results()
```

Sau một hồi ngồi đoán:
```
Key:  Nhập vào 1 kí tự: n
Chọn một phần tử từ danh sách trên (nhập số): 12
Key:  b'\x89d\x82\x04\x1d\xcc\xf4m%\xb1\x94\xec\xad\x93\x17<\xabg\x94\xd2/\xe3\xa6\xcc\xb1-\xcc\x03\x05sj\xcf'
0 b"I shall, I'll lose everything if"
1 b'Why do they go on painting and b'
2 b'Would I have believed then that '
3 b"I'm unhappy, I deserve it, the f"
4 b'And I shall ignore it.n\xc6W\t\x98\xef\x82v.\x12'
5 b'Our? Why our?U\x06\xcc\x90Z\x0fN;\xe6x-/\xbf\n\x12\xf5HWT'
6 b'Three boys running, playing at h'
7 b'Perhaps he has missed the train '
8 b'What a nasty smell this paint ha'
9 b'crypto{k3y57r34m_r3u53_15_f474l}'
10 b"Love, probably? They don't know "
11 b'I shall lose everything and not '
12 b"Dolly will think that I'm leavin"
13 b'Dress-making and Millinery\x01\x15\xe2\x04\x04.'
14 b'These horses, this carriage - ho'
15 b'What a lot of things that then s'
16 b'As if I had any wish to be in th'
17 b"No, I'll go in to Dolly and tell"
18 b'But I will show him.\xe4\xf2P\xe8\xe5\xc1O\x07L\xae\xdeP'
19 b'The terrible thing is that the p'
20 b"It can't be torn out, but it can"
21 b"How proud and happy he'll be whe"
```
Flag: *crypto{k3y57r34m_r3u53_15_f474l}*

## Diffie Hellman
### Diffie-Hellman
1. Alice và Bob thỏa thuận sử dụng chung một số nguyên tố $p$ và căn nguyên thủy $g$
2. Alice chọn một số nguyên bí mật $a$, và gửi cho Bob giá trị $A$ = $g^a$ mod $p$
3. Bob chọn một số nguyên bí mật $b$, và gửi cho Alice giá trị $B$ = $g^b$ mod $p$
4. Alice tính $s$ = $B^a$ mod $p$
5. Bob tính $s$ = $A^b$ mod $p$

Cả Alice và Bob đều có được giá trị chung cuối cùng vì $(g^a)^b$ = $(g^b)^a$ mod $p$. Lưu ý rằng chỉ có $a$, $b$ và $s$ là được giữ bí mật. Tất cả các giá trị khác như $p$, $g$, $A$ và $B$ được truyền công khai. Sau khi Alice và Bob tính được bí mật chung, cả hai có thể sử dụng nó làm khóa mã hóa chung chỉ có hai người biết để gửi dữ liệu trên kênh truyền thông mở.

### Parameter Injection
You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages. Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any discrete logarithm problem.

Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.

Connect at `nc socket.cryptohack.org 13371`

```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0x92832cafd045eb4b070651f025cd8726fd477731b2b2fe4d118f38c1d06cf0d81051c5d86445f86cb65f45fc956cc09c654964a1a41c43c909c0de19e4c227b6f54ce132d7b75fc3b551bf9717050677895ee354f09c9d4074554ac9041d4aba9745802beae88dc5f92395815cd200b4545a07387c160dd7565046d68e1ef3c74b2bcb71b5bcb7569cf43c921e1b394eb121562b55f9fbd898ea688ecb58d796fe35b7cdd76a775e528261d98fa48d5745e89abfecd951f997042969a13bd73b"}
Send to Bob: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0x92832cafd045eb4b070651f025cd8726fd477731b2b2fe4d118f38c1d06cf0d81051c5d86445f86cb65f45fc956cc09c654964a1a41c43c909c0de19e4c227b6f54ce132d7b75fc3b551bf9717050677895ee354f09c9d4074554ac9041d4aba9745802beae88dc5f92395815cd200b4545a07387c160dd7565046d68e1ef3c74b2bcb71b5bcb7569cf43c921e1b394eb121562b55f9fbd898ea688ecb58d796fe35b7cdd76a775e528261d98fa48d5745e89abfecd951f997042969a13bd73b"}
Intercepted from Bob: {"B": "0x603a1ff9bff4f88cbebcc9ffebdc9c3541ad9575cc6e0f9cdb82e802351808d077e64bc8be0fb06224d0fe9d7f2cfae5a3fdf23c8495f4da097b27000b9d4fb532616a9d9a7036fdaf3ddfa5b7ce2d5918696ec4d6baa84fe63f5fce1a01a16b12eab0b30c58a10d4dd8b147bdef206bb3923a440f142d1f448edf540b3145704fcd116069126adf00ae846136a130e8620f1f474ce9f4e49d03e500f8b487db890cdc737fb577a3bb6ef0d84bbecebb108fb25f14891ad838c162560cccd247"}
Send to Alice: {"B": "0x603a1ff9bff4f88cbebcc9ffebdc9c3541ad9575cc6e0f9cdb82e802351808d077e64bc8be0fb06224d0fe9d7f2cfae5a3fdf23c8495f4da097b27000b9d4fb532616a9d9a7036fdaf3ddfa5b7ce2d5918696ec4d6baa84fe63f5fce1a01a16b12eab0b30c58a10d4dd8b147bdef206bb3923a440f142d1f448edf540b3145704fcd116069126adf00ae846136a130e8620f1f474ce9f4e49d03e500f8b487db890cdc737fb577a3bb6ef0d84bbecebb108fb25f14891ad838c162560cccd247"}
Intercepted from Alice: {"iv": "b1ced97538319178619c3fce18d01d6d", "encrypted_flag": "a42b0125c670876f832f2bf6854b86fa2162735de9233d4a4f13dffcc7ea5ee1"}
{"iv": "b1ced97538319178619c3fce18d01d6d", "encrypted_flag": "a42b0125c670876f832f2bf6854b86fa2162735de9233d4a4f13dffcc7ea5ee1"}
```


Bài này cho phép mình đứng giữa cuộc trao đổi của Alice và Bob, tùy ý sửa đổi nội dung được gửi. Sau cùng, Alice sẽ gửi `iv` và `encrypted_flag` cho Bob.

Ý tưởng của mình là gửi B = 1. Khi đó dễ dàng biết được s = B^a mod p = 1^a mod p = 1.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pwn import *
import json


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
    
conn = remote("socket.cryptohack.org", "13371")

A = conn.recvuntil(b"}").decode().strip()
conn.sendline(A[24:].encode())
conn.recvuntil(b'}')
conn.sendline(b'{"B":"0x01"}')
infor = conn.recvuntil(b'}').decode().strip()[39:]
infor = json.loads(infor)

shared_secret = 1
iv = infor['iv']
ciphertext = infor['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))
```
Flag: *crypto{n1c3_0n3_m4ll0ry!!!!!!!!}*

### Export-grade
Alice and Bob are using legacy codebases and need to negotiate parameters they both support. You've man-in-the-middled this negotiation step, and can passively observe thereafter. How are you going to ruin their day this time?

Connect at `nc socket.cryptohack.org 13379`

```
Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
Send to Bob: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}
Intercepted from Bob: {"chosen": "DH1024"}
Send to Alice: {"chosen": "DH1024"}
Intercepted from Alice: {"p": "0xf2639ce2bdb2e67154813bcbda8e5a09ddaa1235c5e76300602e29ada9dd6dfddf36b3c6a676891ddb1462de67cc27a45f84d8720b8bfdcb653c82814397998e84aafca63a8b4ae05d3193e7566173441d505dc3caea006f938d421de7e80748297496436e559fe9c443201de066cd7570a8a40c80a306309dfb4da48277858b", "g": "0x2", "A": "0x30c1c9627d51042c163bac20c6edb2f7680868cee34a2f71ce8c2f7432934622e331a43fc25159dc9383088605a7476f4f773a5a625189d49d832ea79dd04bad5235e847e5a900a5c35f7f6ca1ecaf57dc4c9cd86026decf6848c9439056fad3642ea546d1331a11d66715403052514b1c4c7b874eb5d2e7ccfbdd7ceca4ded"}
Intercepted from Bob: {"B": "0x10435051c95cdd8fa9436ae0bbe49aa2c4e767673257bcc1abee9ea1144aab0c694e07a2353aec72b28a839ecb50a10e93d29b81abdea059e7728b0d349b72476afb6f1993639768ca84da8a02dc1e3f08bcbba647462258230d6d18dafe3f604f187d26675cb9b67d6219ca058e6b6a4b6e322511744316cfcdec2548d0129b"}
Intercepted from Alice: {"iv": "3e4f208eb32be9c0da46bebda95562e2", "encrypted_flag": "9d8744e8dd0dd2c96f6dfc286edb6bda8cd713b838bad94d5b76298f77588685"}
```

Ở đây, Alice cho Bob chọn kiểu Diffie-Hellman, sau đó sử dụng nó để trao đổi khóa. Dữ liệu trả về là các khóa công khai.
Mình sẽ bắt Bob chỉ được chọn DH64. Khi đó, các khóa bí mật sẽ chỉ là 64-bit. Mình có thể dễ dàng giải bài toán logarith rời rạc để tìm ra chúng.

Trước hết, sử dụng pwntool để lấy dữ liệu từ server
```python
from pwn import *
import json

conn = remote("socket.cryptohack.org", "13379")

conn.recvuntil(b'Send to Bob:')
conn.sendline(b'{"supported": ["DH64"]}')
conn.recvline(b'Send to Alice:')
conn.sendline(b'{"chosen": "DH64"}')

Alice = json.loads(conn.recvline().decode().strip()[39:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
infor = json.loads(conn.recvline().decode().strip()[24:])

p = int(Alice['p'], 16)
g = int(Alice['g'], 16)
A = int(Alice['A'], 16)
B = int(Bob['B'], 16)

print(f"p = {p}\ng = {g}\nA = {A}\nB = {B}\ninfor = {infor}")
```

Ta có $B$ = $g^b$ mod $p$. Mình sẽ sử dụng logarith rời rạc trong sagemath để tính b.

```
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 9.5, Release Date: 2022-01-30                     │
│ Using Python 3.10.6. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: G = Integers(16007670376277647657)
sage: B = G(405929529387091256)
sage: g = G(2)
sage: b = B.log(g)
sage: b
856295849221861333
```

Tìm ra b thì dễ dàng tính được s qua công thức $s$ = $A^b$ mod $p$ để giải mã flag
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
    

p = 16007670376277647657
g = 2
A = 12703859298456983579
B = 405929529387091256
infor = {'iv': '2ec5ac64fba6a1667aacb2ebdaaa895a', 'encrypted_flag': '7842eaf213d949c9255c48392cd8eab1e8793ae6c75b3ca7b9140407bbf90067'}

b = 856295849221861333

shared_secret = pow(A,b,p)
iv = infor['iv']
encrypted_flag = infor['encrypted_flag']

print(decrypt_flag(shared_secret, iv, encrypted_flag))
```
Flag: *crypto{d0wn6r4d35_4r3_d4n63r0u5}*

### Static Client
You've just finished eavesdropping on a conversation between Alice and Bob. Now you have a chance to talk to Bob. What are you going to say?

Connect at `nc socket.cryptohack.org 13373`

```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xedcf481fd750b2fc7ee5daa95b90f42657e071ea39421bc56c2fdfc62a893e3a1fa1ebdd29f60e5ce51d313d0774ed061a35b0daee81a4ef4b8ee3748643bb61b805e60704e79b8567c388f1b6c5ed0c8bb00b717f0737e4fef99a18f8223c252da15f01951a3fa4be570035d2d66aa7a15d7f8aba28fb997cdbf2dbfca3f61f53b94547ce20c702e6d8567e4ff4354ff205028cf75924e8e526082384ed2ee29e63e01d5012007fe180c68a986e186be6ed9b92736955c3fab5d6739b1cdc4a"}
Intercepted from Bob: {"B": "0x8d79b69390f639501d81bdce911ec9defb0e93d421c02958c8c8dd4e245e61ae861ef9d32aa85dfec628d4046c403199297d6e17f0c9555137b5e8555eb941e8dcfd2fe5e68eecffeb66c6b0de91eb8cf2fd0c0f3f47e0c89779276fa7138e138793020c6b8f834be20a16237900c108f23f872a5f693ca3f93c3fd5a853dfd69518eb4bab9ac2a004d3a11fb21307149e8f2e1d8e1d7c85d604aa0bee335eade60f191f74ee165cd4baa067b96385aa89cbc7722e7426522381fc94ebfa8ef0"}
Intercepted from Alice: {"iv": "1249b18ac1720c3ecf0335bb3b6a3ce7", "encrypted": "9b136c4de5bcf1618ec9ab6ffa05fa87153508fc248932fd96aee39f5aadff91"}
Bob connects to you, send him some parameters: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xedcf481fd750b2fc7ee5daa95b90f42657e071ea39421bc56c2fdfc62a893e3a1fa1ebdd29f60e5ce51d313d0774ed061a35b0daee81a4ef4b8ee3748643bb61b805e60704e79b8567c388f1b6c5ed0c8bb00b717f0737e4fef99a18f8223c252da15f01951a3fa4be570035d2d66aa7a15d7f8aba28fb997cdbf2dbfca3f61f53b94547ce20c702e6d8567e4ff4354ff205028cf75924e8e526082384ed2ee29e63e01d5012007fe180c68a986e186be6ed9b92736955c3fab5d6739b1cdc4a"}
Bob says to you: {"B": "0x8d79b69390f639501d81bdce911ec9defb0e93d421c02958c8c8dd4e245e61ae861ef9d32aa85dfec628d4046c403199297d6e17f0c9555137b5e8555eb941e8dcfd2fe5e68eecffeb66c6b0de91eb8cf2fd0c0f3f47e0c89779276fa7138e138793020c6b8f834be20a16237900c108f23f872a5f693ca3f93c3fd5a853dfd69518eb4bab9ac2a004d3a11fb21307149e8f2e1d8e1d7c85d604aa0bee335eade60f191f74ee165cd4baa067b96385aa89cbc7722e7426522381fc94ebfa8ef0"}
Bob says to you: {"iv": "aae2cdd8d2547a1e0c640b7429e6596b", "encrypted": "7c73ce982f6d7416b76373378fc90860f52517a4eb43e71df63975e1d24aae04e3a3e874fee57dde00f17b3761ef178577b5680d2460a53c8d3df06db0b4e56bd626fc3b53752a72b5dfc67bf043e2c9"}
```
Khác với trước, giờ mình có thể gửi yêu cầu tới Bob, rồi Bob sẽ trả về *B*, *iv* và *encrypted_flag*. 

Ở đây, ta biết *shared_secret* của Bob sẽ được tính bằng công thức $s$ = $A^b$ mod $p$. Vậy, mình có thể gửi cho Bob g = A. Khi đó, khóa B gửi đi của B sẽ trở thành $B$ = $g^b$ mod $p$ = $A^b$ mod $p$ = $s$. Nếu số bí mật b của Bob không đổi (Đề bài là static client) thì $s$ ở đây chính là *shared_secret* ban đầu khi trao đổi khóa với Alice.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pwn import *
import json


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
    
conn = remote("socket.cryptohack.org", "13373")

Alice = json.loads(conn.recvline().decode().strip()[24:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
info = json.loads(conn.recvline().decode().strip()[24:])
payload = {"p" : Alice['p'], "g" : Alice['A'], "A": "0xff"}
conn.sendline(json.dumps(payload).encode())

s = conn.recvline().decode().strip()[71:-2]
conn.recvline()


shared_secret = int(s, 16)
iv = info['iv']
ciphertext = info['encrypted']

print(decrypt_flag(shared_secret, iv, ciphertext))

```

Flag: *crypto{n07_3ph3m3r4l_3n0u6h}*

### Static Client 2
Bob got a bit more careful with the way he verifies parameters. He's still insisting on using the p and g values provided by his partner. Wonder if he missed anything?

Connect at `nc socket.cryptohack.org 13378`

```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xb2137c78247c9741b7b7e163fa3591a71e22864b5c50d7fe7c163e2223f537ae743ab81e6c4e1c891ed872dffd5ca77544fb7c0d730844203ce7e2defec6fa89b13ce51ad4244deac72ce97776e6c2bc843268023eb0737b8de132445eabcbf133b5d13cd55670142243ee8b8f42d84cc3f156c3bfaf897964680a6ae2c2ee74e236f06f52b405e90becea8f52c9cbabcb9179750089e7d6d773867c24e9c14971f2998c34b14364b13d5e19fc31854435a6f5b4045190af31ad5f7e4f90c0e7"}
Intercepted from Bob: {"B": "0xd0d69585c6586c3b1a23e04245826be6db4aed1c9bc70f7110a30165ca878d31434aa357c2bd26d3c398284a17319504e1aeead141234afeb57dfef11417fdec44b21cea83920f300f4e0c3fb573a895371b24652c5e6ea0539b7719f0f966ac7adb9a292cc49f4d8b39560e02fa82aab3c273cc7df512a80e2de6f0e8840c00554f09460eaa2e221173a9ca13182d4e1342b1e54965e16ca5fc23b1aae80aedc7fb80e1aa9be8b0274812676e8e570e1abf65eea0c49f18794a5afba975c7c7"}
Intercepted from Alice: {"iv": "0e0c4321b016de2eb36b01d2df93ed75", "encrypted": "2a1867ceba61e4b84c6f02b48628c75e33a068ea464594c4317abf28283f2d44dc75fc95881682aafce2dc98b39a555c"}
Bob connects to you, send him some parameters: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g":"0xb2137c78247c9741b7b7e163fa3591a71e22864b5c50d7fe7c163e2223f537ae743ab81e6c4e1c891ed872dffd5ca77544fb7c0d730844203ce7e2defec6fa89b13ce51ad4244deac72ce97776e6c2bc843268023eb0737b8de132445eabcbf133b5d13cd55670142243ee8b8f42d84cc3f156c3bfaf897964680a6ae2c2ee74e236f06f52b405e90becea8f52c9cbabcb9179750089e7d6d773867c24e9c14971f2998c34b14364b13d5e19fc31854435a6f5b4045190af31ad5f7e4f90c0e7", "A":"0x02"}
Bob says to you: {"error": "That g value looks mighty suspicious"}
```

Trông cũng giống bài trước, tuy nhiên cách làm đã được fix. Vậy chúng ta phải nghĩ ra cách khác. Ở đây sẽ là dựa vào $p$, hay chính xác là hướng đến một $p$ là **smooth number**.

Về cơ bản, một số n-smooth number là số có các thừa số nguyên tố đều nhỏ hơn hoặc bằng n. Cơ mà để làm gì?

Trong bài toán Logarit rời rạc, có thuật toán gọi là Pohlig-Hellman. Thuật toán này khi được sử dụng với các nhóm smooth (smooth p) có thể dễ dàng giải bài toán logarit rời rạc. Điều kiện ở đây là smooth p + 1 phải là số nguyên tố.

https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm

Vậy ở đây ta muốn tìm một p có thể viết dưới dạng tích của các số nguyên tố nhỏ (do đó tạo ra nhiều nhóm con nhỏ) để sau này dễ dàng phân tích thành thừa số nguyên tố. Một số phương pháp mà người ta có thể thử là: 
* Primorial: Viết số p-smooth là tích của mọi số nguyên tố liên tiếp (tức là 2 * 3 * 5 * 7). *
* Factorial: Tạo tích của các số thừa số nhỏ tăng theo lũy thừa nào đó bằng cách tính tích của mọi số (tức là 2 * 3 * 4 * 5 ...) cho đến khi bạn tìm thấy p-smooth như mong muốn. Lưu ý: hãy nghĩ rằng kết quả cuối cùng sẽ chỉ chứa các thừa số nguyên tố. Ví dụ: 4 không phải là số nguyên tố nhưng có thể được viết là 2^2 trong đó cơ số 2 của bạn là số nguyên tố (điều này đề cập đến định lý cơ bản của số học: Mọi số nguyên lớn hơn 1 là số nguyên tố hoặc có thể được viết dưới dạng tích các thừa số nguyên tố của nó ).

Ở đây mình sẽ chọn cách thứ 2 vì nó sẽ nhanh hơn. Sau đó mình sử dụng số nguyên tố p-smooth + 1. Bằng cách này, khi Bob gửi cho mình B, đó sẽ là 1 số mà ta hoàn toàn có thể tính ngược lại b thông qua Logarith rời rạc sử dụng Pohlig-Hellman

```python
from pwn import *
import json
from Crypto.Util.number import isPrime

conn = remote("socket.cryptohack.org", 13378)

def get_nsmooth(n):
    i = 2
    p_smooth = 1
    for _ in range(1000):
        if p_smooth < n or not isPrime(p_smooth + 1):
            p_smooth *= i
            i += 1
        else:
            break

    if(p_smooth > p and isPrime(p_smooth + 1)):
        return p_smooth
    else:
        return -1

Alice = json.loads(conn.recvline().decode().strip()[24:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
info = json.loads(conn.recvline().decode().strip()[24:])
p = int(Alice['p'], 16)
    
p_smooth = get_nsmooth(p)
print(f"p_new = {p_smooth + 1}")

payload = {'p': f'{hex(p_smooth + 1)}', 'g': '0x02', 'A': Alice['A']}
payload = json.dumps(payload).encode()

conn.sendline(payload)
B = conn.recvline().decode().strip()[71:-2]
B = int(B, 16)
print(f"B = {B}\ng = 2\nA = {int(Alice['A'], 16)}\np = {int(Alice['p'], 16)}\niv = {info['iv']}\nencrypted = {info['encrypted']}")
```

Sử dụng B thu được và g để tìm ra b sử dụng sagemath discrete_log
```
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 9.5, Release Date: 2022-01-30                     │
│ Using Python 3.10.6. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: p_new = 211610334721925248295571704107762986587946391083761306765577830155780903308444721678617883710831709407225912
....: 41807108382859295872641348645166391260040395583908986502774347856154314632614857393087562331369896964916313777278292
....: 96520278062630483972525432308332124593592034544576046931571668880818138608393573770528435339586952086174215612749638
....: 50907436023090498209349171347554618730129457049389551327246630758804369959040936547093495526569656105465403720484210
....: 26608925808493978164019986593442564905462745669412326023291812269608558332157759989142549649265359278848084868920655
....: 698461242425344000000000000000000000000000000000000000000000000000000000000000000000000000001
....: B = 1600729160738925969058103184728822977949974564637406354038540199676215526297798147821613486406916540653800683149
....: 59785767853439240452801998048915395942179651207760147591350824251210426090210055280816549042813602445078273544574475
....: 46944225866080782042852597289847705024436037858968761035090575707827446431870582128988960557196060711830455235473950
....: 82899280410250574666923154481615031969792114266918194572453521149320090704020682099779986161228831722308894105906923
....: 01951911223761282657222638891640442839658757635514445826007981483807580104208867763910610010473053646720408322053462
....: 71901253494378160709499034229971447322456128744848304514349631590285459515180345452750189
....: g = 2
sage: G = Integers(p_new)
sage: b = discrete_log(G(B), G(g))
sage: b
1919572943691512325783103720167834163677411292709378502535498859989993544026380143919501049584589675317643993465536543895780854808442293000014297210200227069779643763121704810281976733978781152126062646602812482025293137787739116693980988513420732289020477701182639042794562638875881378349771734410919106042203493166198706573467903966100368713572415175654342828296086659529676015616513470105470901979846373335352656586302787870238998914215908919919219987614105175
```
Có thể thấy, dù B rất dài nhưng nhờ có số p như trên, ta hoàn toàn có thể lấy lại được b nhanh chóng.

Cuối cùng, sử dụng A, b, p để tính ra flag
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
    

A = 2052730840778522725669668850809100712528424084675319406137452322054730931900872505650905496995116498865694271228892449276411398359180769611581068217937446024620680285675403816343216083830861126241167102300716748426835012242070425228077263131787826383516688770855625484564656277372321822956964293646818485386901681307133741734402033783689740031735720766591298216351519474361285666397800101752787565713771157365592038104615137119676266163984114479946897453459568557
b = 1919572943691512325783103720167834163677411292709378502535498859989993544026380143919501049584589675317643993465536543895780854808442293000014297210200227069779643763121704810281976733978781152126062646602812482025293137787739116693980988513420732289020477701182639042794562638875881378349771734410919106042203493166198706573467903966100368713572415175654342828296086659529676015616513470105470901979846373335352656586302787870238998914215908919919219987614105175
p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
iv = 'fb884e8e30e911a3bfbe45bce9f72967'
encrypted = '7ad7f3c9b9ecbd329b2f5bc7d85f459a8f7b07b10670648dd22895fb66bbaf0ae3e5279a8b5fe917192c57641fbd3acd'

print(decrypt_flag(pow(A,b,p), iv, encrypted))
```
Flag: *crypto{uns4f3_pr1m3_sm4ll_oRd3r}*


### Additive
Alice and Bob decided to do their DHKE in an additive group rather than a multiplicative group. What could go wrong?

Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.

Connect at `nc socket.cryptohack.org 13380`
```
Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0xe934888a059a8395fc4c28b8fb79aeac618a691f50b185fbc75a53223985758c8a23fa3112b6d75c483179f933f19cbc5806b824b542c2b70908b5e48f2d389839236f5bf8f9859bba758de6fa6faeb8992ce576051689f38dd06a2b8ea59ca2a8ab4562166a5f96a4870d49a7b3ba5f3474c81831fa1920ee9071385a226849da3106258b36e6ceea4b09ddb18d66860f471c202fed3646a59f0c6dab8c18390d334e4c2222272437fcd215512728364ecf11199827178c436917a713812683"}
Intercepted from Bob: {"B": "0xf7702e78b6af7646301422ff13e9395368830173a6df07005553b6d2862a45470fde3284e7f52371b2120349fcce20d425a9bd12715da9a0901e2cdf27e0412c5fa45f9b0854c570633decd511b3da61eb088398ed69f3d51274e9f870d0a52be2ce4cb1fd3187d27509a64c77bdf598e840d5672b7e96a96ec4b2dc103dd82d3c58a0922051b088020c7f40c6446ec4f7baf582d87e1b54d51f9d25ce46166084b0ec0fbea3635858516b0f9effa4f50d160d86af12af7d689c2fda50c5369d"}
Intercepted from Alice: {"iv": "2309518f3a14126e348581233d705be1", "encrypted": "447f036f950f6d61a4ea199ca0b85f825b9e27699b1dda8be8d71b499a51bd0a3f7e4a9db3c889293afccf1bbf0f040f"}
```
Chương trình cho chúng ta đủ thông tin công khai và không cho input gì hết.

Theo như mình tìm hiểu thì bình thường DH sử dụng Multiplicative group. Nếu sử dụng Additive group, nó sẽ thành kiểu như này:
1. Alice và Bob thỏa thuận sử dụng chung một số nguyên tố $p$ và căn nguyên thủy $g$
2. Alice chọn một số nguyên bí mật $a$, và gửi cho Bob giá trị $A$ = $g*a$ mod $p$
3. Bob chọn một số nguyên bí mật $b$, và gửi cho Alice giá trị $B$ = $g*b$ mod $p$
4. Alice tính $s$ = $B*a$ mod $p$
5. Bob tính $s$ = $A*b$ mod $p$

Ơ thế dễ vl :v code thôi
```python
from pwn import *
import json
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

conn = remote("socket.cryptohack.org", 13380)

Alice = json.loads(conn.recvline().decode().strip()[24:])
Bob = json.loads(conn.recvline().decode().strip()[22:])
info = json.loads(conn.recvline().decode().strip()[24:])


B = int(Bob['B'], 16)
g = 2
p = int(Alice['p'], 16)
A = int(Alice['A'], 16)
iv = info['iv']
encrypted = info['encrypted']

b = B*int(inverse(g, p))
s = A*b % p

print(decrypt_flag(s, iv, encrypted))
```

Flag: *crypto{cycl1c_6r0up_und3r_4dd1710n?}*

## Elliptic Curve
**Lý thuyết**\
https://nhattruong.blog/2022/03/06/khai-niem-duong-cong-eliptic/\
https://nhattruong.blog/2022/03/06/chuan-mat-ma-khoa-cong-khai-tren-duong-cong-elliptic-elliptic-curve-cryptography/

**EC Diffie Hellman**\
Trước tiên ta chọn một số nguyên $p$ lớn, với $p$ là số nguyên tố (nếu sử dụng đường cong Elliptic Zp) hoặc $p$ có dạng $2^m$(nếu chọn đường cong GF($2^m$)), và chọn 2 tham số $a$, $b$ tương ứng để tạo thành nhóm $E\_p(a,b)$. Ta gọi $G$ là điểm cơ sở của nhóm nếu tồn tại một số nguyên $n$ sao cho $nG$=0. Số nguyên $n$ nhỏ nhất như vậy được gọi là hạng của $G$.

Trong trao đổi khóa EC Diffie-Hellman, ta chọn một điểm $G$ có hạng $n$ lớn, và giao thức trao đổi khóa giữa Alice và Bob tiến hành như sau:

1. Alice chọn một số $n\_A$ < $n$ và giữ bí mật số $n\_A$ này. Sau đó trong $E\_p(a,b)$ Alice tính $Q\_A$ = $n\_AG$ và gửi cho Bob.
2. Tương tự Bob chọn một số bí mật $n\_B$, tính $Q\_B$ và gửi $Q\_B$ cho Alice.
3. Alice tạo khóa phiên bí mật là $S$ = $n\_A Q\_B$ =$n\_An\_BG$
4. Bob tạo khóa phiên bí mật là $S$ = $n\_B Q\_A$ = $n\_An\_BG$ (nhóm Abel có tính giao hoán) giống với khóa của Alice.

Trudy có thể chặn được $Q\_A$ và $Q\_B$, tuy nhiên chỉ có thể tính được điều này là bất khả thi như ta đã thấy ở phần trên.

Chú ý: khóa phiên $S$ là một điểm trong đường cong Elliptic, để sử dụng khóa này cho mã hóa đối xứng như DES hay AES, ta cần chuyển $S$ về dạng số thường.

#### Smooth Criminal

Spent my morning reading up on ECC and now I'm ready to start encrypting my messages. Sent a flag to Bob today, but you'll never read it.

Attachments: _source.py_

```python
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# The point at infinity (origin for the group law).
O = 'Origin'

FLAG = b'crypto{??????????????????????????????}'


def check_point(P: tuple):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P: tuple, Q: tuple):
    # based of algo. in ICM
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P: tuple, n: int):
    # based of algo. in ICM
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


def gen_shared_secret(Q: tuple, n: int):
    # Bob's Public key, my secret int
    S = double_and_add(Q, n)
    return S.x


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data


# Define the curve
p = 310717010502520989590157367261876774703
a = 2
b = 3

# Generator
g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = Point(g_x, g_y)

# My secret int, different every time!!
n = randint(1, p)

# Send this to Bob!
public = double_and_add(G, n)
print(public)

# Bob's public key
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = Point(b_x, b_y)

# Calculate Shared Secret
shared_secret = gen_shared_secret(B, n)

# Send this to Bob!
ciphertext = encrypt_flag(shared_secret)
print(ciphertext)
```

_output.txt_

```
Point(x=280810182131414898730378982766101210916, y=291506490768054478159835604632710368904)

{'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}
```

Ở đây, bậc của generator là smooth, nên chúng ta có thể tính được logarit rời rạc của mọi điểm trên đường cong sử dụng Pohlig-Hellman.

Pohlig-Hellman:

* Suppose we're solving the equation n\*P = Q where P and Q are points on a elliptic curve
* Since the curve is modular, there are only so many values that n\*P can take on before getting wrapped around. Let's call the total number of these values ord(P).
* Using an algorithm called Pollard's Rho, the time it takes to compute the ECDLP will be on the order of sqrt(ord(P))
* Say ord(P) has prime factors p1, p2, ... pn. The Pohlig Hellman algorithm lets us break the big ECDLP into a bunch of smaller ECDLP's with orders of p1, p2, ... pn. The answers to each of these mini-ECDLP's are then combined using the Chinese Remainder Theorem to give us n.
* Since the running time of this algorithm is on the order of sqrt(p1) + sqrt(p2) + ... + sqrt(pn), this is a lot faster if ord(P) can be factored into small primes

Dựa trên lý thuyết trên, có thể viết lại thuật toán này như sau:

```python
def PolligHellman(P,Q):
	zList = list()
	conjList = list()
	rootList = list()
	n = P.order()
	factorList = n.factor()
	for facTuple in factorList:
		P0 = (ZZ(n/facTuple[0]))*P
		conjList.append(0)
		rootList.append(facTuple[0]^facTuple[1])
		for i in range(facTuple[1]):
			Qpart = Q
			for j in range(1,i+1):
				Qpart = Qpart - (zList[j-1]*(facTuple[0]^(j-1))*P)
			Qi = (ZZ(n/(facTuple[0]^(i+1))))*Qpart
		zList.insert(i,discrete_log(Qi,P0,operation='+'))
		conjList[-1] = conjList[-1] + zList[i]*(facTuple[0]^i)
	return crt(conjList,rootList)
```

(Tham khảo paper `Weak Curves In Elliptic Curve Cryptography`)

Tuy nhiên, với sagemath, thực ra hàm discrete\_log trong EllipticCurve đã sử dụng Pohlig-Hellman. Vì vậy, với những bài như này mình có thể sử dụng trực tiếp luôn

```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


msg = {'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}

p = 310717010502520989590157367261876774703
a = 2
b = 3

#When p is prime, Zmod and GF is the same
E = EllipticCurve(Zmod(p), [a,b])
# Generator point
G = E(179210853392303317793440285562762725654, 105268671499942631758568591033409611165)

# Bob's public key
B = E(272640099140026426377756188075937988094, 51062462309521034358726608268084433317)

# Our public key
A = E(280810182131414898730378982766101210916, 291506490768054478159835604632710368904)

# Compute Bob's private key
b = G.discrete_log(B)
shared_secret = (A * b).xy()[0]
iv = msg['iv']
ciphertext = msg['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))

```

Flag: _crypto{n07\_4ll\_curv3s\_4r3\_s4f3\_curv3s}_

#### Curveball

Here's my secure search engine, which will only search for hosts it has in its trusted certificate cache.

Connect at `socket.cryptohack.org 13382`

Attachment: _13382.py_

```python
#!/usr/bin/env python

import fastecdsa
from fastecdsa.point import Point
from utils import listener


FLAG = "crypto{????????????????????????????????????}"
G = fastecdsa.curve.P256.G
assert G.x, G.y == [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5]


class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my secure search engine backed by trusted certificate library!\n"
        self.trusted_certs = {
            'www.cryptohack.org': {
                "public_key": Point(0xE9E4EBA2737E19663E993CF62DFBA4AF71C703ACA0A01CB003845178A51B859D, 0x179DF068FC5C380641DB2661121E568BB24BF13DE8A8968EF3D98CCF84DAF4A9),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.bing.com': {
                "public_key": Point(0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.gchq.gov.uk': {
                "public_key": Point(0xDEDFC883FEEA09DE903ECCB03C756B382B2302FFA296B03E23EEDF94B9F5AF94, 0x15CEBDD07F7584DBC7B3F4DEBBA0C13ECD2D2D8B750CBF97438AF7357CEA953D),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            }
        }

    def search_trusted(self, Q):
        for host, cert in self.trusted_certs.items():
            if Q == cert['public_key']:
                return True, host
        return False, None

    def sign_point(self, g, d):
        return g * d

    def connection_host(self, packet):
        d = packet['private_key']
        if abs(d) == 1:
            return "Private key is insecure, certificate rejected."
        packet_host = packet['host']
        curve = packet['curve']
        g = Point(*packet['generator'])
        Q = self.sign_point(g, d)
        cached, host = self.search_trusted(Q)
        if cached:
            return host
        else:
            self.trusted_certs[packet_host] = {
                "public_key": Q,
                "curve": "secp256r1",
                "generator": G
            }
            return "Site added to trusted connections"

    def bing_it(self, s):
        return f"Hey bing! Tell me about {s}"

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        host = self.connection_host(your_input)
        if host == "www.bing.com":
            return self.bing_it(FLAG)
        else:
            return self.bing_it(host)


listener.start_server(port=13382)

```

Đường cong Elliptic P-256: https://neuromancer.sk/std/nist/P-256

Chương trình sẽ bắt chúng ta truyền vào JSON bao gồm các trường `host`, `private_key`, `curve` và `generator`. Chúng ta được biết các thông tin công khai của 3 domain trong đó có `public_key`. Khi chúng ta truyền input, `public_key` sẽ được tính bằng cách nhân `private_key` với `generator`, nếu trùng với `public_key` của domain `www.bing.com` thì sẽ trả về FLAG. Vậy thì chúng ta chỉ cần tìm ra `private_key` của nó là có thể có được FLAG. Tuy nhiên vì đây là Đường cong Elliptic P-256, việc sử dụng logarit rời rạc dường như là bất khả thi. Vậy phải làm như nào?

Vì đề bài là "CurveBall", chúng ta có thể liên tưởng tới một lỗ hổng có tên y hệt, và nó là CVE-2020-0601. Lỗ hổng này xảy ra ở khi ta được truyền vào phần tử sinh G và nó không được check xem có giống với phần tử sinh gốc của hệ thống sử dụng Elliptic Curve (Và hệ thống của chúng ta cũng đang như vậy). Khi đó, attacker có thể truyền vào $d'$ = $1$ và $G'$ = $Q$. Điều này làm attacker dễ dàng bypass khâu check publickey vì nó vẫn sẽ thỏa mãn do $Q'$ = $d'G'$ = $Q$.

Tuy nhiên, có một vấn đề là việc cho $d$ = $1$ đã bị filter. Chúng ta sẽ có một số cách để bypass:

* Gửi $d$ = $i$ và $Q'$ = $i^{-1}Q$ với $i^{-1}$ = `inverse(i, E.order())`
* Gửi $d$ = $i^{-1}$ và $Q'$ = $iQ$ với $i^{-1}$ = `inverse(i, E.order())`
* Gửi $d$ = $x+1$ và $Q'$ = $Q$ với `x = Q.order() + 1`

Giải thích cho cách thứ 3 thì thì Q.order() là số x đầu tiên thỏa mãn`x*Q=0`. Vì vậy, `(x+1)*Q = Q`

Áp dụng vào code, mình ra được flag:

```python
from sage.all import *
from pwn import *
import json
from Crypto.Util.number import *

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


Q = E((0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A))

conn = remote('socket.cryptohack.org', '13382')
conn.recvline()
'''
#Method 1
d = 2
Q = Q*int(inverse(2,E.order()))

#Method 2
d = int(inverse(2, E.order()))
Q = 2*Q
'''
# Method 3
d = int(Q.order() + 1)

payload = {"host": "www.bing.com","private_key": d,"curve": "secp256r1","generator": list(map(int,(Q.xy())))}
payload = (json.dumps(payload)).encode()

conn.sendline(payload)
print(conn.recvline())
```

Flag: _crypto{Curveballing\_Microsoft\_CVE-2020-0601}_

#### ProSign 3

This is my secure timestamp signing server. Only if you can produce a signature for "unlock" can you learn more.

Connect at `socket.cryptohack.org 13381`

Attachment: _13381.py_

```python
#!/usr/bin/env python

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa.ecdsa import Public_key, Private_key, Signature, generator_192
from utils import listener
from datetime import datetime
from random import randrange

FLAG = "crypto{?????????????????????????}"
g = generator_192
n = g.order()


class Challenge():
    def __init__(self):
        self.before_input = "Welcome to ProSign 3. You can sign_time or verify.\n"
        secret = randrange(1, n)
        self.pubkey = Public_key(g, g * secret)
        self.privkey = Private_key(self.pubkey, secret)

    def sha1(self, data):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.digest()

    def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        current = f"{m}:{n}"
        msg = f"Current time is {current}"
        hsh = self.sha1(msg.encode())
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
        return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}

    def verify(self, msg, sig_r, sig_s):
        hsh = bytes_to_long(self.sha1(msg.encode()))
        sig_r = int(sig_r, 16)
        sig_s = int(sig_s, 16)
        sig = Signature(sig_r, sig_s)

        if self.pubkey.verifies(hsh, sig):
            return True
        else:
            return False

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'sign_time':
            signature = self.sign_time()
            return signature

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            r = your_input['r']
            s = your_input['s']
            verified = self.verify(msg, r, s)
            if verified:
                if msg == "unlock":
                    self.exit = True
                    return {"flag": FLAG}
                return {"result": "Message verified"}
            else:
                return {"result": "Bad signature"}

        else:
            return {"error": "Decoding fail"}


listener.start_server(port=13381)

```

Có thể thấy, đây là code minh họa cho việc ứng dụng Elliptic Curve vào chữ ký số (ECDSA).

Các bước khởi tạo chữ ký số trong thuật toán ECDSA bao gồm:

1. Tạo ra cặp khóa công khai và khóa bí mật cho người dùng: Để thực hiện điều này, ta cần tạo ra một đường cong elliptic và một điểm gốc trên đường cong. Sau đó, sử dụng thuật toán Diffie-Hellman, ta tính được khóa công khai và khóa bí mật cho người dùng.
2. Tạo ra thông điệp cần ký: Đây là thông tin cần được ký và gửi đi.
3. Tính toán giá trị băm của thông điệp: Sử dụng một hàm băm như SHA-256 hoặc SHA-512, ta tính toán được giá trị băm của thông điệp cần ký.
4. Tạo chữ ký số: Đầu tiên, ta tạo một số ngẫu nhiên gọi là $k$. Sau đó, tính toán đường cong elliptic $P = k \* G$, trong đó G là base point trên đường cong. Tiếp theo, tính toán giá trị $r = xP (mod n),$ trong đó $xP$ là hoành độ của điểm P trên đường cong elliptic và n là order của base point G. Sau đó, tính toán giá trị $s = k^{-1} \* (hash + d\*r) (mod n)$, trong đó $d$ là khóa bí mật của người ký và hash là giá trị băm của thông điệp cần ký. Cuối cùng, chữ ký số là cặp giá trị $(r,s).$
5. Gửi thông điệp và chữ ký số đến người nhận.

Sau khi nhận được thông điệp và chữ ký số, người nhận sẽ thực hiện quá trình xác thực để kiểm tra tính hợp lệ của chữ ký số.

Quá trình xác nhận (verification) chữ ký số trong ECDSA bao gồm các bước sau:

1. Nhận được thông điệp gốc M, chữ ký số $(r,s)$ và khóa công khai của người ký ECDSA (Q).
2. Tính băm SHA-1 hoặc SHA-256 của thông điệp gốc M, đây là giá trị h.
3. Tính $w = s^{-1} mod n$, với n là order của base point G trên đường cong elliptic, tương ứng với khóa cá nhân của người ký ECDSA.
4. Tính $u1 = hash.w mod n$ và $u2 = r.w mod n.$
5. Tính điểm $W = u1_G + u2_Q$ trên đường cong elliptic. Nếu W = O (điểm vô cùng), thì chữ ký số không hợp lệ.
6. Tính $r' = x(W) mod n$. Nếu $r'$ khác với giá trị $r$ được gửi kèm theo thì chữ ký số không hợp lệ.
7. Nếu $r'$ bằng với giá trị $r$ được gửi kèm theo, thì chữ ký số là hợp lệ. Ngược lại, nếu $r'$ khác với $r$ thì chữ ký số không hợp lệ.

Quá trình xác nhận chữ ký số trong ECDSA sẽ giúp cho người nhận thông điệp có thể đảm bảo rằng thông điệp đó được gửi từ người ký đã được xác thực và không bị sửa đổi trên đường truyền.

Quay lại với challenge của chúng ta, có lỗ hổng xảy ra khi chúng ta chọn số ngẫu nhiên $k$:

```python
def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        current = f"{m}:{n}"
        msg = f"Current time is {current}"
        hsh = self.sha1(msg.encode())
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
        return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}
```

Có thể thấy, số $k$ được lấy ngẫu nhiên trong khoảng từ 1 tới n. Đáng nói ở đây là ở dòng 2 ta có `n = int(now.strftime("%S"))` vì vậy n đã không còn là `g.order()` nữa mà là một số khá nhỏ, chỉ nằm trong khoảng 1 tới 59. Để ý thêm, $s = k^{-1} \* (hash + d\*r) (mod n)$. Ta có thể gọi `sign_time` để lấy được `hash`, `r`, `s` và bruteforce `k` để tính ngược lại `d`, hay `secret`. Khi đã có `secret`, ta hoàn toàn có thể tạo ra chữ ký số của riêng mình và gửi lên server.

Dưới đây là code khai thác:

```python
from pwn import *
import json
from ecdsa.ecdsa import *
import hashlib
from Crypto.Util.number import *
from datetime import datetime
from random import randrange

def sha1(data):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(data)
    return sha1_hash.digest()

conn = remote('socket.cryptohack.org', '13381')

conn.recvline()

payload = {"option":"sign_time"}
payload = (json.dumps(payload)).encode()

conn.sendline(payload)

output = conn.recvline().decode().strip()

r = int(output[41:89], 16)
s = int(output[100:148], 16)
hash = output[9:30] 
hash = bytes_to_long(sha1(hash.encode()))

g = generator_192
n = g.order()

# k = 1 to 59
# P = k*G
# r = x*P mod n
# s = k^{-1} * (hash + d*r) (mod n), d = secret
for k in range(1,60):
    secret = ((s*k - hash) * inverse(r, n)) % n
    pubkey = Public_key(g, g * secret)
    privkey = Private_key(pubkey, secret)

    now = datetime.now()
    m, n_vul = int(now.strftime("%m")), int(now.strftime("%S"))
    current = f"{m}:{n}"
    msg = f"unlock"
    hsh = sha1(msg.encode())
    sig = privkey.sign(bytes_to_long(hsh), randrange(1, n_vul))
    payload = json.dumps({"option": "verify", "msg": msg, "r": hex(sig.r), "s": hex(sig.s)})

    conn.sendline(payload)
    print(conn.recvline())
```

Flag: _crypto{ECDSA\_700\_345y\_70\_5cr3wup}_

## Lattice
### Find the Lattice
As we've seen, lattices contain hard problems which can form trapdoor functions for cryptosystems. We also find that in cryptanalysis, lattices can break cryptographic protocols which seem at first to be unrelated to lattices.

This challenge uses modular arithmetic to encrypt the flag, but hidden within the protocol is a two-dimensional lattice. We highly recommend spending time with this challenge and finding how you can break it with a lattice. This is a famous example with plenty of resources available, but knowing how to spot the lattice within a system is often the key to breaking it.

As a hint, you will be able to break this challenge using the Gaussian reduction from the previous challenge.

Attachments: *source.py*
```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long
import random
import math

FLAG = b'crypto{?????????????????????}'


def gen_key():
    q = getPrime(512)
    upper_bound = int(math.sqrt(q // 2))
    lower_bound = int(math.sqrt(q // 4))
    f = random.randint(2, upper_bound)
    while True:
        g = random.randint(lower_bound, upper_bound)
        if math.gcd(f, g) == 1:
            break
    h = (inverse(f, q)*g) % q
    return (q, h), (f, g)


def encrypt(q, h, m):
    assert m < int(math.sqrt(q // 2))
    r = random.randint(2, int(math.sqrt(q // 2)))
    e = (r*h + m) % q
    return e


def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m


public, private = gen_key()
q, h = public
f, g = private

m = bytes_to_long(FLAG)
e = encrypt(q, h, m)

print(f'Public key: {(q,h)}')
print(f'Encrypted Flag: {e}')
```

*output.txt*
```
Public key: (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
Encrypted Flag: 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523
```

Đọc qua source code, mình nhận ra đây là NTRU public key cryptosystem. Nôm na cách hoạt động sẽ là như sau:
1. Alice chọn một số nguyên lớn công khai $p$, cùng với đó là 2 số nguyên bí mật $f$ và $g$ thỏa mãn
    - $f$ < $\sqrt{q/2}$
    - $\sqrt{q/4}$ < $g$ < $\sqrt{q/2}$
    - $gcd(f, qg)$ = 1

2. Alice tính $h$ $\equiv$ $f^{-1}g$ (mod $q$) với 0 < $h$ < $q$

    Note: $f$, $g$ là nhỏ so với $q$ bởi chúng là $O(\sqrt{q})$. h sẽ lớn bằng $O(q)$.
3. Bob chọn tin nhắn $m$ và 1 số nguyên ngẫu nhiên $r$ thỏa mãn
    - 0 < $m$ < $\sqrt{q/4}$
    - 0 < $r$ < $\sqrt{q/2}$
4. Bob mã hóa tin nhắn để gửi cho Alice sử dụng công thức:
    - $e$ $\equiv$ $rh$ + $m$ (mod $q$) với 0 < $e$ < $q$

5. Alice giải mã tin nhắn bằng cách tính:
    - $a$ $\equiv$ $fe$ (mod $q$) với 0 < $a$ < $q$
    - $b$ $\equiv$ $f^{-1}a$ (mod $g$) với 0 < $b$ < $g$

6. Để chứng minh $b$ là message của Bob, chúng ta xem xét xem $a$ có thỏa mãn:
    - $a$ $\equiv$ $fe$ $\equiv$ $f(rh + m)$ $\equiv$ $frf^{-1}g + fm$ $\equiv$ $rg + fm$ (mod $q$)

    Giới hạn kích thước của $f,g,r,m$ đảm bảo $rg+fm$ là số nhỏ:
    - $rg + fm$ < $\sqrt{q/2}\sqrt{q/2}$ + $\sqrt{q/2}\sqrt{q/4}$ < $q$
    
    Vậy nên khi Alice tính $a$ sẽ thu được:
    - $a$ = $rg +fm$
    
    Đây là điểm mấu chốt vì nó là biểu thức không có sự xuất hiện của module $q$. Cuối cùng, Alice tính:
    -  $b$ $\equiv$ $f^{-1}a$ $\equiv$ $f^{-1}(rg + fm)$ $\equiv$ $f^{-1}fm$ $\equiv$ $m$ (mod $g$) với 0 < $b$ < $g$

    Vì $m$ < $\sqrt{q/4}$ < $g$, ta được $b$ = $m$.
    
Vậy phải tấn công như nào? Chúng ta sẽ tìm cách tính được private key $(f,g)$ thông qua public key $(q, h)$. Trước tiên, ta phải tìm cặp số nguyên $F, G$ thỏa mãn
- $Fh$ $\equiv$ $G$ (mod $q$)  (1)
- $F$ = $O(\sqrt{q})$
- $G$ = $O(\sqrt{q})$

Khi đó, $(F, G)$ có thể được sử dụng như khóa giải mã. Viết lại phương trình (1), ta có:
- $Fh$ = $G$ + $qR$

Từ đó, ta tìm được 2 vecto thỏa mãn:
- $F(1,h) - R(0,q)$ = $(F,G)$

Với $v1$ = $(1,h)$, $v2$ = $(0,q)$, chúng ta cần tính được short nonzero vector ở trong lattice $L$ = {a1$v1$ + a2$v2$ : a1, a2 $\in$ $Z$}. Ở đây, mình sẽ dùng $LLL$.

https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm

Vậy là xong, áp dụng vô code thôi:
```python
from Crypto.Util.number import long_to_bytes as l2b, inverse
from sage.all import *

q, h = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
e = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m

v1 = vector([1,h])
v2 = vector([0,q])
M = Matrix(ZZ, [v1,v2])

for res in M.LLL():
    f, g = map(int, res)
    print(l2b(decrypt(q,h,f,g,e)))
```

Flag: *crypto{Gauss_lattice_attack!}*

### Backpack Cryptography
I love this cryptosystem so much, I carry it everywhere in my backpack. To lighten the load, I make sure I don't pack anything with high densities.

Attachments: *source.py*
```python
import random
from collections import namedtuple
import gmpy2
from Crypto.Util.number import isPrime, bytes_to_long, inverse, long_to_bytes

FLAG = b'crypto{??????????????????????????}'
PrivateKey = namedtuple("PrivateKey", ['b', 'r', 'q'])

def gen_private_key(size):
    s = 10000
    b = []
    for _ in range(size):
        ai = random.randint(s + 1, 2 * s)
        assert ai > sum(b)
        b.append(ai)
        s += ai
    while True:
        q = random.randint(2 * s, 32 * s)
        if isPrime(q):
            break
    r = random.randint(s, q)
    assert q > sum(b)
    assert gmpy2.gcd(q,r) == 1
    return PrivateKey(b, r, q)


def gen_public_key(private_key: PrivateKey):
    a = []
    for x in private_key.b:
        a.append((private_key.r * x) % private_key.q)
    return a


def encrypt(msg, public_key):
    assert len(msg) * 8 <= len(public_key)
    ct = 0
    msg = bytes_to_long(msg)
    for bi in public_key:
        ct += (msg & 1) * bi
        msg >>= 1
    return ct


def decrypt(ct, private_key: PrivateKey):
    ct = inverse(private_key.r, private_key.q) * ct % private_key.q
    msg = 0
    for i in range(len(private_key.b) - 1, -1, -1):
         if ct >= private_key.b[i]:
             msg |= 1 << i
             ct -= private_key.b[i]
    return long_to_bytes(msg)


private_key = gen_private_key(len(FLAG) * 8)
public_key = gen_public_key(private_key)
encrypted = encrypt(FLAG, public_key)
decrypted = decrypt(encrypted, private_key)
assert decrypted == FLAG

print(f'Public key: {public_key}')
print(f'Encrypted Flag: {encrypted}')

```

*output.txt*
```
Public key: [260288377891444370372615148009023640057294926547602419331406531383682223097787288755377467188515435381259752760746, 322734358011758862401399370931929863052553602421714393280581187496537763321855751120439457234561080720455397490349, 88092359256403564783665281993130133541226601877969436905267415353041909757324746080398461245281826552421872983184, 601684701300110945921036937572461050140352984401874675917155063594305583314408001377505387079690115000992094388032, 193814643850628739958152744041743058858484088269609293429408490294552345005365776962194365813796130165113184925621, 51510606914703888409341761261103125433754505248101513818740574350196563260563818621033222936301769697693287778876, 502702742677974540308798846750017003106263447846689040491266463798703222616320168069962523670400796196343460832764, 86989835783586738140883150201327374176124588410464188692884973334241681514702306716383785095564084499563152815246, 515511378187957676256419959601984383408150348796281656976955880729383340611785836962788715725367023923811376366815, 119845178983025037005174732553931706284024826223176718982111213579707091766057320315419827781508690979405126062061, 207867794910968434026003881920029657224591376925067493713968219177352819759854486838459675245909787840416982457750, 239399986603216503029402544900610984881160101923294396792665204486222975420081300661354603175384772323551980155480, 306665236132315336961576566094908486196981556971172170145299174389720334940261512384837950321772782983903454058725, 558130280550827068212352576387713811027468233905173944680355562037815257403446113128895937326412940859588204361963, 123471925832174980344066571541132411467266736109103860421447462536930482316849470378251137263190870093702164003085, 146089706629012142384661350988216882483919264673129621404831339166566056469572087759748854086023354002641923689390, 446097892684389219719742914373867457099954499449824602532333181169038249081395758983133906564840000962001976506057, 204029934276059225352901134714823317920576872465404508059719045291560482057171052793698580294637069578017200124432, 412333373143000457741307988470055504576675151299345387733692618218275177027643785881042018546460452418506341967356, 171418413940299360322712423004114364681865276057786947919043883366302567169869592290151559269290446563185553350080, 401593473337411114258578268223784182795068785564101722335215736591292301602077751376477881087346810602041717163104, 204003688543820354337113938494979311981574571424756883928855286926734578790400322291262042466654212377708831289347, 555612926496986208337317871061684502803594375654879680702581403987248292734014139717756900004905653768133795128973, 462785612281910846822645629160953231999037081137615204334672445418078665808070086646804794186256411131615189487813, 77961961618173276050791733447969083544152711482614563228085622136316525792569658878271751219358260960116292497570, 517789370221435419776588087490678991824021927945387533283088388790482913301281733115458601414668206432512998904516, 281870328340314395150658482932699114581743200279996227099530744754750289102031518563761975024621347281374162044877, 60204977937304337797770029325498234132893935850995809547662640467737007197647697381430963693698522962733473746281, 395936787836195675178388359277761575381601972138693830435288611414489963379399027975388601714741876831895709497105, 90921357930302550361827901642067284191268695594120415817202534786924330392421221829361546010764453051928814876700, 238523907687908075601117120608130752369082206676107364350347208286323115036939777325067473364465438898353765093766, 277515010021988996116595000889051160811249034599876556819610707794016612800585201793339332495839495779526504613846, 187215937497318890199135284983515062319988136636108170852591598862524363777870331888216170582220867500042557737272, 411220029331367081136918789112083235781237730079305782620378994961505282090962448446931628731751970521853108685376, 433613620456520979627974441205441942311133790647897226320388205340695256818608765746266662314499649013982035729731, 509613591091334719216567967380183602959933686617275815879939870258332674755345348802452058256788513837941126219238, 352708166022264045150842358964512080203788453464883319778517822047480718640858804837886057264514786742694419419735, 486272357335492500753956372299255798603575392697018451800774427752724312455328655650777691830508441976819499348269, 1291533249748053824342851185451970324561531056195308125673915619130780992270420765078102812914222570167615953050, 520707501920546816250915326019351261090208813534492143136485743644939372232638461802625700978801768541842624647274, 272359456788721692618768612190222453304838934916628492701462591276450281926223118982602858211688086607842351391495, 119534191144397164327417397593964021477488683311215644770010641745736480039094209273092223959694752862193314087240, 394945131470603614379767959704654538029557537489316246092982427107641617479545488843535929537498546432123287486437, 395979428475608101765230328218274625986674115712051764903732593018454264017781340199795540039285257513438842708672, 322101629493887220159199019582810892418957941946300752245249462093036697035162212557261470168522953435341905295650, 60610073299031334532969727880668989046838926047395613981473675505442500833244137863225398782029541439420403686372, 492582431835005621441922899995666806499437611069193099072247918597047415020628078410849119945608854080040163699375, 356290614124448077864884136922409291617128370298210212357882465167338600485728936925448944675136056707929560080237, 469737185578879122378016959759297464132272432425745272107998534197014940235018335349886398896979254122985841196030, 522871107234918024128768136315123497251902274681110489386594944387181296826024289163431880961506314580935567743910, 407151723612481391724375429193917289623669496278028982297086458062111012958436324350527302865535766565677711383191, 597354385774970715448797740483856119139152021834911852144490298736330354118482480147237280491305029710326837274157, 541106433608213985607913120402276000940203625086988929757276286018099336445558864548353610869729642196223750468493, 417269959280528548156948994397262973057821055108288565091113745409730174626359955737489143948177504667498654245449, 165844467199853002181647516786815801413939363188955720855463610698066730208657222822269457713666541555820608908443, 54875733171006797537647859403084623422036246809497621662400918381496284440644503330411668895858884933248328986102, 465819050441857934210906305127374377291850450707906416261994960542649394393702032587209990932960399224341143990297, 369322923825463715724411404444452360125845865658673947242361968271863944079047696087621731311243573179527276498509, 553158781749591211954659671173145767949897795287325677938373702443265138456771264711232588438786042792968904732769, 409812013938165700887519758386718364160025926340003407045361393371862966914817952304595560620453598830906305966865, 494654868138757552768371639418237489264099471894419220273147503624077564865563661914136003656825657044284503346448, 583613295252460993144403074130901622751986348055784728175987246652496523293580989652454868505577305787293683850652, 45623098408168398769971239387495928980835555721564847009059790575158770295430426790200773274288087331109699336204, 39196430635656777174378129146834600960125068266405306877726260536750371354188413207203531511343645151492477471286, 269811462520469960288594953357779332541515563494806499705455036716689694055741096626927182558039773813984145657639, 56129158162087034209035841739296133948708529713411817898928727109770418208078239244331640522507423413446203417794, 524210107239750288249530336771864024916995632570549267972428294539507299820629133801771958736839361325798918246415, 74499040113803277306263886217659673645883223840279171192334357737741618882160648968176974754905084576184804774369, 537566085689080717108870646705458338163437075433046077845999622035879463636776663759447985884960181167857417860517, 67053890181708018909161683393261532526993578729770554741021482840348299866927821016301415949708659944497709907470, 226687291544149270579995169198961617407190234578516732237756117257869929434434889879973211444301745820066870869034, 30119130560797352224094299766590747178156378314088092947830899847927767559391822485618397327733723834195435500170, 273554685078063587415670757725663508130498751998110442807136494763920302805098071555958936900406570453984774374060, 87980277743580170573607118853300224477595233902389343863665172738347967268089655736029345194767280704236057718111, 415325115863346791298232938393411393462777451386243842830553121689594926353646948497680883539360608323603975987452, 291860381996369849963997875749710331697722876276851205203280910491894467229365951220031470367159168511107680106262, 554653569462940342418063467925252548314485118886100002832290030505991378878498660088540140703141291011055029173137, 323189774384600834625013268084915768916855209746568551595158521873406091567687194674213765428238599317205811518692, 271805885895959097314720980134407607645324820417975238169874050425279962478579515969226563851125481000349196674810, 273580504244152469063405670227951980303621824057876058884978331188257821496852334599050020207990127348359965113465, 89994080154200685717636930068317931325931168723237899144166312528962957042842197915530047017893088501681215899095, 179903529806043505032581494908566846659773117049401056767669943330229935007822437549131470977810261112485254094386, 337553339737054880017288314951575451797426862530219763936855885416298554494199226261714888518914541341927073075939, 55576723594346882914517616915509260915444308762551400560217462518909289055446940809390878002725822401595827206530, 16748220768196858904499918524709172735166549515085689048938405549141121222201553686060172878474455615920723669801, 317380564633191615800168658676142557493413060315417096622564923156521630376263849705099633192226251101432134441153, 533990888376667129575141849433166253104032964155895368357797314378260092470904627861359175864364684662961150582207, 51339665999563119517609216115086272052501396280925354694804471629521639434841281422984348587180771099209184749005, 598751671521816401429095343374521592165563401213195481604556405443389323390172923217639290327197434030974530635632, 502516418942980462174586089858060912235797554801782186782319843655355616321036648106166017773986280053024012403712, 96757697084956246010025820107260538706827163135748809142998937362457169471061108292297066769079020843197361323396, 160715027762704553320571142674023737670353756130518440136900430091151963142004047232920245715827837173811719927140, 279138292123840748082780689543574043699162822819208361733228093396335579794292477744981338016264347327181324984710, 76445842054689324523514421681098261857514827631364695255959418519245612571199123499205752729124353901548286671941, 383675319414133753635121914615218464358220814208747712016103562476157464944897131756675168140846189629485664787044, 260741648290568813857849033448155840373964568801980310694295413631289231242930901519918814851819352903132884286000, 572815144956474380133620797676157654285774633299428534205241845335783095326631133195133798583360396067031309578073, 326258465939147178368353573060965288327891986807699582822092415027094204965326681853802159504539722937811913340954, 270266570242986488258809014590807152136633692716132669770748395523214017062557603428657196661342410476403164567952, 594635668324174018778140793057815156885870465660609865234586849536688338135131804764199647040009222634146148815637, 112066852946512058163194024984815176069074331367673763590415760757313750687675218022751871678411881684718198988959, 72643140251973593561700085821570131390914743121754868577502110904091989089708201436984242838820806097191225214858, 418558767829526524235103555737958351573183096833081038769308995724925326439890724874671213539641031754157727776067, 196559288823369030489094238610617412012659194878611686482089456487889879135369906410569754176462601644487717691079, 484475844260869041475828428835126624027291693283800645559775410528136122290210564467730445814182429120097372738911, 397895531572254423225385975618860549078025992059379971480526615942245245283818149065605766495091059477544617632303, 173098235745543952336517747078283517802667869630628062474315240281111485771833849083340162673485620557610425012773, 395438744730241817782361196255681827924847041028664896503460681041226871979986416514203189980456170013127549062319, 470021990867207717347003710359490169212637212255796418181420825247262094876084196634243149241752002339736588912053, 116393009019558569654503508922282193810180596603376432764270301486325221610807518426481578453602546466299515294456, 312679236344738874814229979243462639486594453393064312671149009880980836289564409215088541509970023077739205203468, 125633612607015147027292740679836345332097512816636698981581758992992116056276272361001165705597842757882238693825, 550545747650576990464265884382499274254872311986381675090751886824037811235625095205217845451891396561893492715391, 582344947379262203945082609921047126789902458640974947174265099323728700596079597139164883619347159500887293859913, 597445807393853093495564866081359122814348105478914638258595339515168987499771664924728981250079847198831836930965, 203086100710322798737771097067197649738932976573837729229038404179992238381339090779534246758253939763462200026384, 366083021996787911206272856169665720981308167177143125303074466648545813452157612764258146407782634619278092168081, 568425067761875823198893591966757461338470700675615033946429149483970138055665377562238998722395767377075284081587, 292063178202410186631443519138674436645163233411161937085629856088259050827382985093506892763617302007759121037731, 572237520943575841301998365238940412928982617335768155394691567092595694943290938278464533099223273214233507106207, 130730938892686892107630262721901246969052318133502728671984157629171554435251506312878040499761922665301495030981, 185117108148352276973404708807613996548096583954940273525781406848525491758486946236965943611210198389159091280333, 37060990092986925132287820152354618271473589014825595897838753632315007172710154561879917551705194656825456571032, 403396730776194870459199627544122636010870768257463359235766775533882938128146112838489577777497432203020030499998, 390519053219213422305599109947414047895590808796368085342860468917268018310638864392199371679272174634278410878307, 128444781947873592602609418783055715736876557725608932301613294446934930933474014020041434831899064316552264614235, 543291373538613455155809248493830432520680330961337677793905220928838352322514565851452650441518480234729892153780, 488514444383813071753894478409325136755661751625837651637348989332739608743318097848609715931362718450900659714726, 345584582429475420526208382863826459005483455209655712636957752389218040279848223862500232738960994712140028026289, 93010878843154734421543561265196548806562081923037074596459052686633775723171466088126269822057315393084026072218, 12533412965882925987419497258660569237455714460582608620237638858642686843645624645184949324869641399446820464020, 562770032030414047557952904910126027215456025343530350248616818594366525600180778011275466074764589844321872364272, 128451705070871056157396910591766296038989235798264982434769256144115712608648937222298167066517556774062311420353, 490278961434267039693706795888817653385586689501848271165345121922956317504140732421546020494675482464550410472502, 212287543946551782522399704940695532581109453008804375002654843122502975490312129477869621998080277682674199046031, 351228167329138957128592454766411142609836239330479331051630155591459798299725613134325016512314887321869487481161, 364056580106158102895694571253671943571916920885795142960090311722444269241247963009814588199874030295862636577768, 323410613174912128865174768949092780979646178505039555025194364419990442219941948707117457621400459111231556621585, 555979459475319018276106133189578589964687373772995549423813902773304274184448885651570001083614054140692063026580, 471645896888183848879918063770091917659270906648819201901346651975957177950753583099047587304484006413716362087065, 595746107902898270905714635379070716651708771264047581902664532594897071557252807014533004074458867603957329534516, 557816517693603351719661411054144374250247040672226934534604151399902780319198098821629853612396635344596388943480, 75653615683769023911143698869320584951015514055697266638646507368530841035631560833198288977975782471517557394092, 386729218862361591185009654369415880766336899946663823664818477204172007165198875809899277634660190797185025579614, 393108265477944240661308455550612796769200470498502703905073280606596277788078742986164286625262059483908055127428, 365065802583204450004435661912506592532468753723399406740663534070289404492293680764078659588454240436160849321237, 343474792575856700080726394177083134771079426798042359193966109700850531408037245425173307797050676647933775237484, 449270583610225180914452784540333562631570453995885992409935055758994173533991695282410200635020830187612444056607, 152477148608000973940085532267319492932629609199964217167273279315109403426434432473053141371160594251975646390787, 215758046810520029171417357963508549726865838830930981174495643955719506571398771447950049727234258305885220507020, 388644732079570479249894814593945177309689613386566508292336098907992239994635374799070003303374928382563877494312, 33174396496627497383579687586254392056231321534282758587681567913835717050445163816449882425899904436708697640574, 293328356964375951072242072976851267186828242468018707810599907336525314670450502681522283876131924077746023996643, 292804486280753504026674757794166015519590385505528937148184945726179320137391480944836180610675717906694042510411, 278315915715399524055936806996907092937794467054749462150463756152176847617395557111508306851465386462011262385630, 103884040577296119486012754822466682224025370872916939490159319500421058932999421365377738193002421767097172706341, 111463652129659874006915288174831654634146152513640366449316440114829594116719772451443937868409442532699879776869, 475152124260969797265060453354454799124845717445357239027249597786029156307488697633998763174770332805926500738683, 220597335944113643138040910019263318251616203954548724660953303915089233301354511542662225751359573592406567125779, 460838912228809947843094986154780694841314087685379351551107763714127613789323858795003275958350186756130179585099, 140183105024444619512158726537661171898184380568070161231133567610679885584873426652521827961950911404383912561621, 100258312363732149931656549158547430770829888011033153048299126820116382987576385251423248018523377569893042593237, 405290867185420593972711092047858403431415058957648108848290712855486205273135789994549738296802436972506132007215, 256955277068974586752505570703153051582682851398012077625721880852140628262494489158976679841716540706155916871083, 598549159802958710401362839481280273681933957841944662088149512518476573000011803427513695903373248355980692446393, 308263288681016807641714404434630877489176754884164049322636274036076916608089721011418189274379096133290778967977, 8342859679410179631729508842147337278025979845268212054683951869690623917413242667876438120214556608223950514653, 439895086294728342454449126955941890844828534912064877350830376651948083146591737071488196253116258629344717466258, 91881226123407259536921548434174382841001791568169293198769940131230256611806601058471105885254628422499512141440, 377266324363766263400630205724731218877243980277025204567255708828742612895175112462476548764041808998472515741645, 116673062533491873681185131034931580572262852751033929144868000941380674942800523209276875356733463592351603448680, 57238242567269156027816815706946539463493497634492900168501163766058930300567388616552782194562204025116893421410, 589774086517371498643669747060802896861503240906569357013148621028285639980785543690656162836694887880501379427719, 299125626128142030020988742420785075132372751191528474146303145649473683269241675130370288768899920531289674244113, 304688395547666111898109663337992917557352968749730125549180444196974698222351897080702952045364871753888027443342, 482739851676824100473920409347215848398789318900117561465297399614115666738614477259195415015272146741220074932513, 223546862652113236935862556158177901803806229739994958195958127700830125319767534179348037800919714328649801362322, 150425375689725206871177727482717625428944121456212788472446922564113718518867636855506280578641904259888006038685, 143374483079122348274771015162872747263883105211675941440480524305910827744168931572051691220561136775398957657059, 128633351158033453796356108560970241527889904619011394383277988372280437398843373552825146090070247278923404428730, 249625701621261544438183108711205773478938560640571200325127252485779481701078452759513943692466279038851599018511, 330098489762871879773681019559732262466172018773272582308614672671671001199307865518506835519360693927579848132122, 97272570979206528424127336981516817168566955222510512261839537633559389914877185855268875504270285494647179225542, 74718841026645027941391238796126141775030441881552798010185595153873780524478674202965665888738730228577064111032, 59009205910055868684561742529451214311094377006520731342399475542159755492342086349692903126315766192176134558364, 147954106872023713951463145691216475084430006306060416221364896834795769425749212897622105818492094458111589403860, 555992830271936179812799550002813412539390844307434015514327261249472823762801208645240806724751727789206958497458, 459223438688559571249116685914649450095540121668933258507609746609794374539448063463326591749261191192370815662117, 571393209200912648822312183637054598815269397678580613768957089116765483865121162495918269935152288322187647411253, 177286186824084038346767370297094817293812392957721642873053028629715330336525966361030541938870465423944241324109, 587491267113142201933590855412985429253948652679543672927232780837039223665539177593879438262959884768626979925026, 121073719992748558849282996502703446279240313956823650619682240860630373634948798695523514085879310433388769297911, 326992821821879354165502695961028240084978294787383957718963930070776372845305415470613976088436935751047043512627, 55897462658973985554837453480984923331777372313619418297379632868358904708526448610515770876401568010074036247, 474281517111080897542557845865286041097457650249727914745876496139882777461227076272058949306156001543709356614827, 40880447006931568560802817837347288973549001731224760995212446282117046967004745589464560120352241602331262757637, 199377582253379978414081552664345738394226248383486423477706857549702059554694037264958719644482986837756496613246, 67583806809325529684782118654476643411516600285151896093983454855502714712133346956141976654071062935812737453191, 452546341988439193982297214011678766258506490290911066090290647614068455151806621409756646430532117713333419814200, 63154079944843452528208874183624055953361990336542165468695871390964383215223885775202331596927466794955939855669, 334551033942583568474606741839213957101383590286251155186668543235920975897931743928357631453433934808796703330473, 437000125133660712403788025992205090698484430907657894066272071296035483375078474260228687865444802416063967634962, 79996507523856267942889507576300340014719316733731500178081582238768493408405645914333660158893963260211116177267, 136957270824318341027124989034235585855646981093281453761145461440890955503793684517186875995202144027265329969201, 280204753198588906275980318398478729285287961542920285529979812275266316580102545873587416433404212703776245726478, 537734235993878341769434982550042490365981751251428660237179942734374485415922424357453321846937022328664895920607, 498357256878949571854248804622370932859926894994690120526235824883083753765132401863605500892090016764206939698756, 593183658694608014094449104249771865876595121367209656250471158771632486392533730913932393504513988512194994235126, 471525047958971655208534107052287853913949987926476676197514310320411235020283503103705707957701802098089852040455, 515550195522086342769232739520750768345601850976320014312405876943691700378141377151414091085616391824613041356222, 229784654767967355149909497709811119368560654037206880944035229827691011815016913131119422451043820980926353941725, 217169654015051285238559403576147518221573574303291047729813710960725792892550445720464605476174663800328177597453, 445865555254101127829958642102675927687168710569707725467286103803938348116926832834254624089519482737855028080263, 83946997792088073746354410376458121354546477090285151121896293987266118404260723878401677521317330022928683440101, 472119354862263268431251633432424976904384210603399093568806291862332048310282050100842204125396472101319620313029, 46843467515693389983627938872598324284244171067988563260495985345821466093790361374194115630948136965603015643581, 277302589126799360982750111603442360555051934636756171066424884732490616874962892980005637968336486277371298105284, 37796860324947087933757452089444569583341754367174335457777874936449439863762482510080776848131952814291888228252, 329201662631483519275850208043421059140347420462580260818216051307977255139454956805683010032538225008290753339066, 410958260744814455637908317160979333881545314073457621559204623145344687279791103290567233048673594441768330391568, 391184069150039601440639067557184862816991051523817132396666190555512106382919904848895224325098711230221328168893, 341778180155955688649827271577690269253924367106359453768062062983194302766144996692233530585116870343939549344048, 482885184891891026832543019680624112333051960746415331234199075553060933581630480706330420552017650892318225421994, 227417029879602291913898154454350465334192275455983368980997243946371067766121862949125088496933933053493304375082, 131891059077173823480681683274809296700667012054595015489329798567668841455882278540434006611778254351469315756836, 103977685400575936876007245351080422734569291709540152622222483086840011211808484758839889045266405362833100572217, 430039690420862864710328860317916251552162738538460131045295388990486621940999260820629946807283129550503791042360, 336054039341779369078755981618338727567421739252984379060088264565052065080902800664605952509539644185937023210384, 414650487301520195860820485747902373712957920758077572646321108690388934071745453432265035539090489903222596288408, 589576193361941267176015154197092338077060428665767302320550323024382985851379047593411265195718688560873123744185, 218382333622730104159935425552756841820388948639519923842495333910150980936866251625988964615764772159578862214025, 2542356543181698813075957157401385706512468063673241076844194782908937880847391489213422972872487843717747974071, 19012712934576590810330358701965194246607393288484627129050567402003333386833300009773236871643918870071025370112, 261459449945270346696260426170010104493420330959761424072408598127181246567262293489464049721489266230568086023687, 393057872763078249377870634042993942252544393136978340205701555086856991894130814830449765311294161681995357980571, 31706670785655144489258744219717253455873175486088498446357251628824725653898017817866303775262383346847940227722, 352845629675989592022318947558037109666715372268243939061740352176833050420783754677666411876876865226448815643420, 579523499570692157776642365278787278074363193157128877724940050501652213832135926670258239249988403301949338255538, 534781322034571849183222718240938369181782069830117215874801137890227720544463940037268498986061166881241864175911, 293947547828174245724554745263997068016996177889470503383528004805559670712802640725469343616840367100443153534752, 20256488447976344493484944853334005566670073013412177398480406734598723283264289836587474269370253077015786359305, 475307340957345844876811923970449788514706891727480716267956523131203845997503382023500463149439850432076379159007, 9532193777031501443256432870520743234491840911054244783623102207162388499144070592024440812057106927678514406207, 30376455906399256126534181227692885553266283699913099449205248506625206632827693466133644861846223565145288661633, 310323302397755654510284518631138079981439265632852684852876254116989091445393487579911757256043570018377230904180, 407387187512823516321154849212634322952876110252179375736935664859854509488826142049903683991617538259494461983206, 211765773488300500716796064525502573590145731868562963063378748592341237756767589777342751660513980880169703658019, 118119996850569812443799306306875048213209686043987665925365129711742300844060014347898233682054000714610165352429, 456288037921986114882644161559494182818651772335241262800783776696209877706906644069180867207555069937013686421247, 321798425169971169912343295962697085577508076571119888196289113181080013814133443673221049860354996979915353284172, 324976521789232911848337505841284978746361536915903971011255451438673522500730537005137182463678372897314198988595, 395621759076694189110473461483468243816716472466025836871653502259071450104902960119128530517955567830675053452079, 539300517585750216948117617165146582589224695990488749904551961039061424290129525221984586819908097960720708938354, 29279302128607422250205549520059282069518559284219582605487413142781822276106373289432262133635053599391124926385, 554047387889265384869858916477442181952403597250555948392949469296673941793381852004501421929101000148453680659392, 117780825424837288494479009381221759361151487239443821133102414888864152904732196195473813006762420646998382258677, 513764579681988270425418630365712613073908798769959690739998792846173650211508078458011456784363312999085649615413, 421686906289957894155024887354760839265000904451245772175308131137467275202489561700021659858819873604538650489994, 420037832423259525388141394520857134457021929872555809167052539034540217718781279113965175987358081438109891771580, 36451605745112040602804954235939462081346791770310181663631699054048414835838956409055640948581948016033003511333, 65866443469866248828119099994518897685990064406903627156894902667947376070679854260383038634727146436274230980496, 27676413701492447763964945205769602759768347623741189980278225943728587187940271050634054217590942659542302722334, 500312789935788689187812810985806111797362028998353677843819125485045576943472901976055579663665267905809820905862, 520064354401353505774803720281331074080600746212325401527048530022713769008774050816490541356142354757805595273068, 495854656037423684061417113244964481431602915324717605570975073575414392233479237472936965636133612283412033946051, 91739870792230359210043046401786959190045929124141709653873699398574077579395785555200462734509728806350612588545, 484531754577892922131892661653620989224382080321025512011181426678442547912964573223048519566085582623517825865418, 112714684344084391078866980839255594355187885339701715768009153551270432322826715969989728340963213693095849427668, 404429204723786534299525333122163342588586991421902466839808468487493896330979873416105908841447535426923681220957, 92404742424217640040375362532444172359091402942418950195520660310216430170054358290537973281349284862065214755739, 224043393969043013532511880223075809120842856165608086692928112430171548569493398551019081676395857489451126409940, 4305919427803364191555497499680058924116536587126751817219863902878291078989381194676206640960307162723876513248]
Encrypted Flag: 45690752833299626276860565848930183308016946786375859806294346622745082512511847698896914843023558560509878243217521
```

Đây là bài toán Knapsack. Để hiểu hơn, các bạn có thể xem qua link này:
https://drx.home.blog/2019/02/24/crypto-he-ma-merkle-hellman/

## Crypto On The Web
### Secure Protocols
Cryptographic protocols (giao thức mật mã) là những gì xảy ra khi các nguyên lý mật mã học được kết hợp lại với nhau để cho phép các bên giao tiếp một cách an toàn.

Một giao thức mật mã tốt sẽ giải quyết đủ 3 vấn đề của tam giác CIA:
- Confidentiality: giữ bí mật
- Authenticity: xác minh danh tính
- Integrity: đảm bảo truyền dữ liệu an toàn

Transport Layer Security (TLS) là giao thức mật mã phổ biến nhất; một người dùng bình thường thực hiện hàng trăm kết nối TLS mỗi ngày. Nó cung cấp việc giao tiếp một cách an toàn, đáp ứng tam giác CIA, trên các cơ sở hạ tầng mạng không an toàn của Internet. Thông thường TLS được sử dụng để giúp bảo mật cho lưu lượng HTTP trên trình duyệt. Để đạt được điều này sẽ cần một số các thành phần chính bao gồm TLS Certificates, Certificate Authorities (CA), handshake phase, etc

> Secure Socket Layer (SSL) là phiên bản cũ hơn của TLS. Phiên bản TLS đầu tiên ra đời năm 1999

Ngoài mục tiêu chính là để tăng cường bảo mật cho HTTP, TLS còn có các mục tiêu sau:
- Interoperability: đảm bảo hai thiết bị có thể giao tiếp với nhau ngay cả khi chúng sử dụng kiểu triển khai TLS khác nhau.
- Extensibility: hỗ trợ các tiện ích mở rộng mà không làm phức tạp hóa giao thức cốt lõi
- Efficiency: hoạt động tốt trên cả các thiết bị cấp thấp, nơi các hoạt động mật mã diễn ra chậm.

Hầu hết các thiết bị hiện nay sử dụng TLS 1.2 (2008), được coi là tương đối an toàn, mặc cho phiên bản ngon hơn hiện tại là TLS 1.3 (2018). Các phiên bản cũ hơn có thể sẽ dễ bị tấn công.


Flag: *Let's Encrypt*
> Xem cert trong Chrome -> Issued By -> Organization (O)

### Sharks on the Wire
Cách tự phân giải IP trong Wireshark:

`View > Name Resolution > Edit Resolved Name`

Bật phân giải IP:

`View > Name Resolution > Resolve Network Address`




Flag: *15*
> ip.dst == 178.62.74.206

### TLS Handshake
The TLS communication only begins at packet 10, but what happens before provides important context:

- **Packets 1-2**: First, when we typed cryptohack.org into the address bar and hit enter, a Domain Name System (DNS) request was made to translate the domain name (cryptohack.org) to an IP address (`178.62.74.206`).
- **Packets 3-4**: The "Safe Browsing" feature in Firefox reached out to a Google server to check that cryptohack.org was not a phishing or malicious domain.
- **Packets 5-6**: DNS responses to our DNS requests came back, saying that cryptohack.org can be reached at IP address `178.62.74.206`.
- **Packets 7-9**: A TCP three-way handshake (SYN, SYN-ACK, ACK) was initiated between our laptop and port 443 (the TLS port) of the server at `178.62.74.206`. This negotiated a stable connection between the two computers over the Internet before the real data transfer could start.
- **Packet 10-11**: A TLS ClientHello message was sent from our laptop to the server. The next challenge will expand on this, but for now note this was our laptop sending a bunch of important parameters such as the ciphers it supports. Packet 11 is an ACK TCP packet sent from the server ACKnowledging it received the packet from our laptop.
- **Packet 12-17**: The server sent TLS ServerHello, Change Cipher Spec, and Application Data messages. TLS 1.3 is designed to be really fast - the server sends back its own parameters, then signals Change Cipher Spec which means it is switching over to sending encrypted communications from now on. Then the server sends its TLS certificate encrypted.
- **Packets 18-21**: An Online Certificate Status Protocol (OCSP) connection was made from our laptop to an OCSP server, to check that the TLS certificate presented by CryptoHack hadn't been revoked... yet another thing we'll explore later!
- **Packets 22-27**: Our laptop sent a Change Cipher Spec message to note that it is switching over to sending encrypted data, and it finally made a HTTP request requesting the CryptoHack home page. The actual HTTP content of the connection can't be seen in the packet capture, as it's now encrypted!
- **Packets 28-39**: The server started sending the contents of the CryptoHack homepage to our client over HTTP wrapped in TLS.
- **Packets 40-50**: Firefox's HTML parser saw that it needed external resources from Content Delivery Networks such as `cdnjs.cloudflare.com` to load JavaScript resources on the page and sent DNS requests to resolve those domains. This isn't relevant to TLS apart from the notable fact that DNS requests on most systems by default are not encrypted (but DNS-over-HTTPS, which fixes this obvious leak, is starting to get more common).


