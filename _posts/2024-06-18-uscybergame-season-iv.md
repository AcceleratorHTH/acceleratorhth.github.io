---
title: Season IV US Cyber Games
description: CTF-Crypto
author: Pr0pylTh10ur4C1L
date: 2024-06-18 23:57:00 +0700
categories: [Capture The Flag]
tags: [Cryptography]
math: true
mermaid: true
---

## Encryptomatic
### Description:
Our new Encryptomatic tool makes securing your messages a snap!

`nc 0.cloud.chals.io 28962`

### Attachment:
*main.py*
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Random Key
key = os.urandom(16)
flag = os.getenv("FLAG","SIVUSCG{t3st_fl4g}")

cipher = AES.new(key, AES.MODE_ECB)

print("****************************************")
print("   Welcome to the USCG Encryptomatic!   ")
print("  Please enter your message to encrypt  ")
print("and I will add my flag for safe-keeping.")
print("****************************************")

while True:
    try:
        msg = input("> ")
        msg += flag

        ciphertext = cipher.encrypt(pad(msg.encode(),16))
        print("Encrypted: "+ciphertext.hex())
    except EOFError:
        pass
```

### Analysis:
Bài này là một challenge mà ở đây ta chỉ một chức năng là mã hóa, sử dụng AES_ECB. Đến đây thì đủ để ta hiểu là một bài dạng **ECB Oracle** phổ biến. Ta sẽ sử dụng **ECB Oracle Attack** để tấn công.

Về ý tưởng, sẽ nôm na như sau:

Ban đầu, theo lý thuyết ta sẽ cần xác định độ dài của flag. Thật ra thì không cần lắm. Nếu muốn thì các bạn chỉ cần input rỗng, sau đó tăng dần input cho tới khi nào một block mới được tạo ra trong ciphertext là sẽ đoán được len.

Giả sử flag dài 40-bytes, ta sẽ làm tiếp như sau:
```
Khi input 16 chữ 'A':
AAAAAAAAAAAAAAAA SIVUSCG{xxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxx00000000

Vì flag có dạng SIVUSCG{, mình nhập 7 chữ 'A':
AAAAAAAxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xx00000000000000

Với i chạy từ 33 -> 125 trong bảng mã ascii, gửi payload bao gồm 7 chữ A + SIVUSCG{ + i:
AAAAAAASIVUSCG{i xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxx0000000

Với mỗi i, so sánh kết quả trả về nhận được với khi mình nhập 10 chữ 'A'. Nếu trùng khớp, ta sẽ có được kí tự đầu tiên

Làm tương tự, mình sẽ leak được toàn bộ flag.
```

### Solution:
> Warning: Code này mình code tay để cho nhớ nên có thể sẽ là bad-code. Hãy xài code có sẵn trên mạng hoặc nhờ gpt thì tốt hơn  

```python
from pwn import *
from tqdm import tqdm

conn = remote('0.cloud.chals.io','28962')

def recvLine(n):
    for _ in range(n):
        print(conn.recvline())

recvLine(5)

known = b''

for u in range(13,13+32+32+32,32):
    for i in range(16):
        payload = b'A' * (15 - i)
        conn.sendline(payload)
        res = conn.recvline().decode().strip()[u:u+32]
        for j in tqdm(range(33, 125)):
            oracle = payload + known + chr(j).encode()
            conn.sendline(oracle)
            res_oracle = conn.recvline().decode().strip()[u:u+32]
            if res_oracle == res:
                known += chr(j).encode()
                print("Known = ", known)
                break
```
Flag: *SIVUSCG{3CB_sl1d3_t0_th3_l3ft}*

## Sign... Compress... Encrypt???
### Description:
I can never remember what order I'm supposed to do these in... I think I got it right this time!

`https://uscybercombine-s4-crypto-sign-compress-encrypt.chals.io`

### Attachment:
*sign_compress_encrypt.py*
```python
from fastapi import FastAPI
import zlib
import string
from secret import secret
from Crypto.Cipher import ChaCha20

app = FastAPI()

assert len(secret) == 32
assert secret.startswith("SIVUSCG{") and secret.endswith("}")
assert set(secret[8:-1]).issubset(string.ascii_letters + string.digits + '_')

@app.get("/sign_compress_encrypt")
def sign_compress_encrypt(data: str):
    signed = secret + data + secret
    compressed = zlib.compress(signed.encode())
    cipher = ChaCha20.new(key=secret.encode())
    encrypted = cipher.encrypt(compressed)
    return {"nonce": cipher.nonce.hex(), "ciphertext": encrypted.hex()}
```

### Analysis:
Với bài này, ta có một trang web với một endpoint là `/sign_compress_encrypt` với phương thức nhận request là GET. Nhìn vào hàm thực hiện của endpoint này:
```python
def sign_compress_encrypt(data: str):
    signed = secret + data + secret
    compressed = zlib.compress(signed.encode())
    cipher = ChaCha20.new(key=secret.encode())
    encrypted = cipher.encrypt(compressed)
    return {"nonce": cipher.nonce.hex(), "ciphertext": encrypted.hex()}
```

Ta có thể thấy có một parameter là `data`. Dữ liệu này sau đó sẽ được nối vào giữa 2 "secret" với secret chính là flag. Nén chuỗi này lại sử dụng `zlib.compress` và mã hóa bằng `ChaCha20`, cuối cùng trả về `nonce` và `ciphertext`.

Ở đây thì do ChaCha20 là một thuật toán mã hóa dòng nên ta có thể lấy được 8-bytes đầu của keystream, tuy nhiên không để làm gì cả. Vuln ở đây nằm ở cách mà zlib nén.

Zlib.compress trong python sử dụng thuật toán deflate để nén dữ liệu. Thuật toán deflate bao gồm 2 phương pháp chính là LZ77 encoding và Huffman encoding. 
- Về Huffman encoding, đây đơn thuần là phương pháp encode theo từng ký tự một dựa trên cây Huffman, các ký tự xuất hiện nhiều như chữ 'e' sẽ được sub thành một chuỗi các bit ngắn hơn (3-4 bits thay vì 8 bits như bình thường), cách ký tự xuất hiện ít như chữ 'q' thì được encode bằng các bit dài hơn (không quá 7 bits). Default trong python thì cây Huffman được lấy theo quy chuẩn chung (fixed) nên cuối cùng thì đây chỉ là bước thay thế từng byte thành các bits tương ứng, không có tác dụng gì nhiều lắm. 
- Tiếp theo là LZ77, đây là một thuật toán khá phức tạp, hiểu đơn giản là nó sẽ thay các chuỗi ký tự bị lặp bằng cách tham chiếu đến chuỗi ký tự tương ứng đã được tìm thấy trước đó. Ví dụ minh họa đơn giản:  
```
AAAAABCDEE => A5BCDE2  
AAAAXBCDEE => A4XBCDE2  
ABABABABXYZT => AB4XYZT  
ABABABACXYZT => AB3ACXYZT  
ABCABCABCABCMNPQ => ABC4MNPQ  
ABCABCABCABXMNPQ => ABC3ABXMNPQ
```

Từ các ví dụ trên, ta nhận thấy LZ77 sẽ encode ra các chuỗi có độ dài khác nhau nếu số chuỗi ký tự lặp khác nhau, cụ thể là lặp càng nhiều chuỗi, càng liên tục thì kết quả sau khi LZ77 càng ngắn. Mà ChaCha20 là sẽ giữ nguyên độ dài plaintext. Như vậy ta sẽ brute từng ký tự với một độ lặp nhất định và xem sự thay đổi độ dài của ciphertext, và ta sẽ chọn ký tự nào cho ra ciphertext có độ dài ngắn hơn. Minh họa:  
```
FLAG = "SIVUSCG{thisIsFlag}"
input = "xxxx"
=> plaintext = "SIVUSCG{thisIsFlag}xxxxSIVUSCG{thisIsFlag}"
len(zlib(plaintext)) min <=> input = "SSSS" => Xác định được byte đầu của FLAG là 'S'
input2 = 'SISISISI'
=> plaintext = "SIVUSCG{thisIsFlag}SISISISISIVUSCG{thisIsFlag}"
len(zlib(plaintext)) min <=> input = "SISISISI" => Xác định được phần tiếp theo là 'SI'
```

### Solution
> Bài này khi mình code thì nếu để brute cả đoạn "SIVUSCG{" thì output cứ ngu ngu sao sao nên mình sẽ chỉ brute đoạn chưa biết. (dù gì cũng chỉ cần thế)

Mình sẽ sử dụng số thread ứng với số kí tự mình brute để có thể tìm ra flag nhanh hơn. 

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

url = "https://uscybercombine-s4-crypto-sign-compress-encrypt.chals.io/sign_compress_encrypt"

def fetch_data(payload):
    data = {
        "data": payload * 3
    }

    response = requests.get(url, params=data)

    ciphertext = response.json()['ciphertext']
    return payload, len(ciphertext)

flag = 'SIVUSCG{'

while True:
    with ThreadPoolExecutor(max_workers=125 - 48) as executor:
        futures = {executor.submit(fetch_data, flag + chr(i)): chr(i) for i in range(48, 125)}

        smallest_result = None
        smallest_length = float('inf')

        for future in as_completed(futures):
            result = future.result()
            payload, length = result
            if length < smallest_length:
                smallest_result = payload
                smallest_length = length

    if smallest_result is None:
        break

    flag += smallest_result[-1]

    print(f"Current flag: {flag}, Smallest Length: {smallest_length}")

    if len(flag) == 31:
        flag += "}"
        break

print(f"Final flag: {flag}")
```
Flag: *SIVUSCG{C0mpr3SS10n_IsnT_s3cUr3}*

## I Love Crypto Mechanix
### Description:
The infamous LCG... It's back!

### Attachment:
*chall2.py*
```python
from Crypto.Util.number import *
from math import gcd
import random

P = getPrime(512)
Q = getPrime(512)
N = P*Q

e = 3
assert gcd(e, (P-1)*(Q-1)) == 1

flag = bytes_to_long(b"SIVUSCG{REDACTED}")

class LCG:
	def __init__(self, a, b, p, seed):
		self.a = a
		self.b = b
		self.p = p
		self.seed = seed

	def next(self):
		self.seed = (self.a*self.seed + self.b) % self.p
		return self.seed


p = getPrime(128)
a = random.randint(0, 2**32)
b = random.randint(0, 2**32)
seed = random.randint(0, p)
lcg = LCG(a,b,p, seed)

outputs = []
for i in range(6):
	outputs.append(lcg.next())

hints = []
for i in range(3):
	hints.append(lcg.next())

c1 = pow(outputs[0] * flag + outputs[1], e, N)
c2 = pow(outputs[2] * flag + outputs[3], e, N)
c3 = pow(outputs[4] * flag + outputs[5], e, N)

print(f"{p = }")
print(f"{N = }")
print(f"{c1 = }")
print(f"{c2 = }")
print(f"{c3 = }")
print(f"{hints = }")
```

*output.txt*
```
p = 186635132765484126250996539793206145667
N = 58875529304338905505953736667221291201023306734480969247806744848754691476474059614663016432386992446676367074190570583945448346734199513681690392081616727023248926447123883344310985916849639888321099825559426707949564522612871413289064362345332045923908212157578793253630638285901734823301475623394385357159
c1 = 45714565771547930229226359824324184612765804704488147361405122171431410830457625531894507696079301820876695796609440647494597444433096375990065249515774077523541239928616914554861842429334485025363517166565849602924745902936379628721161367954518076487229592008473203339185677650566708246361459229275716576568
c2 = 2938205115049708668056485138176403871361086853648934101627506232566239668541574581519458081557120773367632388591435452676969637296270182244964860487777690358171660162952614090569560548502878423451486434716376263912348986733178496729565668523867452903707337375044080831942666690338685816022188990893636320298
c3 = 34981007099734837238533299758138649644651788051104771864691106724937500933145648874428721015045379341994110064523365875150245487954955323710192812559532234986873511482994229494347841043885794519388227924113364604772627940274894512640323396807771050836451224652645782605991571363112070128949113272566961274576
hints = [5817979666070064699383212732256070495, 122803915435033307307080628491122907417, 96413833466614190818049520251833161905]
```

### Analysis:
Đầu tiên ta sẽ có một class để gen ra số giả ngẫu nhiên:
```python
class LCG:
	def __init__(self, a, b, p, seed):
		self.a = a
		self.b = b
		self.p = p
		self.seed = seed

	def next(self):
		self.seed = (self.a*self.seed + self.b) % self.p
		return self.seed
```
Cái này thì vẫn đúng như format bình thường của **Linear Congruential Generator**. Và cũng vì thế mà nếu có 4 outputs, ta có thể khôi phục tất cả các tham số của thuật toán này mà không cần biết trước một tham số nào.

Để ý đoạn code bên dưới thì ta có như sau:
```python
p = getPrime(128)
a = random.randint(0, 2**32)
b = random.randint(0, 2**32)
seed = random.randint(0, p)
lcg = LCG(a,b,p, seed)

outputs = []
for i in range(6):
	outputs.append(lcg.next())

hints = []
for i in range(3):
	hints.append(lcg.next())
```

Ở trong *output.txt* thì ta đã được cung cấp `p` và `hints` bao gồm 3 phần tử gen ra từ thuật toán LCG. Khi đã có modulus và 3 outputs, ta hoàn toàn có thể khôi phục mutipler và increment - `a` và `b`. 

Đoạn code tiếp theo, ta có được 3 ciphertext mã hóa sử dụng RSA:
```python
c1 = pow(outputs[0] * flag + outputs[1], e, N)
c2 = pow(outputs[2] * flag + outputs[3], e, N)
c3 = pow(outputs[4] * flag + outputs[5], e, N)
```
Với `N` được lấy ở đầu code như sau:
```python
P = getPrime(512)
Q = getPrime(512)
N = P*Q

e = 3
assert gcd(e, (P-1)*(Q-1)) == 1
```

Do có thể recover lại được `a`, `b` nên ta hoàn toàn có thể tính được seed và thu được mảng `outputs`. Từ 3 biểu thức trên, ta sẽ có được 3 phương trình:

$$ \left\{ \begin{array}{l}f_1 \equiv (Y_0x + Y_1)^3 - c_1 \pmod N \\ f_2 \equiv (Y_2x + Y_3)^3 - c_2 \pmod N \\ f_3 \equiv (Y_4x + Y_5)^3 - c_3 \pmod N \end{array} \right. $$ 

Do bậc của các phương trình này là tương đối nhỏ, ta có thể tìm được ước chung lớn nhất của chúng với số mũ cao nhất là 1 (x hay flag). Hay nói cách khác là **Franklin–Reiter related-message attack**.

### Solution:
```python
from math import gcd
from Crypto.Util.number import *
from sage.all import *

def attack(y, m=None, a=None, c=None):
    """
    Recovers the parameters from a linear congruential generator.
    If no modulus is provided, attempts to recover the modulus from the outputs (may require many outputs).
    If no multiplier is provided, attempts to recover the multiplier from the outputs (requires at least 3 outputs).
    If no increment is provided, attempts to recover the increment from the outputs (requires at least 2 outputs).
    :param y: the sequential output values obtained from the LCG
    :param m: the modulus of the LCG (can be None)
    :param a: the multiplier of the LCG (can be None)
    :param c: the increment of the LCG (can be None)
    :return: a tuple containing the modulus, multiplier, and the increment
    """
    if m is None:
        assert len(
            y) >= 4, "At least 4 outputs are required to recover the modulus"
        for i in range(len(y) - 3):
            d0 = y[i + 1] - y[i]
            d1 = y[i + 2] - y[i + 1]
            d2 = y[i + 3] - y[i + 2]
            g = d2 * d0 - d1 * d1
            m = g if m is None else gcd(g, m)

        assert is_prime_power(
            m), "Modulus must be a prime power, try providing more outputs"

    gf = GF(m)
    if a is None:
        assert len(
            y) >= 3, "At least 3 outputs are required to recover the multiplier"
        x0 = gf(y[0])
        x1 = gf(y[1])
        x2 = gf(y[2])
        a = int((x2 - x1) / (x1 - x0))

    if c is None:
        assert len(
            y) >= 2, "At least 2 outputs are required to recover the multiplier"
        x0 = gf(y[0])
        x1 = gf(y[1])
        c = int(x1 - a * x0)

    return m, a, c

p = 186635132765484126250996539793206145667
N = 58875529304338905505953736667221291201023306734480969247806744848754691476474059614663016432386992446676367074190570583945448346734199513681690392081616727023248926447123883344310985916849639888321099825559426707949564522612871413289064362345332045923908212157578793253630638285901734823301475623394385357159
c1 = 45714565771547930229226359824324184612765804704488147361405122171431410830457625531894507696079301820876695796609440647494597444433096375990065249515774077523541239928616914554861842429334485025363517166565849602924745902936379628721161367954518076487229592008473203339185677650566708246361459229275716576568
c2 = 2938205115049708668056485138176403871361086853648934101627506232566239668541574581519458081557120773367632388591435452676969637296270182244964860487777690358171660162952614090569560548502878423451486434716376263912348986733178496729565668523867452903707337375044080831942666690338685816022188990893636320298
c3 = 34981007099734837238533299758138649644651788051104771864691106724937500933145648874428721015045379341994110064523365875150245487954955323710192812559532234986873511482994229494347841043885794519388227924113364604772627940274894512640323396807771050836451224652645782605991571363112070128949113272566961274576
hints = [5817979666070064699383212732256070495, 122803915435033307307080628491122907417, 96413833466614190818049520251833161905]

p, a, b = attack(hints, m=p)

a_inv = inverse(a, p)

recovers = [0] * 7
x = hints[0]
for i in range(7):
    recovers[6 - i] = (x - b) * a_inv % p
    x = (x - b) * a_inv % p

class LCG:
    def __init__(self, a, b, p, seed):
        self.a = a
        self.b = b
        self.p = p
        self.seed = seed

    def next(self):
        self.seed = (self.a*self.seed + self.b) % self.p
        return self.seed

seed = recovers[0]
lcg = LCG(a, b, p, seed)

outputs = []
for i in range(6):
    outputs.append(lcg.next())

hints = []
for i in range(3):
    hints.append(lcg.next())

assert hints == [5817979666070064699383212732256070495,
                 122803915435033307307080628491122907417, 96413833466614190818049520251833161905]

# Franklin–Reiter related-message attack
e = 3

pgcd = lambda g1, g2: g1.monic() if not g2 else pgcd(g2, g1%g2)

x = PolynomialRing(Zmod(N), 'x').gen()
f1 = (outputs[0] * x + outputs[1])**e - c1
f2 = (outputs[2] * x + outputs[3])**e - c2

g = int(-pgcd(f1, f2)[0])
print(long_to_bytes(g))
```
Flag: *SIVUSCG{Y0u_mus1_b3_M4ster_0f_th3_LCGs!}*

## Limitless Learning Links
### Description:
A simple ECC problem.

### Attachments:
*chall2.sage*
```python
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import random
import os
import hashlib

flag = b"SIVUSCG{REDACTED}"

p = getPrime(256)
a = random.randint(2024, 2^32)
b = random.randint(2024, a)

F = GF(p)

E = EllipticCurve(F, [a, b])
G = list(E.gens()[0])[:2]

print(f"{G = }")

secret = (str(a) + str(b)).encode()
key = hashlib.sha256(secret).digest()[:16]
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)

ct = iv + cipher.encrypt(pad(flag, 16))
print(f"{p = }")
print(f"{ct = }")
```

*output.txt*
```
G = [47955680961873936976498017250517754087050557384283400732143179213184250507270, 29032426704946836093200696288262246197660493082656478242711220086643009788423]
p = 61858486249019152861579012404896413787226732625798419511000717349447821289579
ct = b"\x18\xf4$\xf1\xe5WA[\xf2P\xfa\xfcEE\t\xed\xe2m\xaf\xf6$K\xf6\xae\xd9K\x81\x95D\xe3`W\x8f\x04\xfbI\xe5\x06\xd3\xe9\x1a\x1e\x16\xfbZ\xe6\xd2\x06\xd6o|#ns'm\x12\x96\x1d\x8d\xd1\xbd<\xd9\x1dy\x0b\xa95i\xfds\x86|\xad\x92\x88\xa7\x07="
```

### Analysis:

### Solution:



