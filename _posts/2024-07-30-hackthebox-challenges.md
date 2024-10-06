---
title: HackTheBox Challenges
description: CTF-Crypto
author: Pr0pylTh10ur4C1L
date: 2024-07-30 22:46:00 +0700
categories: [Capture The Flag]
tags: [Cryptography]
math: true
mermaid: true
---

## RSAisEasy
### Description:
I think this is safe... Right?

### Attachments:
*RSAisEasy.py*
```python
#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, getPrime
from secrets import flag1, flag2
from os import urandom

flag1 = bytes_to_long(flag1)
flag2 = bytes_to_long(flag2)

p, q, z = [getPrime(512) for i in range(3)]

e = 0x10001

n1 = p * q
n2 = q * z

c1 = pow(flag1, e, n1)
c2 = pow(flag2, e, n2)

E = bytes_to_long(urandom(69))

print(f'n1: {n1}')
print(f'c1: {c1}')
print(f'c2: {c2}')
print(f'(n1 * E) + n2: {n1 * E + n2}')
```

*output.txt*
```
n1: 101302608234750530215072272904674037076286246679691423280860345380727387460347553585319149306846617895151397345134725469568034944362725840889803514170441153452816738520513986621545456486260186057658467757935510362350710672577390455772286945685838373154626020209228183673388592030449624410459900543470481715269
c1: 92506893588979548794790672542461288412902813248116064711808481112865246689691740816363092933206841082369015763989265012104504500670878633324061404374817814507356553697459987468562146726510492528932139036063681327547916073034377647100888763559498314765496171327071015998871821569774481702484239056959316014064
c2: 46096854429474193473315622000700040188659289972305530955007054362815555622172000229584906225161285873027049199121215251038480738839915061587734141659589689176363962259066462128434796823277974789556411556028716349578708536050061871052948425521408788256153194537438422533790942307426802114531079426322801866673
(n1 * E) + n2: 601613204734044874510382122719388369424704454445440856955212747733856646787417730534645761871794607755794569926160226856377491672497901427125762773794612714954548970049734347216746397532291215057264241745928752782099454036635249993278807842576939476615587990343335792606509594080976599605315657632227121700808996847129758656266941422227113386647519604149159248887809688029519252391934671647670787874483702292498358573950359909165677642135389614863992438265717898239252246163
```

### Analysis:
Ở bài này, ta biết $n_1 = p.q$, $n_2 = q.z$. Xét phương trình:

$$ sum = n_1.E + n_2 $$  
$$ \Leftrightarrow sum = p.q.E + q.z $$  
$$ \Leftrightarrow sum = q(p.E + z) $$

Do có `q` là nhân tử nên ta chỉ cần lấy GCD của sum với `n1` hoặc `n2` là sẽ có được `q`. Từ đó tính được `p` và giải ra flag1.

Ngoài ra, để ý thêm thì phương trình:

$$ sum = n_1.E + n_2 $$  
$$ \Leftrightarrow n_2 \equiv sum \pmod{n_1} $$  

Có `n2` và `q` rồi ta sẽ tính được `z` và giải ra flag2.

### Solution:
```python
from Crypto.Util.number import *
from sage.all import *

n1 = 101302608234750530215072272904674037076286246679691423280860345380727387460347553585319149306846617895151397345134725469568034944362725840889803514170441153452816738520513986621545456486260186057658467757935510362350710672577390455772286945685838373154626020209228183673388592030449624410459900543470481715269
c1 = 92506893588979548794790672542461288412902813248116064711808481112865246689691740816363092933206841082369015763989265012104504500670878633324061404374817814507356553697459987468562146726510492528932139036063681327547916073034377647100888763559498314765496171327071015998871821569774481702484239056959316014064
c2 = 46096854429474193473315622000700040188659289972305530955007054362815555622172000229584906225161285873027049199121215251038480738839915061587734141659589689176363962259066462128434796823277974789556411556028716349578708536050061871052948425521408788256153194537438422533790942307426802114531079426322801866673
sum = 601613204734044874510382122719388369424704454445440856955212747733856646787417730534645761871794607755794569926160226856377491672497901427125762773794612714954548970049734347216746397532291215057264241745928752782099454036635249993278807842576939476615587990343335792606509594080976599605315657632227121700808996847129758656266941422227113386647519604149159248887809688029519252391934671647670787874483702292498358573950359909165677642135389614863992438265717898239252246163
e = 0x10001


q = gcd(n1, sum)
p = n1 // q
d1 = inverse(e, (p-1)*(q-1))

flag1 = long_to_bytes(pow(c1, d1, n1))

n2 = sum % n1
z = n2 // q
d2 = inverse(e, (q-1)*(z-1))

flag2 = long_to_bytes(pow(c2, d2, n2))

print(flag1 + flag2)
```
Flag: *HTB{1_m1ght_h4v3_m3ss3d_uP_jU$t_4_l1ttle_b1t?}*

## Secure Signing
### Description:
Can you crack our Ultra Secure Signing Oracle?

### Attachment:
*server.py*
```python
from hashlib import sha256
from secret import FLAG

WELCOME_MSG = """
Welcome to my Super Secure Signing service which uses unbreakable hash function.
We combine your Cipher with our secure key to make sure that it is more secure than it should be.
"""


def menu():
    print("1 - Sign Your Message")
    print("2 - Verify Your Message")
    print("3 - Exit")


def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


def H(m):
    return sha256(m).digest()


def main():
    print(WELCOME_MSG)

    while True:
        try:
            menu()
            choice = int(input("> "))
        except:
            print("Try again.")
            continue

        if choice == 1:
            message = input("Enter your message: ").encode()
            hsh = H(xor(message, FLAG))
            print(f"Hash: {hsh.hex()}")
        elif choice == 2:
            message = input("Enter your message: ").encode()
            hsh = input("Enter your hash: ")
            if H(xor(message, FLAG)).hex() == hsh:
                print("[+] Signature Validated!\n")
            else:
                print(f"[!] Invalid Signature!\n")
        else:
            print("Good Bye")
            exit(0)


if __name__ == "__main__":
    main()
```

### Analysis:
Mấu chốt của bài này là ở hàm `xor`:
```python
def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])
```
Với code xor như này thì nếu `a`, `b` khác độ dài thì nó sẽ chỉ xor tới độ dài của cái ngắn hơn. Ví dụ: Nếu lấy HTB ^ X, ta sẽ được kết quả của H ^ X. Ngoài ra, ta cũng biết, khi lấy H ^ H, ta sẽ thu được giá trị 0.

Dựa vào đó, mình có thể bruteforce flag bằng cách gửi kiểu như sau (giả sử với kí tự đầu tiên):
- Tính sha256 của b"\x00"
- Ở choice2, bruteforce message bằng 256 kí tự ascii, đi kèm với nó là sha256 vừa nãy. Khi này hệ thống sẽ check: sha256(X ^ flag[0]) == sha256(b'\x00') hay không. Nếu có, đó chính là kí tự của flag.
- Lặp lại cho tới khi nào tìm ra hết flag (tính hash của b'\x00' * 2, *3, ...)

### Solution:
```python
from hashlib import sha256
from Crypto.Util.number import *
from pwn import *
from tqdm import tqdm

conn = remote("94.237.59.231","34037")

for _ in range(7):
    conn.recvline()

known = b'HTB{'
for i in range(5,100):
    
    payload = b'\x00' * i
    hsh = sha256(payload).hexdigest().encode()
    
    for i in tqdm(range(33,127)):
        conn.sendline(b'2')
        conn.sendline(known + chr(i).encode())
        conn.sendline(hsh)

        res = conn.recvline()
        for _ in range(4):
            conn.recvline()

        if b'[+] Signature Validated!' in res:
            known += chr(i).encode()
            print(known)
            break
        
    if b"}" in known:
        break
    
print(known)
```
Flag: *HTB{r0ll1n6_0v3r_x0r_w17h_h@5h1n6_0r@cl3_15_n07_s3cur3!@#}*
