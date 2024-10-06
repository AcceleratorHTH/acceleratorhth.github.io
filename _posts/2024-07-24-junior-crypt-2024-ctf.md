---
title: Junior.Crypt.2024 CTF
description: CTF-Crypto
author: Pr0pylTh10ur4C1L
date: 2024-07-24 22:43:00 +0700
categories: [Capture The Flag]
tags: [Cryptography]
math: true
mermaid: true
---

Sorry vì giải như cc dbrr nên mình chỉ viết wu bài cuối Misc vì mình thấy còn học được gì đó :v

## From 4 to 7
### Description:
Непростая жизнь в эпоху радио-электронной борьбы. Везде шумы и помехи ...

A difficult life in the era of electronic warfare. There is noise and interference everywhere...

### Attachments:
*Hamming.py*
```python
import numpy as np
from random import randint 
from secret import FLAG

mess = FLAG
mess = mess.encode().hex()
inp = [bin(int(h,16))[2:].zfill(4) for h in mess]
inp = [[int(b) for b in c] for c in inp]


imatr = np.array(inp)
print (imatr)

Gen = np.array([[0,1,1,1,0,0,0], 
                [1,0,1,0,1,0,0], 
                [1,1,0,0,0,1,0], 
                [1,1,1,0,0,0,1]])

code = np.mod(np.dot(imatr, Gen), 2)
scode = "".join(["".join([str(x) for x in c]) for c in code])

print ("".join([hex(int(scode[i:i+8],2))[2:].zfill(2) for i in range(0, len(scode),8)]))



for i in range(0, code.shape[0]):
    ind = randint(0, 2 * code.shape[1])
    if ind < code.shape[1]:
        code[i, ind] = code[i, ind] ^ 1


ecode = "".join(["".join([str(x) for x in c]) for c in code])
print (len(ecode), ecode)

print ("".join([hex(int(ecode[i:i+8],2))[2:].zfill(2) for i in range(0, len(ecode),8)]))
```

*Hamming_out.txt*
```
650e3e66cfdbd4643bb3f8ead2c36d36bd42cf12fe8f55f3c25c6393cbbfb1326119566e952ff8f0db24cbf99d4cf89b2d4ffdb0e6fde3c44bfdb71ecda3e669c48f96d512bf2e0193649fd31d7da5b4e69fe3ea4fbdb486c3a1d44c163627cd08910f89b2d6c39b5326482ef6d8592e7dd13ff6431b7f2fc63926eb6bbd
```

### Analysis:
Vì bài này có ghi rõ chữ **Hamming**, nên mình đã xem qua kha khá các video về một kỹ thuật để sửa lỗi trong truyền tin (error correction).

- But what are Hamming codes? The origin of error correction: https://www.youtube.com/watch?v=X8jsijhllIA  
- Hamming codes part 2: The one-line implementation: https://www.youtube.com/watch?v=X8jsijhllIA

Cụ thể thì bài này là về **Hamming Code (7, 4)**, hệ thống sửa lỗi Hamming sử dụng ma trận sinh 4x7

....



### Solution:
```python
import numpy as np
from random import randint

np.set_printoptions(threshold=np.inf)

ciphertext = "650e3e66cfdbd4643bb3f8ead2c36d36bd42cf12fe8f55f3c25c6393cbbfb1326119566e952ff8f0db24cbf99d4cf89b2d4ffdb0e6fde3c44bfdb71ecda3e669c48f96d512bf2e0193649fd31d7da5b4e69fe3ea4fbdb486c3a1d44c163627cd08910f89b2d6c39b5326482ef6d8592e7dd13ff6431b7f2fc63926eb6bbd"
# ciphertext = "6d9e1e26ffcb546c29bfb8eafb622e909386d509a1260ab932751b47264d2f727c23930bfe38026223c76c96be36dd1b366d89b7127448e09e76a73a9d6af3a9c6a75a9c6e71a9c2a31a9c6271adc6b71a9c6a7188c6231b9e6871a9c6a71a9c6a71e986a71e9c6a75a986a7189d6a73e9c6a712946a70e9d6a31a9c6a70"


ecode = "".join([bin(int(ciphertext[i:i+2], 16))[2:].zfill(8)
                for i in range(0, len(ciphertext), 2)])

ecode_list = [int(bit) for bit in ecode]
code = np.array(ecode_list).reshape(len(ecode_list) // 7, 7)  # 144x7
# => 36 block 4x7

imatr = np.array([[1, 0, 1, 0]])

Gen = np.array([[0, 1, 1, 1, 0, 0, 0],
                [1, 0, 1, 0, 1, 0, 0],
                [1, 1, 0, 0, 0, 1, 0],
                [1, 1, 1, 0, 0, 0, 1]])

encode = np.mod(np.dot(imatr, Gen), 2)


H = np.array([[1, 0, 0, 0, 1, 1, 1],
              [0, 1, 0, 1, 0, 1, 1],
              [0, 0, 1, 1, 1, 0, 1]])


def flip_bit(vector, index):
    vector[index] = 1 ^ vector[index]

for i, row in enumerate(code):
    result = np.mod(np.dot(H, row.T), 2)
    print(f"Original row {i}: {row}, Result: {result}")
    
    # Kiểm tra xem kết quả có giống cột nào của H không
    for j in range(H.shape[1]):
        if np.array_equal(result, H[:, j]):
            print(f"Flipping bit at position {j} of row {i}")
            flip_bit(row, j)
    
    print(f"Corrected row {i}: {row}")

print("Final corrected matrix X:")


for row in code:
    error = row.reshape(1, -1)
    result = np.mod(np.dot(H, error.T), 2)
    print(result)

imatr = code[:,-4:]

hex_string = ''.join([hex(int(''.join(map(str, row)), 2))[2:].zfill(1) for row in imatr])

flag = bytes.fromhex(hex_string)

print(flag)
```

Flag: *grodno{With_th1s_c0de_we_4re_not_afra1d_0f_minor_interf3renc3_and_no1se}*