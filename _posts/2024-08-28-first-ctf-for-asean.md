---
title: FIRST CTF for ASEAN
description: CTF-Crypto
author: Pr0pylTh10ur4C1L
date: 2024-08-28 10:35:00 +0700
categories: [Capture The Flag]
tags: [Cryptography]
math: true
mermaid: true
media_subpath: /assets/img/2024-08-28-first-ctf-for-asean/
---

## Russian handbook and an USB key
### Description:
**Evengii Mikhaylovich Serebriakov handbook and an USB key**

In the conflict-ridden region of Bakhmut, Ukraine, a Ukrainian soldier was on patrol in an area that had been abandoned by Russian forces. While exploring the area, the soldier stumbled upon an abandoned building and upon entering, found a handbook and a USB key tagged with "vx-подземный пароль" lying on a dusty table.

The handbook appeared to be a manual for operating a sophisticated piece of military equipment. Upon closer inspection, the soldier realized that it was written in bureaucratic Russian.

Curious about the contents of the USB key, the soldier plugged it into his laptop and found that it contained a treasure trove of information about the Russian' activities in the area. There were photographs of their base camps, plans for upcoming attacks, and even information about their leaders and chain of command.

Realizing the importance of the find, the soldier immediately reported it to his superiors, who were able to use the information to gain valuable intelligence on the Russian forces in the area and especially concerning their cybersecurity operations. This discovery was a significant impact for the Ukrainian military, and it helped them to gain an advantage over their opponents in the ongoing conflict.

A remaining encrypted zip file was never analyzed. The zip file contains potential cryptographic materials which were used in the conflict.

> Hint: Focus on a single MISP event.

### Attachment:
\<Nah>

### Analysis:
Do bài này cho một file zip có đặt mật khẩu nên mình đã thử crack zip các kiểu nhưng không ra. Sau cùng thì, đây mới là mật khẩu

```
zarazhennyy
```

Nôm na thì đây là cách lấy được nó

![1](<1.png>)

Sau khi unzip thì mình sẽ được folder tên là `misp_json` chứa các file json như sau:

![2](<2.png>)

Dựa trên đề bài thì mình sẽ phải tìm được "cryptographic materials" ở đâu đó trong các file này, cụ thể là mình thấy như sau trong file `f438b116-58db-44d5-b37f-167d1b3a2f41.json`, có vẻ sẽ chứa thông tin quan trọng

![3](3.png)

Tại sao? Đây là lí do:

![4](4.png)

Trong này có kha nhiều thông tin tình báo như ảnh, vé,..., nói chung là các bạn decode ra xem sẽ thấy khá là thú vị. Sau cùng, mình tìm được cụm từ như sau

![5](5.png)

Lướt xuống dưới, mình thấy được một key như sau. Một số dòng bên trên cũng có ghi nó là dạng RC4. 

![6](6.png)

Đến đây thì mình đoán key chính là thứ đề bài yêu cầu, hay flag nên mình đã nộp thử. Tuy nhiên thì không thành công. Mình thử tìm "generic-symmetric-key" và nhận ra key này còn 2 phần nữa.

![7](7.png)
![8](8.png)

Vậy là mình thu được giá trị key như sau:

```
8jEUgjnuO0fOUxQjL.XXRJmX2EYHY2buG9I/YCQ
```

Submit và mình đã thành công giải được bài này

### Solution:
Flag: _8jEUgjnuO0fOUxQjL.XXRJmX2EYHY2buG9I/YCQ_
> Thật ra về kĩ thuật thì bài này không có gì thú vị lắm. Lí do khiến cho mình cố làm ra nó là vì mình thấy đống tài liệu này có vẻ hay ho, một phần nữa cũng là chưa có ai solve nó :>

## Unexpected Hash - part 1/2
### Description:
During an incident analysis you have received the following line found into the /etc/shadow file of a given host.

`masterone:$6$EdDCRT.jrR/rgrqa$ABawIS7d1LJ9SxxyuRI4d6JRKlpnNfAg19Si/X1NohliQEPcz.h2ybgjYrFLIDr2IsxLQR2eBwyc3ZgcMNy4p0:19478:0:99999:7:::`

It looks like the same user was used in lateral movement and it would be nice to recover the password in order to proceed with the investigation of other hosts.

What is the password?

### Analysis:

Bài này thì chày cối hashcat thoi :< Mình chạy đủ kiểu hashcat từ chỉ a-z, A-z, 0-9, $\... hay kết hợp chúng lại. Và sau cùng thì terminal chạy lệnh này sẽ ra được kết quả

```powershell
hashcat -m 1800 -a 3 hashes.txt ?l?l?l?l?l
```

Giải thích thì `$6$` là sha512crypt trong UNIX, nên mình sẽ dùng -m là 1800, -a 3 là mode bruteforce, hashes.txt là file chứa chuỗi đề bài cho ("masterone:....7:::") và ?l?l?l?l?l là dài 5 kí tự, tất cả đều chỉ trong [a-z]

### Solution:
```terminal
PTU@ENIGMA:~/firstctf/Unexpected_Hash_-_part_1_2$ hashcat -m 1800 -a 3 hashes.txt ?l?l?l?l?l
hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2870/5804 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Brute-Force
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>

$6$EdDCRT.jrR/rgrqa$ABawIS7d1LJ9SxxyuRI4d6JRKlpnNfAg19Si/X1NohliQEPcz.h2ybgjYrFLIDr2IsxLQR2eBwyc3ZgcMNy4p0:msctf

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$EdDCRT.jrR/rgrqa$ABawIS7d1LJ9SxxyuRI4d6JRKlpnNfA...MNy4p0
Time.Started.....: Wed Aug 28 10:13:24 2024 (1 hour, 33 mins)
Time.Estimated...: Wed Aug 28 11:46:31 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?l?l?l?l?l [5]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1318 H/s (17.33ms) @ Accel:128 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 7435008/11881376 (62.58%)
Rejected.........: 0/7435008 (0.00%)
Restore.Point....: 285952/456976 (62.57%)
Restore.Sub.#1...: Salt:0 Amplifier:1-2 Iteration:4096-5000
Candidate.Engine.: Device Generator
Candidates.#1....: muntf -> mosog

Started: Wed Aug 28 10:13:22 2024
Stopped: Wed Aug 28 11:46:32 2024
```
Flag: _msctf_

## Unexpected Hash - part 2/2
### Description:
According to the Linux man pages, what is the hashing method used?

Answer format [prefix:hashing_mehod]

### Analysis:
Tôi đã mất công ngồi crack suốt cả tháng để có thể thấy được bài 2/2 mà trông nó lại ez như thế này :( Làm được câu 1 thì câu này phân tích gì nữa.

### Solution:
Flag: `$6$:sha512crypt`