---
title: Install Sagemath
description: CTF-Crypto
author: Pr0pylTh10ur4C1L
date: 2024-07-24 22:38:00 +0700
categories: [Capture The Flag]
tags: [Cryptography]
math: true
mermaid: true
published: false
---

Cài các gói cần thiết cho quá trình install

```bash
sudo apt-get install bc binutils bzip2 ca-certificates cliquer cmake curl ecl eclib-tools fflas-ffpack flintqs g++ gengetopt gfan gfortran git glpk-utils gmp-ecm lcalc libatomic-ops-dev libboost-dev libbraiding-dev libbrial-dev libbrial-groebner-dev libbz2-dev libcdd-dev libcdd-tools libcliquer-dev libcurl4-openssl-dev libec-dev libecm-dev libffi-dev libflint-arb-dev libflint-dev libfreetype6-dev libgc-dev libgd-dev libgf2x-dev libgiac-dev libgivaro-dev libglpk-dev libgmp-dev libgsl-dev libhomfly-dev libiml-dev liblfunction-dev liblrcalc-dev liblzma-dev libm4rie-dev libmpc-dev libmpfi-dev libmpfr-dev libncurses5-dev libntl-dev libopenblas-dev libpari-dev libpcre3-dev libplanarity-dev libppl-dev libprimesieve-dev libpython3-dev libqhull-dev libreadline-dev librw-dev libsingular4-dev libsqlite3-dev libssl-dev libsuitesparse-dev libsymmetrica2-dev libz-dev libzmq3-dev libzn-poly-dev m4 make nauty openssl palp pari-doc pari-elldata pari-galdata pari-galpol pari-gp2c pari-seadata patch perl pkg-config planarity ppl-dev python3-distutils python3-venv r-base-dev r-cran-lattice singular sqlite3 sympow tachyon tar tox xcas xz-utils

sudo apt-get install texlive-latex-extra texlive-xetex latexmk pandoc dvipng
```

Clone repo trên Github về
```bash
git clone --branch develop https://github.com/sagemath/sage.git
```

Cài đặt sagemath (quá trình này sẽ tương đối lâu ~ 100 phút, và sage cài kiểu này nặng vl ~ 20gb)
```bash
cd sage
make configure
./configure
MAKE="make -j8" make
```
> Để tối ưu, sửa 8 là số core của CPU x2

Tạo symbolic link để có thể sử dụng
```bash
sudo ln -sf $(pwd)/sage /usr/local/bin
```

Thành quả
```bash
trungpq@ENIGMA:~/sage$ sage
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 10.4, Release Date: 2024-07-19                    │
│ Using Python 3.10.12. Type "help()" for help.                      │
└────────────────────────────────────────────────────────────────────┘
sage:
```








