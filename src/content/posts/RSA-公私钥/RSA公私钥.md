---
title: RSA公私钥
published: 2025-11-29
description: "RSA公私钥相关知识"
tags: ["RSA", "博客", "Markdown"]
category: RSA
image: "api"
draft: false
---
## <u></u>1. 概述
在公钥密码学（也称为 非对称密码学）中，加密机制依赖于两个相关的密钥，一个公钥和一个私钥。公钥用于加密消息，而只有私钥的所有者才能解密消息。

在本教程中，我们将了解如何从 PEM 文件中读取公钥和私钥。

首先，我们将研究有关公钥密码学的一些重要概念。然后，我们将学习如何解析 PEM 文件。

## 2. 概念
在开始之前，让我们先了解一些关键概念。

**X.509 **是定义公钥证书格式的标准。 因此，这种格式描述了其他信息中的公钥。

DER是最流行的编码格式，用于在文件中存储 X 证书、<font style="background-color:#FBDE28;">PKCS8 </font>私钥等数据。这是一种二进制编码，无法使用文本编辑器查看生成的内容。

PKCS8是用于存储私钥信息的标准语法。可以选择使用对称算法对私钥进行加密。

该标准不仅可以处理 RSA 私钥，还可以处理其他算法。PKCS8 私钥通常通过 PEM 编码格式进行交换。

PEM是 DER 证书的 base-64 编码机制。PEM 还可以对其他类型的数据进行编码，例如公钥/私钥和证书请求。

PEM 文件还包含描述编码数据类型的页眉和页脚，举例如下：

-----BEGIN RSA PRIVATE KEY-----

…Base64 encoding of the DER encoded certificate…

-----END RSA PRIVATE KEY-----

## 3.解析PEM证书
### 示例证书：
-----BEGIN RSA PRIVATE KEY-----

MIICXAIBAAKBgQDnsN1F66mF6h6y/XpyN+ZU/w5AyeWBjZNIqi33/ATn4qQpw+kD

HrKyF7sQ/RNw6tibM90iM6VOA14305umPbPROJJs3JoB6Lao74SUm58aO9T+Ct7r

O52E+3r5jyDQicdRl6lIhLigNADXPD/KoNwfrRrCyw4wTHMZhSHc8eUHeQIDAQAB

AoGABVTIgqddiztL4Yp7ms02e5Yy2cLLiSOc0/s2e5JM+pj4dg2P+wZlzjtFjqqE

HAELYubam8LcduMU8+vmlPiufoK9fo47fLsX1PFCY9TDKL1dFlZgBAmJU7hR27h/

gCo4r3PMub/snq7n+skrbarZbX1J6Q1o5UYKFIrrIjNObEECQQD0DIzIdMObPUUu

W+JXg10kz/ayYn3irxZmp5ngc+b9WZfSOPehZBsLWsIb1eC7y9DZMhZfBQ/sPaO8

0tvqJMUFAkEA8wlj3B3zK20pK+Hj+vFiAlaQmqILTSfv/9jMm8tbVfXt+bHrmZdN

jruGVQDb7V2pW9HeG5PgDB3vKXeOiVfC5QJAYikKFzaf1rj2ModSqtBzjnL3Txi+

eYbjA7c19UmpBw4aOrwfHhMdrZt7p6aHFgIMps+2n9Fxbhv8194YBj1z4QJAPONW

XFg4iuGvVeoi9sSwvEs5sTP1xt/BlgSXxlRdTpztgQgdMX6hlKfQkM1FTCOSAYoD

rj8O+5ooR+hHEoulLQJBAOtaMvMWIOG7mARngpwqfJ07L41/T0ITHteiiYJfCurz

kLVCx1XA3MlN+u5gn7osUHMbah0Ze3uakSZ6za3mL5Y=

-----END RSA PRIVATE KEY-----

### 解析：
1）删除页眉、页脚和新行。

2）将 Base64 编码的字符串解码为其对应的二进制格式。

解析之后的16进制数据：

3082025C02010002818100E7B0DD45EBA985EA1EB2FD7A7237E654FF0E40C9E5818D9348AA2DF7FC04E7E2A429C3E9031EB2B217BB10FD1370EAD89B33DD2233A54E035E37D39BA63DB3D138926CDC9A01E8B6A8EF84949B9F1A3BD4FE0ADEEB3B9D84FB7AF98F20D089C75197A94884B8A03400D73C3FCAA0DC1FAD1AC2CB0E304C73198521DCF1E5077902030100010281800554C882A75D8B3B4BE18A7B9ACD367B9632D9C2CB89239CD3FB367B924CFA98F8760D8FFB0665CE3B458EAA841C010B62E6DA9BC2DC76E314F3EBE694F8AE7E82BD7E8E3B7CBB17D4F14263D4C328BD5D16566004098953B851DBB87F802A38AF73CCB9BFEC9EAEE7FAC92B6DAAD96D7D49E90D68E5460A148AEB22334E6C41024100F40C8CC874C39B3D452E5BE257835D24CFF6B2627DE2AF1666A799E073E6FD5997D238F7A1641B0B5AC21BD5E0BBCBD0D932165F050FEC3DA3BCD2DBEA24C505024100F30963DC1DF32B6D292BE1E3FAF1620256909AA20B4D27EFFFD8CC9BCB5B55F5EDF9B1EB99974D8EBB865500DBED5DA95BD1DE1B93E00C1DEF29778E8957C2E5024062290A17369FD6B8F6328752AAD0738E72F74F18BE7986E303B735F549A9070E1A3ABC1F1E131DAD9B7BA7A68716020CA6CFB69FD1716E1BFCD7DE18063D73E102403CE3565C58388AE1AF55EA22F6C4B0BC4B39B133F5C6DFC1960497C6545D4E9CED81081D317EA194A7D090CD454C2392018A03AE3F0EFB9A2847E847128BA52D024100EB5A32F31620E1BB980467829C2A7C9D3B2F8D7F4F42131ED7A289825F0AEAF390B542C755C0DCC94DFAEE609FBA2C50731B6A1D197B7B9A91267ACDADE62F96

### **解析数据：**
3082025C# 标签头，类型为SEQUENCE (sequence 序列)，此标签头共 4 字节。注（不确定）：3082 应该指 私钥  
以下共 604 字节 (0x025c)

020100 # 整型 长度 为 0 (0x00)，内容：version

028181 # 整型 长度 为 129 字节 (0x81)，内容：模数 n (modulus)

00e7b0dd45eba985ea1eb2fd7a7237e654ff0e40c9e5818d9348aa2df7fc04e7e2a429c3e9031eb2b217bb10fd1370ead89b33dd2233a54e035e37d39ba63db3d138926cdc9a01e8b6a8ef84949b9f1a3bd4fe0adeeb3b9d84fb7af98f20d089c75197a94884b8a03400d73c3fcaa0dc1fad1ac2cb0e304c73198521dcf1e50779

0203 # 整型 长度 为 3 字节(0x03)，内容：e (公钥指数)

010001

028180 # 整型 长度 为 128 字节(0x80)，内容：d (私钥指数)

0554c882a75d8b3b4be18a7b9acd367b9632d9c2cb89239cd3fb367b924cfa98f8760d8ffb0665ce3b458eaa841c010b62e6da9bc2dc76e314f3ebe694f8ae7e82bd7e8e3b7cbb17d4f14263d4c328bd5d16566004098953b851dbb87f802a38af73ccb9bfec9eaee7fac92b6daad96d7d49e90d68e5460a148aeb22334e6c41

0241 # 整型 长度 为 65 字节(0x41)，内容：p (素数)

00f40c8cc874c39b3d452e5be257835d24cff6b2627de2af1666a799e073e6fd5997d238f7a1641b0b5ac21bd5e0bbcbd0d932165f050fec3da3bcd2dbea24c505

0241 # 整型 长度 为 65 字节(0x41)，内容：q (素数)

00f30963dc1df32b6d292be1e3faf1620256909aa20b4d27efffd8cc9bcb5b55f5edf9b1eb99974d8ebb865500dbed5da95bd1de1b93e00c1def29778e8957c2e5

0240 # 整型 长度 为 64 字节(0x40)，内容：d mod(p-1)

62290a17369fd6b8f6328752aad0738e72f74f18be7986e303b735f549a9070e1a3abc1f1e131dad9b7ba7a68716020ca6cfb69fd1716e1bfcd7de18063d73e1

0240 # 整型 长度 为 64 字节(0x40)，内容：d mod(q-1)

3ce3565c58388ae1af55ea22f6c4b0bc4b39b133f5c6dfc1960497c6545d4e9ced81081d317ea194a7d090cd454c2392018a03ae3f0efb9a2847e847128ba52d

0241 # 整型 长度 为 65 字节(0x41)，内容：(1/q)mod p <即 (q**-1)mod p>

00eb5a32f31620e1bb980467829c2a7c9d3b2f8d7f4f42131ed7a289825f0aeaf390b542c755c0dcc94dfaee609fba2c50731b6a1d197b7b9a91267acdade62f96

通过上面解析可以获取到证书中的RSA密钥。

## 生成过程
### 公钥生成
```python
from Crypto.PublicKey import RSA
rsa_components = (int(n), int(e))  # 只需要n，e
keypair = RSA.construct(rsa_components)
with open('pubckey.pem', 'wb') as f :
    f.write(keypair.exportKey())

```



### 私钥生成
```python
from Crypto.PublicKey import RSA
rsa_components = (int(n),int(e),int(d),int(p),int(q))  # 至少需要n、e、d
keypair = RSA.construct(rsa_components)
with open('private1.pem', 'wb') as f :
    f.write(keypair.exportKey())

```

### 公钥读取
```python
from Crypto.PublicKey import RSA
with open("pubckey.pem","rb") as f:
    key = RSA.import_key(f.read())
    print('n = %d' % key.n)
    print('e = %d' % key.e)
```

### 私钥读取
```python
from Crypto.PublicKey import RSA
with open("private1.pem", "rb") as f:
        key = RSA.import_key(f.read())
        print('n = %d' % key.n)
    print('e = %d' % key.e) 
    print('d = %d' % key.d)
    print('p = %d' % key.p) 
    print('q = %d' % key.q)
    print('u = %d' % key.u)
```

有 ` n ,e ,d ,p , q, u ` 个6个参数，其中u=p−1 mod q 。

### OAEP
> **最优非对称加密填充**（英语：**Optimal Asymmetric Encryption Padding**，缩写：**OAEP**
>

![](./e57957088b7385803809a4499c0c0a2c_MD5.jpeg)  
OAEP结构，正常读取求解会导致结果乱码。  
需要针对性的代码

```python
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


random_generator = Random.new().read
rsa = RSA.generate(2048, random_generator)
# 生成私钥
private_key = rsa.exportKey()
# print(private_key.decode('utf-8'))
with open('rsa_private_key.pem', 'wb')as f:
    f.write(private_key)
# 生成公钥
public_key = rsa.publickey().exportKey()
# print(public_key.decode('utf-8'))
with open('rsa_public_key.pem', 'wb')as f:
    f.write(public_key)


#测试用密钥加密
public_key = RSA.importKey(public_key)
msg='flag'
pk = PKCS1_v1_5.new(public_key)
encrypt_text = pk.encrypt(msg.encode())
print(encrypt_text)

#测试密钥解密
private_key = RSA.importKey(private_key)
pk = PKCS1_v1_5.new(private_key)
msg = pk.decrypt(encrypt_text)
print(msg)


#两种标准
rsa_components = (n, e, int(d), p, q)
arsa = RSA.construct(rsa_components)
rsakey = RSA.importKey(arsa.exportKey())
rsakey = PKCS1_OAEP.new(rsakey)
decrypted = rsakey.decrypt(c)
print(decrypted)
```

## 解析公私钥
### openssl
openssl 是linux系统里一个开源的的软件包，应用程序通过 openssl 加密通信避免窃听，主要库为C语言写成。openssl还支持许多加密算法，例如 RSA、DSA、ECDSA、ECDHE、Diffie–Hellman key exchange等。这里主要介绍 openssl 用于RSA中 pem文件的加解密。

**生成RSA私钥文件**

```shell
openssl genrsa -out private_rsa.pem 1024
```

**生成RSA公钥文件**

```shell
openssl rsa -in private_rsa.pem -pubout -out public_rsa.pem
```

**读取公钥pem**

```shell
openssl rsa -pubin -text -modulus -in 1.pem
```

**其中** `Modulus` **为模数** `n` **的16进制下的值，** `Exponent` **为加密指数** `e` 。

**读取私钥pem**

```shell
openssl rsa -in 1.pem -text
```

**其中一共有8个参数，分别为：**

> **RSAPrivateKey::= SEQUENCE {**
>
> **version Version,**
>
> **modulus INTEGER, -- n 模数 n**
>
> **publicExponent INTEGER, -- e 加密指数 e**
>
> **privateExponent INTEGER, -- d 解密指数 d**
>
> **prime1 INTEGER, -- p 模数n的两个大因子p和q**
>
> **prime2 INTEGER, -- q**
>
> **exponent1 INTEGER, -- d mod (p-1)**
>
> **exponent2 INTEGER, -- d mod (q-1)**
>
> **coefficient INTEGER -- (inverse of q) mod p**
>
> **}**
>

### 原始数据读取
**一、读取公钥pem**

例如一个pem公钥文件

```python
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXrGq02sFKE5Znv2GljNLThSWB
P6N2NfV41vaADS/ZEZB6JPo0RLTg4UYZOGg5SLYQkr5IvO6thXQJ+xFduuOYl8oe
p4BeLZLIwFnxZQIjSDe5GD/Id6wPLTDTGFB4y7aVK/D0v+y12uW44HrYAUeTCNU8
renYB8YQwZIwuO2qZwIDAQAB
-----END PUBLIC KEY-----
```

读取其中的base64编码并转hex得到

```python
30819f300d06092a864886f70d010101050003818d0030818902818100d7ac6ab4dac14a139667bf61a58cd2d38525813fa37635f578d6f6800d2fd911907a24fa3444b4e0e1461938683948b61092be48bceead857409fb115dbae39897ca1ea7805e2d92c8c059f16502234837b9183fc877ac0f2d30d3185078cbb6952bf0f4bfecb5dae5b8e07ad801479308d53cade9d807c610c19230b8edaa670203010001
```

其中

|  |  |
| --- | --- |
| 内容 | 解析 |
| 3081 | 标签头，81表示后面接1bytes，82表示后接2bytes表示长度 |
| 9f | 后接上0xdf(159)bytes的内容 |
| 300d06092a864886f70d010101050003 | 固定序列(具体包含的内容未知) |
| 81 | 后面接1bytes，为82则表示后接2bytes表示长度 |
| 8d | 后接上0x8d(141)bytes的内容 |
| 0030 | 固定序列 |
| 81 | 后面接1bytes，为82则表示后接2bytes表示长度 |
| 89 | 后接上0x89(137)bytes的内容 |
| 0281 | 81表示后面接1bytes，82表示后接2bytes表示长度 |
| 81 | 后面的模数n长度为0x81bytes，但是其中1bytes为00，故生成的模数二进制位数为1024 |
| 00d7-67 | 模数n的16进制形式 |
| 0203010001 | 02后接加密指数e的长度03即内容010001 |


**二、读取私钥pem**

私钥的读取和公钥大同小异，但是私钥的内容会比公钥多一些，相比于公钥，私钥还有

`p,q,dp,dq,qinvp` **。**

测试样例，生成了个1024位的RSA对象之后，讲该变量中每一个值给读出来。

```python
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
with open('1.pem','wb') as f:
    f.write(b'n = ' + str(hex(key.n)[2:]).encode() + b'\n')
    f.write(b'e = ' + str(hex(key.e)[2:]).encode() + b'\n')
    f.write(b'p = ' + str(hex(key.p)[2:]).encode() + b'\n')
    f.write(b'q = ' + str(hex(key.q)[2:]).encode() + b'\n')
    f.write(b'd = ' + str(hex(key.d)[2:]).encode() + b'\n')
    f.write(b'dp = '+ str(hex((key.d) % ((key.p) - 1))[2:]).encode() + b'\n')
    f.write(b'dq = ' + str(hex((key.d) % ((key.q) - 1))[2:]).encode() + b'\n')
    f.write(b'p_q = ' + str(hex(pow(key.p,-1,key.q))[2:]).encode() + b'\n')
    f.write(b'q_p = ' + str(hex(pow(key.q, -1, key.p))[2:]).encode() + b'\n')
    f.write(key.exportKey('PEM'))

with open('1.pem','rb') as f:
    print(f.read().decode())
```

例如一个私钥文件

```python
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCw/aHmn+xs4OCJbVu1U0JhR/M4h42TYeVyR02wdtV+Dwt+CrE7
JlZyKBCM+jOXx+tgoxZ6e/U+voP9iU4Fpdmyi/HE8U5ZZ6YH8Bzx8Qh8vM3QM8XU
W4NGfg6N9VG7uVdwioOBbZ9AoOBYHjMdxoZ8O5AxO3Lp0rzkfQTUe9CQFwIDAQAB
AoGAE+puYeOj+HpzebNXCvfT89tjSHykVy3AYlQYr18n1df+jI/KcqP1PUI53os2
7ADggQ7I9D5nkchhVNGy+Fq5vLgdTRYZ859iT1h9i+bTwt7Uq2OfJR/NRkVcvaSv
7UKHmF3AyzNOpSf2NunvYUSJ5n92jUuXdXkvqmeS3/FOWA0CQQDJbCjac+mVzCzZ
U84s+7JXviTHPoN9GXZY3vr1tIBogwyftCa1+pVIYu7WTwwHzcKe9KU4GPbLCTYU
45FJ0ejjAkEA4PK+h3cB65Oahwmxza1w7tugGNTXcLhMpJ8PCO65pG0wRIpp3doC
TRLKdUUAcVromiiU8m/Mt8jwyhVxFMpGPQJAN6/uj47yapbbY253FxqzUOzh8DAJ
XGHYxXNIgPvZcIuixtigxzkzYqLvk1KhadrqTtYmg57rRHEUgav09CrTrwJANTc3
+7QbsC9rDycr+Qxe+yLZ7QXtMa1n9EnstKBFKrDqCkz0XpeEk9cuLi/0utxWyqFv
Gyt3ssLGtAf+iHyRwQJAIWcJAM/jTFTMXNUrYK0fa0MMpNMrwnlDb6uyMn/4Q41g
f3RB/34+gFrCRZEhMtasgaOkoHYP3VZQvqkXzyaycg==
-----END RSA PRIVATE KEY-----
```

读取base64转hex(手动排版换行过后)

```python
3082025b02010002818100
b0fda1e69fec6ce0e0896d5bb553426147f338878d9361e572474db076d57e0f0b7e0ab13b26567228108cfa3397c7eb60a3167a7bf53ebe83fd894e05a5d9b28bf1c4f14e5967a607f01cf1f1087cbccdd033c5d45b83467e0e8df551bbb957708a83816d9f40a0e0581e331dc6867c3b90313b72e9d2bce47d04d47bd09017
0203010001
028180 13ea6e61e3a3f87a7379b3570af7d3f3db63487ca4572dc0625418af5f27d5d7fe8c8fca72a3f53d4239de8b36ec00e0810ec8f43e6791c86154d1b2f85ab9bcb81d4d1619f39f624f587d8be6d3c2ded4ab639f251fcd46455cbda4afed4287985dc0cb334ea527f636e9ef614489e67f768d4b9775792faa6792dff14e580d
024100 c96c28da73e995cc2cd953ce2cfbb257be24c73e837d197658defaf5b48068830c9fb426b5fa954862eed64f0c07cdc29ef4a53818f6cb093614e39149d1e8e3
024100 e0f2be877701eb939a8709b1cdad70eedba018d4d770b84ca49f0f08eeb9a46d30448a69ddda024d12ca754500715ae89a2894f26fccb7c8f0ca157114ca463d
0240   37afee8f8ef26a96db636e77171ab350ece1f030095c61d8c5734880fbd9708ba2c6d8a0c7393362a2ef9352a169daea4ed626839eeb44711481abf4f42ad3af
0240   353737fbb41bb02f6b0f272bf90c5efb22d9ed05ed31ad67f449ecb4a0452ab0ea0a4cf45e978493d72e2e2ff4badc56caa16f1b2b77b2c2c6b407fe887c91c1
0240   21670900cfe34c54cc5cd52b60ad1f6b430ca4d32bc279436fabb2327ff8438d607f7441ff7e3e805ac245912132d6ac81a3a4a0760fdd5650bea917cf26b272
```

**解析过程如下：**

|  |  |
| --- | --- |
| 内容 | 解析 |
| 3082 | 标签头，81表示后面接1bytes，82表示后接2bytes表示长度。 |
| 025e | 后接0x25e(606)bytes的内容。 |
| 02010002 | 固定序列 |
| 81 | 81表示后面接1bytes，82表示后接2bytes表示长度。 |
| 81 | 后面的模数n长度为0x81bytes，但是其中1bytes为00，故生成的模数二进制位数为1024 |
| b0fd-9017 | 模数n的16进制 |
| 0203010001 | 02后接加密指数e的长度03即内容010001 |
| 028180 | 81表示后面接1bytes的长度信息，80表示后接0x80(128)bytes长度的信息 |
| 13ea-580d | 私钥指数d的16进制 |
| 024100 | 起始序列 |
| c96c-e8e3 | p的16进制 |
| 024100 | 起始序列 |
| e0f2-463d | q的16进制 |
| 0240 | 起始序列 |
| 37af-d3af | dp的16进制 |
| 0240 | 起始序列 |
| 3537-91c1 | dq的16进制 |
| 0240 | 起始序列 |
| 2167-b272 | q inv p |


+ 用private.pem解密flag.enc

```shell
openssl rsautl -decrypt -in flag.enc -inkey private.pem
```



## 相关例题
### 题目一:
```python
#break.pem
-----BEGIN BREAK PEM PRIVATE-----
MIIEowIBAAKCAQEAw6JUixKmoIZjLyR1Qc/D/3mfTC3YvqKienLM7Nt/83UqpYeg
9rOw02xLtIqgBdVyVkI+MknQdB5tB1W/bo95M8JjmNxi5rcEzXK4A5HiKtNxK9hC
dE1GIt78XcT1FLoM86zxFonkDQ8LxHXPbU22+Ex8ov269pS/BEwZuKohqbIUU4iZ
UltNYW2kaVsavAZw4NyQcQCQoijprdrQZLV6XjC/3+uX6baLaZS+NWHm1M16UHde
IF9B1gNuifO0xnuAWxRENjBIXw/3W8OVvRuRUppY2WYgeEG31fgfOCDoXhWVbqAD
6fJA9JWdkOPDqUAsqFCr2VKnORa2X9V9HdO5lwIDAQABAoIBAQD/////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////AoGBAP//////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////AoGBAP//
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////AoGAZFBey/5KFQ1nOL6xe00r
ehGXxxNQF/7oym0kzI6BBi4awYZ4FCtuGiiAfkcsOS0UhlhFn1gEemnl2f2EF78M
THN5zVM5FSY5Cf8XwJT/fEytuWdCQke7JxVYOLNsEJeViicsasXeWeSL1nPYS3a5
+T4027LUdjikIbu508dTT6UCgYAY+t0pv5nJ93J3773ZZYkLSCG+zXZBSgUtcCoQ
GTBa4Qcr3MLeeUGDkb4qNIBdqWsQR0GiIXLkoIxcmOr66Rs+Hl60MD0kWQA6uz5/
aJOhZc8pO0vGVG3+RbKA4xTxZshopp4CVdCrM20SqXXa3OEqr48Ec1aIES/ymZO8
GuaOwQKBgB4ZWvOfPzCFOselDYyjz2Tub1RY3YrvI1do3jl42nhy/1Aoc6G3XLi4
AIg8gxJGx36aPjpxBfe1HTicBhtUThBxq/A2/Ed1TwxFDvDPjhDc1Js/LL0qxhaP
Z/xYCgGGZftjQqPTy+S62ppYVcTxjDON6vNBssatGUIzuGglC2Lf
-----END BREAK PEM PRIVATE-----
```

```python
2280855825153079369164514405327170396436620371664464526496429415733055203155893358484242996086505609777681080427906338470140692619928813296029361848636902023401977358243759630394370381376771421271028169492126347929997983519619222735581769019133156193638407197605823449074124544232663174637158818370904094998560600412703805652546502801423946150024740398302185572802694514470006408627417645654400501165391976205173956917696904810606259304153658230235808250378495226246727449749944446621780268923502478344984402162063011322533642498211989023200258638304752854056875616723925602248635708248865548095231743243612632966212
```

#### 解题思路:
+ 首先题目给出了`c`以及破损私钥文件
+ 在**PKCS#1 RSA**算法标准中定义RSA公钥结构如下

```plain
RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
```

+ 在**PKCS#1 RSA**算法标准中定义RSA私钥结构如下

```plain
RSAPrivateKey ::= SEQUENCE {

version Version,

modulus INTEGER, -- n

publicExponent INTEGER, -- e

privateExponent INTEGER, -- d

prime1 INTEGER, -- p

prime2 INTEGER, -- q

exponent1 INTEGER, -- d mod (p-1) （dp）

exponent2 INTEGER, -- d mod (q-1) （dq）

coefficient INTEGER, -- (inverse of q) mod p （inv）

otherPrimeInfos OtherPrimeInfos OPTIONAL

}
```

+ 能提取出`n,e,dp,dq,inv`
+ 假设我们有**公钥**就这么提取(将base64字符串解码后,再转换为16进制)

```python
import base64

common_key = '''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzGjK21FO8/FjPZM+gGJ3
TvykTBocH9CReiBWuzkZwZmVt6wTJzerWS+DPRFJo7IviUxR0VOncEwxNgBzy5Ii
DXDvR6gwSXRjCvKD8fHBg3I96Lj2yV29t0J0mVyCoWqVAnxv09cUBIa25K5vmUIU
Pd1pA1m2xDLCQ54knHUjwK/fayGMrHHrT+bhSSFSIIguqKUOQ5ucgwWApTTF8CF7
yXITpq3kkYoZtSS4XewWr90xE+4v6vXNJ6vWJnxjaztEJ5meThH0DTgGTyq2/R59
jlCQ7suLqjH0S8HtSGQ4bM7sJkL+3WWDoyCgqKNvMpJmx9cQ5Gq8qgQ5ZZnqEI+0
MQIDAjKf'''
#common_key = "".join(common_key.split("\n"))
common_key = common_key.split("\n")
for i in common_key:
    print(base64.b64decode(i).hex())
'''
30820122300d06092a864886f70d01010105000382010f003082010a0282010100cc68cadb514ef3f1633d933e806277
4efca44c1a1c1fd0917a2056bb3919c19995b7ac132737ab592f833d1149a3b22f894c51d153a7704c31360073cb9222
0d70ef47a8304974630af283f1f1c183723de8b8f6c95dbdb74274995c82a16a95027c6fd3d7140486b6e4ae6f994214
3ddd690359b6c432c2439e249c7523c0afdf6b218cac71eb4fe6e149215220882ea8a50e439b9c830580a534c5f0217b
c97213a6ade4918a19b524b85dec16afdd3113ee2feaf5cd27abd6267c636b3b4427999e4e11f40d38064f2ab6fd1e7d
8e5090eecb8baa31f44bc1ed4864386cceec2642fedd6583a320a0a8a36f329266c7d710e46abcaa04396599ea108fb4
31020302329f
'''
```

**30820122:****表示后面是一个****SEQUENCE**,总长度为`0x122`,即使`290`字节

**02820101:表示后面是一个INTEGER**,长度是`0101`即`257`字节,后面跟的`00…`即为`n`的内容,`257`字节

**0203:表示后面是一个INTEGER**,长度是`03`即`3`字节,内容`0x02329f`,这就是`e`

+ 这里我们有**私钥**,就这么提取(将base64字符串解码后,再转换为16进制)

```python
import base64

private_key = '''MIIEowIBAAKCAQEAw6JUixKmoIZjLyR1Qc/D/3mfTC3YvqKienLM7Nt/83UqpYeg
9rOw02xLtIqgBdVyVkI+MknQdB5tB1W/bo95M8JjmNxi5rcEzXK4A5HiKtNxK9hC
dE1GIt78XcT1FLoM86zxFonkDQ8LxHXPbU22+Ex8ov269pS/BEwZuKohqbIUU4iZ
UltNYW2kaVsavAZw4NyQcQCQoijprdrQZLV6XjC/3+uX6baLaZS+NWHm1M16UHde
IF9B1gNuifO0xnuAWxRENjBIXw/3W8OVvRuRUppY2WYgeEG31fgfOCDoXhWVbqAD
6fJA9JWdkOPDqUAsqFCr2VKnORa2X9V9HdO5lwIDAQABAoIBAQD/////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////AoGBAP//////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////AoGBAP//
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////AoGAZFBey/5KFQ1nOL6xe00r
ehGXxxNQF/7oym0kzI6BBi4awYZ4FCtuGiiAfkcsOS0UhlhFn1gEemnl2f2EF78M
THN5zVM5FSY5Cf8XwJT/fEytuWdCQke7JxVYOLNsEJeViicsasXeWeSL1nPYS3a5
+T4027LUdjikIbu508dTT6UCgYAY+t0pv5nJ93J3773ZZYkLSCG+zXZBSgUtcCoQ
GTBa4Qcr3MLeeUGDkb4qNIBdqWsQR0GiIXLkoIxcmOr66Rs+Hl60MD0kWQA6uz5/
aJOhZc8pO0vGVG3+RbKA4xTxZshopp4CVdCrM20SqXXa3OEqr48Ec1aIES/ymZO8
GuaOwQKBgB4ZWvOfPzCFOselDYyjz2Tub1RY3YrvI1do3jl42nhy/1Aoc6G3XLi4
AIg8gxJGx36aPjpxBfe1HTicBhtUThBxq/A2/Ed1TwxFDvDPjhDc1Js/LL0qxhaP
Z/xYCgGGZftjQqPTy+S62ppYVcTxjDON6vNBssatGUIzuGglC2Lf
'''
private_key = private_key.split("\n")
for i in private_key:
   print(base64.b64decode(i).hex())
'''
308204a30201000282010100c3a2548b12a6a086632f247541cfc3ff799f4c2dd8bea2a27a72ccecdb7ff3752aa587a0
f6b3b0d36c4bb48aa005d57256423e3249d0741e6d0755bf6e8f7933c26398dc62e6b704cd72b80391e22ad3712bd842
744d4622defc5dc4f514ba0cf3acf11689e40d0f0bc475cf6d4db6f84c7ca2fdbaf694bf044c19b8aa21a9b214538899
525b4d616da4695b1abc0670e0dc90710090a228e9addad064b57a5e30bfdfeb97e9b68b6994be3561e6d4cd7a50775e
205f41d6036e89f3b4c67b805b14443630485f0ff75bc395bd1b91529a58d966207841b7d5f81f3820e85e15956ea003
e9f240f4959d90e3c3a9402ca850abd952a73916b65fd57d1dd3b99702030100010282010100ffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffff02818100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02818100ffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02818064505ecbfe4a150d6738beb17b4d2b
7a1197c7135017fee8ca6d24cc8e81062e1ac18678142b6e1a28807e472c392d148658459f58047a69e5d9fd8417bf0c
4c7379cd533915263909ff17c094ff7c4cadb967424247bb27155838b36c1097958a272c6ac5de59e48bd673d84b76b9
f93e34dbb2d47638a421bbb9d3c7534fa502818018fadd29bf99c9f77277efbdd965890b4821becd76414a052d702a10
19305ae1072bdcc2de79418391be2a34805da96b104741a22172e4a08c5c98eafae91b3e1e5eb4303d2459003abb3e7f
6893a165cf293b4bc6546dfe45b280e314f166c868a69e0255d0ab336d12a975dadce12aaf8f04735688112ff29993bc
1ae68ec10281801e195af39f3f30853ac7a50d8ca3cf64ee6f5458dd8aef235768de3978da7872ff502873a1b75cb8b8
00883c831246c77e9a3e3a7105f7b51d389c061b544e1071abf036fc47754f0c450ef0cf8e10dcd49b3f2cbd2ac6168f
67fc580a018665fb6342a3d3cbe4bada9a5855c4f18c338deaf341b2c6ad194233b868250b62df
'''
```

**308204a3:****表示后面是一个****SEQUENCE**,总长度为`0x4a3`,即使`1187`字节

**第一个02820101:表示后面是一个INTEGER**,长度是`0101`即`257`字节,后面的`00…`即为`n`的内容,`257`字节

**0203:表示后面是一个INTEGER**,长度是`03`即`3`字节,内容`0x10001`,这就是`e`

第二个02820101:**表示后面是一个**INTEGER,**长度是`0101`即`257`字节,后面的`00…`即为`d`的内容,`257`字节

**第一个028181:表示INTEGER**,长度为`129`字节,其内容为`p`

**第二个028181:表示INTEGER**,长度为`129`字节,其内容为`q`

**第一个028180:表示INTEGER**,长度为`128`字节,其内容为`dp`

**第二个028180:表示INTEGER**,长度为`128`字节,其内容为`dq`

**第三个028180:表示INTEGER,**长度为`128`字节,其内容为`inv`

+ 最后根据`dp`泄露攻击解题即可

#### 解答:
```python
from Crypto.Util.number import *
import gmpy2

c = 2280855825153079369164514405327170396436620371664464526496429415733055203155893358484242996086505609777681080427906338470140692619928813296029361848636902023401977358243759630394370381376771421271028169492126347929997983519619222735581769019133156193638407197605823449074124544232663174637158818370904094998560600412703805652546502801423946150024740398302185572802694514470006408627417645654400501165391976205173956917696904810606259304153658230235808250378495226246727449749944446621780268923502478344984402162063011322533642498211989023200258638304752854056875616723925602248635708248865548095231743243612632966212
n = int("c3 a2 54 8b 12 a6 a0 86 63 2f 24 75 41 cf c3 ff 79 9f 4c 2d d8 be a2 a2 7a 72 cc ec db 7f f3 75 2a a5 87 a0 f6 b3 b0 d3 6c 4b b4 8a a0 05 d5 72 56 42 3e 32 49 d0 74 1e 6d 07 55 bf 6e 8f 79 33 c2 63 98 dc 62 e6 b7 04 cd 72 b8 03 91 e2 2a d3 71 2b d8 42 74 4d 46 22 de fc 5d c4 f5 14 ba 0c f3 ac f1 16 89 e4 0d 0f 0b c4 75 cf 6d 4d b6 f8 4c 7c a2 fd ba f6 94 bf 04 4c 19 b8 aa 21 a9 b2 14 53 88 99 52 5b 4d 61 6d a4 69 5b 1a bc 06 70 e0 dc 90 71 00 90 a2 28 e9 ad da d0 64 b5 7a 5e 30 bf df eb 97 e9 b6 8b 69 94 be 35 61 e6 d4 cd 7a 50 77 5e 20 5f 41 d6 03 6e 89 f3 b4 c6 7b 80 5b 14 44 36 30 48 5f 0f f7 5b c3 95 bd 1b 91 52 9a 58 d9 66 20 78 41 b7 d5 f8 1f 38 20 e8 5e 15 95 6e a0 03 e9 f2 40 f4 95 9d 90 e3 c3 a9 40 2c a8 50 ab d9 52 a7 39 16 b6 5f d5 7d 1d d3 b9 97".replace(" ", ""), 16)
e = 65537
dp = int("64 50 5e cb fe 4a 15 0d 67 38 be b1 7b 4d 2b 7a 11 97 c7 13 50 17 fe e8 ca 6d 24 cc 8e 81 06 2e 1a c1 86 78 14 2b 6e 1a 28 80 7e 47 2c 39 2d 14 86 58 45 9f 58 04 7a 69 e5 d9 fd 84 17 bf 0c 4c 73 79 cd 53 39 15 26 39 09 ff 17 c0 94 ff 7c 4c ad b9 67 42 42 47 bb 27 15 58 38 b3 6c 10 97 95 8a 27 2c 6a c5 de 59 e4 8b d6 73 d8 4b 76 b9 f9 3e 34 db b2 d4 76 38 a4 21 bb b9 d3 c7 53 4f a5".replace(" ", ""), 16)
dq = int("18 fa dd 29 bf 99 c9 f7 72 77 ef bd d9 65 89 0b 48 21 be cd 76 41 4a 05 2d 70 2a 10 19 30 5a e1 07 2b dc c2 de 79 41 83 91 be 2a 34 80 5d a9 6b 10 47 41 a2 21 72 e4 a0 8c 5c 98 ea fa e9 1b 3e 1e 5e b4 30 3d 24 59 00 3a bb 3e 7f 68 93 a1 65 cf 29 3b 4b c6 54 6d fe 45 b2 80 e3 14 f1 66 c8 68 a6 9e 02 55 d0 ab 33 6d 12 a9 75 da dc e1 2a af 8f 04 73 56 88 11 2f f2 99 93 bc 1a e6 8e c1".replace(" ", ""), 16)
inv = int("1e 19 5a f3 9f 3f 30 85 3a c7 a5 0d 8c a3 cf 64 ee 6f 54 58 dd 8a ef 23 57 68 de 39 78 da 78 72 ff 50 28 73 a1 b7 5c b8 b8 00 88 3c 83 12 46 c7 7e 9a 3e 3a 71 05 f7 b5 1d 38 9c 06 1b 54 4e 10 71 ab f0 36 fc 47 75 4f 0c 45 0e f0 cf 8e 10 dc d4 9b 3f 2c bd 2a c6 16 8f 67 fc 58 0a 01 86 65 fb 63 42 a3 d3 cb e4 ba da 9a 58 55 c4 f1 8c 33 8d ea f3 41 b2 c6 ad 19 42 33 b8 68 25 0b 62 df".replace(" ", ""), 16)

def dp_leak(dp, c, n, e):
    for i in range(1, e):
        t = (dp * e - 1) % i
        if t == 0:
            p = (dp * e - 1) // i + 1
            if n % p == 0:
                q = n // p
                d = gmpy2.invert(e, (p - 1) * (q - 1))
                print(long_to_bytes(pow(c, d, n)))

dp_leak(dp, c, n, e)
#NSSCTF{(115.36517E, 39.30839N)}
```

### 题目二（2025 ？CTF)：
> 我们得到了一份受损的私钥和密文
>

```python
cipher: 82404436498466895324733436901056359489189960512493202570903960333247277400247388969097533191635462377037232768074464944681385506170855774688613792302290304494481765906529480985984818897269069587516233500512849282866396228645039453616712857020451120948641770106851301755195757766245239907077580562163260112662
```

```python
-----BEGIN RSA PRIVATE KEY-----
MIICewIBAAKBgQCdA0+pqynKvc3/BH5ojnUXBMdWy9Lzi9TwSaOgiJ6ky//QBrWG
CNan98CYNcoKux2yOtHKIjxUrPh+LdgjmW+/paWPJyrnoQw5SqD+FvqNTjG7Akvx
+TUXyMflL9qodrWBEbl/xmN01Qbivo36+U1mFDB+6LENk/3BwWXHVj0DvQIhAL7t
Vc3/3jEFe+paWKNoTV++2B8D1T+ii7ZYsy3kU1yNAoGA????????????????????
????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????
??????????????????????kCQQ??????????????????????????????????????
????????????????????????????????????????????????AkE?????????????
????????????????????????????????????????????????????????????????
?????????wJAJrKFhI5pl/oBN2BZqLTf+NacGqTFrzmbi7RVFaN43kXYXu11urXy
LTncfJXBpRhtGFdsL31jiswhiYRp9yjT+wJB????????????????????????????
??????????????????????????????????????????????????????????MCQQ??
????????????????????????????????????????????????????????????????
????????????????????
-----END RSA PRIVATE KEY-----
```

转成hex（手动排版换行过后）

```python
3082027b
020100
028181
009d034fa9ab29cabdcdff047e688e751704c756cbd2f38bd4f049a3a0889ea4cbffd006b586
08d6a7f7c09835ca0abb1db23ad1ca223c54acf87e2dd823996fbfa5a58f272ae7a10c394aa0fe16fa8d4e31bb024bf1
f93517c8c7e52fdaa876b58111b97fc66374d506e2be8dfaf94d6614307ee8b10d93fdc1c165c7563d03bd
0221
00beed55cdffde31057bea5a58a3684d5fbed81f03d53fa28bb658b32de4535c8d
028180
ffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
fffffffffffffffffffffffffffffffff9
0241
0fffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
0241
3fffffffffffffffffff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffff
0240
26b285848e6997fa01376059a8b4dff8d69c1aa4c5af399b8bb45515a378de45d85eed75bab5f2
2d39dc7c95c1a5186d18576c2f7d638acc21898469f728d3fb
0241
ffffffffffffffffffffffffffffffffffffffffff
fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff302410fff
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffff
```

得到n ,e , dp   （dp=d mod (p-1）)

#### exp
```python
import sys
from Crypto.Util.number import *
from random import *
sys.setrecursionlimit(2000)

################################################### part1 read pem
# with open('./certificate/private.pem', 'r') as file:
#     cipher = file.readlines()[1:-1]
cipher='''MIICewIBAAKBgQCdA0+pqynKvc3/BH5ojnUXBMdWy9Lzi9TwSaOgiJ6ky//QBrWG
CNan98CYNcoKux2yOtHKIjxUrPh+LdgjmW+/paWPJyrnoQw5SqD+FvqNTjG7Akvx
+TUXyMflL9qodrWBEbl/xmN01Qbivo36+U1mFDB+6LENk/3BwWXHVj0DvQIhAL7t
Vc3/3jEFe+paWKNoTV++2B8D1T+ii7ZYsy3kU1yNAoGA????????????????????
????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????
??????????????????????kCQQ??????????????????????????????????????
????????????????????????????????????????????????AkE?????????????
????????????????????????????????????????????????????????????????
?????????wJAJrKFhI5pl/oBN2BZqLTf+NacGqTFrzmbi7RVFaN43kXYXu11urXy
LTncfJXBpRhtGFdsL31jiswhiYRp9yjT+wJB????????????????????????????
??????????????????????????????????????????????????????????MCQQ??
????????????????????????????????????????????????????????????????
????????????????????
'''
cipher = ''.join(cipher).replace('\n','')
print(cipher)
table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

bitstream = ""
for i in cipher:
    if(i == "?"):
        bitstream += "******"
    else:
        bitstream += bin(table.index(i))[2:].zfill(6)
print(bitstream)

################################################### part2 split params
info1 = hex(int(bitstream[:4*8],2))[2:].zfill(4*2)
print(info1) # 30（标识头） 82 027b（总长度） 
bitstream = bitstream[4*8:]
info2 = hex(int(bitstream[:3*8],2))[2:].zfill(3*2)
bitstream = bitstream[3*8:]
print(info2)# 0201 00 （版本信息）
##### n,e
infon = hex(int(bitstream[:3*8],2))[2:].zfill(3*2)
print(infon) # 0281 81 （数据长度0x81字节）
bitstream = bitstream[3*8:]
n = int(bitstream[:0x81*8],2)
print(n.bit_length())
print('n='+hex(n))
bitstream = bitstream[0x81*8:]

infoe = hex(int(bitstream[:2*8],2))[2:].zfill(2*2)
print(infoe) # 02 21 （数据长度0x21字节）
bitstream = bitstream[2*8:]
e = int(bitstream[:0x21*8],2) 
print(e.bit_length())
print('e='+hex(e))
bitstream = bitstream[0x21*8:]

###### d
infod = hex(int(bitstream[:3*8],2))[2:].zfill(3*2) 
print(infod) # 0281 80 (数据长度0x80字节)
bitstream = bitstream[3*8:]
d = bitstream[:0x80*8]
bitstream = bitstream[0x80*8:]

###### p,q
infop = hex(int(bitstream[:2*8],2))[2:].zfill(2*2) 
print(infop) # 02 41 (数据长度0x41字节)
bitstream = bitstream[2*8:]
p = bitstream[:0x41*8]
# print('p=',hex(p))
bitstream = bitstream[0x41*8:]
infoq = hex(int(bitstream[:2*8],2))[2:].zfill(2*2)
print(infoq) # 02 41 (数据长度0x41字节)
bitstream = bitstream[2*8:]
q = bitstream[:0x41*8]
bitstream = bitstream[0x41*8:]

# ##### dp,dq
infodp = hex(int(bitstream[:2*8],2))[2:].zfill(2*2)
print(infodp) # 02 40 (数据长度0x40字节)
bitstream = bitstream[2*8:]
dp = int(bitstream[:0x40*8],2)
print('dp=',hex(dp))

bitstream = bitstream[0x40*8:]
infodq = hex(int(bitstream[:2*8],2))[2:].zfill(2*2)
print(infodq)# 02 41 (数据长度0x41字节)
bitstream = bitstream[2*8:]
dq = bitstream[:0x41*8]
bitstream = bitstream[0x41*8:]

###### invert(q, p)
infodmqp = hex(int(bitstream[:2*8],2))[2:].zfill(2*2)
print(infodmqp)# 02 41 (数据长度0x41字节)
bitstream = bitstream[2*8:]
dmpq = bitstream[:0x41*8]
bitstream = bitstream[0x41*8:]
print(bitstream)

################################################### part3 recover the flag
cipher = 82404436498466895324733436901056359489189960512493202570903960333247277400247388969097533191635462377037232768074464944681385506170855774688613792302290304494481765906529480985984818897269069587516233500512849282866396228645039453616712857020451120948641770106851301755195757766245239907077580562163260112662
p = GCD(pow(2, e*dp, n) - 2, n)
q = n // p    
d = inverse(e, (p - 1) * (q - 1))
m = pow(cipher, d, n)
print(long_to_bytes(m))
```

### 题目三（buuctf rsa）：
题目给了公钥文件 `pub.key`

```python
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMAzLFxkrkcYL2wch21CM2kQVFpY9+7+
/AvKr1rzQczdAgMBAAE=
-----END PUBLIC KEY-----
```

在线网站解析公钥： [http://ctf.ssleye.com/](http://ctf.ssleye.com/)

得到n和e之后，用factordb： [http://factordb.com/](http://factordb.com/)

分解模n，得到p,q的值。

> 这道题使用的是 Crypto.PublicKey 的 RSA 模块进行加密，没有使用PKCS1等协议进行填充，所以用在线的RSA公私钥解析是没有用的
>

#### EXP：
```python
# %%
import rsa
from Crypto.PublicKey import RSA
from gmpy2 import *  # gmpy2模块
from Crypto.Cipher import PKCS1_OAEP

pub = open('pub.key', 'r').read()
key = RSA.import_key(pub)
n = key.n
e = key.e
print('n =', n)
print('e =', e)
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

# %%
phi = (p - 1) * (q - 1)
d = invert(e, phi)  # gmpy2.invert(),用来求模逆的方法

print('d =', d)
d = 81176168860169991027846870170527607562179635470395365333547868786951080991441

key = rsa.PrivateKey(n, e, d, p, q)
print(key)
with open("flag.enc", 'rb') as f:
    f = f.read()
    flag = rsa.decrypt(f,key)
    print(flag)
```

这里的flag 也可以直接使用 RSA 的解密公式计算出。

```python
with open("flag.enc", 'rb') as f:
    f = f.read()
    c = bytes_to_long(f)
    print(long_to_bytes(pow(c,d,n)))
    flag = rsa.decrypt(f,key)
    print(flag)
```

### 题目四（2024CISCN——ezrsa）：
```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import random
from secret import flag

m = bytes_to_long(flag)
key = RSA.generate(1024)
passphrase = str(random.randint(0,999999)).zfill(6).encode()
output = key.export_key(passphrase=passphrase).split(b'\n')
for i in range(7, 15):
    output[i] = b'*' * 64
with open("priv.pem", 'wb') as f:
    for line in output:
        f.write(line + b'\n')
with open("enc.txt", 'w') as f:
    f.write(str(key._encrypt(m)))
```

```python
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBCBF84C562FE793

9phAgeyjnJYZ6lgLYflgduBQjdX+V/Ph/fO8QB2ZubhBVOFJMHbwHbtgBaN3eGlh
WiEFEdQWoOFvpip0whr4r7aGOhavWhIfRjiqfQVcKZx4/f02W4pcWVYo9/p3otdD
ig+kofIR9Ky8o9vQk7H1eESNMdq3PPmvd7KTE98ZPqtIIrjbSsJ9XRL+gr5a91gH
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
hQds7ZdA9yv+yKUYv2e4de8RxX356wYq7r8paBHPXisOkGIVEBYNviMSIbgelkSI
jLQka+ZmC2YOgY/DgGJ82JmFG8mmYCcSooGL4ytVUY9dZa1khfhceg==
-----END RSA PRIVATE KEY-----
```

#### 思路
类似蓝帽杯2022的corrupted_key  
不一样的是，这题得到的pem文件内容是加密的  
根据代码

```plain
key.export_key(passphrase=passphrase).split(b'\n')
```

找到Crypto下的源代码

![](https://cdn.nlark.com/yuque/0/2025/png/39243091/1761535339710-2e4a1cf1-9914-4c20-b322-8a48914d361c.png)  


发现关键代码![](https://cdn.nlark.com/yuque/0/2025/png/39243091/1761535280034-918e9a9b-1ece-4cf2-9f65-8ae3090af9e3.png)  
如果passphrase存在，则随机生成一个salt，然后使用PKBDF1方法加密两次拼接得到key。  
此时使用的加密方式为3des,模式为cbc,iv为salt  
由此我们可以根据passphrase的生成方式来爆破出唯一的passphrase  
根据私钥的格式，开头一定是3082，再根据n为1024bit，那么在私钥中n的格式为028181,加密参数e大概率为65537，即0x10001  
那么其在私钥中则为 0203010001。  
解密后存在如下特征的明文，那么当前的passphrase为所求

```python
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Hash import MD5
import base64


enc1 = "9phAgeyjnJYZ6lgLYflgduBQjdX+V/Ph/fO8QB2ZubhBVOFJMHbwHbtgBaN3eGlhWiEFEdQWoOFvpip0whr4r7aGOhavWhIfRjiqfQVcKZx4/f02W4pcWVYo9/p3otdDig+kofIR9Ky8o9vQk7H1eESNMdq3PPmvd7KTE98ZPqtIIrjbSsJ9XRL+gr5a91gH"
enc2 = "hQds7ZdA9yv+yKUYv2e4de8RxX356wYq7r8paBHPXisOkGIVEBYNviMSIbgelkSIjLQka+ZmC2YOgY/DgGJ82JmFG8mmYCcSooGL4ytVUY9dZa1khfhceg=="

salt = bytes.fromhex("435bf84c562fe793")
dict = [str(i).zfill(6).encode() for i in range(0,1000000)]
for passphrase in dict:
    key = PBKDF1(passphrase, salt, 16, 1, MD5)
    key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
    cipher = DES3.new(key, DES3.MODE_CBC, salt)
    data = cipher.decrypt(base64.b64decode(enc1)).hex()
    if data.startswith("3082") and "028181" in data and "0203010001" in data:
        print(data)
        print(passphrase)
        data2 = cipher.decrypt(base64.b64decode(enc2)).hex()
        print(data2)
        break
```

得到

```plain
30 82 02 5c
    02 01
        00 		 
        
    02 81 81 00
a1 8f 01 1b eb ac ce da 1c 68 12 73 0b 9e 62 72 0d 3c bd 68 57 af 2c f8 43 18 60 f5 dc 83 c5 52 0f 24 2f 3b e7 c9 e9 6d 7f 96 b4 18 98 ff 00 0f db 7e 43 ef 6f 1e 71 7b 2b 79 00 f3 56 60 a2 1d 1b 16 b5 18 49 be 97 a0 b0 f7 cb cf 5c fe 0f 00 37 0c ce 61 93 fe fa 1f ed 97 b3 7b d3 67 a6 73 56 51 62 ce 17 b0 22 57 08 c0 32 96 1d 17 5b bc 2c 82 9b f2 e1 6e ab c7 e0 88 1f ec a0 97 5c 81

    02 03 
        01 00 01

6a 03 30 64 c5 a0 dff c8 f2 36 3b 34 0e 50 24 05 f1 52 c4 29 87 1a 7a cd d2 8b e1 b6 43 b4 65 28 00 b8 8a 3d 23 cc 57 47 7d 75 dd 55 55 b6 35 16 76 16 ef 5c 60 9d 69 ce 3c 2a ed cb 03 b6 2f 92 9b bc d8 91 ca dc 0b a0 31 ae 6f ec 8a 21 16 d0 80 80 80 80 80 80 80 8

```

再根据私钥格式提取`n,e,dq,inv`  
因为本题中中间部分的私钥文件缺失，而且加密是cbc的，导致enc2第一块解密的结果错误，需要去掉，也就是说正确的dq只有48bit  
因此得到

```python
n = 0xa18f011bebacceda1c6812730b9e62720d3cbd6857af2cf8431860f5dc83c5520f242f3be7c9e96d7f96b41898ff000fdb7e43ef6f1e717b2b7900f35660a21d1b16b51849be97a0b0f7cbcf5cfe0f00370cce6193fefa1fed97b37bd367a673565162ce17b0225708c032961d175bbc2c829bf2e16eabc7e0881feca0975c81
e = 65537
dq_leak= 0x8f2363b340e5
inv = 0x5f152c429871a7acdd28be1b643b4652800b88a3d23cc57477d75dd5555b635167616ef5c609d69ce3c2aedcb03b62f929bbcd891cadc0ba031ae6fec8a2116d
```

![](https://cdn.nlark.com/yuque/0/2025/jpeg/39243091/1761535376227-2f1c7082-312d-497a-8a98-1ef83759176c.jpeg)

#### exp
```python
from tqdm import *
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

n = 0xa18f011bebacceda1c6812730b9e62720d3cbd6857af2cf8431860f5dc83c5520f242f3be7c9e96d7f96b41898ff000fdb7e43ef6f1e717b2b7900f35660a21d1b16b51849be97a0b0f7cbcf5cfe0f00370cce6193fefa1fed97b37bd367a673565162ce17b0225708c032961d175bbc2c829bf2e16eabc7e0881feca0975c81
e = 65537
dq_leak= 0x8f2363b340e5
inv = 0x5f152c429871a7acdd28be1b643b4652800b88a3d23cc57477d75dd5555b635167616ef5c609d69ce3c2aedcb03b62f929bbcd891cadc0ba031ae6fec8a2116d
c = 55149764057291700808946379593274733093556529902852874590948688362865310469901900909075397929997623185589518643636792828743516623112272635512151466304164301360740002369759704802706396320622342771513106879732891498365431042081036698760861996177532930798842690295051476263556258192509634233232717503575429327989

def coppersmith(k):
    R.<x> = PolynomialRing(Zmod(n))
    tmp = e * (x * 2^48 + dq_leak) + k - 1          # kq
    f = inv * tmp^2 - k*tmp
    f = f.monic()
    x0 = f.small_roots(X=2^464,beta=1,epsilon=0.09)
    return x0

for k in trange(1，e):
    x0 = coppersmith(k)
    if x0 != []:
        dq = int(x0[0]) * 2^48 + dq_leak
        q = (e*dq + k - 1) // k
        # print(f"k = {k}")
        # k = 47794
        p = n // q
        d = inverse(e,(p-1)*(q-1))
        m = pow(c,d,n)
        print(long_to_bytes(int(m)))
        # b'flag{df4a4054-23eb-4ba4-be5e-15b247d7b819}'
        break
```

在求出q后，其实`pow(c,dq,q)`也能出flag，不用求p

### 题目五（2022蓝帽杯corrupted_key）：
该题主要考察对私钥文件pem的读取理解，附件如下

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from secret import flag

key = RSA.generate(1024)
open("flag.enc",'wb').write(PKCS1_OAEP.new(key.publickey()).encrypt(flag))
open('priv.pem','wb').write(key.exportKey('PEM'))
```

平平无奇的附件，关键在私钥

```python
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDXFSUGqpzsBeUzXWtG9UkUB8MZn9UQkfH2Aw03YrngP0nJ3NwH
UFTgzBSLl0tBhUvZO07haiqHbuYgBegO+Aa3qjtksb+bH6dz41PQzbn/l4Pd1fXm
dJmtEPNh6TjQC4KmpMQqBTXF52cheY6GtFzUuNA7DX51wr6HZqHoQ73GQQIDAQAB

yQvOzxy6szWFheigQdGxAkEA4wFss2CcHWQ8FnQ5w7k4uIH0I38khg07HLhaYm1c
zUcmlk4PgnDWxN+ev+vMU45O5eGntzaO3lHsaukX9461mA==
-----END RSA PRIVATE KEY-----
```

其中可以看出，私钥文件中间是有很大程度的缺失，首先进行原始数据读取，将base64编码解码后转成hex，然后手动进行一下参数解析

```python
第一段：
3082025e02010002818100
d7152506aa9cec05e5335d6b46f5491407c3199fd51091f1f6030d3762b9e03f49c9dcdc075054e0cc148b974b41854bd93b4ee16a2a876ee62005e80ef806b7aa3b64b1bf9b1fa773e353d0cdb9ff9783ddd5f5e67499ad10f361e938d00b82a6a4c42a0535c5e76721798e86b45cd4b8d03b0d7e75c2be8766a1e843bdc641
0203010001

第二段：
c90bcecf1cbab3358585e8a041d1b1
024100
e3016cb3609c1d643c167439c3b938b881f4237f24860d3b1cb85a626d5ccd4726964e0f8270d6c4df9ebfebcc538e4ee5e1a7b7368ede51ec6ae917f78eb598
```

从第一段可以提取出数据

```python
n = 0xd7152506aa9cec05e5335d6b46f5491407c3199fd51091f1f6030d3762b9e03f49c9dcdc075054e0cc148b974b41854bd93b4ee16a2a876ee62005e80ef806b7aa3b64b1bf9b1fa773e353d0cdb9ff9783ddd5f5e67499ad10f361e938d00b82a6a4c42a0535c5e76721798e86b45cd4b8d03b0d7e75c2be8766a1e843bdc641

e = 0x10001
```

从第二段可以提取出数据

```plain
dq_low = 0xc90bcecf1cbab3358585e8a041d1b1

qinvp = 0xe3016cb3609c1d643c167439c3b938b881f4237f24860d3b1cb85a626d5ccd4726964e0f8270d6c4df9ebfebcc538e4ee5e1a7b7368ede51ec6ae917f78eb598
```

通过构造一元多项式结合 coppersmith 算法可以求出多项式的根值，得到如下数据

```python
dq = 11263269100321843418340309033584057768246046953115325020896491943793759194249558697334095131684279304657225064156696057310019203890620314290203835007881649

p = 12112790828812363063315417237469719611888243756064158121348026938824270601623590308149025542977097905953795136774300936003505715307199422663647014200158449

q = 12469144192094336933187534132907623337514842804208163244218540727384104398951558782195384932941310035462094951428865175221316720981428462265191789302379089
```

**然后私钥解密即可**

#### EXP:
```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import gmpy2

with open("flag.enc", "rb")as f:
    c = f.read()

n = 0xd7152506aa9cec05e5335d6b46f5491407c3199fd51091f1f6030d3762b9e03f49c9dcdc075054e0cc148b974b41854bd93b4ee16a2a876ee62005e80ef806b7aa3b64b1bf9b1fa773e353d0cdb9ff9783ddd5f5e67499ad10f361e938d00b82a6a4c42a0535c5e76721798e86b45cd4b8d03b0d7e75c2be8766a1e843bdc641
e = 0x10001
dq = 11263269100321843418340309033584057768246046953115325020896491943793759194249558697334095131684279304657225064156696057310019203890620314290203835007881649
p = 12112790828812363063315417237469719611888243756064158121348026938824270601623590308149025542977097905953795136774300936003505715307199422663647014200158449
q = 12469144192094336933187534132907623337514842804208163244218540727384104398951558782195384932941310035462094951428865175221316720981428462265191789302379089
phi = (p - 1) * (q - 1)

d = int(gmpy2.invert(e, phi))
key = RSA.construct((n, e, d, p, q))
flag = PKCS1_OAEP.new(key)
flag = flag.decrypt(c)
print(flag)
```

### 题目六（攻防世界wtc_rsa_bbq)：
改后缀为zip后得到cipher.bin和key.pem  

 先用openssl查看n和e

```shell
 openssl rsa -pubin -in key.pem -text -modulus
```

![](https://cdn.nlark.com/yuque/0/2025/png/39243091/1761540686781-3fdb4064-7122-481c-9e9a-e62e0c8ec499.png)

n很大，但还是可以分解  
bin文件解密

#### exp
```python
import gmpy2
from Crypto.Util.number import bytes_to_long, long_to_bytes
p = (2**4244)*699549860111847+1
q = (2**4244)*699549860111847-1
n=0x62D3D61C92452630147E89670FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

e=65537
phi = (p-1)*(q-1)
d=gmpy2.invert(e,phi)
with open('.\cry200\cipher.bin', 'rb') as file:
    data = bytes_to_long(file.read())
    res = long_to_bytes(pow(data, d, n)).decode()
    print(res)
```

### 题目七（攻防世界 cr4-poor-rsa）
> 题目给了key.pub和output.txt
>

```python
from Crypto.PublicKey import RSA
f = open("key.pub","rb").read()
pub = RSA.importKey(f)
print(pub.n,pub.e)
```

得到n和e （n可以分解）

打开flag.b64并用base64解码，再利用key解密即可得到flag   

outpu. txt 中为全部 base 64 串

#### exp
```python
import gmpy2
from Crypto.Util.number import *
from base64 import b64decode
from Crypto.PublicKey import RSA
f = open("D:\\ctf-problems\\bf930316910b451c94c41ce8a9d851a8\\key.pub","rb").read()
pub = RSA.importKey(f)
n=pub.n
e=pub.e
print(pub.n,pub.e)
f = open("D:\\ctf-problems\\bf930316910b451c94c41ce8a9d851a8\\flag.b64",'r').read()
c = b64decode(f)
c = bytes_to_long(c)
p=863653476616376575308866344984576466644942572246900013156919
q=965445304326998194798282228842484732438457170595999523426901
phi=(p-1)*(q-1)
d=gmpy2.invert(e,phi)
m=pow(c,d,n)
print(long_to_bytes(m))
```



## 相关链接
[密码学基础3：密钥文件格式完全解析](https://www.jianshu.com/p/ce7ab5f3f33a)

