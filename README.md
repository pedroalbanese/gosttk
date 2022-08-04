## GOST Toolkit: GOST Security Suite written in Go ☭
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/gosttk/blob/master/LICENSE.md) 
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/gosttk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/gosttk/releases)
[![GoDoc](https://godoc.org/github.com/pedroalbanese/gosttk?status.png)](http://godoc.org/github.com/pedroalbanese/gosttk)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/gosttk)](https://goreportcard.com/report/github.com/pedroalbanese/gosttk)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/gosttk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/gosttk)](https://github.com/pedroalbanese/gosttk/releases)

Multi-purpose cross-platform cryptography tool for symmetric encryption, cipher-based message authentication code (CMAC), recursive hash digest, hash-based message authentication code (HMAC), digital signature, shared key agreement (VKO) and PBKDF2 function for embedded systems. 

**GOST refers to a set of technical standards maintained by the Euro-Asian Council for Standardization, Metrology and Certification (EASC), a regional standards organization operating under the auspices of the Commonwealth of Independent States (CIS).**

#### GOST is GOvernment STandard of Russian Federation (and Soviet Union):
* GOST 28147-89 64-bit block cipher (RFC 5830)
* GOST R 34.11-94 hash function 256-bit (RFC 5831)
* GOST R 50739-95 data sanitization method (non-cryptographic)
* GOST R 34.10-2001 public key signature function (RFC 5832)
* VKO GOST R 34.10-2001 key agreement function (RFC 4357)
* GOST R 34.10-2012 public key signature function (RFC 7091)
* VKO GOST R 34.10-2012 key agreement function (RFC 7836)
* GOST R 34.11-2012 Стрибог (Streebog) hash function 256/512-bit (RFC 6986)
* GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznechik) (RFC 7801)
* GOST R 34.12-2015 64-bit block cipher Магма (Magma)
* MGM AEAD mode for 64 and 128 bit ciphers (RFC 9058)

## Algorithms
#### Symmetric:
- Block Ciphers:
   - GOST 28147-89 CryptoPro
   - GOST R 34.12-2015 Magma (default)
   - GOST R 34.12-2015 Kuznechik (Grasshopper)

- Supported ParamSets:
   - GOST 28147-89 CryptoPro: A, B, C, D, EAC, Z

- Modes of Operation:
   - MGM: Multilinear Galois Mode (AEAD)
   - CTR: Counter Mode (a.k.a. CNT)
   - OFB: Output Feedback Mode

- Message Digest Algorithms:
   - GOST R 34.11-94 CryptoPro 256-bit
   - GOST R 34.11-2012 Streebog 256/512-bit (default) 

#### Asymmetric:
- Public key Algorithms:
   - GOST R 34.10-2001 CryptoPro 256-bit
   - GOST R 34.10-2012 256/512-bit (default) 

- Supported ParamSets:
   - GOST R 34.10-2001 256-bit: A, B, C, XA, XB
   - GOST R 34.10-2012 256-bit: A, B, C, D
   - GOST R 34.10-2012 512-bit: A, B, C

## Features

- Cryptographic Functions:
   - Symmetric Encryption + AEAD Mode
   - Digital Signature (ECDSA equivalent)
   - VKO (выработка ключа общего) shared key negociation (ECDH equivalent)
   - Recursive Hash Digest + Check 
   - CMAC (Cipher-based message authentication code)
   - HMAC (Hash-based message authentication code)
   - HKDF (HMAC-based key derivation function)
   - PBKDF2 (Password-based key derivation function 2)
   - TLS 1.2 (Transport Layer Security)

- Non-Cryptographic Functions:
   - GOST R 50739-95 data sanitization method
   - Bin to Hex/Hex to Bin string conversion
   - Random Art (Public key Fingerprint)

#### TODO:
  - [ ] TLS 1.3
  - [x] MGM Mode of operation
  - [x] OFB Mode of operation
  - [x] PBKDF2 Function
  - [x] GOST 28147-89 CMAC
  - [x] GOST 28147-89 symmetric cipher
  - [x] GOST R 34.11-94 HMAC
  - [x] GOST R 50739-95 data sanitization method 
  - [x] GOST R 34.10-2001 public key signature function
  - [x] VKO GOST R 34.10-2001 key agreement function
  - [x] GOST R 34.12-2015 Magma symmetric cipher

## Usage
<pre> -128
       Block size: 64 or 128. (for symmetric encryption only) (default 64)
 -512
       Bit length: 256 or 512. (default 256)
 -check string
       Check hashsum file. ('-' for STDIN)
 -crypt string
       Encrypt/Decrypt with symmetric ciphers.
 -digest string
       File/Wildcard to generate hashsum list. ('-' for STDIN)
 -hex string
       Encode binary string to hex format and vice-versa.
 -hkdf int
       HMAC-based key derivation function with a given output bit length.
 -info string
       Associated data, additional info. (for HKDF and AEAD encryption)
 -iter int
       Iterations. (for SHRED and PBKDF2 only) (default 1)
 -iv string
       Initialization vector. (for non-AEAD symmetric encryption)
 -key string
       Private/Public key, password or HMAC key, depending on operation.
 -mac string
       Compute hash-based/cipher-based message authentication code.
 -mode string
       Mode of operation: MGM, CTR or OFB. (default "MGM")
 -old
       Use old roll of algorithms.
 -paramset string
       Elliptic curve ParamSet: A, B, C, D, XA, XB. (default "A")
 -pbkdf2
       Password-based key derivation function 2.
 -pkey string
       Generate keypair, Derive shared secret, Sign and Verify.
 -pub string
       Remote's side public key.
 -rand int
       Generate random cryptographic key with a given output bit length.
 -recursive
       Process directories recursively. (for DIGEST command only)
 -salt string
       Salt. (for PBKDF2 and HKDF commands)
 -shred string
       Files/Path/Wildcard to apply data sanitization method.
 -signature string
       Input signature. (verification only)
 -version
       Print version information.</pre>
## Examples
#### Asymmetric GOST R 34.10-2001 256-bit keypair generation (INI format):
```sh
./gosttk -pkey generate -old [-paramset A|B|C|XA|XB]
```
#### Asymmetric GOST R 34.10-2012 256/512-bit keypair generation (default):
```bash
./gosttk -pkey gen [-paramset A|B|C|D] [-512 -paramset A|B|C]
```
#### Signature (ECDSA equivalent):
```sh
./gosttk -pkey sign [-512|-old] -key $prvkey < file.ext > sign.txt
sign=$(cat sign.txt)
./gosttk -pkey verify [-512|-old] -key $pubkey -signature $sign < file.ext
echo $?
```
#### VKO: Shared key negociation (ECDH equivalent):
```sh
./gosttk -pkey derive [-512|-old] -key $prvkey -pub $pubkey
```
#### Encryption/decryption with Magma (GOST R 34.12-2015) block cipher (default):
```sh
./gosttk -crypt enc -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt dec -key $shared < ciphertext.ext > plaintext.ext
```
#### Encryption/decryption with Kuznyechik (GOST R 34.12-2015) block cipher:
```sh
./gosttk -crypt enc -128 -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt dec -128 -key $shared < ciphertext.ext > plaintext.ext
```
#### Encryption/decryption with GOST 28147-89 CryptoPro block cipher:
```sh
./gosttk -crypt enc -old -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt dec -old -key $shared < ciphertext.ext > plaintext.ext
```
#### CMAC-Kuznechik (cipher-based message authentication code):
```sh
./gosttk -mac cmac -128 -key $128bitkey < file.ext
./gosttk -mac cmac -128 -key $128bitkey -signature &128bitkey < file.ext
```
#### CMAC-Magma (cipher-based message authentication code):
```sh
./gosttk -mac cmac [-old] -key $128bitkey < file.ext
./gosttk -mac cmac [-old] -key $128bitkey -signature &64bitkey < file.ext
```
#### GOST94-CryptoPro hashsum (list):
```sh
./gosttk -digest "*.*" -old [-recursive]
```
#### GOST94-CryptoPro hashsum (single):
```sh
./gosttk -digest - -old < file.ext
```
#### HMAC-GOST94-CryptoPro (hash-based message authentication code):
```sh
./gosttk -mac hmac -old -key $256bitkey < file.ext
./gosttk -mac hmac -old -key $256bitkey -signature $256bitkey < file.ext
```
#### Streebog256/512 hashsum:
```sh
./gosttk -digest - [-512] < file.ext
```
#### HMAC-Streebog256/512:
```sh
./gosttk -mac hmac [-512] -key $256bitkey < file.ext
./gosttk -mac hmac [-512] -key $256bitkey -signature $256bitkey < file.ext
```
#### HKDF (HMAC-based key derivation function 256-bit output):
```sh
./gosttk -hkdf 256 [-512|-old] -key "IKM" -info "AD" -salt "salt"
```
#### PBKDF2 (password-based key derivation function 2):
```sh
./gosttk -pbkdf2 [-512|-old] -key "pass" -iter 10000 -salt "salt"
```

#### Note:
PBKDF2 function can be combined with the CRYPT, HMAC commands:
```sh
./gosttk -crypt enc -128 -pbkdf2 -512 -key "pass" < plaintext.ext > ciphertext.ext
./gosttk -mac hmac [-512] -pbkdf2 -key "pass" -salt "salt" -iter 10000 < file.ext
```

#### Shred (GOST R 50739-95 data sanitization method, 25 iterations):
```sh
./gosttk -shred "keypair.ini" -iter 25
```

#### Bin to Hex/Hex to Bin:
```sh
./gosttk -hex enc < File.ext > File.hex
./gosttk -hex dec < File.hex > File.ext
```

#### TLS Layer (TCP/IP):
```sh
./gostls -tcp ip > PubIP.txt
./gostls -tcp dump [-pub "8081"] > Token.jwt
./gostls -tcp send [-pub "127.0.0.1:8081"] < Token.jwt

./gostls -tcp listen [-pub "8081"]
./gostls -tcp dial [-pub "127.0.0.1:8081"]
```

#### Random Art (Public Key Fingerprint):
```sh
./gosttk -key $pubkey
./gosttk -key - < Pubkey.txt
```

## License

This project is licensed under the ISC License.

##### Military-Grade Reliability. Copyright (c) 2020-2022 ALBANESE Research Lab.

