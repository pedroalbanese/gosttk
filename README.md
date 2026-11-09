# :ru: GOST Toolkit ☭
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/gosttk/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/gosttk?status.png)](http://godoc.org/github.com/pedroalbanese/gosttk)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/gosttk/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/gosttk/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/gosttk)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/gosttk)](https://github.com/pedroalbanese/gosttk/releases)

Multi-purpose cross-platform cryptography tool for symmetric encryption, cipher-based message authentication code (CMAC), recursive hash digest, hash-based message authentication code (HMAC), digital signature, shared key agreement (VKO), PBKDF2/HKDF functions, PEM key/certificate management, RandomArt fingerprints, X.509 CSR, CRL, and Certificates, and **TLS 1.3** (RFC 9367) for small or embedded systems.

**GOST refers to a set of technical standards maintained by the Euro-Asian Council for Standardization, Metrology and Certification (EASC), a regional standards organization operating under the auspices of the Commonwealth of Independent States (CIS).**

#### GOST is GOvernment STandard of Russian Federation (and Soviet Union):
* GOST 28147-89 64-bit block cipher (RFC 5830)
* GOST R 34.11-94 hash function 256-bit (RFC 5831)
* GOST R 34.10-2012 public key signature function (RFC 7091)
* VKO GOST R 34.10-2012 key agreement function (RFC 7836)
* GOST R 34.11-2012 Стрибог (Streebog) hash function 256/512-bit (RFC 6986)
* GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznyechik) (RFC 7801)
* GOST R 34.12-2015 64-bit block cipher Магма (Magma) (RFC 8891)
* MGM AEAD mode for 64 and 128 bit ciphers (RFC 9058)
* GOST cipher suites for TLS 1.3 (RFC 9367)

> **Note:** GOST R 34.10-2001 (RFC 5832) and VKO GOST R 34.10-2001 (RFC 4357) were **removed**. The `-old` flag now refers **only** to the legacy GOST R 34.11-94 hash function. GOST R 50739-95 data sanitization (`-shred`) was **removed**.

## Algorithms

#### Symmetric:
- Block Ciphers (selectable with `-cipher`):
   - `gost89` — GOST 28147-89 CryptoPro (64-bit)
   - `magma` — GOST R 34.12-2015 Magma (64-bit)
   - `kuznyechik` — GOST R 34.12-2015 Kuznyechik (128-bit, **default**)

- Supported ParamSets (for `gost89`):
   - GOST 28147-89 CryptoPro: A, B, C, D and Z

- Modes of Operation:
   - MGM: Multilinear Galois Mode (AEAD, default)
   - CTR: Counter Mode (a.k.a. CNT)
   - OFB: Output Feedback Mode
   - CFB8: Cipher Feedback Mode (8-bit)

- Message Digest Algorithms:
   - GOST R 34.11-94 CryptoPro 256-bit (`-old`)
   - GOST R 34.11-2012 Streebog 256/512-bit (default)

#### Asymmetric:
- Public key Algorithms:
   - GOST R 34.10-2012 256/512-bit (default)

- Supported ParamSets:
   - GOST R 34.10-2012 256-bit: A, B, C, D
   - GOST R 34.10-2012 512-bit: A, B, C

## Features

- Cryptographic Functions:
   - Symmetric Encryption + AEAD Mode (MGM)
   - Digital Signature (ECDSA equivalent)
   - VKO (выработка ключа общего) shared key negotiation (ECDH equivalent)
   - Recursive Hash Digest + Check
   - CMAC (Cipher-based message authentication code)
   - HMAC (Hash-based message authentication code)
   - HKDF (HMAC-based key derivation function)
   - PBKDF2 (Password-based key derivation function 2)
   - **TLS 1.3** with GOST cipher suites (RFC 9367), via `tls.GOSTInstall()`

- Non-Cryptographic Functions:
   - PEM key/certificate management (encrypted private keys via Kuznyechik-CBC)
   - Bin to Hex / Hex to Bin string conversion
   - Random Art (Public key fingerprint, only in `keygen` and `-pkey randomart`)

#### TODO:
  - [x] TLS 1.3
  - [x] MGM Mode of operation
  - [x] OFB Mode of operation
  - [x] PBKDF2 Function
  - [x] GOST 28147-89 CMAC
  - [x] GOST 28147-89 symmetric cipher
  - [x] GOST R 34.11-94 HMAC
  - [x] GOST R 34.10-2012 public key signature function
  - [x] VKO GOST R 34.10-2012 key agreement function
  - [x] GOST R 34.12-2015 Magma symmetric cipher
  - [x] PEM key/certificate generation

## Usage

<pre> -512
        Bit length: 256 or 512. (default 256)
  -cert string
        Certificate name. (default "Certificate.pem")
  -check string
        Check hashsum file. ('-' for STDIN)
  -cipher string
        Symmetric cipher: gost89, magma or kuznyechik. (default "kuznyechik")
  -crl string
        Certificate Revocation List path.
  -crypt string
        Encrypt/Decrypt with symmetric ciphers.
  -days int
        Defines the validity of the certificate from the date of creation.
  -digest string
        File/Wildcard to generate hashsum list. ('-' for STDIN)
  -hex string
        Encode binary string to hex format and vice-versa.
  -hkdf int
        HMAC-based key derivation function with a given output bit length.
  -info string
        Associated data, additional info. (for HKDF and AEAD encryption)
  -ipport string
        Local Port/remote's side Public IP:Port.
  -isca
        The requested CSR is for a Certificate Authority (CA).
  -iter int
        Iterations. (for PBKDF2 only) (default 1)
  -iv string
        Initialization vector. (for non-AEAD symmetric encryption)
  -key string
        Private key path (in) or private key output path (keygen).
  -mac string
        Compute hash-based/cipher-based message authentication code.
  -mode string
        Mode of operation: MGM, CFB8, CTR or OFB. (default "MGM")
  -old
        Use legacy GOST R 34.11-94 hash.
  -paramset string
        Elliptic curve ParamSet: A, B, C, D. (for gost89: A, B, C, D, Z) (default "A")
  -pass string
        Password. (for Private key PEM encryption)
  -pbkdf2
        Password-based key derivation function 2.
  -pkey string
        Generate keypair, Derive shared secret (vko), Sign and Verify.
        [keygen|certgen|derive|vko|sign|verify|text|modulus|randomart]
  -pub string
        Public key path (in for derive/vko, out for keygen).
  -rand int
        Generate random cryptographic key with a given output bit length.
  -recursive
        Process directories recursively. (for DIGEST command only)
  -root string
        Root CA Certificate path.
  -salt string
        Salt. (for PBKDF2 and HKDF commands)
  -signature string
        Input signature. (verification only)
  -subj string
        Subject: Identity. (Example: "/CN=/OU=/O=/ST=/L=/C=/emailAddress=")
  -tcp string
        Encrypted TCP/IP Transfer Protocol. [server|ip|client]
  -version
        Print version information.</pre>

## Examples

#### Asymmetric GOST R 34.10-2012 256/512-bit keypair generation (PEM):
```bash
./gosttk -pkey keygen [-512] [-paramset A|B|C|D] [-pwd "pass"] \
  [-key Private.pem] [-pub Public.pem]
```
RandomArt of the generated public key is printed to stdout.

#### Parse keys info:
```bash
./gosttk -pkey text      -key private.pem [-pwd "pass"]
./gosttk -pkey text      -key public.pem
./gosttk -pkey modulus   -key private.pem [-pwd "pass"]
./gosttk -pkey randomart -key public.pem
```

#### Digital signature (ECDSA equivalent):
```bash
./gosttk -pkey sign   [-512] -key private.pem [-pwd "pass"] < file.ext > sign.txt
sign=$(cat sign.txt | awk '{print $2}')
./gosttk -pkey verify [-512] -key public.pem -signature $sign < file.ext
echo $?
```

#### VKO: shared key negotiation (ECDH equivalent):
```bash
./gosttk -pkey derive [-512] -key private.pem -pub peerkey.pem
# or the alias:
./gosttk -pkey vko    [-512] -key private.pem -pub peerkey.pem
```

#### Generate certificate (self-signed, PEM):
```bash
./gosttk -pkey certgen -key private.pem [-pass "pass"] [-cert "Certificate.pem"]
```

#### Parse certificate info:
```bash
./gosttk -pkey text    -cert certificate.pem
./gosttk -pkey modulus -cert certificate.pem
```

#### Generate Certificate Signing Request (CSR, PEM):
```bash
./gosttk -pkey req -key private.pem -cert "Request.csr" \
  -subj "/CN=example.com/OU=TI/O=MyOrg/ST=SP/L=SaoPaulo/C=BR/emailAddress=admin@example.com"
```

#### Sign a CSR with the CA (X.509, PEM):
```bash
./gosttk -pkey x509 -root "Certificate.pem" -key ca-private.pem \
  -cert "Request.csr" [-pass "pass"] [-days 365] "Signed.crt"
```

#### Generate a Certificate Revocation List (CRL, PEM):
```bash
./gosttk -pkey crl -key ca-private.pem -cert "Certificate.pem" [-pass "pass"] \
  [-crl "CRL.pem"] "serials.txt" "CRL.pem"
```

#### Parse CRL info:
```bash
./gosttk -pkey text -crl "CRL.pem"
```

#### Validate a certificate against a CRL (revocation check):
```bash
./gosttk -pkey validate -cert "Signed.crt" -crl "CRL.pem"
```

#### Verify a certificate or CRL signature:
```bash
./gosttk -pkey check -cert "Signed.crt" -key ca-public.pem
./gosttk -pkey check -crl  "CRL.pem"    -cert "Certificate.pem"
```

#### Generate a keypair (private + public, PEM):
```bash
./gosttk -pkey keygen -key "Private.pem" -pub "Public.pem" [-pass "pass"] [-paramset A]
```

#### Symmetric encryption — default cipher (Kuznyechik, MGM):
```bash
./gosttk -crypt enc -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt dec -key $shared < ciphertext.ext > plaintext.ext
```

#### Symmetric encryption — Magma:
```bash
./gosttk -crypt enc -cipher magma -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt dec -cipher magma -key $shared < ciphertext.ext > plaintext.ext
```

#### Symmetric encryption — GOST 28147-89:
```bash
./gosttk -crypt enc -cipher gost89 -paramset A -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt dec -cipher gost89 -paramset A -key $shared < ciphertext.ext > plaintext.ext
```

#### Symmetric encryption — non-AEAD modes (CTR / OFB / CFB8):
```bash
./gosttk -crypt enc -mode CTR  -cipher kuznyechik -key $shared -iv $iv < plaintext.ext > ciphertext.ext
./gosttk -crypt enc -mode OFB  -cipher magma       -key $shared -iv $iv < plaintext.ext > ciphertext.ext
./gosttk -crypt enc -mode CFB8 -cipher gost89      -key $shared -iv $iv < plaintext.ext > ciphertext.ext
```

#### CMAC (cipher-based message authentication code):
```bash
./gosttk -mac cmac -cipher kuznyechik -key $128bitkey < file.ext
./gosttk -mac cmac -cipher kuznyechik -key $128bitkey -signature $128bitmac < file.ext
./gosttk -mac cmac -cipher magma      -key $128bitkey < file.ext
./gosttk -mac cmac -cipher gost89     -key $128bitkey -signature $64bitmac < file.ext
```

#### HMAC — Streebog (default) or GOST R 34.11-94 (`-old`):
```bash
./gosttk -mac hmac [-512]      -key $256bitkey < file.ext
./gosttk -mac hmac -old        -key $256bitkey < file.ext
./gosttk -mac hmac [-512|-old] -key $256bitkey -signature $mac < file.ext
```

#### Digest (recursive hashsum list / single file):
```bash
./gosttk -digest "*.*" [-recursive] [-512|-old]
./gosttk -digest -     [-512|-old] < file.ext
```

#### Check hashsum file:
```bash
./gosttk -check hashsum.txt [-512|-old]
```

#### HKDF (HMAC-based key derivation function):
```bash
./gosttk -hkdf 256 [-512|-old] -key "IKM" -info "AD" -salt "salt"
```

#### PBKDF2 (password-based key derivation function 2):
```bash
./gosttk -pbkdf2 [-512|-old] -key "pass" -iter 10000 -salt "salt"
```

#### PBKDF2 combined with CRYPT / HMAC:
```bash
./gosttk -crypt enc -cipher kuznyechik -pbkdf2 -512 -key "pass" < plaintext.ext > ciphertext.ext
./gosttk -mac hmac [-512] -pbkdf2 -key "pass" -salt "salt" -iter 10000 < file.ext
```

#### Bin to Hex / Hex to Bin / Dump:
```bash
./gosttk -hex enc  < File.ext > File.hex
./gosttk -hex dec  < File.hex > File.ext
./gosttk -hex dump < File.ext
```

#### Random Art (public key fingerprint):
```bash
./gosttk -pkey randomart -key public.pem
```

#### TLS 1.3 layer (TCP/IP, GOST cipher suites):
```bash
./gosttk -tcp ip > PubIP.txt
./gosttk -tcp server -cert certificate.pem -key private.pem [-ipport "8081"]
./gosttk -tcp client -cert certificate.pem -key private.pem [-ipport "127.0.0.1:8081"]
```
The TLS layer uses `tls.GOSTInstall()` from the patched `crypto/tls` in the local toolchain; keys and certificates are always in PEM format.

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

##### Military-Grade Reliability. Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
