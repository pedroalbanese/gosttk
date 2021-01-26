## GOST Toolkit: GOST Cipher Suite written in Go ☭
Multi purpose cross-platform cryptography tool for encryption / decryption, hash digest, hash-based message authentication code (HMAC), digital signature, shared key agreement (VKO) and PBKDF2 function.

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

#### Symmetric Ciphers:
* GOST 28147-89
* GOST R 34.12-2015 Magma (default)
* GOST R 34.12-2015 Kuznechik (Grasshopper)

#### Asymmetric Ciphers:
* GOST R 34.10-2001 CryptoPro 256-bit
* GOST R 34.10-2012 256/512-bit (default) 

#### Hash Ciphers:
* GOST R 34.11-94 CryptoPro 256-bit
* GOST R 34.11-2012 Streebog 256/512-bit (default) 

#### Cryptographic Functions:
* Symmetric Encryption/Decryption
* Digital Signature
* VKO (выработка ключа общего) shared key negociation
* Hash Digest 
* HMAC (Hash-based message authentication code)
* PBKDF2 (Password-based key derivation function 2)

#### Non-Cryptographic Functions:
* GOST R 50739-95 data sanitization method

#### Supported ParamSet:
* GOST R 34.10-2001 256-bit: A, B, C, XA, XB
* GOST R 34.10-2012 256-bit: A, B, C, D
* GOST R 34.10-2012 512-bit: A, B

#### TODO:
  - [ ] MGM Mode of operation
  - [x] OFB Mode of operation
  - [x] PBKDF2 Function
  - [x] GOST 28147-89 symmetric cipher
  - [x] GOST R 34.11-94 HMAC
  - [x] GOST R 50739-95 data sanitization method 
  - [x] GOST R 34.10-2001 public key signature function
  - [x] VKO GOST R 34.10-2001 key agreement function
  - [x] GOST R 34.12-2015 Magma symmetric cipher

### Usage:
<pre> -bits int
       Bit length: 256 or 512. (default 256)
 -block int
       Block size: 64 or 128. (for symmetric encryption only) (default 64)
 -crypt
       Encrypt/Decrypt with symmetric ciphers.
 -derive
       Derive shared key negociation (VKO).
 -digest
       Compute a single hashsum.
 -generate
       Generate asymmetric keypair.
 -hashsum string
       File/Wildcard to generate hashsum list.
 -hmac
       Hash-based message authentication code.
 -iter int
       Iterations. (for shred and PBKDF2 only) (default 1)
 -key string
       Private/Public key, password or HMAC key, depending on operation.
 -mode int
       Mode: 2001 or 2012. (default 2012)
 -operation string
       Operation mode: CTR or OFB. (default "CTR")
 -paramset string
       Elliptic curve ParamSet: A, B, C, D, XA, XB. (default "A")
 -pbkdf2
       Password-based key derivation function 2.
 -pub string
       Remote's side public key. (for shared key derivation only)
 -rand
       Generate random 256-bit cryptographic key.
 -salt string
       Salt. (for PBKDF2 only)
 -shred string
       Files/Path/Wildcard to apply data sanitization method.
 -sign
       Sign with private key.
 -signature string
       Input signature. (verification only)
 -verify
       Verify with public key.</pre>
### Examples:
#### Asymmetric GOST R 34.10-2001 256-bit keypair generation (INI format):
<pre>./gosttk -generate -mode 2001
</pre>
#### Asymmetric GOST R 34.10-2012 256/512-bit keypair generation (default):
<pre>./gosttk -generate [-bits 512]
</pre>
#### Signature:
<pre>./gosttk -sign [-bits 512] -key $prvkey < file.ext > sign.txt
sign=$(cat sign.txt)
./gosttk -verify [-bits 512] -key $pubkey -signature $sign < file.ext
</pre>
#### Shared key negociation (VKO):
<pre>./gosttk -derive [-bits 512|-mode 2001] -key $prvkey -pub $pubkey
</pre>
#### Encryption/decryption with Magma (GOST R 34.12-2015) symmetric cipher (default):
<pre>./gosttk -crypt -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt -key $shared < ciphertext.ext > plaintext.ext
</pre>
#### Encryption/decryption with GOST 28147-89 symmetric cipher:
<pre>./gosttk -crypt -mode 2001 -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt -mode 2001 -key $shared < ciphertext.ext > plaintext.ext
</pre>
#### Encryption/decryption with Kuznyechik (GOST R 34.12-2015) symmetric cipher:
<pre>./gosttk -crypt -block 128 -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt -block 128 -key $shared < ciphertext.ext > plaintext.ext
</pre>
#### GOST94-CryptoPro hashsum:
<pre>./gosttk -digest -mode 2001 < file.ext
</pre>
#### HMAC-GOST94-CryptoPro based (hash-based message authentication code):
<pre>./gosttk -hmac -mode 2001 -key $256bitkey < file.ext
</pre>
#### Streebog256/512 hashsum:
<pre>./gosttk -digest [-bits 512] < file.ext
</pre>
#### HMAC-Streebog256/512:
<pre>./gosttk -hmac [-bits 512] -key $256bitkey < file.ext
</pre>
#### PBKDF2 (password-based key derivation function 2):
<pre>./gosttk -pbkdf2 [-bits|-mode] -key "pass" -iter 10000 -salt "salt"
</pre>
#### Shred (GOST R 50739-95 data sanitization method, 25 iterations):
<pre>./gosttk -shred keypair.ini -iter 25
</pre>

##### Military Grade Reliability. Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.
