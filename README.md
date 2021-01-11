## GOST Toolkit: GOST Cipher Suite written in Go

### GOST is GOvernment STandard of Russian Federation (and Soviet Union).

* GOST 28147-89 (RFC 5830) block cipher
* GOST R 34.11-94 hash function (RFC 5831)
* GOST R 34.10-2001 (RFC 5832) public key signature function
* GOST R 34.11-2012 Стрибог (Streebog) hash function (RFC 6986)
* GOST R 34.10-2012 (RFC 7091) public key signature function
* VKO (выработка ключа общего) GOST R 34.10-2001 key agreement function (RFC 4357)
* VKO GOST R 34.10-2012 key agreement function (RFC 7836)
* GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznechik) (RFC 7801)
* GOST R 34.12-2015 64-bit block cipher Магма (Magma)

#### TODO:
  - [x] GOST 28147-89 symmetric cipher
  - [x] GOST R 34.11-94 HMAC-CryptoPro
  - [x] GOST R 34.12-2015 Magma symmetric cipher
  - [x] GOST R 34.10-2001 public key signature function
  - [x] VKO GOST R 34.10-2001 key agreement function

### Usage:
<pre>  -bits int
        Bit length: 256 or 512. (digest|generate|sign|VKO) (default 256)
  -block int
        Block size: 64 or 128. (for symmetric encryption only) (default 128)
  -crypt
        Encrypt/Decrypt with Kuznyechik (GOST R 34.12-2015) symmetric cipher.
  -derive
        Derive shared key negociation (VKO).
  -digest
        Compute Streebog256/512 or GOST94-CryptoPro hashsum.
  -generate
        Generate GOST R 34.10-2012 or 34.10-2001 asymmetric keypair.
  -hmac
        Compute HMAC-Streebog256/512 or HMAC-GOST94-CryptoPro.
  -key string
        Private/Public key, password or HMAC key, depending on operation.
  -mode int
        Mode: 2001 or 2012. (digest|generate|sign|VKO) (default 2012)
  -pub string
        Remote's side public key. (for shared key derivation only)
  -sign
        Sign with private key.
  -signature string
        Input signature. (verification only)
  -verify
        Verify with public key.</pre>
### Example:
#### Asymmetric GOST R 34.10-2012 512-bit keypair generation (INI format):
<pre>./gosttk -generate -bits 512
</pre>
#### Signature:
<pre>./gosttk -sign -bits 512 -key $prvkey < file.ext > sign.txt
sign=$(cat sign.txt)
./gosttk -verify -bits 512 -key $pubkey -signature $sign < file.ext
</pre>
#### Shared key negociation (VKO):
<pre>./gosttk -derive -key $prvkey -pub $pubkey
</pre>
#### Encryption/decryption with Kuznyechik (GOST R 34.12-2015) symmetric cipher:
<pre>./gosttk -crypt -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt -key $shared < ciphertext.ext > plaintext.ext
</pre>
#### Encryption/decryption with Magma (GOST R 34.13-2015) symmetric cipher:
<pre>./gosttk -crypt -block 64 -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt -block 64 -key $shared < ciphertext.ext > plaintext.ext
</pre>
#### GOST94-CryptoPro hashsum:
<pre>./gosttk -digest -mode 2001 < file.ext
</pre>
#### Streebog512 hashsum:
<pre>./gosttk -digest -bits 512 < file.ext
</pre>
#### HMAC-Streebog512 (hash-based message authentication code):
<pre>./gosttk -hmac -bits 512 -key $key < file.ext
</pre>

##### Military Grade Reliability. Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.
