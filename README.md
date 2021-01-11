# GOST Toolkit
## GOST Cipher Suite written in Go

### GOST is GOvernment STandard of Russian Federation (and Soviet Union).

* GOST R 34.11-94 hash function (RFC 5831)
* GOST R 34.11-2012 Стрибог (Streebog) hash function (RFC 6986)
* GOST R 34.10-2012 (RFC 7091) public key signature function
* VKO (выработка ключа общего) GOST R 34.10-2012 key agreement function (RFC 7836)
* GOST R 34.12-2015 128-bit block cipher Кузнечик (Kuznechik) (RFC 7801)

### Usage:
<pre>  -bits int
        Bit length: 256 or 512. (digest|generate|sign|VKO) (default 256)
  -crypt
        Encrypt/Decrypt with Kuznyechik (GOST R 34.12-2015) symmetric cipher.
  -derive
        Derive shared key negociation (VKO GOST R 34.10-2012).
  -digest
        Compute Streebog256/512 (GOST R 34.11-2012) hashsum.
  -digest94
        Compute GOST94-CryptoPro (GOST R 34.11-94) hashsum.
  -generate
        Generate GOST R 34.10-2012 asymmetric keypair.
  -hmac
        Compute HMAC-Streebog256/512 (GOST R 34.11-2012).
  -key string
        Private/Public key, password or HMAC key, depending on operation.
  -pub string
        Remote's side public key. (for shared key derivation only)
  -sign
        Sign with private key.
  -signature string
        Input signature. (verification only)
  -verify
        Verify with public key.</pre>
###Example:
<h5>Asymmetric GOST R 34.10-2012 512-bit keypair generation (INI format):</h5>
<pre>./gosttk -generate -bits 512
</pre>
<h5>Signature:</h5>
<pre>./gosttk -sign -bits 512 -key $prvkey < file.ext > sign.txt
sign=$(cat sign.txt)
./gosttk -verify -bits 512 -key $pubkey -signature $sign < file.ext
</pre>
<h5>Shared key negociation (VKO):</h5>
<pre>./gosttk -derive -key $prvkey -pub $pubkey
</pre>
<h5>Encryption/decryption with Kuznyechik (GOST2015) symmetric cipher:</h5>
<pre>./gosttk -crypt -key $shared < plaintext.ext > ciphertext.ext
./gosttk -crypt -key $shared < ciphertext.ext > plaintext.ext
</pre>
<h5>GOST94-CryptoPro hashsum:</h5>
<pre>./gosttk -digest94 < file.ext
</pre>
<h5>Streebog512 hashsum:</h5>
<pre>./gosttk -digest -bits 512 < file.ext
</pre>
<h5>HMAC-Streebog512 (hash-based message authentication code):</h5>
<pre>./gosttk -hmac -bits 512 -key $key < file.ext
</pre>

Military Grade Reliability. Copyright (c) 2020-2021 Pedro Albanese - ALBANESE Lab.
