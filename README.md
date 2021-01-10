# GOST Toolkit
<h3>GOST Cipher Suite written in Go</h3>

<h5>Usage:</h5>
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
        Verify with public key.
  <pre>
