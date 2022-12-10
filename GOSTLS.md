# GOST TLS
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/engine/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/engine?status.png)](http://godoc.org/github.com/pedroalbanese/engine)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/engine/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/engine/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/engine)](https://goreportcard.com/report/github.com/pedroalbanese/engine)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/engine)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/engine)](https://github.com/pedroalbanese/engine/releases)

Cross-platform hybrid cryptography tool for shared key agreement (VKO), digital signature and TLS 1.2 for small or embedded systems. 

## Command-line Security Suite

  - GOST R 34.10-2012 public key signature function (RFC 7091)
  - VKO GOST R 34.10-2012 key agreement function (RFC 7836)
  - GOST R 34.11-2012 Streebog hash function 256/512-bit (RFC 6986)
  - GOST R 34.12-2015 128-bit block cipher Kuznechik (RFC 7801)

### Supported ParamSets:
  - GOST R 34.10-2012 256-bit: A, B, C, D
  - GOST R 34.10-2012 512-bit: A, B

## Features
Cryptographic Functions:  

   * Digital Signature (ECDSA-like)
   * VKO Shared Key Agreement (ECDH)
   * TLS 1.2 (Transport Layer Security)
   
Non-cryptographic Functions:  

   * Privacy-Enhanced Mail (PEM format)
   * RandomArt (OpenSSH-like)

## Usage
<pre> -512
       Key length: 256 or 512. (default 256)
 -cert string
       Certificate name. (default "Certificate.pem")
 -ipport string
       Local Port/remote's side Public IP:Port.
 -key string
       Private/Public key, depending on operation.
 -paramset string
       Elliptic curve ParamSet: A, B, C, D. (default "A")
 -pkey string
       Generate keypair, Generate certificate. [keygen|certgen]
 -private string
       Private key path. (for keypair generation) (default "Private.pem")
 -public string
       Public key path. (for keypair generation) (default "Public.pem")
 -pwd string
       Password. (for Private key PEM encryption)
 -signature string
       Input signature. (verification only)
 -tcp string
       Encrypted TCP/IP Transfer Protocol. [server|ip|client]</pre>  

## Examples
#### Asymmetric GOST2012 keypair generation:
```sh
./gostls -pkey keygen [-512] [-paramset B] [-pwd "pass"]
```
#### Parse keys info:
```sh
./gostls -pkey [text|modulus] [-pwd "pass"] -key private.pem
./gostls -pkey [text|modulus] -key public.pem
./gostls -pkey randomart -key public.pem
```
#### Digital signature:
```sh
./gostls -pkey sign -key private.pem [-pwd "pass"] < file.ext > sign.txt
sign=$(cat sign.txt|awk '{print $2}')
./gostls -pkey verify -key public.pem -signature $sign < file.ext
echo $?
```
#### VKO Shared key agreement:
```sh
./gostls -pkey derive -key private.pem -public peerkey.pem
```
#### Generate Certificate:
```sh
./gostls -pkey certgen -key private.pem [-pwd "pass"] [-cert "output.ext"]
```
#### Parse Certificate info:
```sh
./gostls -pkey [text|modulus] -cert certificate.pem
```
#### TLS Layer (TCP/IP):
```sh
./gostls -tcp ip > PubIP.txt
./gostls -tcp server -cert certificate.pem -key private.pem [-ipport "8081"]
./gostls -tcp client -cert certificate.pem -key private.pem [-ipport "127.0.0.1:8081"]
```

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2023 Pedro F. Albanese - ALBANESE Research Lab.
