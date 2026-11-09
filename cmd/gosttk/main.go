// SPDX-License-Identifier: ISC
//
// Copyright (c) 2026 Pedro F. Albanese <pedroalbanese@hotmail.com>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"

	"crypto/go.cypherpunks.su/gogost/v6/gost3410"

	cfb8 "github.com/pedroalbanese/cfb8"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/gogost/gost28147"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/gogost/gost341194"
	"github.com/pedroalbanese/gogost/gost3412128"
	"github.com/pedroalbanese/gogost/gost341264"
	"github.com/pedroalbanese/gogost/mgm"
	"github.com/pedroalbanese/gopass"
	"github.com/pedroalbanese/randomart"
)

const (
	Version     = "1.2.10"
	VersionDate = "08 Nov 2026"
)

var (
	bit       = flag.Bool("512", false, "Bit length: 256 or 512. (default 256)")
	cipherSel = flag.String("cipher", "kuznyechik", "Symmetric cipher: gost89, magma or kuznyechik.")
	check     = flag.String("check", "", "Check hashsum file. ('-' for STDIN)")
	crypt     = flag.String("crypt", "", "Encrypt/Decrypt with symmetric ciphers.")
	encode    = flag.String("hex", "", "Encode binary string to hex format and vice-versa.")
	info      = flag.String("info", "", "Associated data, additional info. (for HKDF and AEAD encryption)")
	iter      = flag.Int("iter", 1, "Iterations. (for PBKDF2 only)")
	kdf       = flag.Int("hkdf", 0, "HMAC-based key derivation function with a given output bit length.")
	key       = flag.String("key", "", "Private key path (in) or private key output path (keygen).")
	mac       = flag.String("mac", "", "Compute hash-based/cipher-based message authentication code.")
	mode      = flag.String("mode", "MGM", "Mode of operation: MGM, CFB8, CTR or OFB.")
	old       = flag.Bool("old", false, "Use legacy GOST R 34.11-94 hash.")
	paramset  = flag.String("paramset", "A", "Elliptic curve ParamSet: A, B, C, D. (for gost89: A, B, C, D, Z)")
	pbkdf     = flag.Bool("pbkdf2", false, "Password-based key derivation function 2.")
	pkey      = flag.String("pkey", "", "Generate keypair, Derive shared secret (vko), Sign and Verify.\n[keygen|certgen|derive|vko|sign|verify|text|modulus|randomart]")
	pub       = flag.String("pub", "", "Public key path (in for derive/vko, out for keygen).")
	pwd       = flag.String("pass", "", "Password. (for Private key PEM encryption)")
	random    = flag.Int("rand", 0, "Generate random cryptographic key with a given output bit length.")
	recursive = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	salt      = flag.String("salt", "", "Salt. (for PBKDF2 and HKDF commands)")
	sig       = flag.String("signature", "", "Input signature. (verification only)")
	digest    = flag.Bool("digest", false, "Generate hashsum list for the given file(s)/wildcard(s). ('-' for STDIN)")
	tcpip     = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [server|ip|client]")
	iport     = flag.String("ipport", "", "Local Port/remote's side Public IP:Port.")
	cert      = flag.String("cert", "Certificate.pem", "Certificate name.")
	vector    = flag.String("iv", "", "Initialization vector. (for non-AEAD symmetric encryption)")
	version   = flag.Bool("version", false, "Print version information.")
	root      = flag.String("root", "", "Root CA Certificate path.")
	crl       = flag.String("crl", "", "Certificate Revocation List path.")
	subj      = flag.String("subj", "", "Subject: Identity. (Example: \"/CN=/OU=/O=/ST=/L=/C=/emailAddress=\")")
	days      = flag.Int("days", 0, "Defines the validity of the certificate from the date of creation.")
	isca      = flag.Bool("isca", false, "The requested CSR is for a Certificate Authority (CA).")
)

var (
	name, number, country, province, locality, organization, organizationunit, street, email, postalcode string
)

var (
	oidEmailAddress             = []int{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent          = []int{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID                   = []int{0, 9, 2342, 19200300, 100, 1, 1}
	oidNSComment                = []int{2, 16, 840, 1, 113730, 1, 13}
	oidStepProvisioner          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
	oidStepCertificateAuthority = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 2}
)

// ===========================================================================
// PEM encryption (RFC 1423) — GOST only
// ===========================================================================

type PEMCipher int

const (
	_ PEMCipher = iota
	PEMCipherGOST
)

type rfc1423Algo struct {
	cipher     PEMCipher
	name       string
	cipherFunc func(key []byte) (cipher.Block, error)
	keySize    int
	blockSize  int
}

var rfc1423Algos = []rfc1423Algo{{
	cipher: PEMCipherGOST,
	name:   "KUZNECHIK-CBC",
	cipherFunc: func(key []byte) (cipher.Block, error) {
		if len(key) != gost3412128.KeySize {
			return nil, errors.New("x509: invalid Kuznyechik key size")
		}
		return gost3412128.NewCipher(key), nil
	},
	keySize:   gost3412128.KeySize,
	blockSize: gost3412128.BlockSize,
},
}

func (c rfc1423Algo) deriveKey(password, salt []byte) []byte {
	hash := md5.New()
	out := make([]byte, c.keySize)
	var digest []byte

	for i := 0; i < len(out); i += len(digest) {
		hash.Reset()
		hash.Write(digest)
		hash.Write(password)
		hash.Write(salt)
		digest = hash.Sum(digest[:0])
		copy(out[i:], digest)
	}
	return out
}

func IsEncryptedPEMBlock(b *pem.Block) bool {
	_, ok := b.Headers["DEK-Info"]
	return ok
}

var IncorrectPasswordError = errors.New("x509: decryption password incorrect")

func DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		return nil, errors.New("x509: no DEK-Info header in block")
	}

	idx := strings.Index(dek, ",")
	if idx == -1 {
		return nil, errors.New("x509: malformed DEK-Info header")
	}

	mode, hexIV := dek[:idx], dek[idx+1:]
	ciph := cipherByName(mode)
	if ciph == nil {
		return nil, errors.New("x509: unknown encryption mode")
	}
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return nil, err
	}
	if len(iv) != ciph.blockSize {
		return nil, errors.New("x509: incorrect IV size")
	}

	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, err
	}

	if len(b.Bytes)%block.BlockSize() != 0 {
		return nil, errors.New("x509: encrypted PEM data is not a multiple of the block size")
	}

	data := make([]byte, len(b.Bytes))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(data, b.Bytes)

	dlen := len(data)
	if dlen == 0 || dlen%ciph.blockSize != 0 {
		return nil, errors.New("x509: invalid padding")
	}
	last := int(data[dlen-1])
	if dlen < last {
		return nil, IncorrectPasswordError
	}
	if last == 0 || last > ciph.blockSize {
		return nil, IncorrectPasswordError
	}
	for _, val := range data[dlen-last:] {
		if int(val) != last {
			return nil, IncorrectPasswordError
		}
	}
	return data[:dlen-last], nil
}

func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg PEMCipher) (*pem.Block, error) {
	ciph := cipherByKey(alg)
	if ciph == nil {
		return nil, errors.New("x509: unknown encryption mode")
	}
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, errors.New("x509: cannot generate IV: " + err.Error())
	}
	key := ciph.deriveKey(password, iv[:8])
	block, err := ciph.cipherFunc(key)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	pad := ciph.blockSize - len(data)%ciph.blockSize
	encrypted := make([]byte, len(data), len(data)+pad)
	copy(encrypted, data)
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	}
	enc.CryptBlocks(encrypted, encrypted)

	return &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  ciph.name + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}, nil
}

func cipherByName(name string) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.name == name {
			return alg
		}
	}
	return nil
}

func cipherByKey(key PEMCipher) *rfc1423Algo {
	for i := range rfc1423Algos {
		alg := &rfc1423Algos[i]
		if alg.cipher == key {
			return alg
		}
	}
	return nil
}

// ===========================================================================
// General helpers
// ===========================================================================

func handleConnection(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
}

// stdinIsPipeOrFile reports whether os.Stdin is a pipe or regular file
// (data can be read). Returns false for a terminal.
func stdinIsPipeOrFile() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	mode := fi.Mode()
	return mode&os.ModeCharDevice == 0 || mode.IsRegular()
}

// openInput returns an io.Reader from STDIN when it's a pipe/file,
// otherwise from the first positional argument (flag.Arg(0)), otherwise
// logs a fatal error.
func openInput() io.Reader {
	if stdinIsPipeOrFile() {
		return os.Stdin
	}
	if flag.Arg(0) != "" {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		return f
	}
	log.Fatal("no input: pipe data via STDIN or pass a file as the first positional argument")
	return nil
}

// readPassword reads a password using gopass.
// If masked is true, asterisks are echoed ('***'); otherwise nothing is echoed.
// The prompt itself must be printed by the caller.
func readPassword(masked bool) string {
	var pw []byte
	var err error
	if masked {
		pw, err = gopass.GetPasswdMasked()
	} else {
		pw, err = gopass.GetPasswd()
	}
	if err != nil {
		log.Fatal(err)
	}
	return string(pw)
}

func hashFactory() func() hash.Hash {
	if *old {
		return func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
	}
	if *bit {
		return gost34112012512.New
	}
	return gost34112012256.New
}

func gost89Sbox() *gost28147.Sbox {
	switch strings.ToUpper(*paramset) {
	case "Z":
		return &gost28147.SboxIdtc26gost28147paramZ
	case "B":
		return &gost28147.SboxIdGost2814789CryptoProBParamSet
	case "C":
		return &gost28147.SboxIdGost2814789CryptoProCParamSet
	case "D":
		return &gost28147.SboxIdGost2814789CryptoProDParamSet
	default:
		return &gost28147.SboxIdGost2814789CryptoProAParamSet
	}
}

// ===========================================================================
// main
// ===========================================================================

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		printBanner()
		os.Exit(0)
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("GOST Toolkit v%s  %s\n", Version, VersionDate)
		return
	}

	if *paramset != "" && (strings.ToUpper(*paramset) != "A" && strings.ToUpper(*paramset) != "B" && strings.ToUpper(*paramset) != "C" && strings.ToUpper(*paramset) != "D" && strings.ToUpper(*paramset) != "Z") {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *random != 0 && (*random == 64 || *random == 128 || *random == 256 || *random == 512) {
		var keyRaw []byte
		var err error
		keyRaw = make([]byte, *random/8)
		_, err = io.ReadFull(rand.Reader, keyRaw)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(keyRaw))
		os.Exit(0)
	} else if *random != 0 && (*random != 64 && *random != 128 && *random != 256 && *random != 512) {
		log.Fatal("RAND must have 64/128/256/512-bit.")
	}

	if *encode == "enc" || *encode == "encode" {
		in := openInput()
		b, err := ioutil.ReadAll(in)
		if len(b) == 0 {
			os.Exit(0)
		}
		if err != nil {
			log.Fatal(err)
		}
		o := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(o, b)
		os.Stdout.Write(o)
		os.Exit(0)
	}

	if *encode == "dec" || *encode == "decode" {
		in := openInput()
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, in)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		if len(b) == 0 {
			os.Exit(0)
		}
		if len(b) < 2 {
			os.Exit(0)
		}
		if len(b)%2 != 0 {
			log.Fatal("invalid hex string: odd length")
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		if _, err := hex.Decode(o, []byte(b)); err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
		os.Exit(0)
	}

	if *encode == "dump" {
		in := openInput()
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, in)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		dump := hex.Dump([]byte(b))
		os.Stdout.Write([]byte(dump))
		os.Exit(0)
	}

	if (*crypt == "enc" || *crypt == "dec") && strings.ToUpper(*mode) == "MGM" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true && *bit == false {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == true && *bit == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var keyBytes []byte
		var err error
		if keyHex == "" {
			keyBytes = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, keyBytes)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyBytes))
		} else {
			keyBytes, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyBytes) != 32 {
				log.Fatal("MGM requires a 32-byte (256-bit) key")
			}
		}

		in := openInput()
		buf := bytes.NewBuffer(nil)
		io.Copy(buf, in)
		msg := buf.Bytes()

		var c cipher.Block
		var n int
		switch strings.ToLower(*cipherSel) {
		case "gost89":
			c = gost28147.NewCipher(keyBytes, gost89Sbox())
			n = 8
		case "magma":
			c = gost341264.NewCipher(keyBytes)
			n = 8
		case "kuznyechik":
			c = gost3412128.NewCipher(keyBytes)
			n = 16
		default:
			log.Fatalf("invalid cipher: %s (use gost89, magma or kuznyechik)", *cipherSel)
		}
		aead, _ := mgm.NewMGM(c, n)

		if *crypt == "enc" {
			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatal(err)
			}

			if *vector != "" {
				nonce, _ = hex.DecodeString(*vector)
			}

			nonce[0] &= 0x7F

			out := aead.Seal(nonce, nonce, msg, []byte(*info))
			fmt.Printf("%s", out)

			os.Exit(0)
		}

		if *crypt == "dec" {
			nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

			out, err := aead.Open(nil, nonce, msg, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", out)

			os.Exit(0)
		}
	}

	if (*crypt == "enc" || *crypt == "dec") && (strings.ToUpper(*mode) == "OFB" || strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CFB8") {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true && *bit == false {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == true && *bit == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}

		var keySize, blocksize int
		switch strings.ToLower(*cipherSel) {
		case "gost89":
			keySize = gost28147.KeySize
			blocksize = gost28147.BlockSize
		case "magma":
			keySize = gost341264.KeySize
			blocksize = gost341264.BlockSize
		case "kuznyechik":
			keySize = gost3412128.KeySize
			blocksize = gost3412128.BlockSize
		default:
			log.Fatalf("invalid cipher: %s (use gost89, magma or kuznyechik)", *cipherSel)
		}

		var keyBytes []byte
		var err error
		if keyHex == "" {
			keyBytes = make([]byte, keySize)
			_, err = io.ReadFull(rand.Reader, keyBytes)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyBytes))
		} else {
			keyBytes, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyBytes) != keySize {
				log.Fatalf("key must be %d bytes for %s", keySize, *cipherSel)
			}
		}

		var ciph cipher.Block
		switch strings.ToLower(*cipherSel) {
		case "gost89":
			ciph = gost28147.NewCipher(keyBytes, gost89Sbox())
		case "magma":
			ciph = gost341264.NewCipher(keyBytes)
		case "kuznyechik":
			ciph = gost3412128.NewCipher(keyBytes)
		}

		var iv []byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			iv = make([]byte, blocksize)
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" {
			stream = cfb8.NewCFB8Encrypt(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" {
			stream = cfb8.NewCFB8Decrypt(ciph, iv)
		}

		in := openInput()
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = in.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *mac == "hmac" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, hashFactory())
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(hashFactory(), keyBytes)
		in := openInput()
		if _, err = io.Copy(h, in); err != nil {
			log.Fatal(err)
		}
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "cmac" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true && *bit == false {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012256.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == true && *bit == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012512.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
			if len(keyHex) != 256/8 {
				fmt.Println("Secret key must have 128-bit. (try \"-rand 128\")")
				os.Exit(1)
			}
		}

		var c cipher.Block
		var tagSize int
		switch strings.ToLower(*cipherSel) {
		case "gost89":
			c = gost28147.NewCipher([]byte(keyHex), gost89Sbox())
			tagSize = 8
		case "magma":
			c = gost341264.NewCipher([]byte(keyHex))
			tagSize = 8
		case "kuznyechik":
			c = gost3412128.NewCipher([]byte(keyHex))
			tagSize = 16
		default:
			log.Fatalf("invalid cipher: %s (use gost89, magma or kuznyechik)", *cipherSel)
		}

		h, _ := cmac.NewWithTagSize(c, tagSize)
		in := openInput()
		io.Copy(h, in)
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "gost" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true && *bit == false {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012256.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == true && *bit == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012512.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == false && *key != "" {
			keyHex = *key
			if len(keyHex) != 256/8 {
				fmt.Println("Secret key must have 128-bit. (try \"-rand 128\")")
				os.Exit(1)
			}
		} else if *pbkdf == false && *key == "" {
			keyRaw, _ = hex.DecodeString("00000000000000000000000000000000")
			keyHex = hex.EncodeToString(keyRaw)
			fmt.Fprintf(os.Stderr, "Key= %s\n", keyHex)
		} else {
			keyHex = *key
		}
		var iv [8]byte
		if *vector == "" {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		} else {
			raw, err := hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
			copy(iv[:], raw)
		}
		var c *gost28147.Cipher
		if strings.ToUpper(*paramset) == "Z" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdtc26gost28147paramZ)
		} else if strings.ToUpper(*paramset) == "A" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProAParamSet)
		} else if strings.ToUpper(*paramset) == "B" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProBParamSet)
		} else if strings.ToUpper(*paramset) == "C" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProCParamSet)
		} else if strings.ToUpper(*paramset) == "D" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProDParamSet)
		}
		h, _ := c.NewMAC(8, iv[:])
		in := openInput()
		io.Copy(h, in)
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				fmt.Println("Verified: false")
				os.Exit(1)
			}
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// digest (multi-file, wildcards, recursive) — edgetk-compatible
	// -----------------------------------------------------------------
	if *digest {
		// No positional args and no "-" → read STDIN.
		if len(flag.Args()) == 0 {
			h := hashFactory()()
			io.Copy(h, os.Stdin)
			fmt.Println(hex.EncodeToString(h.Sum(nil)), "(stdin)")
			os.Exit(0)
		}

		// "-" as the only positional arg → read STDIN.
		if len(flag.Args()) == 1 && flag.Arg(0) == "-" {
			h := hashFactory()()
			io.Copy(h, os.Stdin)
			fmt.Println(hex.EncodeToString(h.Sum(nil)), "(stdin)")
			os.Exit(0)
		}

		if !*recursive {
			// Non-recursive: expand wildcards and hash each file.
			for _, wildcard := range flag.Args() {
				var matches []string
				if strings.ContainsAny(wildcard, "*?[") {
					m, err := filepath.Glob(wildcard)
					if err != nil {
						log.Fatal(err)
					}
					matches = m
				} else {
					matches = []string{wildcard}
				}
				for _, match := range matches {
					f, err := os.Open(match)
					if err != nil {
						log.Fatal(err)
					}
					info, err := f.Stat()
					if err != nil {
						f.Close()
						log.Fatal(err)
					}
					if info.IsDir() {
						f.Close()
						continue
					}
					h := hashFactory()()
					if _, err := io.Copy(h, f); err != nil {
						f.Close()
						log.Fatal(err)
					}
					f.Close()
					fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+filepath.Base(match))
				}
			}
			os.Exit(0)
		}

		// Recursive: for each wildcard, walk the parent directory and
		// match the basename pattern. Deduplicate by full path.
		seen := make(map[string]bool)
		for _, wildcard := range flag.Args() {
			base := filepath.Base(wildcard)
			root := filepath.Dir(wildcard)
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				matched, err := filepath.Match(base, info.Name())
				if err != nil {
					return err
				}
				if !matched || seen[path] {
					return nil
				}
				seen[path] = true
				h := hashFactory()()
				f, err := os.Open(path)
				if err != nil {
					log.Fatal(err)
				}
				if _, err := io.Copy(h, f); err != nil {
					f.Close()
					log.Fatal(err)
				}
				f.Close()
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+filepath.Base(path))
				return nil
			})
			if err != nil {
				log.Println(err)
			}
		}
		os.Exit(0)
	}

	if *check != "" {
		var file io.Reader
		var err error
		if *check == "-" {
			file = os.Stdin
		} else {
			file, err = os.Open(*check)
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var txtlines []string
		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}
		var exit int
		for _, eachline := range txtlines {
			lines := strings.Split(string(eachline), " *")
			if strings.Contains(string(eachline), " *") {
				h := hashFactory()()
				_, err := os.Stat(lines[1])
				if err == nil {
					f, err := os.Open(lines[1])
					if err != nil {
						log.Fatal(err)
					}
					io.Copy(h, f)
					f.Close()
					if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						fmt.Println(lines[1]+"\t", "OK")
					} else {
						fmt.Println(lines[1]+"\t", "FAILED")
						exit = 1
					}
				} else {
					fmt.Println(lines[1]+"\t", "Not found!")
					exit = 1
				}
			}
		}
		os.Exit(exit)
	}

	var err error

	// -----------------------------------------------------------------
	// keygen: prompt password with masking ('***')
	// -----------------------------------------------------------------
	if *pkey == "keygen" && *pwd == "" {
		fmt.Print("Password: ")
		*pwd = readPassword(true)
	}

	// Prompt for password only on existing input key files (silent read).
	if (*pkey == "certgen" || *pkey == "text" || *pkey == "modulus" || *tcpip == "server" || *tcpip == "client" || *pkey == "derive" || *pkey == "vko" || *pkey == "req" || *pkey == "x509" || *pkey == "crl" || *pkey == "sign") && *key != "" && *pwd == "" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		if _, err := file.Read(buf); err != nil {
			file.Close()
			log.Fatal(err)
		}
		file.Close()
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
		}
		if IsEncryptedPEMBlock(block) {
			fmt.Print("Password: ")
			*pwd = readPassword(false)
		}
	}

	// -----------------------------------------------------------------
	// keygen
	// -----------------------------------------------------------------
	if *pkey == "keygen" {
		if *key == "" {
			*key = "Private.pem"
		}
		if *pub == "" {
			*pub = "Public.pem"
		}

		var gost341012PrivRaw []byte
		var curve *gost3410.Curve
		if *bit == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012256paramSetA()
			} else if *bit == false && strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012256paramSetB()
			} else if *bit == false && strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost341012256paramSetC()
			} else if *bit == false && strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost341012256paramSetD()
			}
			gost341012PrivRaw = make([]byte, 32)
		} else if *bit == true && (*paramset == "A" || *paramset == "B") {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			}
			gost341012PrivRaw = make([]byte, 64)
		}
		if curve == nil {
			log.Fatalf("paramset %q invalid for GOST R 34.10-2012 (use A, B, C or D)", *paramset)
		}
		if _, err = io.ReadFull(rand.Reader, gost341012PrivRaw); err != nil {
			log.Fatalf("Failed to read random for GOST private key: %s", err)
		}
		gost341012256Priv, err := gost3410.NewPrivateKey(curve, gost341012PrivRaw)
		if err != nil {
			log.Fatalf("Failed to create GOST private key: %s", err)
		}
		gost341012256Pub := gost341012256Priv.Public()

		privateStream, err := x509.MarshalPKCS8PrivateKey(gost341012256Priv)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{Type: "GOST PRIVATE KEY", Bytes: privateStream}
		file, err := os.Create(*key)
		if err != nil {
			log.Fatal(err)
		}
		if *pwd != "" {
			block, err = EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(*pwd), PEMCipherGOST)
			if err != nil {
				log.Fatal(err)
			}
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = pem.Encode(file, block)
			if err != nil {
				log.Fatal(err)
			}
		}
		file.Close()
		publicStream, err := x509.MarshalPKIXPublicKey(gost341012256Pub)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicStream}
		pubPEM := pem.EncodeToMemory(pubblock)
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}
		pubfile.Close()

		absPrivPath, err := filepath.Abs(*key)
		if err != nil {
			log.Fatal("Failed to get absolute path for private key:", err)
		}
		absPubPath, err := filepath.Abs(*pub)
		if err != nil {
			log.Fatal("Failed to get absolute path for public key:", err)
		}
		println("Private key saved to:", absPrivPath)
		println("Public key saved to:", absPubPath)
		if *bit {
			println("GOST2012 (512-bit)")
		} else {
			println("GOST2012 (256-bit)")
		}
		fmt.Println(randomart.FromString(strings.ReplaceAll(string(pubPEM), "\r\n", "\n")))
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// derive / vko
	// -----------------------------------------------------------------
	if *pkey == "derive" || *pkey == "vko" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "GOST PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		privateKey := privKey.(*gost3410.PrivateKey)

		if *pub == "" {
			log.Fatal("-pub is required (remote's public key path)")
		}
		file, err = os.Open(*pub)
		if err != nil {
			log.Fatal(err)
		}
		info, err = file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf = make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		block, _ = pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*gost3410.PublicKey)

		shared, err := privateKey.KEK2012256(publicKey, big.NewInt(1))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Shared=", hex.EncodeToString(shared))
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// sign
	// -----------------------------------------------------------------
	if *pkey == "sign" {
		var privPEM []byte
		h := hashFactory()()
		in := openInput()
		if _, err := io.Copy(h, in); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "GOST PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		gostKey := privKey.(*gost3410.PrivateKey)
		signature, err := gostKey.Sign(rand.Reader, h.Sum(nil), nil)
		if err != nil {
			log.Fatal(err)
		}

		sigName := "GOST2012_STREEBOG256"
		if *old {
			sigName = "GOST2012_GOST94"
		} else if *bit {
			sigName = "GOST2012_STREEBOG512"
		}
		src := "(stdin)"
		if !stdinIsPipeOrFile() && flag.Arg(0) != "" {
			src = flag.Arg(0)
		}
		fmt.Printf("%s(%s)= %s\n", sigName, src, hex.EncodeToString(signature))

		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// verify
	// -----------------------------------------------------------------
	if *pkey == "verify" {
		h := hashFactory()()
		in := openInput()
		if _, err := io.Copy(h, in); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		block, _ := pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*gost3410.PublicKey)
		inputsig, err := hex.DecodeString(*sig)
		if err != nil {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
		isValid, err := publicKey.VerifyDigest(h.Sum(nil), inputsig)
		if err != nil {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
		if isValid {
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println("Verified: false")
		os.Exit(1)
	}

	var PEM string
	var b []byte
	if *pkey == "text" || *pkey == "modulus" || *pkey == "info" || *pkey == "randomart" {
		switch {
		case *crl != "":
			b, err = ioutil.ReadFile(*crl)
		case *key != "":
			b, err = ioutil.ReadFile(*key)
		default:
			b, err = ioutil.ReadFile(*cert)
		}
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block != nil {
			switch block.Type {
			case "GOST PRIVATE KEY", "PRIVATE KEY":
				PEM = "Private"
			case "PUBLIC KEY":
				PEM = "Public"
			case "CERTIFICATE REQUEST":
				PEM = "CertificateRequest"
			case "X509 CRL", "CRL":
				PEM = "CRL"
			case "CERTIFICATE":
				PEM = "Certificate"
			}
		}
	}

	if (*pkey == "randomart") && PEM == "Public" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		fmt.Println(randomart.FromString(strings.ReplaceAll(string(buf), "\r\n", "\n")))
	}

	if (*pkey == "text" || *pkey == "modulus") && PEM == "Public" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		block, _ := pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		if *pkey == "modulus" {
			var publicKey = publicInterface.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		}
		publicKey := publicInterface.(*gost3410.PublicKey)
		derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			log.Fatal(err)
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}
		public := pem.EncodeToMemory(block)
		fmt.Printf(string(public))
		fmt.Printf("Public key:\n")
		fmt.Printf("   X:%X\n", publicKey.X)
		fmt.Printf("   Y:%X\n", publicKey.Y)
		os.Exit(0)
	}

	if (*pkey == "text" || *pkey == "modulus") && PEM == "Private" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "GOST PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		gostKey := privKey.(*gost3410.PrivateKey)
		pubKey := gostKey.Public()
		if *pkey == "modulus" {
			var publicKey = pubKey.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", publicKey.X)
			fmt.Printf("Public.Y=%X\n", publicKey.Y)
			os.Exit(0)
		}
		fmt.Printf(string(privPEM))
		derBytes, err := x509.MarshalPKIXPublicKey(gostKey.Public())
		if err != nil {
			log.Fatal(err)
		}
		p := fmt.Sprintf("%X", gostKey.Raw())
		fmt.Println("Private key:", p)
		fmt.Printf("Public key: \n")
		var publicKey = pubKey.(*gost3410.PublicKey)
		fmt.Printf("   X:%X\n", publicKey.X)
		fmt.Printf("   Y:%X\n", publicKey.Y)
		var spki struct {
			Algorithm        pkix.AlgorithmIdentifier
			SubjectPublicKey asn1.BitString
		}
		_, err = asn1.Unmarshal(derBytes, &spki)
		if err != nil {
			log.Fatal(err)
		}
		hasher := gost34112012256.New()
		if _, err = hasher.Write(spki.SubjectPublicKey.Bytes); err != nil {
			log.Fatal(err)
		}
		skid := hasher.Sum(nil)[:20]
		fmt.Printf("\nSKID: %x \n", skid)
	}

	// -----------------------------------------------------------------
	// text of CRL (must run BEFORE certificate block)
	// -----------------------------------------------------------------
	if *pkey == "text" && PEM == "CRL" {
		pemData, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal("Failed to read the CRL file:", err)
		}
		pemBlock, _ := pem.Decode(pemData)
		if pemBlock == nil {
			log.Fatal("Failed to decode the PEM block")
		}
		revocationList, err := x509.ParseRevocationList(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse the CRL:", err)
		}
		crlParsed, err := x509.ParseDERCRL(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse the CRL:", err)
		}
		fmt.Println("CRL:")
		fmt.Println("    Data:")
		fmt.Printf("        Number             : %d (%X)\n", revocationList.Number, revocationList.Number)
		fmt.Println("        Last Update        :", crlParsed.TBSCertList.ThisUpdate)
		fmt.Println("        Next Update        :", crlParsed.TBSCertList.NextUpdate)
		fmt.Println("        Issuer")
		fmt.Println("            ", crlParsed.TBSCertList.Issuer)
		fmt.Printf("        Authority Key ID   : %x\n", getAuthorityKeyIdentifierFromCRL(revocationList))
		fmt.Println("    Signature Algorithm:", revocationList.SignatureAlgorithm)
		fmt.Println("    Revoked Certificates:")
		for _, revokedCert := range revocationList.RevokedCertificates {
			fmt.Printf("    - Serial Number: %X\n", revokedCert.SerialNumber)
			fmt.Println("      Revocation Time:", revokedCert.RevocationTime)
		}
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// text of Certificate
	// -----------------------------------------------------------------
	if (*pkey == "modulus" || *pkey == "text" || *pkey == "info") && PEM == "Certificate" {
		var certPEM []byte
		file, err := os.Open(*cert)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		certPEM = buf
		var certPemBlock, _ = pem.Decode([]byte(certPEM))
		var certa, _ = x509.ParseCertificate(certPemBlock.Bytes)
		if *pkey == "modulus" {
			var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", certaPublicKey.X)
			fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
			os.Exit(0)
		}
		var buf2 bytes.Buffer
		buf2.Grow(4096)
		buf2.WriteString(fmt.Sprintf("Certificate:\n"))
		buf2.WriteString(fmt.Sprintf("%4sData:\n", ""))
		printVersion(certa.Version, &buf2)
		buf2.WriteString(fmt.Sprintf("%8sSerial Number : %x\n", "", certa.SerialNumber))
		buf2.WriteString(fmt.Sprintf("%8sCommonName    : %s \n", "", certa.Issuer.CommonName))
		buf2.WriteString(fmt.Sprintf("%8sEmailAddresses: %s \n", "", certa.EmailAddresses))
		buf2.WriteString(fmt.Sprintf("%8sIsCA          : %v \n", "", certa.IsCA))
		buf2.WriteString(fmt.Sprintf("%8sIssuer\n            ", ""))
		printName(certa.Issuer.Names, &buf2)
		buf2.WriteString(fmt.Sprintf("%8sSubject\n            ", ""))
		printName(certa.Subject.Names, &buf2)
		buf2.WriteString(fmt.Sprintf("%8sValidity\n", ""))
		buf2.WriteString(fmt.Sprintf("%12sNot Before: %s\n", "", certa.NotBefore.Format("Jan 2 15:04:05 2006 MST")))
		buf2.WriteString(fmt.Sprintf("%12sNot After : %s\n", "", certa.NotAfter.Format("Jan 2 15:04:05 2006 MST")))
		var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
		x := certaPublicKey.X.Bytes()
		c := []byte{}
		c = append(c, x...)
		buf2.WriteString(fmt.Sprintf("%8sPub.X\n", ""))
		splitz := SplitSubN(hex.EncodeToString(c), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
		}
		y := certaPublicKey.Y.Bytes()
		c = []byte{}
		c = append(c, y...)
		buf2.WriteString(fmt.Sprintf("%8sPub.Y\n", ""))
		splitz = SplitSubN(hex.EncodeToString(c), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
		}
		buf2.WriteString(fmt.Sprintf("%8sSubjectKeyId  : %x \n", "", certa.SubjectKeyId))
		buf2.WriteString(fmt.Sprintf("%8sAuthorityKeyId: %x \n", "", certa.AuthorityKeyId))
		printSignature(certa.SignatureAlgorithm, certa.Signature, &buf2)
		fmt.Print(buf2.String())
		ok := time.Now().Before(certa.NotAfter)
		fmt.Println("IsValid:", ok)
		if ok {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	// -----------------------------------------------------------------
	// certgen (self-signed or CA-signed via -root)
	// -----------------------------------------------------------------
	if *pkey == "certgen" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()

		var priv interface{}
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			priv, err = x509.ParsePKCS8PrivateKey(privKeyBytes)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
		}
		gost341012256Priv := priv.(*gost3410.PrivateKey)
		gost341012256Pub := gost341012256Priv.Public()

		keyUsage := x509.KeyUsageDigitalSignature
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
		}

		var validity string
		if *days > 0 {
			validity = fmt.Sprintf("%d", *days)
		} else {
			fmt.Print("Validity (in Days): ")
			fmt.Scanln(&validity)
		}
		intVar, err := strconv.Atoi(validity)
		if err != nil {
			log.Fatal(err)
		}
		NotAfter := time.Now().AddDate(0, 0, intVar)

		if *subj == "" {
			scanner := bufio.NewScanner(os.Stdin)
			println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")
			print("CommonName: ")
			scanner.Scan()
			name = scanner.Text()
			print("Country: ")
			scanner.Scan()
			country = scanner.Text()
			print("State/Province: ")
			scanner.Scan()
			province = scanner.Text()
			print("Locality: ")
			scanner.Scan()
			locality = scanner.Text()
			print("Organization: ")
			scanner.Scan()
			organization = scanner.Text()
			print("OrganizationUnit: ")
			scanner.Scan()
			organizationunit = scanner.Text()
			print("Email: ")
			scanner.Scan()
			email = scanner.Text()
			print("StreetAddress: ")
			scanner.Scan()
			street = scanner.Text()
			print("PostalCode: ")
			scanner.Scan()
			postalcode = scanner.Text()
			print("SerialNumber: ")
			scanner.Scan()
			number = scanner.Text()
		} else {
			name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
			if err != nil {
				log.Fatal(err)
			}
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName:         name,
				SerialNumber:       number,
				Country:            []string{country},
				Province:           []string{province},
				Locality:           []string{locality},
				Organization:       []string{organization},
				OrganizationalUnit: []string{organizationunit},
				StreetAddress:      []string{street},
				PostalCode:         []string{postalcode},
			},
			EmailAddresses:        []string{email},
			NotBefore:             time.Now(),
			NotAfter:              NotAfter,
			KeyUsage:              keyUsage,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  *isca,
		}
		if *isca {
			template.IsCA = true
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}

		var derBytes []byte
		if *root != "" {
			caData, err := ioutil.ReadFile(*root)
			if err != nil {
				log.Fatal(err)
			}
			caBlock, _ := pem.Decode(caData)
			caCRT, err := x509.ParseCertificate(caBlock.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			if !caCRT.BasicConstraintsValid || !caCRT.IsCA {
				log.Fatal("root certificate is not a valid CA")
			}
			hasher := gost34112012256.New()
			if _, err = hasher.Write(caCRT.PublicKey.(*gost3410.PublicKey).Raw()); err != nil {
				log.Fatal(err)
			}
			akid := hasher.Sum(nil)[:20]
			template.AuthorityKeyId = akid
			template.Issuer = caCRT.Subject
			derBytes, err = x509.CreateCertificate(
				rand.Reader,
				&template, caCRT,
				gost341012256Pub, &gost3410.PrivateKeyReverseDigest{Prv: gost341012256Priv},
			)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			hasher := gost34112012256.New()
			if _, err = hasher.Write(gost341012256Pub.(*gost3410.PublicKey).Raw()); err != nil {
				log.Fatal(err)
			}
			skid := hasher.Sum(nil)[:20]
			template.SubjectKeyId = skid
			template.AuthorityKeyId = skid
			derBytes, err = x509.CreateCertificate(
				rand.Reader,
				&template, &template,
				gost341012256Pub, &gost3410.PrivateKeyReverseDigest{Prv: gost341012256Priv},
			)
			if err != nil {
				log.Fatal(err)
			}
		}
		certfile, err := os.Create(*cert)
		if err != nil {
			log.Fatal(err)
		}
		pem.Encode(certfile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certfile.Close()
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// req (CSR)
	// -----------------------------------------------------------------
	if *pkey == "req" && *key != "" {
		file, err := os.Open(*key)
		if err != nil {
			log.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		file.Close()
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatal("no valid private key found")
		}
		var priva interface{}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			priva, err = x509.ParsePKCS8PrivateKey(privKeyBytes)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			priva, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
		}
		if *subj == "" {
			println("You are about to be asked to enter information \nthat will be incorporated into your certificate.")
			scanner := bufio.NewScanner(os.Stdin)
			print("CommonName: ")
			scanner.Scan()
			name = scanner.Text()
			print("Country: ")
			scanner.Scan()
			country = scanner.Text()
			print("State/Province: ")
			scanner.Scan()
			province = scanner.Text()
			print("Locality: ")
			scanner.Scan()
			locality = scanner.Text()
			print("Organization: ")
			scanner.Scan()
			organization = scanner.Text()
			print("OrganizationUnit: ")
			scanner.Scan()
			organizationunit = scanner.Text()
			print("Email: ")
			scanner.Scan()
			email = scanner.Text()
			print("StreetAddress: ")
			scanner.Scan()
			street = scanner.Text()
			print("PostalCode: ")
			scanner.Scan()
			postalcode = scanner.Text()
			print("SerialNumber: ")
			scanner.Scan()
			number = scanner.Text()
		} else {
			name, number, country, province, locality, organization, organizationunit, street, email, postalcode, err = parseSubjectString(*subj)
			if err != nil {
				log.Fatal(err)
			}
		}
		var sigalg x509.SignatureAlgorithm
		if *bit {
			sigalg = x509.GOST512
		} else {
			sigalg = x509.GOST256
		}
		emailAddress := email
		subjName := pkix.Name{
			CommonName:         name,
			SerialNumber:       number,
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationunit},
			StreetAddress:      []string{street},
			PostalCode:         []string{postalcode},
		}
		rawSubj := subjName.ToRDNSequence()
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: emailAddress},
		})
		asn1Subj, _ := asn1.Marshal(rawSubj)
		template := x509.CertificateRequest{
			RawSubject:         asn1Subj,
			EmailAddresses:     []string{emailAddress},
			SignatureAlgorithm: sigalg,
		}
		var output *os.File
		if *cert == "" {
			output = os.Stdout
		} else {
			file, err := os.Create(*cert)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, &gost3410.PrivateKeyReverseDigest{Prv: priva.(*gost3410.PrivateKey)})
		pem.Encode(output, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// x509 (sign CSR with CA)
	// -----------------------------------------------------------------
	if *pkey == "x509" && *key != "" && *root != "" && *cert != "" {
		caPublicKeyFile, err := ioutil.ReadFile(*root)
		if err != nil {
			log.Fatal(err)
		}
		pemBlock, _ := pem.Decode(caPublicKeyFile)
		if pemBlock == nil {
			log.Fatal("pem.Decode failed")
		}
		caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		if !caCRT.BasicConstraintsValid || !caCRT.IsCA {
			log.Fatal("root certificate is not a valid CA")
		}
		caPrivateKeyFile, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		pemBlock, _ = pem.Decode(caPrivateKeyFile)
		if pemBlock == nil {
			log.Fatal("pem.Decode failed")
		}
		var der []byte
		if IsEncryptedPEMBlock(pemBlock) {
			der, err = DecryptPEMBlock(pemBlock, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
		} else {
			der = pemBlock.Bytes
		}
		clientCSRFile, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal(err)
		}
		pemBlock, _ = pem.Decode(clientCSRFile)
		if pemBlock == nil {
			log.Fatal("pem.Decode failed")
		}
		clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		if err = clientCSR.CheckSignature(); err != nil {
			log.Fatal(err)
		}
		var validity string
		if *days > 0 {
			validity = fmt.Sprintf("%d", *days)
		} else {
			println("Digital certificates are valid for up to three years:")
			fmt.Print("Validity (in Days): ")
			fmt.Scanln(&validity)
		}
		intVar, err := strconv.Atoi(validity)
		if err != nil {
			log.Fatal(err)
		}
		NotAfter := time.Now().AddDate(0, 0, intVar)
		hasher := gost34112012256.New()
		if _, err = hasher.Write(clientCSR.PublicKey.(*gost3410.PublicKey).Raw()); err != nil {
			log.Fatal(err)
		}
		spki := hasher.Sum(nil)[:20]
		hasher = gost34112012256.New()
		if _, err = hasher.Write(caCRT.PublicKey.(*gost3410.PublicKey).Raw()); err != nil {
			log.Fatal(err)
		}
		akid := hasher.Sum(nil)[:20]
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
		}
		clientCRTTemplate := x509.Certificate{
			Signature:             clientCSR.Signature,
			SignatureAlgorithm:    clientCSR.SignatureAlgorithm,
			PublicKeyAlgorithm:    clientCSR.PublicKeyAlgorithm,
			PublicKey:             clientCSR.PublicKey,
			SerialNumber:          serialNumber,
			Issuer:                caCRT.Subject,
			Subject:               clientCSR.Subject,
			SubjectKeyId:          spki,
			EmailAddresses:        clientCSR.EmailAddresses,
			NotBefore:             time.Now(),
			NotAfter:              NotAfter,
			AuthorityKeyId:        akid,
			BasicConstraintsValid: *isca,
			IsCA:                  *isca,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		caPrivateKey, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			log.Fatal(err)
		}
		clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, &gost3410.PrivateKeyReverseDigest{Prv: caPrivateKey.(*gost3410.PrivateKey)})
		if err != nil {
			log.Fatal(err)
		}
		var output *os.File
		if len(flag.Args()) == 0 || flag.Arg(0) == "" {
			output = os.Stdout
		} else {
			file, err := os.Create(flag.Arg(0))
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		pem.Encode(output, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// crl (generate CRL)
	// -----------------------------------------------------------------
	if *pkey == "crl" && *key != "" && *cert != "" {
		revokedCerts := make([]pkix.RevokedCertificate, 0)
		var inputfile io.Reader = os.Stdin
		if len(flag.Args()) > 0 {
			f, err := os.Open(flag.Arg(0))
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			inputfile = f
		}
		scanner := bufio.NewScanner(inputfile)
		existingSerialNumbers := make(map[string]bool)
		for scanner.Scan() {
			serialStr := strings.TrimSpace(scanner.Text())
			serialNumber, success := new(big.Int).SetString(serialStr, 16)
			if !success {
				log.Fatalf("Invalid serial number: %s", serialStr)
			}
			serialKey := serialNumber.String()
			if existingSerialNumbers[serialKey] {
				continue
			}
			revocationTime := time.Now()
			revokedCert := pkix.RevokedCertificate{
				SerialNumber:   serialNumber,
				RevocationTime: revocationTime,
			}
			revokedCerts = append(revokedCerts, revokedCert)
			existingSerialNumbers[serialKey] = true
		}
		if err := scanner.Err(); err != nil {
			log.Fatal("Failed to read serials list:", err)
		}
		if *crl != "" {
			existingCRLData, err := ioutil.ReadFile(*crl)
			if err != nil {
				log.Fatal("Failed to read the existing CRL file:", err)
			}
			existingCRLBlock, _ := pem.Decode(existingCRLData)
			if existingCRLBlock == nil {
				log.Fatal("Failed to decode the PEM block of the existing CRL")
			}
			existingCRL, err := x509.ParseRevocationList(existingCRLBlock.Bytes)
			if err != nil {
				log.Fatal("Failed to parse the existing CRL:", err)
			}
			for _, revokedCert := range existingCRL.RevokedCertificates {
				serialKey := revokedCert.SerialNumber.String()
				if existingSerialNumbers[serialKey] {
					continue
				}
				revokedCerts = append(revokedCerts, revokedCert)
				existingSerialNumbers[serialKey] = true
			}
		}
		desiredLength := 80
		randomNumber, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(desiredLength)), nil))
		if err != nil {
			log.Fatal("Failed to generate a random number:", err)
		}
		issuanceTime := time.Now()
		nextUpdateTime := time.Now().Add(time.Hour * 24 * 365)
		revocationListTemplate := &x509.RevocationList{
			RevokedCertificates: revokedCerts,
			Number:              randomNumber,
			ThisUpdate:          issuanceTime,
			NextUpdate:          nextUpdateTime,
		}
		issuerKeyPEM, err := os.ReadFile(*key)
		if err != nil {
			log.Fatal("Failed to read private key file:", err)
		}
		issuerCertPEM, err := os.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read certificate file:", err)
		}
		keyBlock, _ := pem.Decode(issuerKeyPEM)
		var decryptedKeyBytes []byte
		if IsEncryptedPEMBlock(keyBlock) {
			decryptedKeyBytes, err = DecryptPEMBlock(keyBlock, []byte(*pwd))
			if err != nil {
				log.Fatal("Failed to decrypt private key:", err)
			}
			keyBlock.Bytes = decryptedKeyBytes
		}
		issuerKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse private key:", err)
		}
		certBlock, _ := pem.Decode(issuerCertPEM)
		if certBlock == nil {
			log.Fatal("Failed to decode certificate")
		}
		issuerCert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse certificate:", err)
		}
		crlBytes, err := x509.CreateRevocationList(rand.Reader, revocationListTemplate, issuerCert, &gost3410.PrivateKeyReverseDigest{Prv: issuerKey.(*gost3410.PrivateKey)})
		if err != nil {
			log.Fatal("Failed to create new CRL:", err)
		}
		pemBlock := &pem.Block{Type: "X509 CRL", Bytes: crlBytes}
		var output *os.File
		if len(flag.Args()) < 2 {
			output = os.Stdout
		} else {
			file, err := os.Create(flag.Arg(1))
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			output = file
		}
		pem.Encode(output, pemBlock)
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// validate (certificate against CRL)
	// -----------------------------------------------------------------
	if *pkey == "validate" {
		crlBytes, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal("Failed to read CRL file:", err)
		}
		pemBlock, _ := pem.Decode(crlBytes)
		if pemBlock == nil {
			log.Fatal("Failed to decode CRL PEM block")
		}
		revocationList, err := x509.ParseRevocationList(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse CRL:", err)
		}
		certBytes, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read certificate file:", err)
		}
		pemBlock, _ = pem.Decode(certBytes)
		if pemBlock == nil {
			log.Fatal("Failed to decode certificate PEM block")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse certificate:", err)
		}
		isRevoked := false
		var revocationTime time.Time
		for _, revokedCert := range revocationList.RevokedCertificates {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				isRevoked = true
				revocationTime = revokedCert.RevocationTime
				break
			}
		}
		if isRevoked {
			fmt.Println("The certificate is revoked")
			fmt.Println("Revocation Time:", revocationTime)
			os.Exit(1)
		} else {
			fmt.Println("The certificate is not revoked")
			os.Exit(0)
		}
	}

	// -----------------------------------------------------------------
	// check (verify certificate or CRL signature)
	// -----------------------------------------------------------------
	if *pkey == "check" && *crl == "" {
		certPEM, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal(err)
		}
		certPemBlock, _ := pem.Decode(certPEM)
		certa, err := x509.ParseCertificate(certPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Fatal(err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		h := gost34112012256.New()
		if certa.SignatureAlgorithm == x509.GOST512 {
			h = gost34112012512.New()
		}
		h.Write(certa.RawTBSCertificate)
		hashData := h.Sum(nil)
		reverseBytes(hashData)
		isValid, err := publicKey.(*gost3410.PublicKey).VerifyDigest(hashData, certa.Signature)
		if err != nil {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
		if isValid {
			fmt.Println("Verified: true")
			os.Exit(0)
		}
		fmt.Println("Verified: false")
		os.Exit(1)
	}

	if *pkey == "check" && *crl != "" {
		crlBytes, err := ioutil.ReadFile(*crl)
		if err != nil {
			log.Fatal("Failed to read CRL file:", err)
		}
		pemBlock, _ := pem.Decode(crlBytes)
		if pemBlock == nil {
			log.Fatal("Failed to decode CRL PEM block")
		}
		revocationList, err := x509.ParseRevocationList(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse CRL:", err)
		}
		crlParsed, err := x509.ParseDERCRL(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse CRL:", err)
		}
		issuerCertBytes, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal("Failed to read issuer's certificate file:", err)
		}
		issuerCertBlock, _ := pem.Decode(issuerCertBytes)
		if issuerCertBlock == nil {
			log.Fatal("Failed to decode PEM block of issuer's certificate")
		}
		issuerCert, err := x509.ParseCertificate(issuerCertBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse issuer's certificate:", err)
		}
		err = issuerCert.CheckCRLSignature(crlParsed)
		if err != nil {
			fmt.Println("Verified: false")
			os.Exit(1)
		}
		fmt.Println("Verified: true")
		_ = revocationList
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// text of CSR
	// -----------------------------------------------------------------
	if (*pkey == "text" || *pkey == "modulus") && PEM == "CertificateRequest" {
		certPEM, err := ioutil.ReadFile(*cert)
		if err != nil {
			log.Fatal(err)
		}
		certPemBlock, _ := pem.Decode(certPEM)
		certa, err := x509.ParseCertificateRequest(certPemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		if *pkey == "modulus" {
			var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
			fmt.Printf("Public.X=%X\n", certaPublicKey.X)
			fmt.Printf("Public.Y=%X\n", certaPublicKey.Y)
			os.Exit(0)
		}
		var certaPublicKey = certa.PublicKey.(*gost3410.PublicKey)
		var buf2 bytes.Buffer
		buf2.Grow(4096)
		buf2.WriteString(fmt.Sprintf("Certificate Request:\n"))
		buf2.WriteString(fmt.Sprintf("%4sData:\n", ""))
		printVersion(certa.Version, &buf2)
		buf2.WriteString(fmt.Sprintf("%8sCommonName    : %s \n", "", certa.Subject.CommonName))
		buf2.WriteString(fmt.Sprintf("%8sEmailAddresses: %s \n", "", certa.EmailAddresses))
		buf2.WriteString(fmt.Sprintf("%8sCurve         : %s \n", "", certa.PublicKey.(*gost3410.PublicKey).C.Name))
		buf2.WriteString(fmt.Sprintf("%8sSubject\n            ", ""))
		printName(certa.Subject.Names, &buf2)
		x := certaPublicKey.X.Bytes()
		c := []byte{}
		c = append(c, x...)
		buf2.WriteString(fmt.Sprintf("%8sPub.X\n", ""))
		splitz := SplitSubN(hex.EncodeToString(c), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
		}
		y := certaPublicKey.Y.Bytes()
		c = []byte{}
		c = append(c, y...)
		buf2.WriteString(fmt.Sprintf("%8sPub.Y\n", ""))
		splitz = SplitSubN(hex.EncodeToString(c), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			buf2.WriteString(fmt.Sprintf("            %-10s            \n", strings.ReplaceAll(chunk, " ", ":")))
		}
		printSignature(certa.SignatureAlgorithm, certa.Signature, &buf2)
		fmt.Print(buf2.String())
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// TLS 1.3 (server/client/ip)
	// -----------------------------------------------------------------
	if *tcpip == "server" || *tcpip == "client" {
		var certPEM []byte
		var privPEM []byte
		tls.GOSTInstall()
		if *key == "" {
			var priv interface{}
			var err error
			gost341012256PrivRaw := make([]byte, 32)
			if _, err = io.ReadFull(rand.Reader, gost341012256PrivRaw); err != nil {
				log.Fatalf("Failed to read random for GOST private key: %s", err)
			}
			priv, err = gost3410.NewPrivateKey(
				gost3410.CurveIdtc26gost341012256paramSetA(),
				gost341012256PrivRaw,
			)
			if err != nil {
				log.Fatalf("Failed to create GOST private key: %s", err)
			}
			private := priv.(*gost3410.PrivateKey)
			publicKey := private.Public()
			keyUsage := x509.KeyUsageDigitalSignature
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				log.Fatalf("Failed to generate serial number: %v", err)
			}
			Mins := 12
			NotAfter := time.Now().Local().Add(time.Minute * time.Duration(Mins))
			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					CommonName:         "",
					Country:            []string{""},
					Province:           []string{""},
					Locality:           []string{""},
					Organization:       []string{""},
					OrganizationalUnit: []string{""},
				},
				EmailAddresses:        []string{"pedroalbanese@hotmail.com"},
				NotBefore:             time.Now(),
				NotAfter:              NotAfter,
				KeyUsage:              keyUsage,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			template.IsCA = true
			template.KeyUsage |= x509.KeyUsageCertSign
			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, &gost3410.PrivateKeyReverseDigest{Prv: private})
			if err != nil {
				log.Fatalf("Failed to create certificate: %v", err)
			}
			certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
			privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				log.Fatalf("Unable to marshal private key: %v", err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "GOST PRIVATE KEY", Bytes: privBytes})
		} else {
			file, err := os.Open(*key)
			if err != nil {
				log.Fatal(err)
			}
			info, err := file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf := make([]byte, info.Size())
			file.Read(buf)
			file.Close()
			var block *pem.Block
			block, _ = pem.Decode(buf)
			if block == nil {
				log.Fatal("no valid private key found")
			}
			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Fatal(err)
				}
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "GOST PRIVATE KEY", Bytes: privKeyBytes})
			} else {
				privPEM = buf
			}
			file, err = os.Open(*cert)
			if err != nil {
				log.Fatal(err)
			}
			info, err = file.Stat()
			if err != nil {
				log.Fatal(err)
			}
			buf = make([]byte, info.Size())
			file.Read(buf)
			file.Close()
			certPEM = buf
		}
		if *tcpip == "server" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			if err != nil {
				log.Fatal(err)
			}
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			cfg.Rand = rand.Reader
			port := "8081"
			if *iport != "" {
				port = *iport
			}
			ln, err := tls.Listen("tcp", ":"+port, &cfg)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			defer ln.Close()
			tlscon := conn.(*tls.Conn)
			err = tlscon.Handshake()
			if err != nil {
				log.Fatalf("server: handshake failed: %s", err)
			} else {
				log.Print("server: conn: Handshake completed")
			}
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				derBytes, err := x509.MarshalPKIXPublicKey(v.PublicKey)
				if err != nil {
					log.Fatal(err)
				}
				pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
				fmt.Printf("%s\n", pubPEM)
			}
			go handleConnection(conn)
			fmt.Println("Connection accepted")
			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Client response: " + string(message))
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")
			}
		}
		if *tcpip == "client" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			if err != nil {
				log.Fatal(err)
			}
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			ipport := "127.0.0.1:8081"
			if *iport != "" {
				ipport = *iport
			}
			conn, err := tls.Dial("tcp", ipport, &cfg)
			if err != nil {
				log.Fatal(err)
			}
			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Issuer Name: %s\n", cert.Issuer)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
				fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
			}
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()
			var b bytes.Buffer
			for _, cert := range conn.ConnectionState().PeerCertificates {
				err := pem.Encode(&b, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				if err != nil {
					log.Println(err)
				}
			}
			fmt.Println(b.String())
			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
		os.Exit(0)
	}

	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
		os.Exit(0)
	}

	// -----------------------------------------------------------------
	// text (key in hex)
	// -----------------------------------------------------------------
	if *pkey == "text" {
		var curve *gost3410.Curve
		var oid string
		if *bit == false && (strings.ToUpper(*paramset) == "A" || strings.ToUpper(*paramset) == "B" || strings.ToUpper(*paramset) == "C" || strings.ToUpper(*paramset) == "D") {
			oid = "GOST R 34.10-2012_256"
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if *bit == false && strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if *bit == false && strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if *bit == false && strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
			}
		} else if *bit == true && (strings.ToUpper(*paramset) == "A" || strings.ToUpper(*paramset) == "B" || strings.ToUpper(*paramset) == "C") {
			oid = "GOST R 34.10-2012_512"
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012512paramSetC()
			}
		}
		if *key == "-" {
			data, _ := ioutil.ReadAll(os.Stdin)
			b := strings.TrimSuffix(string(data), "\r\n")
			b = strings.TrimSuffix(b, "\n")
			prvRaw, err := hex.DecodeString(b)
			if err != nil {
				log.Fatal(err)
			}
			privatekey, err := gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}
			pubkey, err := privatekey.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw := pubkey.Raw()
			fmt.Println("Private Key:")
			fmt.Println(" K:", strings.ToUpper(hex.EncodeToString(prvRaw)))
			print(" ", len(hex.EncodeToString(prvRaw))/2, " bytes ", len(hex.EncodeToString(prvRaw))*4, " bits\n")
			splitx := SplitSubN(hex.EncodeToString(prvRaw), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("Public Key:")
			fmt.Println(" X:", pubkey.X)
			fmt.Println(" Y:", pubkey.Y)
			print(" ", len(hex.EncodeToString(pubRaw))/2, " bytes ", len(hex.EncodeToString(pubRaw))*4, " bits\n")
			splitz := SplitSubN(hex.EncodeToString(pubRaw), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("OID:", strings.ToUpper(oid), "ParamSet:", strings.ToUpper(*paramset))
		} else if *key != "-" {
			prvRaw, err := hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			privatekey, err := gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}
			pubkey, err := privatekey.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw := pubkey.Raw()
			fmt.Println("Private Key:")
			fmt.Println(" K:", strings.ToUpper(hex.EncodeToString(prvRaw)))
			print(" ", len(*key)/2, " bytes ", len(*key)*4, " bits\n")
			splitx := SplitSubN(*key, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("Public Key:")
			fmt.Println(" X:", pubkey.X)
			fmt.Println(" Y:", pubkey.Y)
			print(" ", len(hex.EncodeToString(pubRaw))/2, " bytes ", len(hex.EncodeToString(pubRaw))*4, " bits\n")
			splitz := SplitSubN(hex.EncodeToString(pubRaw), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("OID:", strings.ToUpper(oid), "ParamSet:", strings.ToUpper(*paramset))
		}
		os.Exit(0)
	}

	if *pbkdf == true {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, hashFactory())
		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *kdf > 0 {
		keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		keySlice := string(keyRaw[:])
		fmt.Println(hex.EncodeToString([]byte(keySlice)[:*kdf/8]))
		os.Exit(0)
	}

	flag.PrintDefaults()
}

// ===========================================================================
// Helpers
// ===========================================================================

// printBanner prints a short description of the toolkit (fits one screen).
func printBanner() {
	fmt.Printf(`GOST Toolkit v%s %s
Unified GOST cryptography toolkit: hashes, MACs, ciphers, keys,
X.509 CSR, CRL, and certificates, and TLS 1.3 with GOST ciphersuites.

USAGE
  %s [flags] [input-file]
  cat file | %s [flags]

HASHES
  -digest FILE|-   hash a file, wildcard or STDIN ('-' = STDIN)
  -recursive       walk directories recursively (with -digest)
  -check FILE|-    verify a hashsum list
  -old             use legacy GOST R 34.11-94
  -512             use GOST R 34.11-2012 512-bit (default 256)

MACs
  -mac hmac|cmac|gost   compute HMAC, CMAC or GOST 28147-89 MAC
  -key HEX              secret key (hex)
  -signature HEX        expected MAC (verification)

SYMMETRIC CIPHERS
  -crypt enc|dec        encrypt/decrypt
  -cipher gost89|magma|kuznyechik
  -mode MGM|CTR|OFB|CFB8
  -key HEX              key (hex)
  -iv HEX               initialization vector
  -info STRING          additional authenticated data (MGM)

KEY DERIVATION
  -pbkdf2 -key P -salt S -iter N
  -hkdf BITS -key P -salt S -info A

RANDOM / HEX
  -rand 64|128|256|512  generate random key (hex)
  -hex enc|dec|dump     hex encode/decode/dump

KEYS AND CERTIFICATES  (see README for full examples)
  -pkey keygen          generate keypair         (-key, -pub, -pass)
  -pkey certgen         self-signed or CA-signed certificate
  -pkey req             certificate signing request (CSR)
  -pkey x509            sign a CSR with a CA
  -pkey crl             generate a certificate revocation list
  -pkey validate        check a certificate against a CRL
  -pkey check           verify certificate/CRL signature
  -pkey text|modulus    inspect key/cert/CSR/CRL
  -pkey sign|verify     sign/verify stdin with GOST R 34.10-2012
  -pkey derive          VKO shared secret
  -pass PASS            PEM key password (Kuznyechik-CBC)
  -paramset A|B|C|D     elliptic curve parameter set

TLS 1.3
  -tcp server|client    mutual-auth GOST TLS 1.3
  -tcp ip               print this machine's external IP
  -ipport ADDR          listen/connect address

OPTIONS
  -version              print version and exit
  -h, --help            print all flags

EXAMPLES
  %s -digest file.txt
  %s -crypt enc -key 00112233... < in.bin > out.bin
  %s -pkey keygen -key CA.key -pub CA.pub -pass 123
  %s -pkey certgen -key CA.key -cert CA.crt -isca -days 3650
  %s -pkey req -key user.key -cert user.csr -subj "/CN=user/O=Org/C=BR"
  %s -pkey x509 -root CA.crt -key CA.key -cert user.csr user.crt
  %s -pkey crl -key CA.key -cert CA.crt -crl OLD.pem serials.txt CRL.pem
  %s -pkey validate -cert user.crt -crl CRL.pem

Use '-h' or '--help' for the full flag list.
`, Version, VersionDate, os.Args[0], os.Args[0],
		os.Args[0], os.Args[0], os.Args[0], os.Args[0],
		os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	hkdf := hkdf.New(hashFactory(), master, salt, info)
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf, key)
	var result [128]byte
	copy(result[:], key)
	return result, err
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}
	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}
	return subs
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]
	}
	return ss
}

func printVersion(version int, buf *bytes.Buffer) {
	hexVersion := version - 1
	if hexVersion < 0 {
		hexVersion = 0
	}
	buf.WriteString(fmt.Sprintf("%8sVersion: %d (%#x)\n", "", version, hexVersion))
}

func printName(names []pkix.AttributeTypeAndValue, buf *bytes.Buffer) []string {
	values := []string{}
	for _, name := range names {
		oid := name.Type
		switch {
		case len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4:
			switch oid[3] {
			case 3:
				values = append(values, fmt.Sprintf("CN=%s", name.Value))
			case 5:
				values = append(values, fmt.Sprintf("SERIALNUMBER=%s", name.Value))
			case 6:
				values = append(values, fmt.Sprintf("C=%s", name.Value))
			case 7:
				values = append(values, fmt.Sprintf("L=%s", name.Value))
			case 8:
				values = append(values, fmt.Sprintf("ST=%s", name.Value))
			case 9:
				values = append(values, fmt.Sprintf("STREET=%s", name.Value))
			case 10:
				values = append(values, fmt.Sprintf("O=%s", name.Value))
			case 11:
				values = append(values, fmt.Sprintf("OU=%s", name.Value))
			case 17:
				values = append(values, fmt.Sprintf("POSTALCODE=%s", name.Value))
			default:
				values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
			}
		case oid.Equal(oidEmailAddress):
			values = append(values, fmt.Sprintf("emailAddress=%s", name.Value))
		case oid.Equal(oidDomainComponent):
			values = append(values, fmt.Sprintf("DC=%s", name.Value))
		case oid.Equal(oidUserID):
			values = append(values, fmt.Sprintf("UID=%s", name.Value))
		default:
			values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
		}
	}
	if len(values) > 0 {
		buf.WriteString(values[0])
		for i := 1; i < len(values); i++ {
			buf.WriteString("," + values[i])
		}
		buf.WriteString("\n")
	}
	return values
}

func printSignature(sigAlgo x509.SignatureAlgorithm, sig []byte, buf *bytes.Buffer) {
	buf.WriteString(fmt.Sprintf("%4sSignature Algorithm: %s", "", sigAlgo))
	for i, val := range sig {
		if (i % 18) == 0 {
			buf.WriteString(fmt.Sprintf("\n%9s", ""))
		}
		buf.WriteString(fmt.Sprintf("%02x", val))
		if i != len(sig)-1 {
			buf.WriteString(":")
		}
	}
	buf.WriteString("\n")
}

func parseSubjectString(subject string) (name, number, country, province, locality, organization, organizationunit, street, email, postalcode string, err error) {
	parts := strings.Split(subject, "/")
	found := false
	for _, part := range parts {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return "", "", "", "", "", "", "", "", "", "", errors.New("invalid subject string format: missing '=' in " + part)
		}
		found = true
		key := kv[0]
		value := kv[1]
		switch key {
		case "C":
			country = value
		case "ST":
			province = value
		case "L":
			locality = value
		case "O":
			organization = value
		case "OU":
			organizationunit = value
		case "CN":
			name = value
		case "emailAddress":
			email = value
		case "postalCode":
			postalcode = value
		case "STREET":
			street = value
		case "serialNumber":
			number = value
		default:
			return "", "", "", "", "", "", "", "", "", "", errors.New("unknown subject attribute: " + key)
		}
	}
	if !found {
		return "", "", "", "", "", "", "", "", "", "", errors.New("invalid subject string format: empty")
	}
	return name, number, country, province, locality, organization, organizationunit, street, email, postalcode, nil
}

type authorityKeyIdentifier struct {
	Raw                 asn1.RawContent
	ID                  []byte `asn1:"optional,tag:0"`
	KeyIdentifier       []byte `asn1:"optional,tag:1"`
	AuthorityCertIssuer []byte `asn1:"optional,tag:2"`
	AuthorityCertSerial []byte `asn1:"optional,tag:3"`
}

func getAuthorityKeyIdentifierFromCRL(crl *x509.RevocationList) []byte {
	for _, extension := range crl.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) {
			var akid authorityKeyIdentifier
			_, err := asn1.Unmarshal(extension.Value, &akid)
			if err == nil {
				return akid.ID
			}
		}
	}
	return nil
}

func reverseBytes(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}
