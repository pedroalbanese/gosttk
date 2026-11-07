// SPDX-License-Identifier: ISC
//
// gosttk.go — Unified gosttk + gostls.
// TLS 1.3 with GOST cipher suites as default.

package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
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
	"strings"
	"time"
	"unsafe"

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
	"github.com/pedroalbanese/randomart"
)

const Version = "1.2.8"

var (
	bit       = flag.Bool("512", false, "Bit length: 256 or 512. (default 256)")
	cipherSel = flag.String("cipher", "kuznyechik", "Symmetric cipher: gost89, magma or kuznyechik.")
	check     = flag.String("check", "", "Check hashsum file. ('-' for STDIN)")
	crypt     = flag.String("crypt", "", "Encrypt/Decrypt with symmetric ciphers.")
	encode    = flag.String("hex", "", "Encode binary string to hex format and vice-versa.")
	info      = flag.String("info", "", "Associated data, additional info. (for HKDF and AEAD encryption)")
	iter      = flag.Int("iter", 1, "Iterations. (for PBKDF2 only)")
	kdf       = flag.Int("hkdf", 0, "HMAC-based key derivation function with a given output bit length.")
	key       = flag.String("key", "", "Private/Public key, password or HMAC key, depending on operation.")
	mac       = flag.String("mac", "", "Compute hash-based/cipher-based message authentication code.")
	mode      = flag.String("mode", "MGM", "Mode of operation: MGM, CFB8, CTR or OFB.")
	old       = flag.Bool("old", false, "Use legacy GOST R 34.11-94 hash.")
	paramset  = flag.String("paramset", "A", "Elliptic curve ParamSet: A, B, C, D. (for gost89: A, B, C, D, Z)")
	pbkdf     = flag.Bool("pbkdf2", false, "Password-based key derivation function 2.")
	pkey      = flag.String("pkey", "", "Generate keypair, Derive shared secret (vko), Sign and Verify.")
	priv      = flag.String("private", "Private.pem", "Private key path. (for keypair generation)")
	pub       = flag.String("public", "Public.pem", "Public key path. (for keypair generation)")
	public    = flag.String("pub", "", "Remote's side public key.")
	pwd       = flag.String("pass", "", "Password. (for Private key PEM encryption)")
	random    = flag.Int("rand", 0, "Generate random cryptographic key with a given output bit length.")
	recursive = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	salt      = flag.String("salt", "", "Salt. (for PBKDF2 and HKDF commands)")
	sig       = flag.String("signature", "", "Input signature. (verification only)")
	target    = flag.String("digest", "", "File/Wildcard to generate hashsum list. ('-' for STDIN)")
	tcpip     = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [server|ip|client]")
	iport     = flag.String("ipport", "", "Local Port/remote's side Public IP:Port.")
	cert      = flag.String("cert", "Certificate.pem", "Certificate name.")
	vector    = flag.String("iv", "", "Initialization vector. (for non-AEAD symmetric encryption)")
	version   = flag.Bool("version", false, "Print version information.")
)

var (
	oidEmailAddress             = []int{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent          = []int{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID                   = []int{0, 9, 2342, 19200300, 100, 1, 1}
	oidNSComment                = []int{2, 16, 840, 1, 113730, 1, 13}
	oidStepProvisioner          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
	oidStepCertificateAuthority = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 2}
)

func handleConnection(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
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

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *version {
		fmt.Println(Version)
		return
	}

	if *paramset != "" && (strings.ToUpper(*paramset) != "A" && strings.ToUpper(*paramset) != "B" && strings.ToUpper(*paramset) != "C" && strings.ToUpper(*paramset) != "D" && strings.ToUpper(*paramset) != "Z") {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *random != 0 && (*random == 64 || *random == 128 || *random == 256 || *random == 512) {
		var key []byte
		var err error
		key = make([]byte, *random/8)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	} else if *random != 0 && (*random != 64 && *random != 128 && *random != 256 && *random != 512) {
		log.Fatal("RAND must have 64/128/256/512-bit.")
	}

	if *encode == "enc" || *encode == "encode" {
		b, err := ioutil.ReadAll(os.Stdin)
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
		var err error
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		if len(b) == 0 {
			os.Exit(0)
		}
		if len(b) < 2 {
			os.Exit(0)
		}
		if (len(b)%2 != 0) || (err != nil) {
			log.Fatal(err)
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(o, []byte(b))
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
		os.Exit(0)
	}

	if *encode == "dump" {
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
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
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		var c cipher.Block
		var n int
		switch strings.ToLower(*cipherSel) {
		case "gost89":
			c = gost28147.NewCipher(key, gost89Sbox())
			n = 8
		case "magma":
			c = gost341264.NewCipher(key)
			n = 8
		case "kuznyechik":
			c = gost3412128.NewCipher(key)
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

		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, keySize)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != keySize {
				log.Fatalf("key must be %d bytes for %s", keySize, *cipherSel)
			}
		}

		var ciph cipher.Block
		switch strings.ToLower(*cipherSel) {
		case "gost89":
			ciph = gost28147.NewCipher(key, gost89Sbox())
		case "magma":
			ciph = gost341264.NewCipher(key)
		case "kuznyechik":
			ciph = gost3412128.NewCipher(key)
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

		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
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
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(hashFactory(), key)
		if _, err = io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
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
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
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
			iv = *byte8(raw)
			if err != nil {
				log.Fatal(err)
			}
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
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *target == "-" {
		h := hashFactory()()
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *target != "" && *recursive == false {
		files, err := filepath.Glob(*target)
		if err != nil {
			log.Fatal(err)
		}

		for _, match := range files {
			h := hashFactory()()
			f, err := os.Open(match)
			if err != nil {
				log.Fatal(err)
			}
			file, _ := os.Stat(match)
			if file.IsDir() {
			} else {
				if _, err := io.Copy(h, f); err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
			}
		}
		os.Exit(0)
	}

	if *target != "" && *recursive == true {
		err := filepath.Walk(filepath.Dir(*target),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, _ := os.Stat(path)
				if file.IsDir() {
				} else {
					filename := filepath.Base(path)
					pattern := filepath.Base(*target)
					matched, err := filepath.Match(pattern, filename)
					if err != nil {
						fmt.Println(err)
					}
					if matched {
						h := hashFactory()()
						f, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						if _, err := io.Copy(h, f); err != nil {
							log.Fatal(err)
						}
						fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
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

	if *pkey == "keygen" && *pwd == "" {
		scanner := bufio.NewScanner(os.Stdin)
		print("Password: ")
		scanner.Scan()
		*pwd = scanner.Text()
	}

	if (*pkey == "certgen" || *pkey == "keygen" || *pkey == "text" || *pkey == "modulus" || *tcpip == "server" || *tcpip == "client" || *pkey == "derive" || *pkey == "vko") && *key != "" && *pwd == "" {
		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		if IsEncryptedPEMBlock(block) {
			scanner := bufio.NewScanner(os.Stdin)
			print("Password: ")
			scanner.Scan()
			*pwd = scanner.Text()
		}
	}

	if *pkey == "keygen" {
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
		gost341012256Priv, err := gost3410.NewPrivateKey(
			curve,
			gost341012PrivRaw,
		)
		if err != nil {
			log.Fatalf("Failed to create GOST private key: %s", err)
		}
		gost341012256Pub := gost341012256Priv.Public()

		privateStream, err := x509.MarshalPKCS8PrivateKey(gost341012256Priv)
		if err != nil {
			log.Fatal(err)
		}
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateStream,
		}
		file, err := os.Create(*priv)
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
		publicStream, err := x509.MarshalPKIXPublicKey(gost341012256Pub)
		if err != nil {
			log.Fatal(err)
		}
		pubblock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicStream,
		}
		pubPEM := pem.EncodeToMemory(pubblock)
		pubfile, err := os.Create(*pub)
		if err != nil {
			log.Fatal(err)
		}
		err = pem.Encode(pubfile, pubblock)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(randomart.FromString(strings.ReplaceAll(string(pubPEM), "\r\n", "\n")))
		os.Exit(0)
	}

	if *pkey == "derive" || *pkey == "vko" {
		var privPEM []byte
		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Println(err)
		}
		privateKey := privKey.(*gost3410.PrivateKey)

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

	if *pkey == "sign" {
		var privPEM []byte
		h := hashFactory()()
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		file, err := os.Open(*key)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Println(err)
		}
		gostKey := privKey.(*gost3410.PrivateKey)
		signature, err := gostKey.Sign(rand.Reader, h.Sum(nil), nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("(stdin)=", hex.EncodeToString(signature))
		os.Exit(0)
	}

	if *pkey == "verify" {
		h := hashFactory()()
		if _, err := io.Copy(h, os.Stdin); err != nil {
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
		block, _ := pem.Decode(buf)
		publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := publicInterface.(*gost3410.PublicKey)
		inputsig, err := hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}
		isValid, err := publicKey.VerifyDigest(h.Sum(nil), inputsig)
		if err != nil {
			log.Fatal(err)
		}
		if !isValid {
			log.Fatal("signature is invalid")
		}
		fmt.Println("Verify correct.")
		os.Exit(0)
	}

	var PEM string
	var b []byte
	if *pkey == "text" || *pkey == "modulus" || *pkey == "info" || *pkey == "randomart" {
		if *key != "" {
			b, err = ioutil.ReadFile(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else if *key == "" {
			b, err = ioutil.ReadFile(*cert)
			if err != nil {
				log.Fatal(err)
			}
		}
		s := string(b)
		if strings.Contains(s, "PRIVATE") {
			PEM = "Private"
		} else if strings.Contains(s, "PUBLIC") {
			PEM = "Public"
		} else if strings.Contains(s, "CERTIFICATE") {
			PEM = "Certificate"
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
			log.Println(err)
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		}
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
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
		var block *pem.Block
		block, _ = pem.Decode(buf)
		if block == nil {
			errors.New("no valid private key found")
		}
		var privKeyBytes []byte
		if IsEncryptedPEMBlock(block) {
			privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
			if err != nil {
				log.Fatal(err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
		} else {
			privPEM = buf
		}
		var privateKeyPemBlock, _ = pem.Decode([]byte(privPEM))
		var privKey, _ = x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			log.Println(err)
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
			log.Println(err)
		}
		skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
		fmt.Printf("\nSKID: %x \n", skid)
		os.Exit(0)
	}

	if (*pkey == "modulus" || *pkey == "text" || *pkey == "info") && *cert != "" {
		var certPEM []byte
		file, err := os.Open(*cert)
		if err != nil {
			log.Println(err)
		}
		info, err := file.Stat()
		if err != nil {
			log.Println(err)
		}
		buf := make([]byte, info.Size())
		file.Read(buf)
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
		buf2.WriteString(fmt.Sprintf("%8sIP Address    : %s \n", "", certa.IPAddresses))
		buf2.WriteString(fmt.Sprintf("%8sDNSNames      : %s \n", "", certa.DNSNames))
		buf2.WriteString(fmt.Sprintf("%8sIsCA          : %v \n", "", certa.IsCA))

		buf2.WriteString(fmt.Sprintf("%8sIssuer\n            ", ""))
		printName(certa.Issuer.Names, &buf2)

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
		os.Exit(0)
	}

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

		var priv interface{}

		var block *pem.Block
		block, _ = pem.Decode(buf)

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

		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()

		Mins := 1200
		NotAfter := time.Now().Local().Add(time.Minute * time.Duration(Mins))

		scanner := bufio.NewScanner(os.Stdin)

		fmt.Print("CommonName: ")
		scanner.Scan()
		name := scanner.Text()

		fmt.Print("Country: ")
		scanner.Scan()
		country := scanner.Text()

		fmt.Print("State/Province: ")
		scanner.Scan()
		province := scanner.Text()

		fmt.Print("Locality: ")
		scanner.Scan()
		locality := scanner.Text()

		fmt.Print("Organization: ")
		scanner.Scan()
		organization := scanner.Text()

		fmt.Print("OrganizationUnit: ")
		scanner.Scan()
		organizationunit := scanner.Text()

		fmt.Print("Email: ")
		scanner.Scan()
		email := scanner.Text()

		fmt.Print("StreetAddress: ")
		scanner.Scan()
		street := scanner.Text()

		fmt.Print("PostalCode: ")
		scanner.Scan()
		postalcode := scanner.Text()

		fmt.Print("SerialNumber: ")
		scanner.Scan()
		number := scanner.Text()

		fmt.Print("AuthorityKeyId: ")
		scanner.Scan()
		authority, _ := hex.DecodeString(scanner.Text())

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
			EmailAddresses: []string{email},

			NotBefore: time.Now(),
			NotAfter:  NotAfter,

			KeyUsage:              keyUsage,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
			AuthorityKeyId:        authority,

			PermittedDNSDomainsCritical: true,
			DNSNames:                    []string{ip.String()},
			IPAddresses:                 []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign

		derBytes, err := x509.CreateCertificate(
			rand.Reader,
			&template, &template,
			gost341012256Pub, &gost3410.PrivateKeyReverseDigest{Prv: gost341012256Priv},
		)
		if err != nil {
			log.Println(err)
		}

		certfile, err := os.Create(*cert)
		if err != nil {
			log.Println(err)
		}
		pem.Encode(certfile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		os.Exit(0)
	}

	// --- gostls: TLS 1.3 (server/client/ip) ---
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
			public := private.Public()

			keyUsage := x509.KeyUsageDigitalSignature

			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				log.Fatalf("Failed to generate serial number: %v", err)
			}

			consensus := externalip.DefaultConsensus(nil, nil)
			ip, _ := consensus.ExternalIP()

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
				EmailAddresses: []string{"pedroalbanese@hotmail.com"},

				NotBefore: time.Now(),
				NotAfter:  NotAfter,

				KeyUsage:              keyUsage,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  true,

				PermittedDNSDomainsCritical: true,
				DNSNames:                    []string{ip.String()},
				IPAddresses:                 []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			}

			template.IsCA = true
			template.KeyUsage |= x509.KeyUsageCertSign

			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, public, &gost3410.PrivateKeyReverseDigest{Prv: private})
			if err != nil {
				log.Fatalf("Failed to create certificate: %v", err)
			}

			certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
			privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				log.Fatalf("Unable to marshal private key: %v", err)
			}
			privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		} else {
			file, err := os.Open(*key)
			if err != nil {
				log.Println(err)
			}
			info, err := file.Stat()
			if err != nil {
				log.Println(err)
			}
			buf := make([]byte, info.Size())
			file.Read(buf)

			var block *pem.Block
			block, _ = pem.Decode(buf)

			if block == nil {
				errors.New("no valid private key found")
			}

			var privKeyBytes []byte
			if IsEncryptedPEMBlock(block) {
				privKeyBytes, err = DecryptPEMBlock(block, []byte(*pwd))
				if err != nil {
					log.Println(err)
				}
				privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
			} else {
				privPEM = buf
			}

			file, err = os.Open(*cert)
			if err != nil {
				log.Println(err)
			}
			info, err = file.Stat()
			if err != nil {
				log.Println(err)
			}
			buf = make([]byte, info.Size())
			file.Read(buf)
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
				fmt.Printf("IP Address: %s \n", cert.IPAddresses)
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

	// Nenhum comando reconhecido.
	flag.PrintDefaults()
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	hkdf := hkdf.New(hashFactory(), master, salt, info)
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf, key)
	var result [128]byte
	copy(result[:], key)
	return result, err
}

func byte8(s []byte) (a *[8]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
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
