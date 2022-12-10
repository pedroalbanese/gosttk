package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/pedroalbanese/cfb8"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/gogost/gost28147"
	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/gogost/gost341194"
	"github.com/pedroalbanese/gogost/gost3412128"
	"github.com/pedroalbanese/gogost/gost341264"
	"github.com/pedroalbanese/gogost/mgm"
	"github.com/pedroalbanese/gost-shred"
	"github.com/pedroalbanese/randomart"
)

const Version = "1.2.7-Alpha"

var (
	bit       = flag.Bool("512", false, "Bit length: 256 or 512. (default 256)")
	block     = flag.Bool("128", false, "Block size: 64 or 128. (for symmetric encryption only) (default 64)")
	check     = flag.String("check", "", "Check hashsum file. ('-' for STDIN)")
	crypt     = flag.String("crypt", "", "Encrypt/Decrypt with symmetric ciphers.")
	del       = flag.String("shred", "", "Files/Path/Wildcard to apply data sanitization method.")
	encode    = flag.String("hex", "", "Encode binary string to hex format and vice-versa.")
	info      = flag.String("info", "", "Associated data, additional info. (for HKDF and AEAD encryption)")
	iter      = flag.Int("iter", 1, "Iterations. (for SHRED and PBKDF2 only)")
	kdf       = flag.Int("hkdf", 0, "HMAC-based key derivation function with a given output bit length.")
	key       = flag.String("key", "", "Private/Public key, password or HMAC key, depending on operation.")
	mac       = flag.String("mac", "", "Compute hash-based/cipher-based message authentication code.")
	mode      = flag.String("mode", "MGM", "Mode of operation: MGM, CFB8, CTR or OFB.")
	old       = flag.Bool("old", false, "Use old roll of algorithms.")
	paramset  = flag.String("paramset", "A", "Elliptic curve ParamSet: A, B, C, D, XA, XB.")
	pbkdf     = flag.Bool("pbkdf2", false, "Password-based key derivation function 2.")
	pkey      = flag.String("pkey", "", "Generate keypair, Derive shared secret, Sign and Verify.")
	public    = flag.String("pub", "", "Remote's side public key.")
	random    = flag.Int("rand", 0, "Generate random cryptographic key with a given output bit length.")
	recursive = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	salt      = flag.String("salt", "", "Salt. (for PBKDF2 and HKDF commands)")
	sig       = flag.String("signature", "", "Input signature. (verification only)")
	target    = flag.String("digest", "", "File/Wildcard to generate hashsum list. ('-' for STDIN)")
	vector    = flag.String("iv", "", "Initialization vector. (for non-AEAD symmetric encryption)")
	version   = flag.Bool("version", false, "Print version information.")
)

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

	if *paramset != "" && (strings.ToUpper(*paramset) != "A" && strings.ToUpper(*paramset) != "B" && strings.ToUpper(*paramset) != "C" && strings.ToUpper(*paramset) != "D" && strings.ToUpper(*paramset) != "XA" && strings.ToUpper(*paramset) != "XB" && strings.ToUpper(*paramset) != "EAC" && strings.ToUpper(*paramset) != "Z") {
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
		if *block == false && *old == true {
			if strings.ToUpper(*paramset) == "A" {
				c = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProAParamSet)
				n = 8
			} else if strings.ToUpper(*paramset) == "B" {
				c = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProBParamSet)
				n = 8
			} else if strings.ToUpper(*paramset) == "C" {
				c = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProCParamSet)
				n = 8
			} else if strings.ToUpper(*paramset) == "D" {
				c = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProDParamSet)
				n = 8
			} else if strings.ToUpper(*paramset) == "EAC" {
				c = gost28147.NewCipher(key, &gost28147.SboxEACParamSet)
				n = 8
			} else if strings.ToUpper(*paramset) == "Z" {
				c = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
				n = 8
			}
		} else if *block == true && *old == false {
			c = gost3412128.NewCipher(key)
			n = 16
		} else if *block == false && *old == false {
			c = gost341264.NewCipher(key)
			n = 8
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

	if (*crypt == "enc" || *crypt == "dec") && *block == true && *old == false && (strings.ToUpper(*mode) == "OFB" || strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CFB8") {
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
			key = make([]byte, gost3412128.KeySize)
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
			if len(key) != gost3412128.KeySize {
				log.Fatal(err)
			}
		}
		var iv []byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			iv = make([]byte, gost3412128.BlockSize)
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		ciph := gost3412128.NewCipher(key)
		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
		}

		buf := make([]byte, 128*1<<10)
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

	if (*crypt == "enc" || *crypt == "dec") && *block == false && *old == false && (strings.ToUpper(*mode) == "OFB" || strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CFB8") {
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
			key = make([]byte, gost341264.KeySize)
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
			if len(key) != gost341264.KeySize {
				log.Fatal(err)
			}
		}
		ciph := gost341264.NewCipher(key)
		var iv []byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			iv = make([]byte, gost341264.BlockSize)
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
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

	if (*crypt == "enc" || *crypt == "dec") && *block == false && *old == true && (strings.ToUpper(*mode) == "OFB" || strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CFB8") {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, f)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, gost28147.KeySize)
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
			if len(key) != gost28147.KeySize {
				log.Fatal(err)
			}
		}
		var ciph *gost28147.Cipher
		if strings.ToUpper(*paramset) == "A" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProAParamSet)
		} else if strings.ToUpper(*paramset) == "B" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProBParamSet)
		} else if strings.ToUpper(*paramset) == "C" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProCParamSet)
		} else if strings.ToUpper(*paramset) == "D" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGost2814789CryptoProDParamSet)
		} else if strings.ToUpper(*paramset) == "EAC" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxEACParamSet)
		} else if strings.ToUpper(*paramset) == "Z" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
		}
		var iv []byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			iv = make([]byte, gost28147.BlockSize)
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		} else if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Encrypt(ciph, iv)
		} else if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" {
			stream = CFB8.NewCFB8Decrypt(ciph, iv)
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

	if *mac == "hmac" && *bit == false && *old == false {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(gost34112012256.New, key)
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

	if *mac == "hmac" && *bit == true && *old == false {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(gost34112012512.New, key)
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

	if *mac == "hmac" && *bit == false && *old == true {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, f)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		g := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		h := hmac.New(g, key)
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

	if *mac == "cmac" && *block == true && *old == false {
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
		c := gost3412128.NewCipher([]byte(keyHex))
		h, _ := cmac.NewWithTagSize(c, 16)
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

	if *mac == "cmac" && *block == false && *old == false {
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
		c := gost341264.NewCipher([]byte(keyHex))
		h, _ := cmac.New(c)
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

	if *mac == "cmac" && *block == false && *old == true {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true && *old == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, f)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
			if len(keyHex) != 256/8 {
				fmt.Println("Secret key must have 128-bit. (try \"-rand 128\")")
				os.Exit(1)
			}
		}
		var c *gost28147.Cipher
		if strings.ToUpper(*paramset) == "A" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProAParamSet)
		} else if strings.ToUpper(*paramset) == "B" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProBParamSet)
		} else if strings.ToUpper(*paramset) == "C" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProCParamSet)
		} else if strings.ToUpper(*paramset) == "D" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProDParamSet)
		} else if strings.ToUpper(*paramset) == "EAC" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxEACParamSet)
		} else if strings.ToUpper(*paramset) == "Z" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdtc26gost28147paramZ)
		}
		var iv [8]byte
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

	if *mac == "gost" {
		var keyHex string
		var keyRaw []byte
		if *pbkdf == true && *bit == false {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012256.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == true && *bit == true {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012512.New)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *pbkdf == true && *old == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, f)
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
		if strings.ToUpper(*paramset) == "A" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProAParamSet)
		} else if strings.ToUpper(*paramset) == "B" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProBParamSet)
		} else if strings.ToUpper(*paramset) == "C" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProCParamSet)
		} else if strings.ToUpper(*paramset) == "D" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGost2814789CryptoProDParamSet)
		} else if strings.ToUpper(*paramset) == "EAC" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxEACParamSet)
		} else if strings.ToUpper(*paramset) == "Z" {
			c = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdtc26gost28147paramZ)
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
		var h hash.Hash
		if *old == true {
			h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *old == false && *bit == false {
			h = gost34112012256.New()
		} else if *bit == true {
			h = gost34112012512.New()
		}
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
			var h hash.Hash
			if *old == true {
				h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			} else if *old == false && *bit == false {
				h = gost34112012256.New()
			} else if *bit == true {
				h = gost34112012512.New()
			}
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
						var h hash.Hash
						if *old == true {
							h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
						} else if *old == false && *bit == false {
							h = gost34112012256.New()
						} else if *bit == true {
							h = gost34112012512.New()
						}
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

				var h hash.Hash
				if *old == true {
					h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
				} else if *old == false && *bit == false {
					h = gost34112012256.New()
				} else if *bit == true {
					h = gost34112012512.New()
				}

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
	if *pkey == "derive" && *old == false && (*paramset != "XA" && *paramset != "XB") {

		var curve *gost3410.Curve
		if *bit == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if *bit == false && strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if *bit == false && strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if *bit == false && strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
			}
		} else if *bit == true && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012512paramSetC()
			}
		}

		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		prvRaw, err = hex.DecodeString(*key)
		if err != nil {
			log.Fatal(err)
		}
		if len(prvRaw) != 256/8 && len(prvRaw) != 512/8 {
			log.Fatal(err, "private key has wrong length")
		}
		prv, err = gost3410.NewPrivateKey(curve, prvRaw)
		if err != nil {
			log.Fatal(err)
		}
		pubRaw, err = hex.DecodeString(*public)
		if err != nil {
			log.Fatal(err)
		}
		if len(pubRaw) != 2*256/8 && len(pubRaw) != 2*512/8 {
			log.Fatal(err, "public key has wrong length")
		}
		pub, err = gost3410.NewPublicKey(curve, pubRaw)
		if err != nil {
			log.Fatal(err)
		}

		shared, err := prv.KEK2012256(pub, big.NewInt(1))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Shared=", hex.EncodeToString(shared))
		os.Exit(0)
	}

	if *pkey == "derive" && *old == true {

		var curve *gost3410.Curve
		if *paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB" {
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if strings.ToUpper(*paramset) == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if strings.ToUpper(*paramset) == "XB" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
			}
		}

		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		prvRaw, err = hex.DecodeString(*key)
		if err != nil {
			log.Fatal(err)
		}
		if len(prvRaw) != 256/8 {
			log.Fatal(err, "private key has wrong length")
		}
		prv, err = gost3410.NewPrivateKey(curve, prvRaw)
		if err != nil {
			log.Fatal(err)
		}
		pubRaw, err = hex.DecodeString(*public)
		if err != nil {
			log.Fatal(err)
		}
		if len(pubRaw) != 2*256/8 {
			log.Fatal(err, "public key has wrong length")
		}
		pub, err = gost3410.NewPublicKey(curve, pubRaw)
		if err != nil {
			log.Fatal(err)
		}

		shared, err := prv.KEK2001(pub, big.NewInt(1))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Shared=", hex.EncodeToString(shared)[0:16])
	}

	if (*pkey == "generate" || *pkey == "gen") && *old == false {

		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		if *bit == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
			}

			if *key != "" && *pbkdf == false {
				prvRaw, _ = hex.DecodeString(*key)
			} else if *key != "" && *pbkdf {
				prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			} else {
				prvRaw = make([]byte, 256/8)
				_, err = io.ReadFull(rand.Reader, prvRaw)
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println("Private=", hex.EncodeToString(prvRaw))

			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			pub, err = prv.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw = pub.Raw()
			fmt.Println("Public=", hex.EncodeToString(pubRaw))

			os.Exit(0)
		}

		if *bit == true && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012512paramSetC()
			}

			if *key != "" && *pbkdf == false {
				prvRaw, _ = hex.DecodeString(*key)
			} else if *key != "" && *pbkdf {
				prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 64, gost34112012512.New)
			} else {
				prvRaw = make([]byte, 512/8)
				_, err = io.ReadFull(rand.Reader, prvRaw)
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println("Private=", hex.EncodeToString(prvRaw))

			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			pub, err = prv.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw = pub.Raw()
			fmt.Println("Public=", hex.EncodeToString(pubRaw))

			os.Exit(0)
		}
	}

	if (*pkey == "generate" || *pkey == "gen") && *old == true && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB") {
		var curve *gost3410.Curve
		if strings.ToUpper(*paramset) == "A" {
			curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
		} else if strings.ToUpper(*paramset) == "B" {
			curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
		} else if strings.ToUpper(*paramset) == "C" {
			curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
		} else if strings.ToUpper(*paramset) == "XA" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
		} else if strings.ToUpper(*paramset) == "XB" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
		}

		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		if *bit == false {
			if *key != "" && *pbkdf == false {
				prvRaw, _ = hex.DecodeString(*key)
			} else if *key != "" && *pbkdf {
				f := func() hash.Hash {
					return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
				}
				prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, f)
			} else {
				prvRaw = make([]byte, 256/8)
				_, err = io.ReadFull(rand.Reader, prvRaw)
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Println("Private=", hex.EncodeToString(prvRaw))

			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			pub, err = prv.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw = pub.Raw()
			fmt.Println("Public=", hex.EncodeToString(pubRaw))

		}
		os.Exit(0)
	}

	if *pkey == "sign" || *pkey == "verify" {

		buf := bytes.NewBuffer(nil)
		scanner := os.Stdin
		io.Copy(buf, scanner)
		hash := string(buf.Bytes())

		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		var inputsig []byte
		inputsig, err = hex.DecodeString(*sig)
		if err != nil {
			log.Fatal(err)
		}

		if *pkey == "sign" && *bit == false && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {

			data := []byte(hash)
			hasher := gost34112012256.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
			}
			prvRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(prvRaw) != 256/8 {
				log.Fatal(err, "private key has wrong length")
			}
			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			signature, err := prv.Sign(rand.Reader, dgst, nil)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(hex.EncodeToString(signature))
			os.Exit(0)
		}

		if *pkey == "verify" && *bit == false && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			data := []byte(hash)
			hasher := gost34112012256.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if strings.ToUpper(*paramset) == "D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
			}
			pubRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(pubRaw) != 2*256/8 {
				log.Fatal(err, "public key has wrong length")
			}
			pub, err = gost3410.NewPublicKey(curve, pubRaw)
			if err != nil {
				log.Fatal(err)
			}
			isValid, err := pub.VerifyDigest(dgst, inputsig)
			if err != nil {
				log.Fatal(err)
			}
			if !isValid {
				log.Fatal("signature is invalid")
			}
			fmt.Println("Verify correct.")
			os.Exit(0)
		}

		if *pkey == "sign" && *bit == true && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			data := []byte(hash)
			hasher := gost34112012512.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012512paramSetC()
			}
			prvRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(prvRaw) != 512/8 {
				log.Fatal(err, "private key has wrong length")
			}
			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			signature, err := prv.Sign(rand.Reader, dgst, nil)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(hex.EncodeToString(signature))
			os.Exit(0)
		}

		if *pkey == "verify" && *bit == true && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			data := []byte(hash)
			hasher := gost34112012512.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdtc26gost34102012512paramSetC()
			}
			pubRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(pubRaw) != 2*512/8 {
				log.Fatal(err, "public key has wrong length")
			}
			pub, err = gost3410.NewPublicKey(curve, pubRaw)
			if err != nil {
				log.Fatal(err)
			}
			isValid, err := pub.VerifyDigest(dgst, inputsig)
			if err != nil {
				log.Fatal(err)
			}
			if !isValid {
				log.Fatal("signature is invalid")
			}
			fmt.Println("Verify correct.")
		}

		if *pkey == "sign" && *old == true && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB") {
			data := []byte(hash)
			hasher := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if strings.ToUpper(*paramset) == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if strings.ToUpper(*paramset) == "XB" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
			}
			prvRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(prvRaw) != 256/8 {
				log.Fatal(err, "private key has wrong length")
			}
			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			signature, err := prv.Sign(rand.Reader, dgst, nil)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(hex.EncodeToString(signature))
			os.Exit(0)
		}

		if *pkey == "verify" && *old == true && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB") {
			data := []byte(hash)
			hasher := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if strings.ToUpper(*paramset) == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if strings.ToUpper(*paramset) == "XB" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
			}
			pubRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(pubRaw) != 2*256/8 {
				log.Fatal(err, "public key has wrong length")
			}
			pub, err = gost3410.NewPublicKey(curve, pubRaw)
			if err != nil {
				log.Fatal(err)
			}
			isValid, err := pub.VerifyDigest(dgst, inputsig)
			if err != nil {
				log.Fatal(err)
			}
			if !isValid {
				log.Fatal("signature is invalid")
			}
			fmt.Println("Verify correct.")
		}
		os.Exit(0)
	}

	if *pbkdf == true {
		var h func() hash.Hash
		if *old {
			g := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			h = g
		} else if *old == false && *bit == false {
			h = gost34112012256.New
		} else if *bit == true {
			h = gost34112012512.New
		}
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, h)

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

	if *del != "" {
		shredder := shred.Shredder{}
		shredconf := shred.NewShredderConf(&shredder, shred.WriteZeros|shred.WriteRand, *iter, true)
		matches, err := filepath.Glob(*del)
		if err != nil {
			log.Fatal(err)
		}

		for _, match := range matches {
			err := shredconf.ShredDir(match)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}

	if *pkey == "text" {
		var curve *gost3410.Curve
		var oid string
		if *old == true && (strings.ToUpper(*paramset) == "A" || strings.ToUpper(*paramset) == "B" || strings.ToUpper(*paramset) == "C" || strings.ToUpper(*paramset) == "XA" || strings.ToUpper(*paramset) == "XB") {
			oid = "GOST R 34.10-2001"
			if strings.ToUpper(*paramset) == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if strings.ToUpper(*paramset) == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if strings.ToUpper(*paramset) == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if strings.ToUpper(*paramset) == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if strings.ToUpper(*paramset) == "XB" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
			}
		} else if *old == false && *bit == false && (strings.ToUpper(*paramset) == "A" || strings.ToUpper(*paramset) == "B" || strings.ToUpper(*paramset) == "C" || strings.ToUpper(*paramset) == "D") {
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
		} else if *old == false && *bit == true && (strings.ToUpper(*paramset) == "A" || strings.ToUpper(*paramset) == "B" || strings.ToUpper(*paramset) == "C") {
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

	if *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else {
		fmt.Println(randomart.FromString(*key))
	}
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	var h func() hash.Hash
	if *old {
		g := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		h = g
	} else if *old == false && *bit == false {
		h = gost34112012256.New
	} else if *bit == true {
		h = gost34112012512.New
	}
	hkdf := hkdf.New(h, master, salt, info)
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
