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
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"

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
	"github.com/pedroalbanese/gosttk"
	"github.com/pedroalbanese/randomart"
)

var (
	bit       = flag.Bool("512", false, "Bit length: 256 or 512. (default 256)")
	block     = flag.Bool("128", false, "Block size: 64 or 128. (for symmetric encryption only) (default 64)")
	check     = flag.String("check", "", "Check hashsum file. (- for STDIN)")
	ciphmac   = flag.Bool("cmac", false, "Compute cipher-based message authentication code.")
	crypt     = flag.String("crypt", "", "Encrypt/Decrypt with symmetric ciphers.")
	del       = flag.String("shred", "", "Files/Path/Wildcard to apply data sanitization method.")
	derive    = flag.Bool("derive", false, "Derive shared secret key (VKO).")
	encode    = flag.String("hex", "", "Encode binary string to hex format and vice-versa.")
	generate  = flag.Bool("keygen", false, "Generate asymmetric keypair.")
	iter      = flag.Int("iter", 1, "Iterations. (for SHRED and PBKDF2 only)")
	key       = flag.String("key", "", "Private/Public key, password or HMAC key, depending on operation.")
	mac       = flag.Bool("hmac", false, "Compute hash-based message authentication code.")
	mode      = flag.String("mode", "MGM", "Mode of operation: MGM, CTR or OFB.")
	old       = flag.Bool("old", false, "Use old roll of algorithms.")
	paramset  = flag.String("paramset", "A", "Elliptic curve ParamSet: A, B, C, D, XA, XB.")
	pbkdf     = flag.Bool("pbkdf2", false, "Password-based key derivation function 2.")
	public    = flag.String("pub", "", "Remote's side public key/remote's side public IP.")
	random    = flag.Int("rand", 0, "Generate random cryptographic key: 128, 256 or 512 bit-length.")
	recursive = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	salt      = flag.String("salt", "", "Salt. (for PBKDF2 only)")
	sig       = flag.String("signature", "", "Input signature. (verification only)")
	sign      = flag.Bool("sign", false, "Sign with private key.")
	target    = flag.String("digest", "", "File/Wildcard to generate hashsum list. (- for STDIN)")
	tcpip     = flag.String("tcp", "", "TCP/IP Transfer Protocol.")
	verbose   = flag.Bool("verbose", false, "Verbose mode. (for CHECK command only)")
	verify    = flag.Bool("verify", false, "Verify with public key.")
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
		fmt.Println(gosttk.Version)
		return
	}

	if *paramset != "" && (*paramset != "A" && *paramset != "B" && *paramset != "C" && *paramset != "D" && *paramset != "XA" && *paramset != "XB") {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *random != 0 && (*random == 128 || *random == 256 || *random == 512) {
		var key []byte
		var err error
		key = make([]byte, *random/8)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	} else if *random != 0 && (*random != 128 && *random != 256 && *random != 512) {
		log.Fatal("RAND must have 128/256/512-bit.")
	}

	if *encode == "e" || *encode == "enc" || *encode == "encode" {
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

	if *encode == "d" || *encode == "dec" || *encode == "decode" {
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

	if *tcpip == "dump" {
		port := "8081"
		if *public != "" {
			port = *public
		}
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		defer ln.Close()

		strRemoteAddr := conn.RemoteAddr().String()
		strLocalAddr := conn.LocalAddr()
		fmt.Fprint(os.Stderr, "Remote TCP address= ")
		fmt.Fprintln(os.Stderr, strRemoteAddr)
		fmt.Fprint(os.Stderr, "Local TCP address= ")
		fmt.Fprintln(os.Stderr, strLocalAddr)

		split := strings.Split(strRemoteAddr, ":")
		ipv4Addr := net.ParseIP(split[0] + "")
		ipv4Mask := net.CIDRMask(24, 32)
		fmt.Fprint(os.Stderr, "IPv4= ")
		fmt.Fprintln(os.Stderr, ipv4Addr.Mask(ipv4Mask))

		var buf bytes.Buffer
		io.Copy(&buf, conn)
		text := strings.TrimSuffix(string(buf.Bytes()), "\n")
		fmt.Println(text)
		os.Exit(0)
	}

	if *tcpip == "send" {
		ipport := "127.0.0.1:8081"
		if *public != "" {
			ipport = *public
		}
		conn, err := net.Dial("tcp", ipport)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		strRemoteAddr := conn.RemoteAddr().String()
		strLocalAddr := conn.LocalAddr()
		fmt.Fprint(os.Stderr, "Remote TCP address= ")
		fmt.Fprintln(os.Stderr, strRemoteAddr)
		fmt.Fprint(os.Stderr, "Local TCP address= ")
		fmt.Fprintln(os.Stderr, strLocalAddr)

		split := strings.Split(strRemoteAddr, ":")
		ipv4Addr := net.ParseIP(split[0])
		ipv4Mask := net.CIDRMask(24, 32)
		fmt.Fprint(os.Stderr, "IPv4= ")
		fmt.Fprintln(os.Stderr, ipv4Addr.Mask(ipv4Mask))

		buf := bytes.NewBuffer(nil)
		scanner := os.Stdin
		io.Copy(buf, scanner)

		text := string(buf.Bytes())

		fmt.Fprintf(conn, text)

		text = strings.TrimSuffix(string(buf.Bytes()), "\n")
		fmt.Println(text)
		os.Exit(0)
	}

	if *crypt == "enc" && *mode == "MGM" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true && *bit == false {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else if *pbkdf == true && *bit == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
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
			c = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			n = 8
		} else if *block == true && *old == false {
			c = gost3412128.NewCipher(key)
			n = 16
		} else if *block == false && *old == false {
			c = gost341264.NewCipher(key)
			n = 8
		}
		aead, _ := mgm.NewMGM(c, n)

		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

		out := aead.Seal(nonce, nonce, msg, nil)
		fmt.Printf("%s", out)
		os.Exit(0)
	}

	if *crypt == "dec" && *mode == "MGM" {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true && *bit == false {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else if *pbkdf == true && *bit == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex != "" {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		} else {
			os.Exit(1)
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()
		var c cipher.Block
		var n int
		if *block == false && *old == true {
			c = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			n = 8
		} else if *block == true && *old == false {
			c = gost3412128.NewCipher(key)
			n = 16
		} else if *block == false && *old == false {
			c = gost341264.NewCipher(key)
			n = 8
		}
		aead, _ := mgm.NewMGM(c, n)

		nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

		out, err := aead.Open(nil, nonce, msg, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", out)
		os.Exit(0)
	}

	if (*crypt == "enc" || *crypt == "dec") && *block == true && *old == false && (*mode == "OFB" || *mode == "CTR") {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true && *bit == false {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else if *pbkdf == true && *bit == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
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
		iv := make([]byte, gost3412128.BlockSize)
		ciph := gost3412128.NewCipher(key)
		var stream cipher.Stream
		if *mode == "CTR" || *mode == "ctr" {
			stream = cipher.NewCTR(ciph, iv)
		} else if *mode == "OFB" || *mode == "ofb" {
			stream = cipher.NewOFB(ciph, iv)
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

	if (*crypt == "enc" || *crypt == "dec") && *block == false && *old == false && (*mode == "OFB" || *mode == "CTR") {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true && *bit == false {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else if *pbkdf == true && *bit == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
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
		iv := make([]byte, gost341264.BlockSize)
		var stream cipher.Stream
		if *mode == "CTR" || *mode == "ctr" {
			stream = cipher.NewCTR(ciph, iv)
		} else if *mode == "OFB" || *mode == "ofb" {
			stream = cipher.NewOFB(ciph, iv)
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

	if (*crypt == "enc" || *crypt == "dec") && *block == false && *old == true && (*mode == "OFB" || *mode == "CTR") {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, f)
			keyHex = hex.EncodeToString(prvRaw)
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
		ciph := gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
		iv := make([]byte, gost28147.BlockSize)
		var stream cipher.Stream
		if *mode == "CTR" || *mode == "ctr" {
			stream = cipher.NewCTR(ciph, iv)
		} else if *mode == "OFB" || *mode == "ofb" {
			stream = cipher.NewOFB(ciph, iv)
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

	if *mac == true && *bit == false && *old == false {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
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
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == true && *bit == true && *old == false {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
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
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == true && *bit == false && *old == true {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, f)
			keyHex = hex.EncodeToString(prvRaw)
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
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *ciphmac == true && *block == true && *old == false {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true && *bit == false {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else if *pbkdf == true && *bit == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
			if len(keyHex) != 256/8 {
				fmt.Println("Secret key must have 128-bit. (try \"-rand 128\")")
				os.Exit(1)
			}
		}
		c := gost3412128.NewCipher([]byte(keyHex))
		h, _ := cmac.New(c)
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *ciphmac == true && *block == false && *old == false {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true && *bit == false {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else if *pbkdf == true && *bit == true {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012512.New)
			keyHex = hex.EncodeToString(prvRaw)
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
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *ciphmac == true && *block == false && *old == true {
		var keyHex string
		var prvRaw []byte
		if *pbkdf == true {
			f := func() hash.Hash {
				return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			}
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, f)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
			if len(keyHex) != 256/8 {
				fmt.Println("Secret key must have 128-bit. (try \"-rand 128\")")
				os.Exit(1)
			}
		}
		c := gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGostR341194CryptoProParamSet)
		var iv [8]byte
		h, _ := c.NewMAC(8, iv[:])
		io.Copy(h, os.Stdin)
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
			file, err := os.Stat(match)
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
				file, err := os.Stat(path)
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

					if *verbose {
						if hex.EncodeToString(h.Sum(nil)) == lines[0] {
							fmt.Println(lines[1]+"\t", "OK")
						} else {
							fmt.Println(lines[1]+"\t", "FAILED")
						}
					} else {
						if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						} else {
							os.Exit(1)
						}
					}
				} else {
					if *verbose {
						fmt.Println(lines[1]+"\t", "Not found!")
					} else {
						os.Exit(1)
					}
				}
			}
		}
		os.Exit(0)
	}

	var err error
	if *derive == true && *old == false && (*paramset != "XA" && *paramset != "XB") {

		var curve *gost3410.Curve
		if *bit == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if *bit == false && *paramset == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if *bit == false && *paramset == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if *bit == false && *paramset == "D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
			}
		} else if *bit == true && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if *paramset == "C" {
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

	if *derive == true && *old == true {

		var curve *gost3410.Curve
		if *paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB" {
			if *paramset == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if *paramset == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if *paramset == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if *paramset == "XB" {
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

	if *generate && *old == false {

		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		if *bit == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if *paramset == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if *paramset == "D" {
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
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if *paramset == "C" {
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

	if *generate && *old == true && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB") {
		var curve *gost3410.Curve
		if *paramset == "A" {
			curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
		} else if *paramset == "B" {
			curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
		} else if *paramset == "C" {
			curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
		} else if *paramset == "XA" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
		} else if *paramset == "XB" {
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

	if *sign == true || *verify == true {

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

		if *sign == true && *bit == false && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {

			data := []byte(hash)
			hasher := gost34112012256.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if *paramset == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if *paramset == "D" {
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

		if *verify == true && *bit == false && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "D") {
			data := []byte(hash)
			hasher := gost34112012256.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
			} else if *paramset == "C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
			} else if *paramset == "D" {
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

		if *sign == true && *bit == true && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			data := []byte(hash)
			hasher := gost34112012512.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if *paramset == "C" {
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

		if *verify == true && *bit == true && *old == false && (*paramset == "A" || *paramset == "B" || *paramset == "C") {
			data := []byte(hash)
			hasher := gost34112012512.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
			} else if *paramset == "C" {
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

		if *sign == true && *old == true && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB") {
			data := []byte(hash)
			hasher := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if *paramset == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if *paramset == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if *paramset == "XB" {
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

		if *verify == true && *old == true && (*paramset == "A" || *paramset == "B" || *paramset == "C" || *paramset == "XA" || *paramset == "XB") {
			data := []byte(hash)
			hasher := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			var curve *gost3410.Curve
			if *paramset == "A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
			} else if *paramset == "B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
			} else if *paramset == "C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
			} else if *paramset == "XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			} else if *paramset == "XB" {
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

	if *pbkdf == true && *old == false && *bit == false && *block == false {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012256.New)

		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *pbkdf == true && *old == false && *bit == false && *block == true {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012256.New)

		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *pbkdf == true && *old == false && *bit == true && *block == false {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, gost34112012512.New)

		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *pbkdf == true && *old == false && *bit == true && *block == true {
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, gost34112012512.New)

		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *pbkdf == true && *old == true && *bit == false && *block == false {
		f := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, f)

		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *pbkdf == true && *old == true && *bit == false && *block == true {
		f := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		prvRaw := pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, f)

		fmt.Println(hex.EncodeToString(prvRaw))
		os.Exit(0)
	}

	if *del != "" {
		shredder := shred.Shredder{}
		shredconf := shred.NewShredderConf(&shredder, shred.WriteZeros|shred.WriteRand, *iter, true)
		matches, err := filepath.Glob(*del)
		if err != nil {
			panic(err)
		}

		for _, match := range matches {
			err := shredconf.ShredDir(match)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}

	if *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else {
		fmt.Println(randomart.FromString(*key))
	}
}
