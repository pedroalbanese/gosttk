package main
import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"github.com/pedroalbanese/gogost/gost28147"
	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/gogost/gost341194"
	"github.com/pedroalbanese/gogost/gost341264"
	"github.com/pedroalbanese/gogost/gost3412128"
	"io"
	"log"
	"math/big"
	"os"
)

	var pubHex = flag.String("pub", "", "Remote's side public key. (for shared key derivation only)")
	var crypt = flag.Bool("crypt", false, "Encrypt/Decrypt with Kuznyechik (GOST R 34.12-2015) symmetric cipher.")
	var derive = flag.Bool("derive", false, "Derive shared key negociation (VKO).")
	var mac = flag.Bool("hmac", false, "Compute HMAC-Streebog256/512 (GOST R 34.11-2012).")
	var key = flag.String("key", "", "Private/Public key, password or HMAC key, depending on operation.")
	var sig = flag.String("signature", "", "Input signature. (verification only)")
	var bit = flag.Int("bits", 256, "Bit length: 256 or 512. (digest|generate|sign|VKO)")
	var block = flag.Int("block", 128, "Block size: 64 or 128. (for symmetric encryption only)")
	var mode = flag.Int("mode", 2012, "Mode: 2001 or 2012. (digest|generate|sign|VKO)")
	var sign = flag.Bool("sign", false, "Sign with private key.")
	var verify = flag.Bool("verify", false, "Verify with public key.")
	var generate = flag.Bool("generate", false, "Generate GOST R 34.10-2012 or 34.10-2001 asymmetric keypair.")
	var digest = flag.Bool("digest", false, "Compute Streebog256/512 or GOST94-CryptoPro hashsum.")


func main() {
    flag.Parse()

        if (len(os.Args) < 2) {
	fmt.Println("Select: -digest|hmac, -sign|verify, -generate, -derive or -crypt. (type -h)")
        os.Exit(1)
        }

        if *sign == false && *verify == false && *generate == false && *digest == false && *derive == false && *crypt == false && *mac == false {
	fmt.Println("Select: -digest|hmac, -sign|verify, -generate, -derive or -crypt. (type -h)")
        os.Exit(1)
        }

	
        if *crypt == true && *block == 128 {
	keyHex := key
	var key []byte
	var err error
	if *keyHex == "" {
		key = make([]byte, gost3412128.KeySize)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
                        log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
	} else {
		key, err = hex.DecodeString(*keyHex)
		if err != nil {
                        log.Fatal(err)
		}
		if len(key) != gost3412128.KeySize {
                        log.Fatal(err)
		}
	}
	ciph := gost3412128.NewCipher(key)
	iv := make([]byte, gost3412128.BlockSize)
	stream := cipher.NewCTR(ciph, iv)
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

	
        if *crypt == true && *block == 64 && *mode == 2012 {
	keyHex := key
	var key []byte
	var err error
	if *keyHex == "" {
		key = make([]byte, gost341264.KeySize)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
                        log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
	} else {
		key, err = hex.DecodeString(*keyHex)
		if err != nil {
                        log.Fatal(err)
		}
		if len(key) != gost341264.KeySize {
                        log.Fatal(err)
		}
	}
	ciph := gost341264.NewCipher(key)
	iv := make([]byte, gost341264.BlockSize)
	stream := cipher.NewCTR(ciph, iv)
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


        if *crypt == true && *block == 64 && *mode == 2001 {
	keyHex := key
	var key []byte
	var err error
	if *keyHex == "" {
		key = make([]byte, gost28147.KeySize)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
                        log.Fatal(err)
		}
		fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
	} else {
		key, err = hex.DecodeString(*keyHex)
		if err != nil {
                        log.Fatal(err)
		}
		if len(key) != gost28147.KeySize {
                        log.Fatal(err)
		}
	}
	ciph := gost341264.NewCipher(key)
	iv := make([]byte, gost28147.BlockSize)
	stream := cipher.NewCTR(ciph, iv)
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


        if *mac == true && *bit == 256 {
	keyHex := key
	flag.Parse()
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
                log.Fatal(err)
	}
	h := hmac.New(gost34112012256.New, key)
	if _, err = io.Copy(h, os.Stdin); err != nil {
                log.Fatal(err)
	}
	fmt.Print(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
        }

        if *mac == true && *bit == 512 {
	keyHex := key
	flag.Parse()
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
                log.Fatal(err)
	}
	h := hmac.New(gost34112012512.New, key)
	if _, err = io.Copy(h, os.Stdin); err != nil {
                log.Fatal(err)
	}
	fmt.Print(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
        }

        if *mac == true && *mode == 2001 {
	keyHex := key
	flag.Parse()
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
                log.Fatal(err)
	}
        f := func() hash.Hash {
	return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	}
	hmac.New(f, key)
	h := hmac.New(gost34112012512.New, key)
	if _, err = io.Copy(h, os.Stdin); err != nil {
                log.Fatal(err)
	}
	fmt.Print(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
        }

        if *digest == true && *mode == 2001 {
	h := gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	io.Copy(h, os.Stdin)
	fmt.Print(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
        }

        if *digest == true && *bit == 256 {
	h := gost34112012256.New()
	io.Copy(h, os.Stdin)
	fmt.Print(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
        }

        if *digest == true && *bit == 512 {
	h := gost34112012512.New()
	io.Copy(h, os.Stdin)
	fmt.Print(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
        }


	var err error
        if *derive == true && *mode == 2012 {

	var curve *gost3410.Curve
	if *bit == 256 {
 	curve = gost3410.CurveIdtc26gost34102012256paramSetA()
        } else if *bit == 512 {
 	curve = gost3410.CurveIdtc26gost341012512paramSetA()
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
	pubRaw, err = hex.DecodeString(*pubHex)
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
	fmt.Print("Shared= ", hex.EncodeToString(shared))
	os.Exit(0)
	}


        if *derive == true && *mode == 2001 {

	var curve *gost3410.Curve
	curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()

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
	pubRaw, err = hex.DecodeString(*pubHex)
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

	shared, err := prv.KEK2012256(pub, big.NewInt(1))
	if err != nil {
                log.Fatal(err)
	}
	fmt.Print("Shared= ", hex.EncodeToString(shared))
	os.Exit(0)
	}

	
	if *generate && *mode == 2012 {
	var curve *gost3410.Curve

	if *bit == 256 {
 	curve = gost3410.CurveIdtc26gost34102012256paramSetA()
        } else if *bit == 512 {
 	curve = gost3410.CurveIdtc26gost341012512paramSetA()
	}

	var prvRaw []byte
	var pubRaw []byte
	var prv *gost3410.PrivateKey
	var pub *gost3410.PublicKey

        if *bit == 256 {
		prvRaw = make([]byte, 256/8)
		_, err = io.ReadFull(rand.Reader, prvRaw)
		if err != nil {
                        log.Fatal(err)
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

        if *bit == 512 {
		prvRaw = make([]byte, 512/8)
		_, err = io.ReadFull(rand.Reader, prvRaw)
		if err != nil {
                        log.Fatal(err)
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


	if *generate && *mode == 2001 {
	var curve *gost3410.Curve
	curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()

	var prvRaw []byte
	var pubRaw []byte
	var prv *gost3410.PrivateKey
	var pub *gost3410.PublicKey

        if *bit == 256 {
		prvRaw = make([]byte, 256/8)
		_, err = io.ReadFull(rand.Reader, prvRaw)
		if err != nil {
                        log.Fatal(err)
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
	}


        if *sign == true || *verify == true {

        scannerWrite := bufio.NewScanner(os.Stdin)
        if !scannerWrite.Scan() {
                log.Printf("Failed to read: %v", scannerWrite.Err())
        return
        }
        hash := scannerWrite.Bytes()
	data := []byte(hash)

	hasher := gost34112012512.New()
	_, err := hasher.Write(data)
		if err != nil {
                        log.Fatal(err)
		}
	dgst := hasher.Sum(nil)

	var prvRaw []byte
	var pubRaw []byte
	var prv *gost3410.PrivateKey
	var pub *gost3410.PublicKey

	var inputsig []byte
	inputsig, err = hex.DecodeString(*sig)
	if err != nil {
                log.Fatal(err)
	}

	if *sign == true && *bit == 256 && *mode == 2012 {
	curve := gost3410.CurveIdtc26gost34102012256paramSetA()
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
		fmt.Print(hex.EncodeToString(signature))
	os.Exit(0)
	}

	if *verify == true && *bit == 256 && *mode == 2012 {
	curve := gost3410.CurveIdtc26gost34102012256paramSetA()
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
	if !isValid { log.Fatal(err, "signature is invalid") }
        fmt.Println("Verify correct.")
	os.Exit(0)
	}


	if *sign == true && *bit == 512 && *mode == 2012 {
	curve := gost3410.CurveIdtc26gost341012512paramSetA()
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
		fmt.Print(hex.EncodeToString(signature))
	os.Exit(0)
	}

	if *verify == true && *bit == 512 && *mode == 2012 {
	curve := gost3410.CurveIdtc26gost341012512paramSetA()
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
	if !isValid { log.Fatal(err, "signature is invalid") }
        fmt.Println("Verify correct.")
	} 


	if *sign == true && *mode == 2001 {
	var curve *gost3410.Curve
	curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
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
		fmt.Print(hex.EncodeToString(signature))
	os.Exit(0)
	}

	if *verify == true && *mode == 2001 {
	var curve *gost3410.Curve
	curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
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
	if !isValid { log.Fatal(err, "signature is invalid") }
        fmt.Println("Verify correct.")
	}
	os.Exit(0)
	}
}
