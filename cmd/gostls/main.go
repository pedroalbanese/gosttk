package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"crypto/go.cypherpunks.ru/gogost/v5/gost3410"
	"github.com/pedroalbanese/go-external-ip"
)

var (
	tcpip = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [dump|ip|send]")
	pub   = flag.String("pub", "", "Remote's side IP address / local port.")
)

func handleConnection(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
	log.Printf("Connection from %v closed.", c.RemoteAddr())
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var err error
	gost341012256PrivRaw := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, gost341012256PrivRaw); err != nil {
		log.Fatalf("Failed to read random for GOST private key: %s", err)
	}
	gost341012256Priv, err := gost3410.NewPrivateKey(
		gost3410.CurveIdtc26gost341012256paramSetA(),
		gost341012256PrivRaw,
	)
	if err != nil {
		log.Fatalf("Failed to create GOST private key: %s", err)
	}
	gost341012256Pub := gost341012256Priv.Public()

	var commonName string
	commonName = "Common"

	Mins := 1
	NotAfter := time.Now().Local().Add(time.Minute * time.Duration(Mins))

	consensus := externalip.DefaultConsensus(nil, nil)
	ip, _ := consensus.ExternalIP()

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: ip.String(),
		},
		DNSNames:    []string{commonName},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		NotBefore:   time.Now(),
		NotAfter:    NotAfter,
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader,
		&template, &template,
		gost341012256Pub, &gost3410.PrivateKeyReverseDigest{Prv: gost341012256Priv},
	)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	privBytes, err := x509.MarshalPKCS8PrivateKey(gost341012256Priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	if *tcpip == "dump" {
		cert, err := tls.X509KeyPair(cert, priv)
		cfg := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
		cfg.Rand = rand.Reader

		port := "8081"
		if *pub != "" {
			port = *pub
		}

		ln, err := tls.Listen("tcp", ":"+port, &cfg)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			go handleConnection(conn)

			var buf bytes.Buffer
			io.Copy(&buf, conn)
			text := strings.TrimSuffix(string(buf.Bytes()), "\n")
			fmt.Println(text)
			os.Exit(0)
		}
	}

	if *tcpip == "send" {
		cert, err := tls.X509KeyPair(cert, priv)
		cfg := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

		ipport := "127.0.0.1:8081"
		if *pub != "" {
			ipport = *pub
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

		buf := bytes.NewBuffer(nil)
		scanner := os.Stdin
		io.Copy(buf, scanner)

		text := string(buf.Bytes())

		fmt.Fprintf(conn, text)

		defer conn.Close()
	}

	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
		os.Exit(0)
	}
}

