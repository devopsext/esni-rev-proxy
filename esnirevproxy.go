package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

type ZeroRTT_t int
type PubKeyAlgo_t int

// Bitset
const (
	ZeroRTT_None   ZeroRTT_t = 0
	ZeroRTT_Offer            = 1 << 0
	ZeroRTT_Accept           = 1 << 1
)

type server struct {
	Address string
	ZeroRTT ZeroRTT_t
	TLS     tls.Config
}

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func NewServer(address string) *server {
	s := new(server)
	s.ZeroRTT = ZeroRTT_None
	s.Address = address
	s.TLS = tls.Config{
		/*
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				// If we send the first flight too fast, NSS sends empty early data.
				time.Sleep(500 * time.Millisecond)
				return nil, nil
			},*/
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert,
	}

	return s
}

func enablePQ(s *server, enableDefault bool) {
	var pqGroups = []tls.CurveID{tls.HybridSIDHp503Curve25519, tls.HybridSIKEp503Curve25519}
	if enableDefault {
		var defaultCurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
		s.TLS.CurvePreferences = append(s.TLS.CurvePreferences, defaultCurvePreferences...)
	}
	s.TLS.CurvePreferences = append(s.TLS.CurvePreferences, pqGroups...)
}

func (s *server) start() {
	var err error

	if (s.ZeroRTT & ZeroRTT_Offer) == ZeroRTT_Offer {
		s.TLS.Max0RTTDataSize = 100 * 1024
	}

	if keyLogFile := os.Getenv("SSLKEYLOGFILE"); keyLogFile != "" {
		s.TLS.KeyLogWriter, err = os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Cannot open keylog file: %v", err)
		}
		log.Println("Enabled keylog")
	}

	s.TLS.ClientCAs = x509.NewCertPool()
	//s.TLS.ClientCAs.AppendCertsFromPEM([]byte(rsaCa_client))
	s.TLS.Accept0RTTData = ((s.ZeroRTT & ZeroRTT_Accept) == ZeroRTT_Accept)
	s.TLS.NextProtos = []string{"npn_proto"}

	httpServer := &http.Server{
		Addr:      s.Address,
		TLSConfig: &s.TLS,
	}
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}

func (s *server) setServerCertificates(sniCertsChain *arrayFlags) {
	s.TLS.NameToCertificate = map[string]*tls.Certificate{}
	for i, elem := range *sniCertsChain {
		//Splitting to SNI, Key and Cert:
		arr := strings.Split(elem, ":")
		if len(arr) != 3 {
			log.Fatalf("Corrupted value '%s', shpold be: SNI:PrivateKey.File:CertChain.File", elem)
		}
		if i == 0 { //Default cert
			log.Printf("Default server cert/key pair would be sourced from %s", elem)
		}

		keyStr, err := ioutil.ReadFile(arr[1])
		if err != nil {
			log.Fatalf("Can't read from file '%s': %v", arr[1], err)
		}
		certStr, err := ioutil.ReadFile(arr[2])
		if err != nil {
			log.Fatalf("Can't read from file '%s': %v", arr[2], err)
		}

		cert, err := tls.X509KeyPair(certStr, keyStr)
		if err != nil {
			log.Fatalf("Can't parse X509 key pair from key:cert '%s:%s': %v", arr[1], arr[2], err)
		}
		s.TLS.Certificates = append(s.TLS.Certificates, cert)
		s.TLS.NameToCertificate[arr[0]] = &cert

	}

}

func main() {
	var err error
	var reverseProxy *httputil.ReverseProxy
	var upstreamURL *url.URL
	var esniKeys *tls.ESNIKeys
	var esniPrivateKey []byte
	var sniCertsChain arrayFlags

	arg_addr := flag.String("b", "0.0.0.0:443", "Address:port used for binding")
	//arg_cert := flag.String("cert", "rsa", "Public algorithm to use:\nOptions [rsa, ecdsa, PrivateKeyFile:CertificateChainFile]")
	flag.Var(&sniCertsChain, "cert", "Triplet of SNI:PrivateKey.File:CertChain.File")
	arg_zerortt := flag.String("rtt0", "n", `0-RTT, accepts following values [n: None, a: Accept, o: Offer, oa: Offer and Accept]`)
	//arg_confirm := flag.Bool("rtt0ack", false, "0-RTT confirm")
	arg_clientauth := flag.Bool("cliauth", false, "Performs client authentication (RequireAndVerifyClientCert used)")
	arg_pq := flag.String("pq", "", "Enable quantum-resistant algorithms [c: Support classical and Quantum-Resistant, q: Enable Quantum-Resistant only]")
	arg_esniKeys := flag.String("esni-keys", "", "File with base64-encoded ESNIKeys")
	arg_esniPrivate := flag.String("esni-private", "", "Private key file for ESNI")
	arg_upstream := flag.String("upstream", "", "Upstream URL to forward traffic to")
	arg_accesslog := flag.Bool("showaccesslog", false, "Show access log")
	flag.Parse()

	s := NewServer(*arg_addr)

	s.setServerCertificates(&sniCertsChain)

	if *arg_zerortt == "a" {
		s.ZeroRTT = ZeroRTT_Accept
	} else if *arg_zerortt == "o" {
		s.ZeroRTT = ZeroRTT_Offer
	} else if *arg_zerortt == "oa" {
		s.ZeroRTT = ZeroRTT_Offer | ZeroRTT_Accept
	}

	if *arg_clientauth {
		s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	}

	if *arg_pq == "c" {
		enablePQ(s, true)
	} else if *arg_pq == "q" {
		enablePQ(s, false)
	}

	if *arg_upstream != "" {
		upstreamURL, err = url.Parse(*arg_upstream)
		if err != nil {
			log.Fatalf("Can't parse upstream URL: %v", err)
		}

		// create the reverse proxy
		reverseProxy = httputil.NewSingleHostReverseProxy(upstreamURL)

	} else {
		log.Fatal("Upstream URL is not set")
	}

	if *arg_esniPrivate == "" && *arg_esniKeys != "" ||
		*arg_esniPrivate != "" && *arg_esniKeys == "" {
		log.Fatal("Both -esni-keys and -esni-private must be provided.")
	}
	if *arg_esniPrivate != "" {
		esniPrivateKey, err = ioutil.ReadFile(*arg_esniPrivate)
		if err != nil {
			log.Fatalf("Failed to read ESNI private key: %s", err)
		}
	}
	if *arg_esniKeys != "" {
		contents, err := ioutil.ReadFile(*arg_esniKeys)
		if err != nil {
			log.Fatalf("Failed to read ESNIKeys: %s", err)
		}
		esniKeysBytes, err := base64.StdEncoding.DecodeString(string(contents))
		if err != nil {
			log.Fatalf("Bad -esni-keys: %s", err)
		}
		esniKeys, err = tls.ParseESNIKeys(esniKeysBytes)
		if esniKeys == nil {
			log.Fatalf("Cannot parse ESNIKeys: %s", err)
		}
		s.TLS.GetServerESNIKeys = func([]byte) (*tls.ESNIKeys, []byte, error) { return esniKeys, esniPrivateKey, nil }
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *arg_accesslog {
			log.Printf("==>INPUT REQUEST \"%v %s\", SNI:%s\n[headers]: %v\n", r.Method, r.URL, r.TLS.ServerName, r.Header)
		}
		// Update the headers to allow for SSL redirection
		r.URL.Host = upstreamURL.Host
		r.URL.Scheme = upstreamURL.Scheme
		if r.Header.Get("Host") == "" && r.TLS.ServerName != "" {
			r.Header.Set("X-Forwarded-Host", r.TLS.ServerName)
			r.Header.Set("Host", r.TLS.ServerName)
		} else if r.Header.Get("Host") == "" && r.TLS.ServerName == "" {
			r.Header.Set("Host", r.Header.Get("Http_host"))
		}
		upstreamURL.Port()
		if *arg_accesslog {
			log.Printf("==>FORWARDED REQUEST upstream: %s://%s\n[headers]: %v\n", upstreamURL.Scheme, upstreamURL.Host, r.Header)
		}
		r.Host = upstreamURL.Host

		// Note that ServeHttp is non blocking and uses a go routine under the hood
		reverseProxy.ServeHTTP(w, r)
	})

	/*
		http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			tlsConn := r.Context().Value(http.TLSConnContextKey).(*tls.Conn)

			with0RTT := ""
			if !tlsConn.ConnectionState().HandshakeConfirmed {
				with0RTT = " [0-RTT]"
			}
			if *arg_confirm || r.URL.Path == "/confirm" {
				if err := tlsConn.ConfirmHandshake(); err != nil {
					log.Fatal(err)
				}
				if with0RTT != "" {
					with0RTT = " [0-RTT confirmed]"
				}
				if !tlsConn.ConnectionState().HandshakeConfirmed {
					panic("HandshakeConfirmed false after ConfirmHandshake")
				}
			}

			resumed := ""
			if r.TLS.DidResume {
				resumed = " [resumed]"
			}

			http2 := ""
			if r.ProtoMajor == 2 {
				http2 = " [HTTP/2]"
			}

			fmt.Fprintf(w, "<!DOCTYPE html><p>Hello TLS %s%s%s%s _o/\n", tlsVersionToName[r.TLS.Version], resumed, with0RTT, http2)
		})

		http.HandleFunc("/ch", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Client Hello packet (%d bytes):\n%s", len(r.TLS.ClientHello), hex.Dump(r.TLS.ClientHello))
		})
	*/
	s.start()
}
