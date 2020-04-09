package main

import (
	"crypto/tls" //This is patched library
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http" //This is patched library
	"strings"
	"testing"
)

var cipherSuiteIdToName = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
}

var namedGroupsToName = map[uint16]string{
	uint16(tls.HybridSIDHp503Curve25519): "X25519-SIDHp503",
	uint16(tls.HybridSIKEp503Curve25519): "X25519-SIKEp503",
	uint16(tls.X25519):                   "X25519",
	uint16(tls.CurveP256):                "P-256",
	uint16(tls.CurveP384):                "P-384",
	uint16(tls.CurveP521):                "P-521",
}

type esniRoundTripPayload struct {
	Decrypted_sni string `json:"decrypted_sni"`
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type","application/json")
	json.NewEncoder(w).Encode(esniRoundTripPayload{Decrypted_sni: r.TLS.ServerName})
}

func getIDByName(m map[uint16]string, name string) (uint16, error) {
	for key, value := range m {
		if value == name {
			return key, nil
		}
	}
	return 0, errors.New("Unknown value")
}

func buildClientTLSConfig(sni string, tlsVersion string,insecure bool,esniKeys string, rootCACert string, namedGroups string) *tls.Config {
	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = insecure
	// ESNI support requires a server name to be set.
	tlsConfig.ServerName = sni

	tlsID, err := getIDByName(tlsVersionToName, tlsVersion)
	if err!=nil {log.Fatalf("Unknown tls version %q",tlsVersion)}
	tlsConfig.MinVersion = tlsID
	tlsConfig.MaxVersion = tlsID

	//tlsConfig.KeyLogWriter = keylog_writer

	if rootCACert != "" {
		contents, err := ioutil.ReadFile(rootCACert)
		if err != nil {
			log.Fatalf("Failed to read root CA cert: %s", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(contents) {
			log.Fatalf("Can't load client CA cert")
		}
	}

	if len(esniKeys) != 0 {
		contents, err := ioutil.ReadFile(esniKeys)
		if err != nil {
			log.Fatalf("Failed to read ESNIKeys: %s", err)
		}
		esniKeysBytes, err := base64.StdEncoding.DecodeString(string(contents))
		if err != nil {
			log.Fatalf("Failed to parse -esni-keys: %s", err)
		}
		tlsConfig.ClientESNIKeys, err = tls.ParseESNIKeys(esniKeysBytes)
		if tlsConfig.ClientESNIKeys == nil {
			log.Fatalf("Failed to parse ESNI key: %s", err)
		}
	}

	// Set requested DH groups
	tlsConfig.CurvePreferences = []tls.CurveID{}
	for _, ng := range strings.Split(namedGroups, ":") {
		id, err := getIDByName(namedGroupsToName, ng)
		if err != nil {
			log.Fatalf("Wrong group name provided: %s", err)
		}
		tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, tls.CurveID(id))
	}

	return tlsConfig
}

//Some integration tests first
func TestESNIRoundtrip(t *testing.T) {
	var sni = "localhost"
	//Creating esni rev proxy
	s := newESNIRevProxy(
		"0.0.0.0:443",
		&arrayFlags{sni +":testData/localhost.key:testData/localhost.crt"},
		"n",
		false,
		"",
		"testData/esni", "testData/esni.pub",
		"https://nomatter-what",
		true,
		"")

	//injecting own request handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", testHandler)
	s.httpServer.Handler = mux

	s.start()

	//Prepare client with ESNI support and make test request
	client := http.Client{Transport: &http.Transport{
		TLSClientConfig:buildClientTLSConfig(
			sni,
		"1.3",
		false,
		"testData/esni.pub",
		"testData/rootCA.crt" ,
		"X25519:P-256:P-384:P-521")}}
	resp, err := client.Get("https://127.0.0.1")
	if err != nil {
		t.Fatalf("handshake failed: %v\n", err)
	}else {
		respJson :=esniRoundTripPayload{}
		err := json.NewDecoder(resp.Body).Decode(&respJson)
		if err != nil {
			t.Fatal("Can't parse response from esni proxy")
		}

		if respJson.Decrypted_sni != sni {
			t.Errorf("ESNI Roundrip failed: initial sni value (%q) NOT EQUAL to value decrypted by server (%q)", sni,respJson.Decrypted_sni)
		}else{ //sni roundtrip successfull
			t.Logf("ESNI Roundrip successfull: initial sni value (%q) EQUAL to value decrypted by server (%q)", sni,respJson.Decrypted_sni)
		}
	}

	s.stop()
}
