package main

import (
	"context"
	"crypto/tls" //This is patched library
	"crypto/x509"
	"encoding/base64"
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"log"
	"net"
	"net/http" //This is patched library
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/paulbellamy/ratecounter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ZeroRTT_t int

// Bitset
const (
	ZeroRTT_None   ZeroRTT_t = 0
	ZeroRTT_Offer            = 1 << 0
	ZeroRTT_Accept           = 1 << 1
)

type revProxy struct {
	upstreamURL  *url.URL
	reverseProxy *httputil.ReverseProxy
}

const (
	tlsNewConn = iota
	tlsActiveConn
	tlsClosedConn
)

type tlsConnEvent struct {
	remoteAddr string
	connID     []byte
	sni        string
	evType     uint
	when       time.Time
}

type rpTransport struct {
	http.RoundTripper
}

func (t *rpTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	start := time.Now()
	resp, err = t.RoundTripper.RoundTrip(req)
	if req != nil && resp != nil {
		upstreamHTTPResponseCodesCounterVec.WithLabelValues(req.Host, strconv.Itoa(resp.StatusCode)).Inc()
		upstreamLatencyCounterVec.WithLabelValues(req.Host).Observe(float64(time.Now().Sub(start).Milliseconds()))
	}
	return resp, err
}

type esniRevProxy struct {
	httpServer *http.Server
	wgServer   sync.WaitGroup

	httpStatsServer *http.Server
	wgStatServer    sync.WaitGroup

	rp            *revProxy
	showAccessLog bool

	//stats
	wg               sync.WaitGroup
	counter          *ratecounter.RateCounter // RPS counting
	rpsTickerDone    chan bool
	tslConnEventChan chan tlsConnEvent
}

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

//Prometheus metrics
var (
	failedTLSHandshakesCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "esnirevproxy",
			Subsystem: "tls",
			Name:      "failed_handshakes",
			Help:      "Total number of failed TLS handshakes",
		},
	)
	successfulTLSHandshakesCounterVec = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "esnirevproxy",
			Subsystem: "tls",
			Name:      "successful_handshakes",
			Help:      "Total number of successful TLS handshakes",
		},
		// Host label (aka SNI)
		[]string{"sni"},
	)

	tlsHandshakeDurationHist = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "esnirevproxy",
			Subsystem: "tls",
			Buckets:   []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
			Name:      "handshake_duration_msec",
			Help:      "Handshake time in milliseconds"})

	totalConnectionsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "esnirevproxy",
			Subsystem: "tcp",
			Name:      "connections_total",
			Help:      "Total active/idle connections",
		},
	)

	rpsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "esnirevproxy",
			Subsystem: "http",
			Name:      "average_last_min_rps",
			Help:      "Incoming HTTP rps average for the last minute"})

	upstreamHTTPResponseCodesCounterVec = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "esnirevproxy",
			Subsystem: "http",
			Name:      "upstream_response_codes",
			Help:      "Upstream response HTTP codes",
		},
		[]string{"upstream", "code"},
	)

	upstreamLatencyCounterVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "esnirevproxy",
			Subsystem: "http",
			Buckets:   []float64{100, 500, 1000, 2500, 5000, 10000},
			Name:      "upstream_latency_msec",
			Help:      "Upstream latency in milliseconds"},
		[]string{"upstream"},
	)
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	if i == nil {
		return ""
	}
	return strings.Join(*i, ",")

}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func buildTLSConig(sniCertsChain *arrayFlags,
	argZeroRTT string,
	clientAuth bool,
	pq string,
	esniPrivateKeyFile, esniKeysFile string) *tls.Config {

	var (
		err            error
		zeroRTT        = ZeroRTT_None
		esniKeys       *tls.ESNIKeys
		esniPrivateKey []byte
	)

	tlsConfig := tls.Config{
		MaxVersion:        tls.VersionTLS13,
		ClientAuth:        tls.NoClientCert,
		NameToCertificate: map[string]*tls.Certificate{},
	}

	//SNI -> key,cert
	for i, elem := range *sniCertsChain {
		//Splitting to SNI, Key and Cert:
		arr := strings.Split(elem, ":")
		if len(arr) != 3 {
			log.Fatalf("Corrupted value '%s', shpold be: SNI:PrivateKey.File:CertChain.File", elem)
		}
		if i == 0 { //Default cert
			log.Printf("Default esniRevProxy cert/key pair would be sourced from %s", elem)
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
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		tlsConfig.NameToCertificate[arr[0]] = &cert

	}

	switch argZeroRTT {
	case "a":
		zeroRTT = ZeroRTT_Accept
	case "o":
		zeroRTT = ZeroRTT_Offer
	case "oa":
		zeroRTT = ZeroRTT_Offer | ZeroRTT_Accept
	}

	if (zeroRTT & ZeroRTT_Offer) == ZeroRTT_Offer {
		tlsConfig.Max0RTTDataSize = 100 * 1024
	}

	if clientAuth {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	tlsConfig.ClientCAs = x509.NewCertPool()
	tlsConfig.Accept0RTTData = (zeroRTT & ZeroRTT_Accept) == ZeroRTT_Accept

	tlsConfig.NextProtos = []string{"npn_proto"}

	if pq != "" {
		tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, []tls.CurveID{tls.HybridSIDHp503Curve25519, tls.HybridSIKEp503Curve25519}...)
		if pq == "c" {
			tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}...)
		}
	}

	//ESNI keys
	if esniPrivateKeyFile != "" {
		esniPrivateKey, err = ioutil.ReadFile(esniPrivateKeyFile)
		if err != nil {
			log.Fatalf("Failed to read ESNI private key: %s", err)
		}
	}
	if esniKeysFile != "" {
		contents, err := ioutil.ReadFile(esniKeysFile)
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
		tlsConfig.GetServerESNIKeys = func([]byte) (*tls.ESNIKeys, []byte, error) { return esniKeys, esniPrivateKey, nil }
	}

	if keyLogFile := os.Getenv("SSLKEYLOGFILE"); keyLogFile != "" {
		tlsConfig.KeyLogWriter, err = os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Cannot open keylog file: %v", err)
		}
		log.Println("Keylog enabled...")
	}
	return &tlsConfig
}

func newESNIRevProxy(
	address string,
	sniCertsChain *arrayFlags,
	argZeroRTT string,
	clientAuth bool,
	pq string,
	esniPrivateKeyFile, esniKeysFile string,
	upstream string,
	showAccessLog bool,
	addrStats string) *esniRevProxy {

	var (
		err         error
		upstreamURL *url.URL
	)
	upstreamURL, err = url.Parse(upstream)
	if err != nil {
		log.Fatalf("Can't parse upstream URL: %v", err)
	}

	rp := revProxy{
		upstreamURL:  upstreamURL,
		reverseProxy: httputil.NewSingleHostReverseProxy(upstreamURL),
	}
	//Set round tripper to get upstream statistics
	rp.reverseProxy.Transport = &rpTransport{http.DefaultTransport}

	s := new(esniRevProxy)

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(s.requestHandler))
	s.httpServer = &http.Server{
		Addr:      address,
		Handler:   mux,
		ConnState: s.gatherTLSConnStats,
		TLSConfig: buildTLSConig(sniCertsChain, argZeroRTT, clientAuth, pq, esniPrivateKeyFile, esniKeysFile)}

	muxStats := http.NewServeMux()
	muxStats.Handle("/metrics", promhttp.Handler())
	muxStats.Handle("/healthz", http.HandlerFunc(s.healthzHandler))
	s.httpStatsServer = &http.Server{
		Addr:    addrStats,
		Handler: muxStats,
	}
	s.showAccessLog = showAccessLog
	s.rp = &rp
	s.counter = ratecounter.NewRateCounter(60 * time.Second)
	return s
}

func (s *esniRevProxy) start() {
	log.Println("Starting esni reverse proxy...")
	//Primary
	s.wgServer.Add(1)
	s.tslConnEventChan = make(chan tlsConnEvent)
	go func() {
		defer s.wgServer.Done()
		if err := s.httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServeTLS(): %v", err)
		}
	}()

	//Stats & healthz
	s.wgStatServer.Add(1)
	go func() {
		defer s.wgStatServer.Done()
		if err := s.httpStatsServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	//rps counter
	s.wg.Add(1)
	s.rpsTickerDone = make(chan bool)
	go func() {
		rpsTicker := time.NewTicker(time.Second)
		defer rpsTicker.Stop()
		defer s.wg.Done()

		for {
			select {
			case <-s.rpsTickerDone:
				return
			case <-rpsTicker.C:
				rpsGauge.Set(float64(s.counter.Rate()) / 60)
			}
		}
	}()

	//tls handshake duration counter
	s.wg.Add(1)
	go func(connEvents <-chan tlsConnEvent) {
		defer s.wg.Done()

		connectionStats := map[string]map[string]interface{}{}

		for event := range connEvents {
			remoteAddr := event.remoteAddr
			if remoteAddr == "" {
				continue
			}
			switch event.evType {
			case tlsNewConn:
				connectionStats[remoteAddr] = map[string]interface{}{}
				connectionStats[remoteAddr]["startedAt"] = event.when
			case tlsActiveConn:
				if _, ok := connectionStats[remoteAddr]["tlsConnectionID"]; !ok {
					successfulTLSHandshakesCounterVec.WithLabelValues(event.sni).Inc()
					tlsHandshakeDurationHist.Observe(
						float64(
							event.when.
								Sub(connectionStats[remoteAddr]["startedAt"].(time.Time)).Milliseconds()))

					connectionStats[remoteAddr]["tlsConnectionID"] = event.connID
				}
			case tlsClosedConn:
				delete(connectionStats, remoteAddr)
			}
		}
	}(s.tslConnEventChan)

}

func (s *esniRevProxy) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("Can't graceful shutdown server: %v", err)
		s.httpServer.Close()
	}
	s.wgServer.Wait()

	if err := s.httpStatsServer.Shutdown(ctx); err != nil {
		log.Printf("Can't graceful shutdown healthz/metrics server: %v", err)
		s.httpStatsServer.Close()
	}
	s.wgStatServer.Wait()

	//Stopping rps counter
	close(s.rpsTickerDone)

	//Stopping tls handshake duration counter
	close(s.tslConnEventChan)

	s.wg.Wait()
}

func (s *esniRevProxy) requestHandler(w http.ResponseWriter, r *http.Request) {

	//TODO: move this counter to middleware
	s.counter.Incr(1)

	if s.showAccessLog {
		log.Printf("==>INPUT REQUEST \"%v %s\", SNI:%s\n[headers]: %v\n", r.Method, r.URL, r.TLS.ServerName, r.Header)
	}
	// Update the headers to allow for SSL redirection
	r.URL.Host = s.rp.upstreamURL.Host
	r.URL.Scheme = s.rp.upstreamURL.Scheme
	if r.Header.Get("Host") == "" && r.TLS.ServerName != "" {
		r.Header.Set("X-Forwarded-Host", r.TLS.ServerName)
		r.Header.Set("Host", r.TLS.ServerName)
	} else if r.Header.Get("Host") == "" && r.TLS.ServerName == "" {
		r.Header.Set("Host", r.Header.Get("Http_host"))
	}
	s.rp.upstreamURL.Port()
	if s.showAccessLog {
		log.Printf("==>FORWARDED REQUEST upstream: %s://%s\n[headers]: %v\n", s.rp.upstreamURL.Scheme, s.rp.upstreamURL.Host, r.Header)
	}
	r.Host = s.rp.upstreamURL.Host

	//We can inject into request the context with call backs to get statistics https://blog.golang.org/http-tracing
	s.rp.reverseProxy.ServeHTTP(w, r)

}

func (s *esniRevProxy) healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *esniRevProxy) gatherTLSConnStats(c net.Conn, state http.ConnState) {
	tlsConn := reflect.ValueOf(c).Interface().(*tls.Conn)
	remoteAddr := tlsConn.RemoteAddr().String()

	switch state {
	case http.StateNew:
		s.tslConnEventChan <- tlsConnEvent{
			remoteAddr: remoteAddr,
			evType:     tlsNewConn,
			when:       time.Now(),
		}
		totalConnectionsGauge.Inc()
	case http.StateActive:
		if tlsConn.ConnectionState().HandshakeComplete {
			sni := tlsConn.ConnectionState().ServerName
			if sni == "" {
				sni = reflect.ValueOf(tlsConn.RemoteAddr()).Interface().(*net.TCPAddr).IP.String()
			}
			s.tslConnEventChan <- tlsConnEvent{
				remoteAddr: remoteAddr,
				connID:     tlsConn.ConnectionState().ConnectionID,
				sni:        sni,
				evType:     tlsActiveConn,
				when:       time.Now(),
			}
		}

	case http.StateClosed:
		s.tslConnEventChan <- tlsConnEvent{
			remoteAddr: remoteAddr,
			evType:     tlsClosedConn,
		}
		totalConnectionsGauge.Dec()

		//connection closed without established TLS handshake,
		//this means that TLS handshake failed
		if !tlsConn.ConnectionState().HandshakeComplete {
			failedTLSHandshakesCounter.Inc()
		}

	}

}

func main() {
	var arg_sniCertsChain arrayFlags

	arg_addr := flag.String("b", "0.0.0.0:443", "Address:port used for binding")
	flag.Var(&arg_sniCertsChain, "cert", "Triplet of SNI:PrivateKey.File:CertChain.File")
	arg_zerortt := flag.String("rtt0", "n", `0-RTT, accepts following values [n: None, a: Accept, o: Offer, oa: Offer and Accept]`)
	//arg_confirm := flag.Bool("rtt0ack", false, "0-RTT confirm")
	arg_clientauth := flag.Bool("cliauth", false, "Performs client authentication (RequireAndVerifyClientCert used)")
	arg_pq := flag.String("pq", "", "Enable quantum-resistant algorithms [c: Support classical and Quantum-Resistant, q: Enable Quantum-Resistant only]")
	arg_esniKeys := flag.String("esni-keys", "", "File with base64-encoded ESNIKeys")
	arg_esniPrivate := flag.String("esni-private", "", "Private key file for ESNI")
	arg_upstream := flag.String("upstream", "", "Upstream URL to forward traffic to")
	arg_accesslog := flag.Bool("showaccesslog", false, "Show access log")
	arg_addrStats := flag.String("stats-metrics-bind", "0.0.0.0:8181", "Address:port used for binding. Metrics available at /metrics (prometheus format), health-check at /helathz")

	arg_cpuProfile := flag.String("cpuprof", "", "CPU profile output file")
	arg_memProfile := flag.String("memprof", "", "Memory profile output file")

	flag.Parse()

	if *arg_cpuProfile != "" {
		f, err := os.Create(*arg_cpuProfile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	if *arg_esniPrivate == "" && *arg_esniKeys != "" ||
		*arg_esniPrivate != "" && *arg_esniKeys == "" {
		log.Fatal("Both -esni-keys and -esni-private must be provided.")
	}

	if *arg_upstream == "" {
		log.Fatal("Upstream URL is not set")
	}

	s := newESNIRevProxy(
		*arg_addr,
		&arg_sniCertsChain,
		*arg_zerortt,
		*arg_clientauth,
		*arg_pq,
		*arg_esniPrivate, *arg_esniKeys,
		*arg_upstream,
		*arg_accesslog,
		*arg_addrStats)

	s.start()

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		log.Println("Received SIGTERM, exiting gracefully...")
		s.stop()
	}

	if *arg_memProfile != "" {
		f, err := os.Create(*arg_memProfile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}

}

func init() {
	prometheus.MustRegister(failedTLSHandshakesCounter)
	prometheus.MustRegister(successfulTLSHandshakesCounterVec)
	prometheus.MustRegister(totalConnectionsGauge)
	prometheus.MustRegister(tlsHandshakeDurationHist)
	prometheus.MustRegister(rpsGauge)
	prometheus.MustRegister(upstreamHTTPResponseCodesCounterVec)
	prometheus.MustRegister(upstreamLatencyCounterVec)
}
