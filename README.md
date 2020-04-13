# esni-rev-proxy
Golang reverse proxy with support of ESNI 01-draft (https://tools.ietf.org/html/draft-ietf-tls-esni-01) on top of TLS 1.3

__Motovation:__ As of April 2020 ESNI, is still a draft extension for TLS 1.3 and not officialy supported by OpenSSL and major projects like nginx, apache, etc (however unofficial forks exists). This project porvides a tiny golang reverse proxy that can terminate TLS 1.3 wint ESNI and forward plain HTTP to upstream. This covers the gap, and if you want to experiment with ESNI draft you can use it right now with your vanilla nginx/apache etc. Also your browser should support ESNI, and for now it is only firefox (https://www.elliotjreed.com/post/security/2019-07-08_Enable_DNS_over_HTTPS_and_Encrypted_SNI_in_Firefox). 

This project is extension of tris-localserver example code : https://github.com/cloudflare/tls-tris/tree/pwu/esni-consolidated/_dev/tris-localserver and was inspired by discussion: https://serverfault.com/questions/976377/how-can-i-set-up-encrypted-sni-on-my-own-servers

---
__How to build:__
As declared here https://github.com/cloudflare/tls-tris/tree/pwu/esni-consolidated, since crypto/tls is very deeply (and not that elegantly) coupled with the Go stdlib, it is impossible to vendor it as crypto/tls because stdlib packages would import the standard one and mismatch. 
Approach here would be to build custom GOROOT (that has patched standard libraries), and then on top of it, build the current code.

Build ___esni reverse proxy___:
1. `git clone https://github.com/devopsext/esni-rev-proxy.git`
2. `cd esni-rev-proxy && git checkout v1.0.1` 
3. `prepareGoRoot.sh` - this script create patched GOROOT folder (`.GOROOT/`) in current directory (applicable to Linux/MacOS)
4. `export GOROOT=$(pwd)/.GOROOT`
5. `go mod vendor`
6. `go build`

Build ___esnitool___ (in case use need to generate esni keys):
Esnitool source code is copied from cloudflare repo: 
https://github.com/cloudflare/tls-tris/tree/pwu/esni-consolidated/_dev/esnitool
1. Copy `GOROOT` folder, that was prepared by script (see steps above) into esnitool/: `cp -r GOROOT/* esnitool/`
2. `cd esnitool/ && export GOROOT=$(pwd)/GOROOT`
3. `go build`


__How to run:__
1. Generate esni keys pair (public and private) with `esnitool`:
Just follow inline help of esnitool:
```
Usage of ./esnitool:
  -esni-keys-file string
        Write base64-encoded ESNI keys to file instead of stdout
  -esni-private-file string
        Write ESNI private key to file instead of stdout
  -validity duration
        Validity period of the keys (default 24h0m0s)
```
As example:
`./esnitool  -esni-keys-file ./esni.pub -esni-private-file ./esni -validity 32h`
Pay attention to validity period. Specify as long as you need. In case you set it short,
you need to rotate key pair.

2. Setup specific DNS record for your server (in addition to A or AAAA record), that you are going to access with ESNI:
 Create TXT record for host name `_esni.<YOUR-DOMAIN>` with the contents of `esni.pub` file (esni public key)
 
3. Run `esni-reverse-proxy` in front of your web server, to accept and terminate TLS 1.3 with ESNI,
and forward decrypted traffic to your web-server. `esni-rev-proxy` has self explanatory flags:
```
Usage of ./esni-rev-proxy:
  -b string
        Address:port used for binding (default "0.0.0.0:443")
  -cert value
        Triplet of SNI:PrivateKey.File:CertChain.File
  -cliauth
        Performs client authentication (RequireAndVerifyClientCert used)
  -esni-keys string
        File with base64-encoded ESNIKeys
  -esni-private string
        Private key file for ESNI
  -pq string
        Enable quantum-resistant algorithms [c: Support classical and Quantum-Resistant, q: Enable Quantum-Resistant only]
  -rtt0 string
        0-RTT, accepts following values [n: None, a: Accept, o: Offer, oa: Offer and Accept] (default "n")
  -showaccesslog
        Show access log
  -upstream string
        Upstream URL to forward traffic to
  -stats-metrics-bind string
        Address:port used for binding. Metrics available at /metrics (prometheus format),
        health-check at /helathz (default "0.0.0.0:8181")
```
Short comments:
* `-cert` flag used to set SNI name and corresponding cert/key pair, in case your proxy severe several domains, you can specify several values.
* `-upstream` is an upstream to forward plain traffic to.

Example:

```
esni-rev-proxy -b 0.0.0.0:443 \
-esni-keys esni.pub -esni-private esni \
-cert "www.example.com:/mycerts/www.example.com.key:/mycerts/www.example.com.crt" \
-cert "other-domain.com:/mycerts/other-domain.com.key:/mycerts/other-domain.com.crt" \
-upstream http://internal-endpoint \
-showaccesslog
```

This would start up the reverse proxy that:
1. Accept incoming connections on all interfaces on port 443
2. Decrypt ESNI (using `esni.pub` and `esni` public and private key pair) and choose appropriate certificate for host name `www.example.com` or `other-domain.com`,
stored in `/mycerts`. The key/cert pair specified in first `-cert` flag is also treated as default cert/key pair - 
so it will be used if no match to SNI host detected.
3. Forward decrypted traffic to `http://internal-endpoint`
4. Print incoming and forwarded requests in stdout (`-showaccesslog` flag)
5. Export 2 endpoints `0.0.0.0:8181/metrics` - metrics in prometheus format and
`0.0.0.0:8181/healthz` - simple http health-check.

---
__Sample list of metrics in prometheus format:__
```
# HELP esnirevproxy_http_average_last_min_rps Incoming HTTP rps average for the last minute
# TYPE esnirevproxy_http_average_last_min_rps gauge
esnirevproxy_http_average_last_min_rps 0

# HELP esnirevproxy_http_upstream_latency_msec Upstream latency in milliseconds
# TYPE esnirevproxy_http_upstream_latency_msec histogram
# Bucket distribution deleted...
esnirevproxy_http_upstream_latency_msec_sum{upstream="www.google.com"} 14243
esnirevproxy_http_upstream_latency_msec_count{upstream="www.google.com"} 20

# HELP esnirevproxy_http_upstream_response_codes Upstream response HTTP codes
# TYPE esnirevproxy_http_upstream_response_codes counter
esnirevproxy_http_upstream_response_codes{code="200",upstream="www.google.com"} 7
esnirevproxy_http_upstream_response_codes{code="204",upstream="www.google.com"} 13

# HELP esnirevproxy_tcp_connections_total Total active/idle connections
# TYPE esnirevproxy_tcp_connections_total gauge
esnirevproxy_tcp_connections_total 1

# HELP esnirevproxy_tls_failed_handshakes Total number of failed TLS handshakes
# TYPE esnirevproxy_tls_failed_handshakes counter
esnirevproxy_tls_failed_handshakes 1

# HELP esnirevproxy_tls_handshake_duration_msec Handshake time in milliseconds
# TYPE esnirevproxy_tls_handshake_duration_msec histogram
# Bucket distribution deleted...
esnirevproxy_tls_handshake_duration_msec_sum 3
esnirevproxy_tls_handshake_duration_msec_count 1

# HELP esnirevproxy_tls_successful_handshakes Total number of successful TLS handshakes
# TYPE esnirevproxy_tls_successful_handshakes counter
esnirevproxy_tls_successful_handshakes{sni="localhost"} 1

#Standard go_ metrics is not printed here.
```
