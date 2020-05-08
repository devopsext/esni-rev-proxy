## v1.0.2 [2020-05-08]
#### Release Notes
Various improvements based on load testing.
Load-testing was performed by wrk, here the results:
```bash
wrk -t50 -c1000 -d360s 'https://127.0.0.1' --timeout 15s
Running 6m test @ https://127.0.0.1
  50 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.45s   743.48ms  13.88s    80.11%
    Req/Sec    17.64     13.36   120.00     75.77%
  254094 requests in 6.00m, 7.48GB read
Requests/sec:    705.57
Transfer/sec:     21.27MB 
```
#### Features
- Reworked scripts for preparing GOROOT (now accepts 1 input that point out the target folder for prepared GOROOT)
- Added `build.sh` - script that prepare GOROOT and build binary.
- Added script `enable_esni_firefox_darwin.sh` - this is example of script to automate ESNI support enablement in fire fox browser
- Add CPU and MEM profiling (-cpuprof, -memprof flags)
#### Bugfixes

- Fix data race when gathering tls handshake statistics.

## v1.0.1 [2020-04-09]
#### Features
- Added telemetry in prometheus format

## v1.0.0 [2020-04-03]
#### Release Notes
Initial version