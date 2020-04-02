# esni-rev-proxy
Golang reverse proxy with draft 01 ESNI support on top of TLS 1.3

__Motovation__ As of April 2020 ESNI, is still a draft extension for TLS 1.3 and not officialy supported by OpenSSL and major projects like nginx, apache, etc (however unofficial forks exists). This project porvides a tiny golang reverse proxy that can terminate TLS 1.3 wint ESNI and forward plain HTTP to upstream. This cover the gap, and if you want to use ESNI draft you can use it right now with your vanilla nginx/apache etc. Also your browser should support ESNI, and for now it is only firefox (https://www.elliotjreed.com/post/security/2019-07-08_Enable_DNS_over_HTTPS_and_Encrypted_SNI_in_Firefox). 

This project is extension of tris-localserver example code : https://github.com/cloudflare/tls-tris/tree/master/_dev/tris-localserver and was inspired by discussion: https://serverfault.com/questions/976377/how-can-i-set-up-encrypted-sni-on-my-own-servers

