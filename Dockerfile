FROM golang:1.13-alpine3.12 as build

WORKDIR /esni-rev-proxy
ADD . /esni-rev-proxy

RUN apk add git upx \
 && commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown") \
 && version=$(git describe --contains "$commit" 2>/dev/null || echo "unknown") \
 && branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown") \
 && ./prepareGoRoot.sh \
 && export GOROOT=$(pwd)/.GOROOT \
 && go mod vendor \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=${version} -X main.branch=${branch} -X main.commit=${commit} -s -w -extldflags '-static'" -o esni-rev-proxy github.com/devopsext/esni-rev-proxy \
 && upx esni-rev-proxy

FROM alpine:3.12
COPY --from=build /esni-rev-proxy/esni-rev-proxy /usr/local/bin/esni-rev-proxy
RUN apk add --no-cache tini
# Tini is now available at /sbin/tini
ENTRYPOINT ["/sbin/tini", "--"]