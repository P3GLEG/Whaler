FROM golang:1.14.4 AS builder
WORKDIR $GOPATH
RUN go get -u github.com/P3GLEG/Whaler
WORKDIR $GOPATH/src/github.com/P3GLEG/Whaler
RUN export CGO_ENABLED=0 && go build .
RUN cp Whaler /root/Whaler

FROM alpine:3.12.0
WORKDIR /root/
COPY --from=builder /root/Whaler .
ENTRYPOINT ["./Whaler"]
