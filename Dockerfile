FROM golang AS builder
WORKDIR $GOPATH
RUN go get -u github.com/P3GLEG/Whaler
WORKDIR $GOPATH/src/github.com/P3GLEG/Whaler
RUN go build .
RUN cp Whaler /root/Whaler

FROM debian
WORKDIR /root/
COPY --from=builder /root/Whaler .
ENTRYPOINT ["./Whaler"]
