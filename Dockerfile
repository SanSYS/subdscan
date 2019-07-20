FROM golang:alpine as builder
RUN apk update && apk add --no-cache git
RUN mkdir /build
ADD . /build/
WORKDIR /build
ENV GOPATH /build
RUN go get -d -v github.com/gorilla/websocket/...
RUN CGO_ENABLED=0 GOOS=linux go build -a -o subdscan .

FROM scratch
COPY --from=builder /build/subdscan /app/
ADD static /app/static
ADD wordlist.txt /app/wordlist.txt
WORKDIR /app
ENTRYPOINT [ "./subdscan", "-ui", "80" ]
EXPOSE 8080