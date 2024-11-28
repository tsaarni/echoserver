# docker build -t ghcr.io/tsaarni/tsaarni/echoserver:latest .

FROM golang:1.23.3-alpine3.20 AS builder
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o main .

FROM scratch
COPY --from=builder /go/main .

CMD ["./main"]
