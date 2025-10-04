# docker build -t ghcr.io/tsaarni/echoserver:latest .

FROM golang:1.23.3-alpine3.20 AS builder
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build .

FROM scratch
COPY --from=builder /go/echoserver .

CMD ["./echoserver"]
