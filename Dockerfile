FROM --platform=$BUILDPLATFORM golang:1.25.4 AS builder
ARG TARGETOS
ARG TARGETARCH
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -o echoserver .


FROM scratch
COPY --from=builder /go/echoserver .

CMD ["./echoserver"]
