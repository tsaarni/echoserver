//go:build e2e

package e2e

import (
	"context"
	"io"
	"strconv"
	"strings"
	"time"

	pb "github.com/tsaarni/echoserver/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (s *E2ETestSuite) TestGRPCEcho() {
	client := s.createEchoServiceClient(false, false)
	var p peer.Peer
	resp, err := client.Echo(context.Background(), &pb.EchoRequest{Message: "hello"}, grpc.Peer(&p))
	s.Require().NoError(err)
	s.Equal("hello", resp.Message)
	s.Equal(p.LocalAddr.String(), resp.RemoteAddr)
	s.NotNil(resp.Headers)
	s.NotNil(resp.Env)
	s.Equal("yes", resp.Env["ENV_E2E_TEST"])
}

func (s *E2ETestSuite) TestGRPCEchoCountdown() {
	client := s.createEchoServiceClient(false, false)
	stream, err := client.EchoCountdown(context.Background(), &pb.EchoCountdownRequest{Start: 3})
	s.Require().NoError(err)

	var counts []int32
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		s.Require().NoError(err)
		counts = append(counts, resp.Count)
	}

	s.Equal([]int32{3, 2, 1, 0}, counts)
}

func (s *E2ETestSuite) TestGRPCEchoDownload() {
	client := s.createEchoServiceClient(false, false)

	// Defaults: 1 MiB in 16 KiB messages.
	stream, err := client.EchoDownload(context.Background(), &pb.EchoDownloadRequest{})
	s.Require().NoError(err)
	messages, payload := s.receiveDownload(stream)
	s.Equal(64, messages)
	s.Len(payload, 1024*1024)

	// Last message is shorter and the byte pattern continues across messages.
	stream, err = client.EchoDownload(context.Background(), &pb.EchoDownloadRequest{Bytes: 1000, MessageBytes: 300})
	s.Require().NoError(err)
	messages, payload = s.receiveDownload(stream)
	s.Equal(4, messages)
	s.Require().Len(payload, 1000)
	for i, b := range payload {
		s.Require().Equal(byte(i), b, "byte %d", i)
	}
}

func (s *E2ETestSuite) TestGRPCEchoDownloadThrottle() {
	client := s.createEchoServiceClient(false, false)
	start := time.Now()
	stream, err := client.EchoDownload(context.Background(), &pb.EchoDownloadRequest{Bytes: 2000, MessageBytes: 500, Throttle: 1000})
	s.Require().NoError(err)
	messages, payload := s.receiveDownload(stream)
	s.Equal(4, messages)
	s.Len(payload, 2000)
	s.GreaterOrEqual(time.Since(start), 1900*time.Millisecond)
}

func (s *E2ETestSuite) TestGRPCEchoDownloadFailNegative() {
	client := s.createEchoServiceClient(false, false)
	stream, err := client.EchoDownload(context.Background(), &pb.EchoDownloadRequest{Bytes: -1})
	s.Require().NoError(err)
	_, err = stream.Recv()
	s.Equal(codes.InvalidArgument, status.Code(err))
}

func (s *E2ETestSuite) receiveDownload(stream grpc.ServerStreamingClient[pb.EchoDownloadResponse]) (int, []byte) {
	var messages int
	var payload []byte
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return messages, payload
		}
		s.Require().NoError(err)
		messages++
		payload = append(payload, resp.Payload...)
	}
}

func (s *E2ETestSuite) TestGRPCEchoUpload() {
	client := s.createEchoServiceClient(false, false)
	stream, err := client.EchoUpload(context.Background())
	s.Require().NoError(err)

	for _, size := range []int{10, 0, 1000} {
		s.Require().NoError(stream.Send(&pb.EchoUploadRequest{Payload: make([]byte, size)}))
	}

	resp, err := stream.CloseAndRecv()
	s.Require().NoError(err)
	s.Equal(int64(3), resp.Messages)
	s.Equal(int64(1010), resp.TotalBytes)
}

func (s *E2ETestSuite) TestGRPCEchoStream() {
	client := s.createEchoServiceClient(false, false)
	stream, err := client.EchoStream(context.Background())
	s.Require().NoError(err)

	var total int64
	for i, size := range []int{10, 0, 1000} {
		s.Require().NoError(stream.Send(&pb.EchoStreamRequest{Payload: make([]byte, size)}))
		resp, err := stream.Recv()
		s.Require().NoError(err)
		total += int64(size)
		s.Equal(int64(i+1), resp.Sequence)
		s.Equal(int64(size), resp.MessageBytes)
		s.Equal(total, resp.TotalBytes)
	}

	s.Require().NoError(stream.CloseSend())
	_, err = stream.Recv()
	s.Require().ErrorIs(err, io.EOF)
}

func (s *E2ETestSuite) TestGRPCWithTLS() {
	client := s.createEchoServiceClient(true, false)
	var p peer.Peer
	resp, err := client.Echo(context.Background(), &pb.EchoRequest{Message: "hello tls"}, grpc.Peer(&p))
	s.Require().NoError(err)
	s.Equal("hello tls", resp.Message)
	s.Equal("tls", p.AuthInfo.AuthType())
	s.NotNil(resp.TlsInfo)
	s.NotEmpty(resp.TlsInfo.Version)
	s.NotEmpty(resp.TlsInfo.CipherSuite)
	s.NotEmpty(resp.TlsInfo.AlpnNegotiatedProtocol)
}

func (s *E2ETestSuite) TestGRPCEchoFailCountdownNegative() {
	client := s.createEchoServiceClient(false, false)
	stream, err := client.EchoCountdown(context.Background(), &pb.EchoCountdownRequest{Start: -1})
	s.Require().NoError(err)
	_, err = stream.Recv()
	s.Require().ErrorIs(err, io.EOF)
}

func (s *E2ETestSuite) TestGRPCWithClientCert() {
	client := s.createEchoServiceClient(true, true)
	resp, err := client.Echo(context.Background(), &pb.EchoRequest{Message: "hello with client cert"})
	s.Require().NoError(err)
	s.Equal("hello with client cert", resp.Message)
	s.NotNil(resp.TlsInfo)
	s.Greater(len(resp.TlsInfo.PeerCertificates), 0)
	for _, cert := range resp.TlsInfo.PeerCertificates {
		s.NotEmpty(cert.Subject)
		s.NotEmpty(cert.Issuer)
		s.NotEmpty(cert.SerialNumber)
	}
}

func (s *E2ETestSuite) TestGRPCMetricsBytes() {
	const (
		received = `grpc_server_msg_received_bytes_total{grpc_method="EchoUpload",grpc_service="echo.EchoService",grpc_type="client_stream"}`
		sent     = `grpc_server_msg_sent_bytes_total{grpc_method="EchoUpload",grpc_service="echo.EchoService",grpc_type="client_stream"}`
	)
	receivedBefore := s.metricValue(received)
	sentBefore := s.metricValue(sent)

	client := s.createEchoServiceClient(false, false)
	stream, err := client.EchoUpload(context.Background())
	s.Require().NoError(err)

	// Wire bytes are the protobuf message plus the 5-byte gRPC message header.
	var wantReceived float64
	for _, size := range []int{10, 0, 1000} {
		req := &pb.EchoUploadRequest{Payload: make([]byte, size)}
		s.Require().NoError(stream.Send(req))
		wantReceived += float64(proto.Size(req) + 5)
	}
	resp, err := stream.CloseAndRecv()
	s.Require().NoError(err)
	wantSent := float64(proto.Size(resp) + 5)

	s.Equal(wantReceived, s.metricValue(received)-receivedBefore)
	s.Equal(wantSent, s.metricValue(sent)-sentBefore)
}

// metricValue returns the value of the metric line with the given name and labels, or 0 if not found.
func (s *E2ETestSuite) metricValue(series string) float64 {
	resp, err := s.makeHTTPRequest("GET", "/metrics", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	for _, line := range strings.Split(string(body), "\n") {
		if value, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(value, 64)
			s.Require().NoError(err)
			return v
		}
	}
	return 0
}
