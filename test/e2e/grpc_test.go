//go:build e2e

package e2e

import (
	"context"
	"io"

	pb "github.com/tsaarni/echoserver/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
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
