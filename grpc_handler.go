package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"

	pb "github.com/tsaarni/echoserver/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
)

type grpcEchoService struct {
	pb.UnimplementedEchoServiceServer
	envContext map[string]string
}

func newGRPCEchoService(envContext map[string]string) *grpc.Server {
	echoService := &grpcEchoService{
		envContext: envContext,
	}
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)
	pb.RegisterEchoServiceServer(grpcServer, echoService)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)

	return grpcServer
}

func (s *grpcEchoService) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	p, _ := peer.FromContext(ctx)
	slog.Debug("Processing gRPC Echo request", "message", req.Message, "remote", p.Addr.String())

	resp := &pb.EchoResponse{
		Message: req.Message,
		Headers: make(map[string]*pb.HeaderValues),
		Env:     s.envContext,
	}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for key, values := range md {
			resp.Headers[key] = &pb.HeaderValues{
				Values: values,
			}
		}
	}

	resp.RemoteAddr = p.Addr.String()

	if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
		state := tlsInfo.State
		resp.TlsInfo = &pb.TLSInfo{
			Version:                tls.VersionName(state.Version),
			CipherSuite:            tls.CipherSuiteName(state.CipherSuite),
			AlpnNegotiatedProtocol: state.NegotiatedProtocol,
		}

		for _, cert := range state.PeerCertificates {
			certInfo := &pb.TLSCertificateInfo{
				Subject:      cert.Subject.String(),
				Issuer:       cert.Issuer.String(),
				SerialNumber: cert.SerialNumber.String(),
				NotBefore:    cert.NotBefore.Format(time.RFC3339),
				NotAfter:     cert.NotAfter.Format(time.RFC3339),
			}
			resp.TlsInfo.PeerCertificates = append(resp.TlsInfo.PeerCertificates, certInfo)
		}
	}

	return resp, nil
}

func (s *grpcEchoService) EchoCountdown(req *pb.EchoCountdownRequest, stream pb.EchoService_EchoCountdownServer) error {
	p, _ := peer.FromContext(stream.Context())
	slog.Debug("Processing gRPC EchoCountdown request", "start", req.Start, "remote", p.Addr.String())

	if req.Start < 0 {
		slog.Debug("Invalid start value for EchoCountdown", "start", req.Start, "remote", p.Addr.String())
		return nil
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for i := req.Start; i >= 0; i-- {
		slog.Debug("Sending countdown", "count", i, "remote", p.Addr.String())
		resp := &pb.EchoCountdownResponse{
			Count: i,
		}
		if err := stream.Send(resp); err != nil {
			return err
		}

		if i == 0 {
			break
		}

		select {
		case <-ticker.C:
			// Continue to next iteration
		case <-stream.Context().Done():
			slog.Debug("Client cancelled countdown", "remote", p.Addr.String())
			return stream.Context().Err()
		}
	}

	return nil
}
