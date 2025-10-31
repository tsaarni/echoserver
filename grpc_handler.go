package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	pb "github.com/tsaarni/echoserver/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type grpcEchoService struct {
	pb.UnimplementedEchoServiceServer
	envContext map[string]string
}

func newGRPCEchoService(envContext map[string]string) *grpc.Server {
	grpcServer := grpc.NewServer()
	echoService := &grpcEchoService{
		envContext: envContext,
	}
	pb.RegisterEchoServiceServer(grpcServer, echoService)
	return grpcServer
}

func (s *grpcEchoService) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	slog.Debug("Processing gRPC echo request", "message", req.Message)

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

	if p, ok := peer.FromContext(ctx); ok {
		resp.RemoteAddr = p.Addr.String()

		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			state := tlsInfo.State
			resp.TlsInfo = &pb.TLSInfo{
				Version:                tls.VersionName(state.Version),
				CipherSuite:            tls.CipherSuiteName(state.CipherSuite),
				AlpnNegotiatedProtocol: state.NegotiatedProtocol,
			}

			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				resp.TlsInfo.ClientCertSubject = cert.Subject.String()
				resp.TlsInfo.ClientCertIssuer = cert.Issuer.String()
				resp.TlsInfo.ClientCertSerialNumber = cert.SerialNumber.String()
				resp.TlsInfo.ClientCertNotBefore = cert.NotBefore.Format(time.RFC3339)
				resp.TlsInfo.ClientCertNotAfter = cert.NotAfter.Format(time.RFC3339)
			}
		}
	}

	return resp, nil
}
