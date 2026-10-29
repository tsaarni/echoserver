package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/tsaarni/echoserver/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type grpcEchoService struct {
	pb.UnimplementedEchoServiceServer
	envContext map[string]string
}

func NewGRPCEchoService(envContext map[string]string) *grpc.Server {
	echoService := &grpcEchoService{
		envContext: envContext,
	}
	metrics := grpc_prometheus.NewServerMetrics()
	prometheus.MustRegister(metrics)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(metrics.UnaryServerInterceptor()),
		grpc.StreamInterceptor(metrics.StreamServerInterceptor()),
		grpc.StatsHandler(grpcBytesStatsHandler{}),
	)
	pb.RegisterEchoServiceServer(grpcServer, echoService)
	reflection.Register(grpcServer)
	metrics.InitializeMetrics(grpcServer)

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
			ServerName:             state.ServerName,
			KeyExchange:            state.CurveID.String(),
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

func (s *grpcEchoService) EchoDownload(req *pb.EchoDownloadRequest, stream pb.EchoService_EchoDownloadServer) error {
	p, _ := peer.FromContext(stream.Context())

	if req.Bytes < 0 || req.MessageBytes < 0 || req.Throttle < 0 {
		return status.Error(codes.InvalidArgument, "bytes, message_bytes and throttle must not be negative")
	}
	total := req.Bytes
	if total == 0 {
		total = 1024 * 1024
	}
	messageBytes := req.MessageBytes
	if messageBytes == 0 {
		messageBytes = 16 * 1024
	}

	slog.Debug("Processing gRPC EchoDownload request", "bytes", total, "message_bytes", messageBytes,
		"throttle", req.Throttle, "remote", p.Addr.String())

	pattern := &patternByteReader{}
	buf := make([]byte, min(messageBytes, total))
	start := time.Now()
	var sent int64
	for sent < total {
		chunk := buf[:min(messageBytes, total-sent)]
		_, _ = pattern.Read(chunk)
		if err := stream.Send(&pb.EchoDownloadResponse{Payload: chunk}); err != nil {
			slog.Debug("EchoDownload interrupted", "sent_bytes", sent, "error", err, "remote", p.Addr.String())
			return err
		}
		sent += int64(len(chunk))
		if req.Throttle > 0 {
			expected := time.Duration(sent) * time.Second / time.Duration(req.Throttle)
			if wait := expected - time.Since(start); wait > 0 {
				select {
				case <-time.After(wait):
				case <-stream.Context().Done():
					slog.Debug("EchoDownload interrupted", "sent_bytes", sent, "error", stream.Context().Err(), "remote", p.Addr.String())
					return stream.Context().Err()
				}
			}
		}
	}

	slog.Debug("EchoDownload completed", "sent_bytes", sent, "remote", p.Addr.String())
	return nil
}

func (s *grpcEchoService) EchoUpload(stream pb.EchoService_EchoUploadServer) error {
	p, _ := peer.FromContext(stream.Context())
	slog.Debug("Processing gRPC EchoUpload request", "remote", p.Addr.String())

	var messages, totalBytes int64
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			slog.Debug("EchoUpload completed", "messages", messages, "total_bytes", totalBytes, "remote", p.Addr.String())
			return stream.SendAndClose(&pb.EchoUploadResponse{
				Messages:   messages,
				TotalBytes: totalBytes,
			})
		}
		if err != nil {
			slog.Debug("EchoUpload interrupted", "messages", messages, "total_bytes", totalBytes, "error", err, "remote", p.Addr.String())
			return err
		}
		messages++
		totalBytes += int64(len(req.Payload))
	}
}

func (s *grpcEchoService) EchoStream(stream pb.EchoService_EchoStreamServer) error {
	p, _ := peer.FromContext(stream.Context())
	slog.Debug("Processing gRPC EchoStream request", "remote", p.Addr.String())

	var sequence, totalBytes int64
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			slog.Debug("EchoStream completed", "messages", sequence, "total_bytes", totalBytes, "remote", p.Addr.String())
			return nil
		}
		if err != nil {
			slog.Debug("EchoStream interrupted", "messages", sequence, "total_bytes", totalBytes, "error", err, "remote", p.Addr.String())
			return err
		}
		sequence++
		totalBytes += int64(len(req.Payload))
		if err := stream.Send(&pb.EchoStreamResponse{
			Sequence:     sequence,
			MessageBytes: int64(len(req.Payload)),
			TotalBytes:   totalBytes,
		}); err != nil {
			return err
		}
	}
}
