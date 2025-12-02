//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/suite"
	pb "github.com/tsaarni/echoserver/proto"
	"github.com/tsaarni/echoserver/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	httpAddr  = "localhost:8080"
	httpsAddr = "localhost:8443"

	serverCertPath = "../testdata/certs/echoserver.pem"
	serverKeyPath  = "../testdata/certs/echoserver-key.pem"
	caCertPath     = "../testdata/certs/ca.pem"
	clientCertPath = "../testdata/certs/client.pem"
	clientKeyPath  = "../testdata/certs/client-key.pem"
)

type E2ETestSuite struct {
	suite.Suite
	stop                      func()
	httpClient                *http.Client
	httpsClient               *http.Client
	httpsClientWithMutualAuth *http.Client

	grpcConnH2c              *grpc.ClientConn
	grpcConnH2               *grpc.ClientConn
	grpcConnH2WithMutualAuth *grpc.ClientConn
}

func (s *E2ETestSuite) SetupSuite() {
	// Ensure test certs are generated.
	cmd := exec.Command("make", "generate-test-certs")
	cmd.Dir = path.Join("../..")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	s.NoError(cmd.Run())

	// Start echoserver.
	files := os.DirFS(path.Join("../..", "apps"))
	envContext := map[string]string{"ENV_E2E_TEST": "yes"}
	stop, errChan, err := server.Start(files, envContext, httpAddr, httpsAddr, serverCertPath, serverKeyPath, "")
	s.Require().NoError(err)
	s.stop = stop

	// Wait for ports
	waitForPort := func(network, address string, timeout time.Duration) error {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			conn, dErr := net.DialTimeout(network, address, 200*time.Millisecond)
			if dErr == nil {
				conn.Close()
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Errorf("timeout waiting for %s://%s to be available", network, address)
	}

	// Monitor for server errors.
	go func() {
		err := <-errChan
		s.Require().NoError(err)
	}()

	s.NoError(waitForPort("tcp", httpAddr, 10*time.Second))
	s.NoError(waitForPort("tcp", httpsAddr, 10*time.Second))

	// Create HTTP client.
	s.httpClient = &http.Client{Timeout: 5 * time.Second}

	// Create HTTPS client.
	certs, err := os.ReadFile(caCertPath)
	s.Require().NoError(err)
	pool := x509.NewCertPool()
	s.Require().True(pool.AppendCertsFromPEM(certs))
	s.httpsClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
		Timeout: 5 * time.Second,
	}

	// Create HTTPS client with client cert.
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	s.Require().NoError(err)
	s.httpsClientWithMutualAuth = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
			},
		},
		Timeout: 5 * time.Second,
	}

	// Create gRPC client over H2c.
	s.grpcConnH2c, err = grpc.NewClient(httpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	s.Require().NoError(err)

	// Create gRPC client over H2 with TLS.
	creds, err := credentials.NewClientTLSFromFile(caCertPath, "")
	s.Require().NoError(err)
	s.grpcConnH2, err = grpc.NewClient(httpsAddr, grpc.WithTransportCredentials(creds))
	s.Require().NoError(err)

	// Create gRPC client over H2 with TLS and mutual authentication.
	clientTLSConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "localhost",
	}
	clientMutualCreds := credentials.NewTLS(clientTLSConf)
	s.grpcConnH2WithMutualAuth, err = grpc.NewClient(httpsAddr, grpc.WithTransportCredentials(clientMutualCreds))
	s.Require().NoError(err)
}

func (s *E2ETestSuite) TearDownSuite() {
	if s.grpcConnH2c != nil {
		s.grpcConnH2c.Close()
	}
	if s.stop != nil {
		s.stop()
	}
}

func (s *E2ETestSuite) makeHTTPRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("http://%s%s", httpAddr, path), body)
	if err != nil {
		return nil, err
	}
	return s.httpClient.Do(req)
}

func (s *E2ETestSuite) makeHTTPSRequestWithClientCert(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s%s", httpsAddr, path), body)
	if err != nil {
		return nil, err
	}
	return s.httpsClientWithMutualAuth.Do(req)
}

func (s *E2ETestSuite) createEchoServiceClient(tls bool, mutualAuth bool) pb.EchoServiceClient {
	var conn *grpc.ClientConn
	if tls {
		if mutualAuth {
			conn = s.grpcConnH2WithMutualAuth
		} else {
			conn = s.grpcConnH2
		}
	} else {
		conn = s.grpcConnH2c
	}
	s.Require().NotNil(conn)
	client := pb.NewEchoServiceClient(conn)
	s.Require().NotNil(client)
	return client
}

func (s *E2ETestSuite) validateWithSchema(resp *http.Response, schema string) {
	s.Require().NotNil(resp)
	s.Require().NotEmpty(schema)

	var decoded interface{}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&decoded))

	compiler := jsonschema.NewCompiler()
	compiler.AddResource("inline-schema.json", strings.NewReader(schema))
	sch, err := compiler.Compile("inline-schema.json")
	s.Require().NoError(err)

	// Print validation errors and the pretty printed decoded JSON for easier debugging.
	marshaled, _ := json.MarshalIndent(decoded, "", "  ")
	s.Require().NoError(sch.Validate(decoded), "response does not match expected schema:\n%s",
		string(marshaled))
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}
