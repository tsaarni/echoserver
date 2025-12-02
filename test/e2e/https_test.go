//go:build e2e

package e2e

import (
	"net/http"
)

func (s *E2ETestSuite) TestHTTPSEcho() {
	resp, err := s.makeHTTPSRequestWithClientCert("GET", "/test", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	s.validateWithSchema(resp, `{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {
				"tls": {
					"type": "object",
					"additionalProperties": false,
					"properties": {
						"alpn_negotiated_protocol": {"type": "string"},
						"cipher_suite": {"type": "string", "pattern": "^TLS_"},
						"key_exchange": {"type": "string"},
						"peer_certificates": {"type": "string", "pattern": "^-----BEGIN CERTIFICATE-----"},
						"peer_certificates_decoded": {
							"type": "array",
							"items": {
								"type": "object",
								"additionalProperties": false,
								"properties": {
									"issuer": {"type": "string"},
									"not_after": {"type": "string"},
									"not_before": {"type": "string"},
									"serial_number": {"type": "string"},
									"subject": {"type": "string"}
								},
								"required": ["issuer", "not_after", "not_before", "serial_number", "subject"]
							}
						},
						"server_name": {"type": "string", "const": "localhost"},
						"version": {"type": "string", "pattern": "^TLS 1\\.[23]$"}
					},
					"required": ["alpn_negotiated_protocol", "cipher_suite", "key_exchange", "peer_certificates", "peer_certificates_decoded", "server_name", "version"]
				}
			},
			"required": ["tls"]
		}`)
}
