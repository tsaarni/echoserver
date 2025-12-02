//go:build e2e

package e2e

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (s *E2ETestSuite) TestHTTPEcho() {
	req, err := http.NewRequest("GET", "http://localhost:8080/test", nil)
	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
		},
	}
	s.Require().NoError(err)
	req.Header.Set("Cookie", "sessionid=abc123")
	req.Header.Set("X-E2e-Test", "yes")
	resp, err := client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	s.validateWithSchema(resp, `{
		       "$schema": "http://json-schema.org/draft-07/schema#",
		       "type": "object",
		       "properties": {
			       "content_length": {"type": "integer", "const": 0},
			       "cookies": {
				       "type": "object",
				       "properties": {
					       "sessionid": {"type": "string", "const": "abc123"}
				       },
				       "required": ["sessionid"],
				       "additionalProperties": false
			       },
			       "env": {
				       "type": "object",
				       "properties": {
					       "ENV_E2E_TEST": {"type": "string", "const": "yes"}
				       },
				       "required": ["ENV_E2E_TEST"],
				       "additionalProperties": false
			       },
			       "headers": {
				       "type": "object",
				       "properties": {
					       "Accept-Encoding": {"type":"array","items":{"type":"string"}},
					       "Cookie": {"type":"array","items":{"type":"string","const":"sessionid=abc123"}},
					       "User-Agent": {"type":"array","items":{"type":"string","pattern":"^Go-http-client/.*"}},
						   "X-E2e-Test": {"type":"array","items":{"type":"string","const":"yes"}}
				       },
				       "required": ["Accept-Encoding","Cookie","User-Agent","X-E2e-Test"],
				       "additionalProperties": false
			       },
			       "host": {"type": "string", "const": "localhost:8080"},
			       "method": {"type": "string", "const": "GET"},
			       "proto": {"type": "string", "const": "HTTP/1.1"},
			       "remote": {"type": "string", "pattern": "^127\\.0\\.0\\.1:\\d+$"},
			       "url": {"type": "string", "const": "/test"}
		       },
		       "required": ["content_length","cookies","env","headers","host","method","proto","remote","url"],
		       "additionalProperties": false
	       }`)
}

func (s *E2ETestSuite) TestFormProcessing() {
	body := strings.NewReader("key1=value1&key2=value2")
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/test", httpAddr), body)
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	var data map[string]interface{}
	s.NoError(json.NewDecoder(resp.Body).Decode(&data))
	s.Contains(data, "form")
	form := data["form"].(map[string]interface{})
	s.Equal("value1", form["key1"].([]interface{})[0])
	s.Equal("value2", form["key2"].([]interface{})[0])
}

func (s *E2ETestSuite) TestHTTPSetStatus() {
	// Set status.
	resp, err := s.makeHTTPRequest("GET", "/status?set=503", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusServiceUnavailable, resp.StatusCode)

	// Get status and check it is still 503.
	resp, err = s.makeHTTPRequest("GET", "/status", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusServiceUnavailable, resp.StatusCode)
}

func (s *E2ETestSuite) TestHTTPStatusCode() {
	resp, err := s.makeHTTPRequest("GET", "/status/404", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusNotFound, resp.StatusCode)
}

func (s *E2ETestSuite) TestHTTPUpload() {
	body := strings.NewReader("test data")
	resp, err := s.makeHTTPRequest("POST", "/upload", body)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)

	var data map[string]interface{}
	s.NoError(json.NewDecoder(resp.Body).Decode(&data))
	s.Equal(float64(len("test data")), data["bytes_uploaded"])
}

func (s *E2ETestSuite) TestHTTPDownload() {
	resp, err := s.makeHTTPRequest("GET", "/download?bytes=100", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	s.NoError(err)
	s.Len(body, 100)
}

func (s *E2ETestSuite) TestHTTPMetrics() {
	resp, err := s.makeHTTPRequest("GET", "/metrics", nil)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Equal(http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	s.NoError(err)
	s.Contains(string(body), "http_requests_total")
}

func (s *E2ETestSuite) TestHTTPServerSentEvents() {
	// Read a couple of events and ensure we got data messages
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/sse", httpAddr), nil)
	s.Require().NoError(err)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	scanner := bufio.NewScanner(resp.Body)
	var counter int
	timeout := time.After(5 * time.Second)
Loop:
	for scanner.Scan() {
		select {
		case <-timeout:
			break Loop
		default:
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			counter++
			if counter >= 2 {
				break
			}
		}
	}
	s.Require().NoError(scanner.Err())
	s.GreaterOrEqual(counter, 1)
}

func (s *E2ETestSuite) TestHTTPDecodeBearerToken() {
	// Bearer JWT-like token
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"123","iat":1600000000,"exp":1600003600}`))
	token := fmt.Sprintf("%s.%s.signature", header, payload)
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	s.Require().NoError(err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.httpClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	var data map[string]interface{}
	s.NoError(json.NewDecoder(resp.Body).Decode(&data))
	jwt := data["jwt"].(map[string]interface{})
	s.Contains(jwt, "header")
	claims := jwt["claims"].(map[string]interface{})
	s.Equal("123", claims["sub"])
	s.Equal(float64(1600000000), claims["iat"])
	s.Equal(float64(1600003600), claims["exp"])
}

func (s *E2ETestSuite) TestHTTPDecodeBasicAuth() {
	basic := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req2, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	s.Require().NoError(err)
	req2.Header.Set("Authorization", "Basic "+basic)
	resp2, err := s.httpClient.Do(req2)
	s.Require().NoError(err)
	defer resp2.Body.Close()
	s.Equal(http.StatusOK, resp2.StatusCode)
	var data map[string]interface{}
	s.NoError(json.NewDecoder(resp2.Body).Decode(&data))
	s.Contains(data, "basic_auth")
	basicAuth := data["basic_auth"].(map[string]interface{})
	s.Equal("user", basicAuth["username"])
	s.Equal("pass", basicAuth["password"])
}
