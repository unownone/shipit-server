package test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// TunnelsTestSuite tests tunnel management endpoints
type TunnelsTestSuite struct {
	suite.Suite
	testSuite *testSuite
}

func (s *TunnelsTestSuite) SetupTest() {
	s.testSuite = setupTestSuite(s.T())
}

func (s *TunnelsTestSuite) TearDownTest() {
	s.testSuite.TearDownTestSuite(s.T())
}

// TestCreateTunnel tests tunnel creation endpoint
func (s *TunnelsTestSuite) TestCreateTunnel() {
	tests := []struct {
		name           string
		user           *testUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "create HTTP tunnel",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": 8080,
			},
			expectedStatus: 201,
		},
		{
			name: "create TCP tunnel",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"protocol":   "tcp",
				"local_port": 3000,
			},
			expectedStatus: 201,
		},
		{
			name: "create HTTP tunnel with custom subdomain",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": 9000,
				"subdomain":  "myapp",
			},
			expectedStatus: 201,
		},
		{
			name: "create tunnel with invalid protocol",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"protocol":   "invalid",
				"local_port": 8080,
			},
			expectedStatus: 400,
			expectedError:  "Invalid protocol",
		},
		{
			name: "create tunnel with invalid port",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": -1,
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name: "create tunnel with port too high",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": 70000,
			},
			expectedStatus: 400,
			expectedError:  "Invalid local_port",
		},
		{
			name: "create tunnel without authentication",
			user: nil,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": 8080,
			},
			expectedStatus: 401,
			expectedError:  "API key header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.testSuite.MakeAPIKeyRequest("POST", "/api/v1/tunnels", test.payload, test.user)
			} else {
				resp = s.testSuite.MakeRequest("POST", "/api/v1/tunnels", test.payload, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "tunnel_id")
				assert.Contains(s.T(), resp.Body, "public_url")
				assert.Contains(s.T(), resp.Body, "protocol")
				assert.Contains(s.T(), resp.Body, "local_port")
				assert.Contains(s.T(), resp.Body, "status")
				assert.Contains(s.T(), resp.Body, "created_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestListTunnels tests tunnel listing endpoint
func (s *TunnelsTestSuite) TestListTunnels() {
	// Create a tunnel first for testing
	createResp := s.testSuite.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8081,
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)

	tests := []struct {
		name           string
		user           *testUser
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "list tunnels with API key",
			user:           s.testSuite.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "list tunnels with status filter",
			user:           s.testSuite.TestUser,
			queryParams:    "?status=active",
			expectedStatus: 200,
		},
		{
			name:           "list tunnels with protocol filter",
			user:           s.testSuite.TestUser,
			queryParams:    "?protocol=http",
			expectedStatus: 200,
		},
		{
			name:           "list tunnels without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "API key header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/tunnels" + test.queryParams
			if test.user != nil {
				resp = s.testSuite.MakeAPIKeyRequest("GET", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "tunnels")
				assert.Contains(s.T(), resp.Body, "total")
				assert.Contains(s.T(), resp.Body, "page")
				assert.Contains(s.T(), resp.Body, "limit")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestGetTunnel tests getting a specific tunnel
func (s *TunnelsTestSuite) TestGetTunnel() {
	// Create a tunnel first for testing
	createResp := s.testSuite.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8082,
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	tunnelID := createResp.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *testUser
		tunnelID       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get tunnel with API key",
			user:           s.testSuite.TestUser,
			tunnelID:       tunnelID,
			expectedStatus: 200,
		},
		{
			name:           "get tunnel for different user",
			user:           s.testSuite.TestUser2,
			tunnelID:       tunnelID,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get non-existent tunnel",
			user:           s.testSuite.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get tunnel without authentication",
			user:           nil,
			tunnelID:       tunnelID,
			expectedStatus: 401,
			expectedError:  "API key header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := fmt.Sprintf("/api/v1/tunnels/%s", test.tunnelID)
			if test.user != nil {
				resp = s.testSuite.MakeAPIKeyRequest("GET", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Equal(s.T(), test.tunnelID, resp.Body["tunnel_id"])
				assert.Contains(s.T(), resp.Body, "public_url")
				assert.Contains(s.T(), resp.Body, "protocol")
				assert.Contains(s.T(), resp.Body, "local_port")
				assert.Contains(s.T(), resp.Body, "status")
				assert.Contains(s.T(), resp.Body, "created_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestDeleteTunnel tests tunnel deletion endpoint
func (s *TunnelsTestSuite) TestDeleteTunnel() {
	// Create a tunnel first for testing
	createResp := s.testSuite.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8083,
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	tunnelID := createResp.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *testUser
		tunnelID       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "delete tunnel with API key",
			user:           s.testSuite.TestUser,
			tunnelID:       tunnelID,
			expectedStatus: 200,
		},
		{
			name:           "delete tunnel for different user",
			user:           s.testSuite.TestUser2,
			tunnelID:       tunnelID,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "delete non-existent tunnel",
			user:           s.testSuite.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "delete tunnel without authentication",
			user:           nil,
			tunnelID:       tunnelID,
			expectedStatus: 401,
			expectedError:  "API key header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := fmt.Sprintf("/api/v1/tunnels/%s", test.tunnelID)
			if test.user != nil {
				resp = s.testSuite.MakeAPIKeyRequest("DELETE", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("DELETE", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "message")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestGetTunnelStats tests tunnel statistics endpoint
func (s *TunnelsTestSuite) TestGetTunnelStats() {
	// Create a tunnel first for testing
	createResp := s.testSuite.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8084,
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	tunnelID := createResp.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *testUser
		tunnelID       string
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get tunnel stats with API key",
			user:           s.testSuite.TestUser,
			tunnelID:       tunnelID,
			expectedStatus: 200,
		},
		{
			name:           "get tunnel stats with period",
			user:           s.testSuite.TestUser,
			tunnelID:       tunnelID,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get stats for different user's tunnel",
			user:           s.testSuite.TestUser2,
			tunnelID:       tunnelID,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get stats for non-existent tunnel",
			user:           s.testSuite.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get tunnel stats without authentication",
			user:           nil,
			tunnelID:       tunnelID,
			expectedStatus: 401,
			expectedError:  "API key header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := fmt.Sprintf("/api/v1/tunnels/%s/stats%s", test.tunnelID, test.queryParams)
			if test.user != nil {
				resp = s.testSuite.MakeAPIKeyRequest("GET", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Equal(s.T(), test.tunnelID, resp.Body["tunnel_id"])
				assert.Contains(s.T(), resp.Body, "metrics")
				assert.Contains(s.T(), resp.Body, "time_series")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

func TestTunnelsTestSuite(t *testing.T) {
	suite.Run(t, new(TunnelsTestSuite))
}
