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
	*TestSuite
}

func (s *TunnelsTestSuite) SetupTest() {
	s.TestSuite = SetupTestSuite(s.T())
}

func (s *TunnelsTestSuite) TearDownTest() {
	s.TestSuite.TearDownTestSuite(s.T())
}

// TestCreateTunnel tests tunnel creation endpoint
func (s *TunnelsTestSuite) TestCreateTunnel() {
	tests := []struct {
		name           string
		user           *TestUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "create HTTP tunnel",
			user: s.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": 8080,
			},
			expectedStatus: 201,
		},
		{
			name: "create TCP tunnel",
			user: s.TestUser,
			payload: map[string]interface{}{
				"protocol":   "tcp",
				"local_port": 3000,
			},
			expectedStatus: 201,
		},
		{
			name: "create HTTP tunnel with custom subdomain",
			user: s.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": 9000,
				"subdomain":  "myapp",
			},
			expectedStatus: 201,
		},
		{
			name: "create tunnel with invalid protocol",
			user: s.TestUser,
			payload: map[string]interface{}{
				"protocol":   "invalid",
				"local_port": 8080,
			},
			expectedStatus: 400,
			expectedError:  "Invalid protocol",
		},
		{
			name: "create tunnel with invalid port",
			user: s.TestUser,
			payload: map[string]interface{}{
				"protocol":   "http",
				"local_port": -1,
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name: "create tunnel with port too high",
			user: s.TestUser,
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
		{
			name: "create tunnel with missing fields",
			user: s.TestUser,
			payload: map[string]interface{}{
				"protocol": "http",
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", test.payload, test.user)
			} else {
				resp = s.MakeRequest("POST", "/api/v1/tunnels", test.payload, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "tunnel_id")
				assert.Contains(s.T(), resp.Body, "public_url")
				assert.Contains(s.T(), resp.Body, "status")
				assert.Contains(s.T(), resp.Body, "protocol")
				assert.Contains(s.T(), resp.Body, "created_at")
				
				protocol := resp.Body["protocol"].(string)
				assert.Equal(s.T(), test.payload["protocol"], protocol)
				
				if protocol == "tcp" {
					assert.Contains(s.T(), resp.Body, "public_port")
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestListTunnels tests listing tunnels endpoint
func (s *TunnelsTestSuite) TestListTunnels() {
	// First, create a few tunnels
	tunnelPayloads := []map[string]interface{}{
		{"protocol": "http", "local_port": 8081},
		{"protocol": "tcp", "local_port": 3001},
		{"protocol": "http", "local_port": 9001, "subdomain": "testapp"},
	}

	for _, payload := range tunnelPayloads {
		resp := s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", payload, s.TestUser)
		assert.Equal(s.T(), 201, resp.StatusCode)
	}

	tests := []struct {
		name           string
		user           *TestUser
		expectedStatus int
		expectedError  string
		minTunnels     int
	}{
		{
			name:           "list tunnels with API key",
			user:           s.TestUser,
			expectedStatus: 200,
			minTunnels:     3,
		},
		{
			name:           "list tunnels for different user",
			user:           s.TestUser2,
			expectedStatus: 200,
			minTunnels:     0, // TestUser2 has no tunnels
		},
		{
			name:           "list tunnels without authentication",
			user:           nil,
			expectedStatus: 403,
			expectedError:  "No Auth Header Provided",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAPIKeyRequest("GET", "/api/v1/tunnels", nil, test.user)
			} else {
				resp = s.MakeRequest("GET", "/api/v1/tunnels", nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "tunnels")
				tunnels := resp.Body["tunnels"].([]interface{})
				assert.GreaterOrEqual(s.T(), len(tunnels), test.minTunnels)
				
				if len(tunnels) > 0 {
					tunnel := tunnels[0].(map[string]interface{})
					assert.Contains(s.T(), tunnel, "tunnel_id")
					assert.Contains(s.T(), tunnel, "protocol")
					assert.Contains(s.T(), tunnel, "public_url")
					assert.Contains(s.T(), tunnel, "status")
					assert.Contains(s.T(), tunnel, "local_port")
					assert.Contains(s.T(), tunnel, "created_at")
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestGetTunnel tests getting specific tunnel endpoint
func (s *TunnelsTestSuite) TestGetTunnel() {
	// Create a tunnel first
	createResp := s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8082,
	}, s.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	tunnelID := createResp.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *TestUser
		tunnelID       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get own tunnel",
			user:           s.TestUser,
			tunnelID:       tunnelID,
			expectedStatus: 200,
		},
		{
			name:           "get tunnel from different user",
			user:           s.TestUser2,
			tunnelID:       tunnelID,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get non-existent tunnel",
			user:           s.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get tunnel without authentication",
			user:           nil,
			tunnelID:       tunnelID,
			expectedStatus: 403,
			expectedError:  "No Auth Header Provided",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := fmt.Sprintf("/api/v1/tunnels/%s", test.tunnelID)
			if test.user != nil {
				resp = s.MakeAPIKeyRequest("GET", path, nil, test.user)
			} else {
				resp = s.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				tunnel := resp.Body
				assert.Equal(s.T(), test.tunnelID, tunnel["tunnel_id"])
				assert.Contains(s.T(), tunnel, "protocol")
				assert.Contains(s.T(), tunnel, "public_url")
				assert.Contains(s.T(), tunnel, "status")
				assert.Contains(s.T(), tunnel, "local_port")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestDeleteTunnel tests deleting tunnel endpoint
func (s *TunnelsTestSuite) TestDeleteTunnel() {
	// Create tunnels for testing
	createResp1 := s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8083,
	}, s.TestUser)
	assert.Equal(s.T(), 201, createResp1.StatusCode)
	tunnelID1 := createResp1.Body["tunnel_id"].(string)

	createResp2 := s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "tcp",
		"local_port": 3002,
	}, s.TestUser2)
	assert.Equal(s.T(), 201, createResp2.StatusCode)
	tunnelID2 := createResp2.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *TestUser
		tunnelID       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "delete own tunnel",
			user:           s.TestUser,
			tunnelID:       tunnelID1,
			expectedStatus: 200,
		},
		{
			name:           "delete tunnel from different user",
			user:           s.TestUser,
			tunnelID:       tunnelID2,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "delete non-existent tunnel",
			user:           s.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "delete tunnel without authentication",
			user:           nil,
			tunnelID:       tunnelID1,
			expectedStatus: 403,
			expectedError:  "No Auth Header Provided",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := fmt.Sprintf("/api/v1/tunnels/%s", test.tunnelID)
			if test.user != nil {
				resp = s.MakeAPIKeyRequest("DELETE", path, nil, test.user)
			} else {
				resp = s.MakeRequest("DELETE", path, nil, nil)
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

// TestGetTunnelStats tests getting tunnel statistics endpoint
func (s *TunnelsTestSuite) TestGetTunnelStats() {
	// Create a tunnel first
	createResp := s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8084,
	}, s.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	tunnelID := createResp.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *TestUser
		tunnelID       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get own tunnel stats",
			user:           s.TestUser,
			tunnelID:       tunnelID,
			expectedStatus: 200,
		},
		{
			name:           "get tunnel stats from different user",
			user:           s.TestUser2,
			tunnelID:       tunnelID,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get stats for non-existent tunnel",
			user:           s.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get tunnel stats without authentication",
			user:           nil,
			tunnelID:       tunnelID,
			expectedStatus: 403,
			expectedError:  "No Auth Header Provided",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := fmt.Sprintf("/api/v1/tunnels/%s/stats", test.tunnelID)
			if test.user != nil {
				resp = s.MakeAPIKeyRequest("GET", path, nil, test.user)
			} else {
				resp = s.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "tunnel_id")
				assert.Contains(s.T(), resp.Body, "active_connections")
				assert.Contains(s.T(), resp.Body, "total_requests")
				assert.Contains(s.T(), resp.Body, "total_bytes_in")
				assert.Contains(s.T(), resp.Body, "total_bytes_out")
				assert.Equal(s.T(), test.tunnelID, resp.Body["tunnel_id"])
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

func TestTunnelsTestSuite(t *testing.T) {
	suite.Run(t, new(TunnelsTestSuite))
} 