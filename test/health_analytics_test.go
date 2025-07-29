package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// HealthAnalyticsTestSuite tests health and analytics endpoints
type HealthAnalyticsTestSuite struct {
	suite.Suite
	*TestSuite
}

func (s *HealthAnalyticsTestSuite) SetupTest() {
	s.TestSuite = SetupTestSuite(s.T())
}

func (s *HealthAnalyticsTestSuite) TearDownTest() {
	s.TestSuite.TearDownTestSuite(s.T())
}

// TestHealthCheck tests the health check endpoint
func (s *HealthAnalyticsTestSuite) TestHealthCheck() {
	resp := s.MakeRequest("GET", "/health", nil, nil)

	AssertSuccessResponse(s.T(), resp, 200)
	assert.Equal(s.T(), "healthy", resp.Body["status"])
	assert.Contains(s.T(), resp.Body, "version")
}

// TestGetAnalyticsOverview tests analytics overview endpoint
func (s *HealthAnalyticsTestSuite) TestGetAnalyticsOverview() {
	tests := []struct {
		name           string
		user           *TestUser
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get overview with default period",
			user:           s.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get overview with 24h period",
			user:           s.TestUser,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get overview with 7d period",
			user:           s.TestUser,
			queryParams:    "?period=7d",
			expectedStatus: 200,
		},
		{
			name:           "get overview with 30d period",
			user:           s.TestUser,
			queryParams:    "?period=30d",
			expectedStatus: 200,
		},
		{
			name:           "get overview without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/analytics/overview" + test.queryParams
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("GET", path, nil, test.user)
			} else {
				resp = s.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "total_tunnels")
				assert.Contains(s.T(), resp.Body, "active_tunnels")
				assert.Contains(s.T(), resp.Body, "total_requests")
				assert.Contains(s.T(), resp.Body, "total_bandwidth")
				assert.Contains(s.T(), resp.Body, "total_bandwidth_bytes")
				assert.Contains(s.T(), resp.Body, "period")
				assert.Contains(s.T(), resp.Body, "generated_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestGetTrafficAnalytics tests traffic analytics endpoint
func (s *HealthAnalyticsTestSuite) TestGetTrafficAnalytics() {
	tests := []struct {
		name           string
		user           *TestUser
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get traffic analytics with default period",
			user:           s.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get traffic analytics with 24h period",
			user:           s.TestUser,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get traffic analytics with 7d period",
			user:           s.TestUser,
			queryParams:    "?period=7d",
			expectedStatus: 200,
		},
		{
			name:           "get traffic analytics without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/analytics/traffic" + test.queryParams
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("GET", path, nil, test.user)
			} else {
				resp = s.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "top_visitors")
				assert.Contains(s.T(), resp.Body, "top_paths")
				assert.Contains(s.T(), resp.Body, "status_codes")
				assert.Contains(s.T(), resp.Body, "user_agents")
				assert.Contains(s.T(), resp.Body, "countries")
				assert.Contains(s.T(), resp.Body, "period")
				assert.Contains(s.T(), resp.Body, "generated_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestGetTunnelAnalytics tests tunnel-specific analytics endpoint
func (s *HealthAnalyticsTestSuite) TestGetTunnelAnalytics() {
	// Create a tunnel first
	createResp := s.MakeAPIKeyRequest("POST", "/api/v1/tunnels", map[string]interface{}{
		"protocol":   "http",
		"local_port": 8085,
	}, s.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	tunnelID := createResp.Body["tunnel_id"].(string)

	tests := []struct {
		name           string
		user           *TestUser
		tunnelID       string
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get tunnel analytics with API key",
			user:           s.TestUser,
			tunnelID:       tunnelID,
			expectedStatus: 200,
		},
		{
			name:           "get tunnel analytics with period",
			user:           s.TestUser,
			tunnelID:       tunnelID,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get analytics for different user's tunnel",
			user:           s.TestUser2,
			tunnelID:       tunnelID,
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get analytics for non-existent tunnel",
			user:           s.TestUser,
			tunnelID:       "non-existent-tunnel-id",
			expectedStatus: 404,
			expectedError:  "Tunnel not found",
		},
		{
			name:           "get tunnel analytics without authentication",
			user:           nil,
			tunnelID:       tunnelID,
			expectedStatus: 403,
			expectedError:  "No Auth Header Provided",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/analytics/tunnels/" + test.tunnelID + "/stats" + test.queryParams
			if test.user != nil {
				resp = s.MakeAPIKeyRequest("GET", path, nil, test.user)
			} else {
				resp = s.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				assert.Equal(s.T(), test.expectedStatus, resp.StatusCode, "Response body: %+v", resp.Body)
				assert.Contains(s.T(), resp.Body, "tunnel_id")
				assert.Contains(s.T(), resp.Body, "metrics")
				assert.Contains(s.T(), resp.Body, "time_series")
				assert.Contains(s.T(), resp.Body, "period")
				assert.Equal(s.T(), test.tunnelID, resp.Body["tunnel_id"])
			} else {
				assert.Equal(s.T(), test.expectedStatus, resp.StatusCode)
				if test.expectedError == "" {
					return
				}
				if errorMsg, ok := resp.Body["error"]; ok {
					assert.Contains(s.T(), errorMsg, test.expectedError)
				} else {
					s.T().Errorf("Expected error message containing '%s', but no error field found in response: %+v", test.expectedError, resp.Body)
				}
			}
		})
	}
}

func TestHealthAnalyticsTestSuite(t *testing.T) {
	suite.Run(t, new(HealthAnalyticsTestSuite))
}
