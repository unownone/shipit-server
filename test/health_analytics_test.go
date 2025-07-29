package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// HealthAnalyticsTestSuite tests health and analytics endpoints
type HealthAnalyticsTestSuite struct {
	suite.Suite
	testSuite *testSuite
}

func (s *HealthAnalyticsTestSuite) SetupTest() {
	s.testSuite = setupTestSuite(s.T())
}

func (s *HealthAnalyticsTestSuite) TearDownTest() {
	s.testSuite.TearDownTestSuite(s.T())
}

// TestHealthCheck tests the health check endpoint
func (s *HealthAnalyticsTestSuite) TestHealthCheck() {
	resp := s.testSuite.MakeRequest("GET", "/health", nil, nil)

	AssertSuccessResponse(s.T(), resp, 200)
	assert.Equal(s.T(), "healthy", resp.Body["status"])
	assert.Contains(s.T(), resp.Body, "version")
}

// TestGetAnalyticsOverview tests analytics overview endpoint
func (s *HealthAnalyticsTestSuite) TestGetAnalyticsOverview() {
	tests := []struct {
		name           string
		user           *testUser
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get overview with default period",
			user:           s.testSuite.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get overview with 24h period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get overview with 7d period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=7d",
			expectedStatus: 200,
		},
		{
			name:           "get overview with 30d period",
			user:           s.testSuite.TestUser,
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
				resp = s.testSuite.MakeAuthenticatedRequest("GET", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", path, nil, nil)
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
		user           *testUser
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get traffic analytics with default period",
			user:           s.testSuite.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get traffic analytics with 24h period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get traffic analytics with 7d period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=7d",
			expectedStatus: 200,
		},
		{
			name:           "get traffic analytics with 30d period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=30d",
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
				resp = s.testSuite.MakeAuthenticatedRequest("GET", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "requests")
				assert.Contains(s.T(), resp.Body, "bandwidth")
				assert.Contains(s.T(), resp.Body, "period")
				assert.Contains(s.T(), resp.Body, "generated_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestGetTunnelAnalytics tests tunnel analytics endpoint
func (s *HealthAnalyticsTestSuite) TestGetTunnelAnalytics() {
	tests := []struct {
		name           string
		user           *testUser
		queryParams    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get tunnel analytics with default period",
			user:           s.testSuite.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get tunnel analytics with 24h period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=24h",
			expectedStatus: 200,
		},
		{
			name:           "get tunnel analytics with 7d period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=7d",
			expectedStatus: 200,
		},
		{
			name:           "get tunnel analytics with 30d period",
			user:           s.testSuite.TestUser,
			queryParams:    "?period=30d",
			expectedStatus: 200,
		},
		{
			name:           "get tunnel analytics without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/analytics/tunnels" + test.queryParams
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("GET", path, nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "tunnels")
				assert.Contains(s.T(), resp.Body, "active_tunnels")
				assert.Contains(s.T(), resp.Body, "total_requests")
				assert.Contains(s.T(), resp.Body, "total_bandwidth")
				assert.Contains(s.T(), resp.Body, "period")
				assert.Contains(s.T(), resp.Body, "generated_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

func TestHealthAnalyticsTestSuite(t *testing.T) {
	suite.Run(t, new(HealthAnalyticsTestSuite))
}
