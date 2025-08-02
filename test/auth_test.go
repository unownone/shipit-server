// Package test provides the authentication test suite
package test

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/unownone/shipit-server/internal/api/middleware"
	"github.com/unownone/shipit-server/internal/auth"
)

// AuthTestSuite tests auth-related endpoints and middleware
type AuthTestSuite struct {
	suite.Suite
	testSuite *testSuite
}

func (s *AuthTestSuite) SetupTest() {
	s.testSuite = setupTestSuite(s.T())
}

func (s *AuthTestSuite) TearDownTest() {
	s.testSuite.TearDownTestSuite(s.T())
}

// TestGetTokenInfo tests the GetTokenInfo endpoint
func (s *AuthTestSuite) TestGetTokenInfo() {
	// Create an API key for testing
	createResp := s.testSuite.MakeAuthenticatedRequest("POST", "/api/v1/users/api-keys", map[string]interface{}{
		"name":        "Test API Key for Token Info",
		"description": "API key for token info test",
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	apiKey := createResp.Body["api_key"].(map[string]interface{})
	apiKeyValue := apiKey["key"].(string)

	// Login to get JWT token
	loginResp := s.testSuite.MakeRequest("POST", "/api/v1/users/login", map[string]interface{}{
		"email":    s.testSuite.TestUser.Email,
		"password": s.testSuite.TestUser.Password,
	}, nil)
	assert.Equal(s.T(), 200, loginResp.StatusCode)
	jwtToken := loginResp.Body["access_token"].(string)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedError  string
		checkResponse  func(*APIResponse)
	}{
		{
			name:           "get token info with API key",
			authHeader:     "Bearer " + apiKeyValue,
			expectedStatus: 200,
			checkResponse: func(resp *APIResponse) {
				assert.Equal(s.T(), true, resp.Body["valid"])
				assert.Equal(s.T(), "api_key", resp.Body["auth_type"])
				assert.Equal(s.T(), s.testSuite.TestUser.ID.String(), resp.Body["user_id"])
				assert.Equal(s.T(), s.testSuite.TestUser.Email, resp.Body["user_email"])
				assert.Equal(s.T(), s.testSuite.TestUser.Name, resp.Body["user_name"])
				assert.Equal(s.T(), s.testSuite.TestUser.Role, resp.Body["user_role"])
				keyInfo := resp.Body["key_info"].(map[string]interface{})
				assert.Contains(s.T(), keyInfo, "id")
				assert.Contains(s.T(), keyInfo, "name")
				assert.Contains(s.T(), keyInfo, "created_at")
				assert.Contains(s.T(), keyInfo, "last_used_at")
				assert.Contains(s.T(), keyInfo, "expires_at")
			},
		},
		{
			name:           "get token info with API key in X-API-KEY header",
			authHeader:     "", // Will be set in the test
			expectedStatus: 200,
			checkResponse: func(resp *APIResponse) {
				assert.Equal(s.T(), true, resp.Body["valid"])
				assert.Equal(s.T(), "api_key", resp.Body["auth_type"])
				assert.Equal(s.T(), s.testSuite.TestUser.ID.String(), resp.Body["user_id"])
				assert.Equal(s.T(), s.testSuite.TestUser.Email, resp.Body["user_email"])
				assert.Equal(s.T(), s.testSuite.TestUser.Name, resp.Body["user_name"])
				assert.Equal(s.T(), s.testSuite.TestUser.Role, resp.Body["user_role"])
				keyInfo := resp.Body["key_info"].(map[string]interface{})
				assert.Contains(s.T(), keyInfo, "id")
				assert.Contains(s.T(), keyInfo, "name")
				assert.Contains(s.T(), keyInfo, "created_at")
				assert.Contains(s.T(), keyInfo, "last_used_at")
				assert.Contains(s.T(), keyInfo, "expires_at")
			},
		},
		{
			name:           "get token info with JWT",
			authHeader:     "Bearer " + jwtToken,
			expectedStatus: 200,
			checkResponse: func(resp *APIResponse) {
				assert.Equal(s.T(), true, resp.Body["valid"])
				assert.Equal(s.T(), "jwt", resp.Body["auth_type"])
				assert.Equal(s.T(), s.testSuite.TestUser.ID.String(), resp.Body["user_id"])
				assert.Equal(s.T(), s.testSuite.TestUser.Email, resp.Body["user_email"])
				assert.Equal(s.T(), s.testSuite.TestUser.Name, resp.Body["user_name"])
				assert.Equal(s.T(), s.testSuite.TestUser.Role, resp.Body["user_role"])
				assert.NotContains(s.T(), resp.Body, "key_info")
			},
		},
		{
			name:           "get token info without auth header",
			authHeader:     "",
			expectedStatus: 403,
			expectedError:  "No Auth Header Provided",
		},
		{
			name:           "get token info with invalid auth header",
			authHeader:     "InvalidHeader",
			expectedStatus: 401,
			expectedError:  "Invalid authorization header format",
		},
		{
			name:           "get token info with invalid token",
			authHeader:     "Bearer invalid-token",
			expectedStatus: 401,
			expectedError:  "Invalid or expired token",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			headers := make(map[string]string)
			if test.authHeader != "" {
				headers["Authorization"] = test.authHeader
			} else if test.name == "get token info with API key in X-API-KEY header" {
				headers["X-API-KEY"] = apiKeyValue
			}

			resp := s.testSuite.MakeRequest("GET", "/api/v1/auth/token/info", nil, headers)

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				if test.checkResponse != nil {
					test.checkResponse(resp)
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestHasPermission tests the hasPermission function through middleware
func (s *AuthTestSuite) TestHasPermission() {
	// Create auth middleware to test the function
	authMiddleware := middleware.NewAuthMiddleware(s.testSuite.JWTManager, s.testSuite.APIKeyManager)

	tests := []struct {
		name           string
		userRole       auth.UserRole
		requiredRole   auth.UserRole
		expectedResult bool
	}{
		{
			name:           "admin has permission for user role",
			userRole:       auth.RoleAdmin,
			requiredRole:   auth.RoleUser,
			expectedResult: true,
		},
		{
			name:           "admin has permission for moderator role",
			userRole:       auth.RoleAdmin,
			requiredRole:   auth.RoleModerator,
			expectedResult: true,
		},
		{
			name:           "admin has permission for admin role",
			userRole:       auth.RoleAdmin,
			requiredRole:   auth.RoleAdmin,
			expectedResult: true,
		},
		{
			name:           "moderator has permission for user role",
			userRole:       auth.RoleModerator,
			requiredRole:   auth.RoleUser,
			expectedResult: true,
		},
		{
			name:           "moderator has permission for moderator role",
			userRole:       auth.RoleModerator,
			requiredRole:   auth.RoleModerator,
			expectedResult: true,
		},
		{
			name:           "moderator does not have permission for admin role",
			userRole:       auth.RoleModerator,
			requiredRole:   auth.RoleAdmin,
			expectedResult: false,
		},
		{
			name:           "user has permission for user role",
			userRole:       auth.RoleUser,
			requiredRole:   auth.RoleUser,
			expectedResult: true,
		},
		{
			name:           "user does not have permission for moderator role",
			userRole:       auth.RoleUser,
			requiredRole:   auth.RoleModerator,
			expectedResult: false,
		},
		{
			name:           "user does not have permission for admin role",
			userRole:       auth.RoleUser,
			requiredRole:   auth.RoleAdmin,
			expectedResult: false,
		},
		{
			name:           "invalid user role",
			userRole:       "invalid_role",
			requiredRole:   auth.RoleUser,
			expectedResult: false,
		},
		{
			name:           "invalid required role",
			userRole:       auth.RoleUser,
			requiredRole:   "invalid_role",
			expectedResult: false,
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			// Test the hasPermission function directly by creating a mock context
			// and testing the middleware behavior
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Set("user_role", test.userRole)

			// Create the middleware with the required role
			middlewareFunc := authMiddleware.RequireRole(test.requiredRole)

			// Call the middleware
			middlewareFunc(c)

			// Check if the request was aborted (permission denied) or not
			if test.expectedResult {
				assert.False(s.T(), c.IsAborted(), "Request should not have been aborted for granted permission")
			} else {
				assert.True(s.T(), c.IsAborted(), "Request should have been aborted for denied permission")
			}
		})
	}
}

// TestGetCurrentUserRole tests the GetCurrentUserRole function
func (s *AuthTestSuite) TestGetCurrentUserRole() {
	// Create a mock gin context
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupContext   func(*gin.Context)
		expectedRole   auth.UserRole
		expectedExists bool
	}{
		{
			name: "get user role from context",
			setupContext: func(c *gin.Context) {
				c.Set("user_role", auth.RoleAdmin)
			},
			expectedRole:   auth.RoleAdmin,
			expectedExists: true,
		},
		{
			name: "get user role from context - user role",
			setupContext: func(c *gin.Context) {
				c.Set("user_role", auth.RoleUser)
			},
			expectedRole:   auth.RoleUser,
			expectedExists: true,
		},
		{
			name: "get user role from context - moderator role",
			setupContext: func(c *gin.Context) {
				c.Set("user_role", auth.RoleModerator)
			},
			expectedRole:   auth.RoleModerator,
			expectedExists: true,
		},
		{
			name: "role not in context",
			setupContext: func(_ *gin.Context) {
				// Don't set anything
			},
			expectedRole:   "",
			expectedExists: false,
		},
		{
			name: "invalid role type in context",
			setupContext: func(c *gin.Context) {
				c.Set("user_role", "invalid_role")
			},
			expectedRole:   "",
			expectedExists: false,
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			c, _ := gin.CreateTestContext(nil)
			test.setupContext(c)

			role, exists := middleware.GetCurrentUserRole(c)
			assert.Equal(s.T(), test.expectedRole, role)
			assert.Equal(s.T(), test.expectedExists, exists)
		})
	}
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
