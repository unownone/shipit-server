package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// AuthTestSuite tests authentication endpoints
type AuthTestSuite struct {
	suite.Suite
	*TestSuite
}

func (s *AuthTestSuite) SetupTest() {
	s.TestSuite = SetupTestSuite(s.T())
}

func (s *AuthTestSuite) TearDownTest() {
	s.TestSuite.TearDownTestSuite(s.T())
}

// TestUserRegistration tests user registration endpoint
func (s *AuthTestSuite) TestUserRegistration() {
	tests := []struct {
		name           string
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful registration",
			payload: map[string]interface{}{
				"email":    "newuser@example.com",
				"password": "newpassword123",
				"name":     "New User",
			},
			expectedStatus: 201,
		},
		{
			name: "duplicate email",
			payload: map[string]interface{}{
				"email":    s.TestUser.Email,
				"password": "password123",
				"name":     "Duplicate User",
			},
			expectedStatus: 409,
			expectedError:  "already exists",
		},
		{
			name: "invalid email",
			payload: map[string]interface{}{
				"email":    "invalid-email",
				"password": "password123",
				"name":     "Test User",
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name: "weak password",
			payload: map[string]interface{}{
				"email":    "weak@example.com",
				"password": "123",
				"name":     "Test User",
			},
			expectedStatus: 400,
		},
		{
			name: "missing fields",
			payload: map[string]interface{}{
				"email": "incomplete@example.com",
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			resp := s.MakeRequest("POST", "/api/v1/users/register", test.payload, nil)
			
			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "user_id")
				assert.Contains(s.T(), resp.Body, "access_token")
				assert.Contains(s.T(), resp.Body, "refresh_token")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestUserLogin tests user login endpoint
func (s *AuthTestSuite) TestUserLogin() {
	tests := []struct {
		name           string
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful login",
			payload: map[string]interface{}{
				"email":    s.TestUser.Email,
				"password": s.TestUser.Password,
			},
			expectedStatus: 200,
		},
		{
			name: "wrong password",
			payload: map[string]interface{}{
				"email":    s.TestUser.Email,
				"password": "wrongpassword",
			},
			expectedStatus: 401,
			expectedError:  "Invalid credentials",
		},
		{
			name: "non-existent user",
			payload: map[string]interface{}{
				"email":    "nonexistent@example.com",
				"password": "password123",
			},
			expectedStatus: 401,
			expectedError:  "Invalid credentials",
		},
		{
			name: "invalid email format",
			payload: map[string]interface{}{
				"email":    "invalid-email",
				"password": "password123",
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name: "missing password",
			payload: map[string]interface{}{
				"email": s.TestUser.Email,
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			resp := s.MakeRequest("POST", "/api/v1/users/login", test.payload, nil)
			
			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "access_token")
				assert.Contains(s.T(), resp.Body, "refresh_token")
				assert.Contains(s.T(), resp.Body, "user")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestRefreshToken tests token refresh endpoint
func (s *AuthTestSuite) TestRefreshToken() {
	tests := []struct {
		name           string
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful token refresh",
			payload: map[string]interface{}{
				"refresh_token": s.TestUser.RefreshToken,
			},
			expectedStatus: 200,
		},
		{
			name: "invalid refresh token",
			payload: map[string]interface{}{
				"refresh_token": "invalid-token",
			},
			expectedStatus: 401,
			expectedError:  "Invalid refresh token",
		},
		{
			name: "missing refresh token",
			payload: map[string]interface{}{},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			resp := s.MakeRequest("POST", "/api/v1/users/refresh", test.payload, nil)
			
			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "access_token")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestLogout tests user logout endpoint
func (s *AuthTestSuite) TestLogout() {
	tests := []struct {
		name           string
		user           *TestUser
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "successful logout",
			user:           s.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "logout without token",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("POST", "/api/v1/users/logout", nil, test.user)
			} else {
				resp = s.MakeRequest("POST", "/api/v1/users/logout", nil, nil)
			}
			
			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestValidateToken tests token validation endpoint
func (s *AuthTestSuite) TestValidateToken() {
	tests := []struct {
		name           string
		payload        map[string]interface{}
		expectedStatus int
		expectedValid  bool
	}{
		{
			name: "valid JWT token",
			payload: map[string]interface{}{
				"token": s.TestUser.AccessToken,
			},
			expectedStatus: 200,
			expectedValid:  true,
		},
		{
			name: "valid API key",
			payload: map[string]interface{}{
				"token": s.TestUser.APIKey,
			},
			expectedStatus: 200,
			expectedValid:  true,
		},
		{
			name: "invalid token",
			payload: map[string]interface{}{
				"token": "invalid-token",
			},
			expectedStatus: 200,
			expectedValid:  false,
		},
		{
			name: "missing token",
			payload: map[string]interface{}{},
			expectedStatus: 400,
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			resp := s.MakeRequest("POST", "/api/v1/auth/validate", test.payload, nil)
			
			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Equal(s.T(), test.expectedValid, resp.Body["valid"])
				if test.expectedValid {
					assert.Contains(s.T(), resp.Body, "user_id")
					assert.Contains(s.T(), resp.Body, "auth_type")
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, "")
			}
		})
	}
}

// TestGetTokenInfo tests token info endpoint
func (s *AuthTestSuite) TestGetTokenInfo() {
	tests := []struct {
		name           string
		user           *TestUser
		useAPIKey      bool
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get JWT token info",
			user:           s.TestUser,
			useAPIKey:      false,
			expectedStatus: 200,
		},
		{
			name:           "get API key info",
			user:           s.TestUser,
			useAPIKey:      true,
			expectedStatus: 200,
		},
		{
			name:           "no authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				if test.useAPIKey {
					resp = s.MakeAPIKeyRequest("GET", "/api/v1/auth/info", nil, test.user)
				} else {
					resp = s.MakeAuthenticatedRequest("GET", "/api/v1/auth/info", nil, test.user)
				}
			} else {
				resp = s.MakeRequest("GET", "/api/v1/auth/info", nil, nil)
			}
			
			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "user_id")
				assert.Contains(s.T(), resp.Body, "auth_type")
				assert.Contains(s.T(), resp.Body, "valid")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
} 