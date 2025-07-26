package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// UsersTestSuite tests user management endpoints
type UsersTestSuite struct {
	suite.Suite
	*TestSuite
}

func (s *UsersTestSuite) SetupTest() {
	s.TestSuite = SetupTestSuite(s.T())
}

func (s *UsersTestSuite) TearDownTest() {
	s.TestSuite.TearDownTestSuite(s.T())
}

// TestGetProfile tests getting user profile
func (s *UsersTestSuite) TestGetProfile() {
	tests := []struct {
		name           string
		user           *TestUser
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get user profile with JWT",
			user:           s.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get profile without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("GET", "/api/v1/users/profile", nil, test.user)
			} else {
				resp = s.MakeRequest("GET", "/api/v1/users/profile", nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				user := resp.Body["user"].(map[string]interface{})
				assert.Equal(s.T(), test.user.Email, user["email"])
				assert.Equal(s.T(), test.user.Name, user["name"])
				assert.Equal(s.T(), test.user.Role, user["role"])
				assert.Contains(s.T(), resp.Body, "api_keys")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestUpdateProfile tests updating user profile
func (s *UsersTestSuite) TestUpdateProfile() {
	tests := []struct {
		name           string
		user           *TestUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "update name only",
			user: s.TestUser,
			payload: map[string]interface{}{
				"name": "Updated Name",
			},
			expectedStatus: 200,
		},
		{
			name: "update email only",
			user: s.TestUser,
			payload: map[string]interface{}{
				"email": "updated@example.com",
			},
			expectedStatus: 200,
		},
		{
			name: "update both name and email",
			user: s.TestUser2,
			payload: map[string]interface{}{
				"name":  "New Name",
				"email": "new.email@example.com",
			},
			expectedStatus: 200,
		},
		{
			name: "update with invalid email",
			user: s.TestUser,
			payload: map[string]interface{}{
				"email": "invalid-email",
			},
			expectedStatus: 400,
			expectedError: "Invalid email",
		},
		{
			name: "update with duplicate email",
			user: s.TestUser,
			payload: map[string]interface{}{
				"email": s.TestUser2.Email,
			},
			expectedStatus: 409,
			expectedError: "Email already exists",
		},
		{
			name:           "update without authentication",
			user:           nil,
			payload:        map[string]interface{}{"name": "Hacker"},
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("PUT", "/api/v1/users/profile", test.payload, test.user)
			} else {
				resp = s.MakeRequest("PUT", "/api/v1/users/profile", test.payload, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				user := resp.Body["user"].(map[string]interface{})
				
				if name, ok := test.payload["name"]; ok {
					assert.Equal(s.T(), name, user["name"])
				}
				if email, ok := test.payload["email"]; ok {
					assert.Equal(s.T(), email, user["email"])
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestCreateAPIKey tests creating API keys
func (s *UsersTestSuite) TestCreateAPIKey() {
	tests := []struct {
		name           string
		user           *TestUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "create API key with name only",
			user: s.TestUser,
			payload: map[string]interface{}{
				"name": "Test API Key",
			},
			expectedStatus: 201,
		},
		{
			name: "create API key with expiration",
			user: s.TestUser,
			payload: map[string]interface{}{
				"name":       "Expiring Key",
				"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			},
			expectedStatus: 201,
		},
		{
			name: "create API key without name",
			user: s.TestUser,
			payload: map[string]interface{}{
				"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name:           "create API key without authentication",
			user:           nil,
			payload:        map[string]interface{}{"name": "Unauthorized Key"},
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("POST", "/api/v1/users/api-keys", test.payload, test.user)
			} else {
				resp = s.MakeRequest("POST", "/api/v1/users/api-keys", test.payload, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "api_key")
				assert.Contains(s.T(), resp.Body, "key_id")
				assert.Contains(s.T(), resp.Body, "name")
				assert.Contains(s.T(), resp.Body, "created_at")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestListAPIKeys tests listing API keys
func (s *UsersTestSuite) TestListAPIKeys() {
	tests := []struct {
		name           string
		user           *TestUser
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "list API keys",
			user:           s.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "list API keys without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("GET", "/api/v1/users/api-keys", nil, test.user)
			} else {
				resp = s.MakeRequest("GET", "/api/v1/users/api-keys", nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "api_keys")
				apiKeys := resp.Body["api_keys"].([]interface{})
				assert.GreaterOrEqual(s.T(), len(apiKeys), 1, "Should have at least one API key from test setup")
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestRevokeAPIKey tests revoking API keys
func (s *UsersTestSuite) TestRevokeAPIKey() {
	// First, create an API key to revoke
	createResp := s.MakeAuthenticatedRequest("POST", "/api/v1/users/api-keys", map[string]interface{}{
		"name": "Key To Revoke",
	}, s.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	keyID := createResp.Body["key_id"].(string)

	tests := []struct {
		name           string
		user           *TestUser
		keyID          string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "revoke own API key",
			user:           s.TestUser,
			keyID:          keyID,
			expectedStatus: 200,
		},
		{
			name:           "revoke non-existent key",
			user:           s.TestUser,
			keyID:          "non-existent-key-id",
			expectedStatus: 404,
			expectedError:  "API key not found",
		},
		{
			name:           "revoke key without authentication",
			user:           nil,
			keyID:          keyID,
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/users/api-keys/" + test.keyID
			if test.user != nil {
				resp = s.MakeAuthenticatedRequest("DELETE", path, nil, test.user)
			} else {
				resp = s.MakeRequest("DELETE", path, nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

func TestUsersTestSuite(t *testing.T) {
	suite.Run(t, new(UsersTestSuite))
} 