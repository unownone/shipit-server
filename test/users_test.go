package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// UsersTestSuite tests user management endpoints
type UsersTestSuite struct {
	suite.Suite
	testSuite *testSuite
}

func (s *UsersTestSuite) SetupTest() {
	s.testSuite = setupTestSuite(s.T())
}

func (s *UsersTestSuite) TearDownTest() {
	s.testSuite.TearDownTestSuite(s.T())
}

// TestGetProfile tests getting user profile
func (s *UsersTestSuite) TestGetProfile() {
	tests := []struct {
		name           string
		user           *testUser
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get user profile with JWT",
			user:           s.testSuite.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "get profile without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("GET", "/api/v1/users/profile", nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", "/api/v1/users/profile", nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				user := resp.Body["user"].(map[string]interface{})
				assert.Equal(s.T(), test.user.Email, user["email"])
				assert.Equal(s.T(), test.user.Name, user["name"])
				assert.Equal(s.T(), test.user.Role, user["role"])
				// Note: API doesn't include api_keys in profile response
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
		user           *testUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "update name only",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"name": "Updated Name",
			},
			expectedStatus: 200,
		},
		{
			name: "update email only",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"email": "updated@example.com",
			},
			expectedStatus: 200,
		},
		{
			name: "update both name and email",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"name":  "Updated Name 2",
				"email": "updated2@example.com",
			},
			expectedStatus: 200,
		},
		{
			name: "update with invalid email",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"email": "invalid-email",
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name: "update profile without authentication",
			user: nil,
			payload: map[string]interface{}{
				"name": "Updated Name",
			},
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("PUT", "/api/v1/users/profile", test.payload, test.user)
			} else {
				resp = s.testSuite.MakeRequest("PUT", "/api/v1/users/profile", test.payload, nil)
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

// TestChangePassword tests password change endpoint
func (s *UsersTestSuite) TestChangePassword() {
	tests := []struct {
		name           string
		user           *testUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "change password successfully",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"current_password": s.testSuite.TestUser.Password,
				"new_password":     "newpassword123",
			},
			expectedStatus: 200,
		},
		{
			name: "change password with wrong current password",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"current_password": "wrongpassword",
				"new_password":     "newpassword123",
			},
			expectedStatus: 401,
			expectedError:  "Current password is incorrect",
		},
		{
			name: "change password with weak new password",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"current_password": s.testSuite.TestUser.Password,
				"new_password":     "123",
			},
			expectedStatus: 400,
			expectedError:  "Password is too weak",
		},
		{
			name: "change password without authentication",
			user: nil,
			payload: map[string]interface{}{
				"current_password": "oldpassword",
				"new_password":     "newpassword123",
			},
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("PUT", "/api/v1/users/password", test.payload, test.user)
			} else {
				resp = s.testSuite.MakeRequest("PUT", "/api/v1/users/password", test.payload, nil)
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

// TestCreateAPIKey tests API key creation endpoint
func (s *UsersTestSuite) TestCreateAPIKey() {
	tests := []struct {
		name           string
		user           *testUser
		payload        map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "create API key successfully",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"name":        "Test API Key",
				"description": "API key for testing",
			},
			expectedStatus: 201,
		},
		{
			name: "create API key without description",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"name": "Test API Key 2",
			},
			expectedStatus: 201,
		},
		{
			name: "create API key without name",
			user: s.testSuite.TestUser,
			payload: map[string]interface{}{
				"description": "API key without name",
			},
			expectedStatus: 400,
			expectedError:  "Invalid request data",
		},
		{
			name: "create API key without authentication",
			user: nil,
			payload: map[string]interface{}{
				"name":        "Test API Key",
				"description": "API key for testing",
			},
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("POST", "/api/v1/users/api-keys", test.payload, test.user)
			} else {
				resp = s.testSuite.MakeRequest("POST", "/api/v1/users/api-keys", test.payload, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "api_key_id")
				assert.Contains(s.T(), resp.Body, "api_key")
				assert.Contains(s.T(), resp.Body, "name")
				if description, ok := test.payload["description"]; ok {
					assert.Equal(s.T(), description, resp.Body["description"])
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestListAPIKeys tests API key listing endpoint
func (s *UsersTestSuite) TestListAPIKeys() {
	// Create an API key first for testing
	createResp := s.testSuite.MakeAuthenticatedRequest("POST", "/api/v1/users/api-keys", map[string]interface{}{
		"name":        "Test API Key for List",
		"description": "API key for listing test",
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)

	tests := []struct {
		name           string
		user           *testUser
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "list API keys with JWT",
			user:           s.testSuite.TestUser,
			expectedStatus: 200,
		},
		{
			name:           "list API keys without authentication",
			user:           nil,
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("GET", "/api/v1/users/api-keys", nil, test.user)
			} else {
				resp = s.testSuite.MakeRequest("GET", "/api/v1/users/api-keys", nil, nil)
			}

			if test.expectedStatus < 400 {
				AssertSuccessResponse(s.T(), resp, test.expectedStatus)
				assert.Contains(s.T(), resp.Body, "api_keys")
				apiKeys := resp.Body["api_keys"].([]interface{})
				assert.GreaterOrEqual(s.T(), len(apiKeys), 1)

				if len(apiKeys) > 0 {
					apiKey := apiKeys[0].(map[string]interface{})
					assert.Contains(s.T(), apiKey, "api_key_id")
					assert.Contains(s.T(), apiKey, "name")
					assert.Contains(s.T(), apiKey, "created_at")
					// Note: API key value is not returned in list
					assert.NotContains(s.T(), apiKey, "api_key")
				}
			} else {
				AssertErrorResponse(s.T(), resp, test.expectedStatus, test.expectedError)
			}
		})
	}
}

// TestRevokeAPIKey tests API key revocation endpoint
func (s *UsersTestSuite) TestRevokeAPIKey() {
	// Create an API key first for testing
	createResp := s.testSuite.MakeAuthenticatedRequest("POST", "/api/v1/users/api-keys", map[string]interface{}{
		"name":        "Test API Key for Revoke",
		"description": "API key for revocation test",
	}, s.testSuite.TestUser)
	assert.Equal(s.T(), 201, createResp.StatusCode)
	apiKeyID := createResp.Body["api_key_id"].(string)

	tests := []struct {
		name           string
		user           *testUser
		apiKeyID       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "revoke API key successfully",
			user:           s.testSuite.TestUser,
			apiKeyID:       apiKeyID,
			expectedStatus: 200,
		},
		{
			name:           "revoke non-existent API key",
			user:           s.testSuite.TestUser,
			apiKeyID:       "non-existent-api-key-id",
			expectedStatus: 404,
			expectedError:  "API key not found",
		},
		{
			name:           "revoke API key without authentication",
			user:           nil,
			apiKeyID:       apiKeyID,
			expectedStatus: 401,
			expectedError:  "Authorization header is required",
		},
	}

	for _, test := range tests {
		s.Run(test.name, func() {
			var resp *APIResponse
			path := "/api/v1/users/api-keys/" + test.apiKeyID
			if test.user != nil {
				resp = s.testSuite.MakeAuthenticatedRequest("DELETE", path, nil, test.user)
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

func TestUsersTestSuite(t *testing.T) {
	suite.Run(t, new(UsersTestSuite))
}
