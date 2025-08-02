package test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// JWTTestSuite tests JWT manager functions
type JWTTestSuite struct {
	suite.Suite
	testSuite *testSuite
}

func (s *JWTTestSuite) SetupTest() {
	s.testSuite = setupTestSuite(s.T())
}

func (s *JWTTestSuite) TearDownTest() {
	s.testSuite.TearDownTestSuite(s.T())
}

// TestRevokeAllUserTokens tests the RevokeAllUserTokens function
func (s *JWTTestSuite) TestRevokeAllUserTokens() {
	ctx := context.Background()
	
	// First, create some refresh tokens for the user by logging in
	loginResp := s.testSuite.MakeRequest("POST", "/api/v1/users/login", map[string]interface{}{
		"email":    s.testSuite.TestUser.Email,
		"password": s.testSuite.TestUser.Password,
	}, nil)
	assert.Equal(s.T(), 200, loginResp.StatusCode)
	
	// Test revoking all tokens for the user
	err := s.testSuite.JWTManager.RevokeAllUserTokens(ctx, s.testSuite.TestUser.ID)
	assert.NoError(s.T(), err, "Should be able to revoke all user tokens")
	
	// Verify that the user can no longer refresh tokens
	// Try to refresh with the old refresh token
	refreshResp := s.testSuite.MakeRequest("POST", "/api/v1/users/refresh", map[string]interface{}{
		"refresh_token": s.testSuite.TestUser.RefreshToken,
	}, nil)
	assert.Equal(s.T(), 401, refreshResp.StatusCode, "Refresh should fail after revoking all tokens")
}

// TestRevokeAllUserTokensWithInvalidUserID tests revoking tokens for non-existent user
func (s *JWTTestSuite) TestRevokeAllUserTokensWithInvalidUserID() {
	ctx := context.Background()
	
	// Test with a non-existent user ID
	invalidUserID := "00000000-0000-0000-0000-000000000000"
	userID, err := uuid.Parse(invalidUserID)
	assert.NoError(s.T(), err, "Should be able to parse UUID")
	
	err = s.testSuite.JWTManager.RevokeAllUserTokens(ctx, userID)
	// This should not error even for non-existent users, as it just tries to revoke tokens
	assert.NoError(s.T(), err, "Should not error when revoking tokens for non-existent user")
}

// TestRevokeAllUserTokensWithEmptyUserID tests revoking tokens with empty user ID
func (s *JWTTestSuite) TestRevokeAllUserTokensWithEmptyUserID() {
	ctx := context.Background()
	
	// Test with empty user ID
	emptyUserID := uuid.Nil
	
	err := s.testSuite.JWTManager.RevokeAllUserTokens(ctx, emptyUserID)
	// This should not error even for empty user ID
	assert.NoError(s.T(), err, "Should not error when revoking tokens for empty user ID")
}

func TestJWTTestSuite(t *testing.T) {
	suite.Run(t, new(JWTTestSuite))
} 