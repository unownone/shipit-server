package test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// APIKeysTestSuite tests API key manager functions
type APIKeysTestSuite struct {
	suite.Suite
	testSuite *testSuite
}

func (s *APIKeysTestSuite) SetupTest() {
	s.testSuite = setupTestSuite(s.T())
}

func (s *APIKeysTestSuite) TearDownTest() {
	s.testSuite.TearDownTestSuite(s.T())
}

// TestCleanupExpiredKeys tests the CleanupExpiredKeys function
func (s *APIKeysTestSuite) TestCleanupExpiredKeys() {
	ctx := context.Background()
	// Test cleanup with no expired keys
	err := s.testSuite.APIKeyManager.CleanupExpiredKeys(ctx)
	assert.NoError(s.T(), err, "Cleanup should succeed even with no expired keys")

	// Create an API key with expiration in the past
	expiredTime := time.Now().Add(-1 * time.Hour) // 1 hour ago
	_, _, err = s.testSuite.APIKeyManager.GenerateAPIKey(ctx, s.testSuite.TestUser.ID, "Expired Key", &expiredTime)
	assert.NoError(s.T(), err, "Should be able to create expired API key")

	// Test cleanup with expired keys
	err = s.testSuite.APIKeyManager.CleanupExpiredKeys(ctx)
	assert.NoError(s.T(), err, "Cleanup should succeed with expired keys")

	// Verify expired key was cleaned up by listing keys
	keys, err := s.testSuite.APIKeyManager.ListAPIKeys(ctx, s.testSuite.TestUser.ID)
	assert.NoError(s.T(), err, "Should be able to list API keys")

	// Check that the expired key is not in the list
	for _, key := range keys {
		assert.NotEqual(s.T(), "Expired Key", key.Name, "Expired key should have been cleaned up")
	}
}

// TestUpdateAPIKeyName tests the UpdateAPIKeyName function
func (s *APIKeysTestSuite) TestUpdateAPIKeyName() {
	ctx := context.Background()

	// Create an API key first
	apiKey, _, err := s.testSuite.APIKeyManager.GenerateAPIKey(ctx, s.testSuite.TestUser.ID, "Original Name", nil)
	assert.NoError(s.T(), err, "Should be able to create API key")

	// Test updating the API key name
	newName := "Updated Name"
	err = s.testSuite.APIKeyManager.UpdateAPIKeyName(ctx, apiKey.ID, s.testSuite.TestUser.ID, newName)

	// This function is not implemented, so it should return an error
	assert.Error(s.T(), err, "UpdateAPIKeyName should return error as it's not implemented")
	assert.Contains(s.T(), err.Error(), "not implemented", "Error should indicate function is not implemented")

	// Verify the key still exists with original name
	keys, err := s.testSuite.APIKeyManager.ListAPIKeys(ctx, s.testSuite.TestUser.ID)
	assert.NoError(s.T(), err, "Should be able to list API keys")

	found := false
	for _, key := range keys {
		if key.ID == apiKey.ID {
			found = true
			// Name should still be original since update failed
			assert.Equal(s.T(), "Original Name", key.Name, "Name should not have changed")
			break
		}
	}
	assert.True(s.T(), found, "API key should still exist")
}

// TestUpdateAPIKeyNameWithInvalidID tests updating API key name with invalid ID
func (s *APIKeysTestSuite) TestUpdateAPIKeyNameWithInvalidID() {
	ctx := context.Background()

	// Test with non-existent key ID
	invalidID := uuid.New()
	err := s.testSuite.APIKeyManager.UpdateAPIKeyName(ctx, invalidID, s.testSuite.TestUser.ID, "New Name")

	// Should return error as function is not implemented
	assert.Error(s.T(), err, "UpdateAPIKeyName should return error as it's not implemented")
	assert.Contains(s.T(), err.Error(), "not implemented", "Error should indicate function is not implemented")
}

// TestUpdateAPIKeyNameWithInvalidUserID tests updating API key name with invalid user ID
func (s *APIKeysTestSuite) TestUpdateAPIKeyNameWithInvalidUserID() {
	ctx := context.Background()

	// Create an API key first
	apiKey, _, err := s.testSuite.APIKeyManager.GenerateAPIKey(ctx, s.testSuite.TestUser.ID, "Test Key", nil)
	assert.NoError(s.T(), err, "Should be able to create API key")

	// Test with invalid user ID
	invalidUserID := uuid.New()
	err = s.testSuite.APIKeyManager.UpdateAPIKeyName(ctx, apiKey.ID, invalidUserID, "New Name")

	// Should return error as function is not implemented
	assert.Error(s.T(), err, "UpdateAPIKeyName should return error as it's not implemented")
	assert.Contains(s.T(), err.Error(), "not implemented", "Error should indicate function is not implemented")
}

func TestAPIKeysTestSuite(t *testing.T) {
	suite.Run(t, new(APIKeysTestSuite))
}
