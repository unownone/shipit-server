package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
	"github.com/unwonone/shipit-server/internal/logger"
)

const (
	APIKeyAuthorizationHeader string = "X-API-KEY" // API KEY HEADER
	APIKeyPrefix                     = "shipit_"   // 7 bytes
	APIKeyLength                     = 32          // Length of the random part
)

// APIKeyManager handles API key generation, validation, and management
type APIKeyManager struct {
	db         *database.Database
	AuthHeader string
}

// NewAPIKeyManager creates a new API key manager
func NewAPIKeyManager(db *database.Database) *APIKeyManager {
	return &APIKeyManager{
		db:         db,
		AuthHeader: APIKeyAuthorizationHeader,
	}
}

// GenerateAPIKey generates a new API key for a user
func (akm *APIKeyManager) GenerateAPIKey(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time) (*sqlc.ApiKeys, string, error) {
	// Generate random bytes
	randomBytes := make([]byte, APIKeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create the full API key
	randomPart := base64.URLEncoding.EncodeToString(randomBytes)
	fullKey := APIKeyPrefix + randomPart

	// Hash the key for storage (never store the actual key)
	keyHash := sha256.Sum256([]byte(fullKey))
	keyHashString := base64.URLEncoding.EncodeToString(keyHash[:])

	// Convert UUID to uuid.UUID
	var pgUserID uuid.UUID
	pgUserID.Scan(userID.String())

	// Convert time to pgtype.Timestamptz
	var pgExpiresAt pgtype.Timestamptz
	if expiresAt != nil {
		pgExpiresAt.Scan(*expiresAt)
	}

	// Create the API key record using SQLC
	params := sqlc.CreateAPIKeyParams{
		UserID:    pgUserID,
		Name:      name,
		Prefix:    APIKeyPrefix + randomPart[:8] + ".", // Store a prefix for identification -> 16 bytes
		Hash:      keyHashString,
		ExpiresAt: pgExpiresAt,
		Scopes:    []string{}, // Default empty scopes
	}

	// Save to database
	apiKey, err := akm.db.Queries.CreateAPIKey(ctx, params)
	if err != nil {
		return nil, "", fmt.Errorf("failed to save API key: %w", err)
	}

	return &apiKey, fullKey, nil
}

// ValidateAPIKey validates an API key and returns the associated user
func (akm *APIKeyManager) ValidateAPIKey(ctx context.Context, key string) (*sqlc.Users, *sqlc.GetAPIKeyByHashRow, error) {
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return nil, nil, fmt.Errorf("invalid API key format")
	}

	// Hash the provided key
	keyHash := sha256.Sum256([]byte(key))
	keyHashString := base64.URLEncoding.EncodeToString(keyHash[:])

	// Find the API key in the database using the hash
	apiKeyRow, err := akm.db.Queries.GetAPIKeyByHash(ctx, keyHashString)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid API key")
	}

	// Get the associated user (the GetAPIKeyByHash already includes user info)
	user, err := akm.db.Queries.GetUserByID(ctx, apiKeyRow.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}

	// Check if the API key has expired
	if apiKeyRow.ExpiresAt.Valid && time.Now().After(apiKeyRow.ExpiresAt.Time) {
		return nil, nil, fmt.Errorf("API key has expired")
	}

	// Check if the user is active
	if !user.IsActive {
		return nil, nil, fmt.Errorf("user account is inactive")
	}

	// Update last used timestamp
	err = akm.db.Queries.UpdateAPIKeyLastUsed(ctx, apiKeyRow.ID)
	if err != nil {
		// Log error but don't fail the validation
		logger.WithError(err).WithField("api_key_id", apiKeyRow.ID.String()).Warn("Failed to update API key last used timestamp")
	}

	return &user, &apiKeyRow, nil
}

// ListAPIKeys returns all API keys for a user
func (akm *APIKeyManager) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]sqlc.ListAPIKeysByUserRow, error) {
	// Convert UUID to uuid.UUID
	var pgUserID uuid.UUID
	pgUserID.Scan(userID.String())

	apiKeys, err := akm.db.Queries.ListAPIKeysByUser(ctx, pgUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}

	return apiKeys, nil
}

// RevokeAPIKey revokes an API key
func (akm *APIKeyManager) RevokeAPIKey(ctx context.Context, keyID, userID uuid.UUID) error {
	// Convert UUIDs to uuid.UUID
	var pgKeyID, pgUserID uuid.UUID
	pgKeyID.Scan(keyID.String())
	pgUserID.Scan(userID.String())

	err := akm.db.Queries.RevokeAPIKey(ctx, sqlc.RevokeAPIKeyParams{
		ID:     pgKeyID,
		UserID: pgUserID,
	})
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	return nil
}

// GetAPIKey returns a specific API key for a user
func (akm *APIKeyManager) GetAPIKey(ctx context.Context, keyID, userID uuid.UUID) (*sqlc.ListAPIKeysByUserRow, error) {
	// Convert UUID to uuid.UUID
	var pgUserID uuid.UUID
	pgUserID.Scan(userID.String())

	// List all user keys and filter for the specific one
	apiKeys, err := akm.db.Queries.ListAPIKeysByUser(ctx, pgUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get API keys: %w", err)
	}

	for _, key := range apiKeys {
		if key.ID == keyID {
			return &key, nil
		}
	}

	return nil, fmt.Errorf("API key not found")
}

// CleanupExpiredKeys removes expired API keys
func (akm *APIKeyManager) CleanupExpiredKeys(ctx context.Context) error {
	err := akm.db.Queries.DeleteExpiredAPIKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired API keys: %w", err)
	}

	return nil
}

// UpdateAPIKeyName updates the name of an API key (not implemented in SQLC queries)
func (akm *APIKeyManager) UpdateAPIKeyName(ctx context.Context, keyID, userID uuid.UUID, newName string) error {
	// This would need a custom SQL query to be added to the queries
	return fmt.Errorf("update API key name not implemented - needs custom SQL query")
}
