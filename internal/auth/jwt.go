package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
)

// UserRole represents user roles
type UserRole string

const (
	RoleUser      UserRole = "user"
	RoleAdmin     UserRole = "admin"
	RoleModerator UserRole = "moderator"
)

// JWTClaims represents the claims stored in a JWT token
// NOTE: JWT tokens are STATELESS and NOT stored in the database
type JWTClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
	Role   UserRole  `json:"role"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token creation and validation
// JWT access tokens are stateless and never stored in database
// Only refresh tokens are stored for secure token refresh
type JWTManager struct {
	config *config.JWTConfig
	db     *database.Database
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(cfg *config.JWTConfig, db *database.Database) *JWTManager {
	return &JWTManager{
		config: cfg,
		db:     db,
	}
}

// GenerateTokenPair generates access and refresh tokens for a user
// Access token: STATELESS JWT (not stored in DB)
// Refresh token: Stored in DB for revocation and security
func (jm *JWTManager) GenerateTokenPair(ctx context.Context, user *sqlc.Users) (accessToken, refreshToken string, err error) {
	// Generate stateless JWT access token (NOT stored in database)
	accessToken, err = jm.generateAccessToken(user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token (stored in database for revocation)
	refreshToken, err = jm.generateRefreshToken(ctx, user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// generateAccessToken creates a stateless JWT access token
// This token is NEVER stored in the database - it's completely stateless
func (jm *JWTManager) generateAccessToken(user *sqlc.Users) (string, error) {
	now := time.Now()

	userID, err := uuid.FromBytes(user.ID.Bytes[:])
	if err != nil {
		return "", fmt.Errorf("failed to convert user ID to UUID: %w", err)
	}

	claims := JWTClaims{
		UserID: userID,
		Email:  user.Email,
		Role:   UserRole(user.Role),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userID.String(),
			Audience:  []string{jm.config.Audience},
			Issuer:    jm.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(jm.config.AccessTokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jm.config.SecretKey))
}

// generateRefreshToken creates a refresh token and stores it in the database
// Unlike JWT access tokens, refresh tokens MUST be stored for revocation
func (jm *JWTManager) generateRefreshToken(ctx context.Context, user *sqlc.Users) (string, error) {
	// Generate a secure random token
	tokenString, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate token string: %w", err)
	}

	// Hash the token before storing (never store plaintext tokens)
	tokenHash := sha256.Sum256([]byte(tokenString))
	tokenHashString := base64.URLEncoding.EncodeToString(tokenHash[:])

	// Convert expiry time to pgtype.Timestamptz
	var pgExpiresAt pgtype.Timestamptz
	expiresAt := time.Now().Add(jm.config.RefreshTokenExpiry)
	pgExpiresAt.Scan(expiresAt)

	// Create refresh token record in database
	_, err = jm.db.Queries.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHashString,
		ExpiresAt: pgExpiresAt,
	})
	if err != nil {
		return "", fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Return the plaintext token (not the hash)
	return tokenString, nil
}

// ValidateAccessToken validates a stateless JWT access token
// This does NOT check the database - JWT tokens are stateless
func (jm *JWTManager) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jm.config.SecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Additional validation
	if claims.Issuer != jm.config.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	if len(claims.Audience) == 0 || claims.Audience[0] != jm.config.Audience {
		return nil, fmt.Errorf("invalid audience")
	}

	return claims, nil
}

// RefreshAccessToken uses a refresh token to generate a new stateless access token
func (jm *JWTManager) RefreshAccessToken(ctx context.Context, refreshTokenString string) (string, error) {
	// Hash the provided refresh token
	tokenHash := sha256.Sum256([]byte(refreshTokenString))
	tokenHashString := base64.URLEncoding.EncodeToString(tokenHash[:])

	// Find the refresh token in the database
	refreshTokenRow, err := jm.db.Queries.GetRefreshToken(ctx, tokenHashString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token")
	}

	// Get the user information
	var userID uuid.UUID
	err = userID.Scan(refreshTokenRow.UserID.Bytes)
	if err != nil {
		return "", fmt.Errorf("invalid user ID")
	}

	user, err := jm.db.Queries.GetUserByID(ctx, refreshTokenRow.UserID)
	if err != nil {
		return "", fmt.Errorf("user not found")
	}

	// Generate new stateless access token
	accessToken, err := jm.generateAccessToken(&user)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return accessToken, nil
}

// RevokeRefreshToken revokes a refresh token
func (jm *JWTManager) RevokeRefreshToken(ctx context.Context, refreshTokenString string) error {
	// Hash the token to find it in the database
	tokenHash := sha256.Sum256([]byte(refreshTokenString))
	tokenHashString := base64.URLEncoding.EncodeToString(tokenHash[:])

	err := jm.db.Queries.RevokeRefreshToken(ctx, tokenHashString)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (jm *JWTManager) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	// Convert UUID to pgtype.UUID
	var pgUserID pgtype.UUID
	pgUserID.Scan(userID.String())

	err := jm.db.Queries.RevokeAllUserRefreshTokens(ctx, pgUserID)
	if err != nil {
		return fmt.Errorf("failed to revoke user tokens: %w", err)
	}

	return nil
}

// CleanupExpiredTokens removes expired refresh tokens
func (jm *JWTManager) CleanupExpiredTokens(ctx context.Context) error {
	err := jm.db.Queries.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return nil
}

// GetUserFromToken extracts user information from a stateless JWT token
// This validates the JWT but does NOT check the database for the token
// It DOES check the database to ensure the user is still active
func (jm *JWTManager) GetUserFromToken(ctx context.Context, tokenString string) (*sqlc.Users, error) {
	claims, err := jm.ValidateAccessToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Convert UUID to pgtype.UUID for database query
	var pgUserID pgtype.UUID
	pgUserID.Scan(claims.UserID.String())

	// Fetch the user from the database to get the latest information
	// and ensure the user is still active
	user, err := jm.db.Queries.GetUserByID(ctx, pgUserID)
	if err != nil {
		return nil, fmt.Errorf("user not found or inactive")
	}

	if !user.IsActive {
		return nil, fmt.Errorf("user account is inactive")
	}

	return &user, nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
