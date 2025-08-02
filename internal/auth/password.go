package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordManager handles password hashing and validation
type PasswordManager struct {
	cost int
}

// NewPasswordManager creates a new password manager with the specified bcrypt cost
func NewPasswordManager(cost int) *PasswordManager {
	return &PasswordManager{
		cost: cost,
	}
}

// HashPassword hashes a password using bcrypt
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), pm.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash
func (pm *PasswordManager) VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// IsPasswordValid checks if a password meets minimum requirements
func (pm *PasswordManager) IsPasswordValid(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must be no longer than 128 characters")
	}

	// Check for at least one letter and one number
	hasLetter := false
	hasNumber := false

	for _, char := range password {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			hasLetter = true
		}
		if char >= '0' && char <= '9' {
			hasNumber = true
		}
	}

	if !hasLetter {
		return fmt.Errorf("password must contain at least one letter")
	}

	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}

	return nil
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
