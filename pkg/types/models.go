package types

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID                     uuid.UUID  `json:"id" db:"id"`
	Email                  string     `json:"email" db:"email"`
	PasswordHash           string     `json:"-" db:"password_hash"`
	Name                   string     `json:"name" db:"name"`
	Role                   string     `json:"role" db:"role"`
	IsActive               bool       `json:"is_active" db:"is_active"`
	EmailVerified          bool       `json:"email_verified" db:"email_verified"`
	EmailVerificationToken *string    `json:"-" db:"email_verification_token"`
	PasswordResetToken     *string    `json:"-" db:"password_reset_token"`
	PasswordResetExpiresAt *time.Time `json:"-" db:"password_reset_expires_at"`
	LastLoginAt            *time.Time `json:"last_login_at" db:"last_login_at"`
	FailedLoginAttempts    int        `json:"-" db:"failed_login_attempts"`
	LockedUntil            *time.Time `json:"-" db:"locked_until"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at" db:"updated_at"`
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	Name       string     `json:"name" db:"name"`
	Prefix     string     `json:"prefix" db:"prefix"`
	Hash       string     `json:"-" db:"hash"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at" db:"expires_at"`
	Scopes     []string   `json:"scopes" db:"scopes"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	User       *User      `json:"user" db:"user"` // User ForeignKey
}

// RefreshToken represents a JWT refresh token
type RefreshToken struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	TokenHash string    `json:"-" db:"token_hash"`
	IsRevoked bool      `json:"is_revoked" db:"is_revoked"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// UserSession represents an active user session
type UserSession struct {
	ID           uuid.UUID `json:"id" db:"id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	SessionToken string    `json:"-" db:"session_token"`
	IPAddress    *string   `json:"ip_address" db:"ip_address"`
	UserAgent    *string   `json:"user_agent" db:"user_agent"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// LoginAttempt represents a login attempt for security monitoring
type LoginAttempt struct {
	ID            uuid.UUID `json:"id" db:"id"`
	Email         string    `json:"email" db:"email"`
	IPAddress     string    `json:"ip_address" db:"ip_address"`
	Success       bool      `json:"success" db:"success"`
	FailureReason *string   `json:"failure_reason" db:"failure_reason"`
	UserAgent     *string   `json:"user_agent" db:"user_agent"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// Tunnel represents a tunnel configuration
type Tunnel struct {
	ID             uuid.UUID   `json:"id" db:"id"`
	UserID         uuid.UUID   `json:"user_id" db:"user_id"`
	Name           string      `json:"name" db:"name"`
	Protocol       string      `json:"protocol" db:"protocol"`
	Subdomain      *string     `json:"subdomain" db:"subdomain"`
	CustomDomain   *string     `json:"custom_domain" db:"custom_domain"`
	TargetHost     string      `json:"target_host" db:"target_host"`
	TargetPort     int         `json:"target_port" db:"target_port"`
	PublicPort     *int        `json:"public_port" db:"public_port"`
	Status         string      `json:"status" db:"status"`
	AuthToken      *string     `json:"-" db:"auth_token"`
	MaxConnections *int        `json:"max_connections" db:"max_connections"`
	ExpiresAt      *time.Time  `json:"expires_at" db:"expires_at"`
	Metadata       interface{} `json:"metadata" db:"metadata"`
	CreatedAt      time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at" db:"updated_at"`
}

// TunnelAnalytics represents tunnel usage analytics
type TunnelAnalytics struct {
	ID              uuid.UUID `json:"id" db:"id"`
	TunnelID        uuid.UUID `json:"tunnel_id" db:"tunnel_id"`
	RequestsCount   int64     `json:"requests_count" db:"requests_count"`
	BytesIn         int64     `json:"bytes_in" db:"bytes_in"`
	BytesOut        int64     `json:"bytes_out" db:"bytes_out"`
	ResponseTimeAvg *float32  `json:"response_time_avg" db:"response_time_avg"`
	ErrorCount      int64     `json:"error_count" db:"error_count"`
	Timestamp       time.Time `json:"timestamp" db:"timestamp"`
}

// Connection represents an active tunnel connection
type Connection struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	TunnelID   uuid.UUID  `json:"tunnel_id" db:"tunnel_id"`
	RemoteAddr string     `json:"remote_addr" db:"remote_addr"`
	LocalAddr  string     `json:"local_addr" db:"local_addr"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	BytesIn    int64      `json:"bytes_in" db:"bytes_in"`
	BytesOut   int64      `json:"bytes_out" db:"bytes_out"`
	StartedAt  time.Time  `json:"started_at" db:"started_at"`
	EndedAt    *time.Time `json:"ended_at" db:"ended_at"`
}

// Role validation
func IsValidRole(role string) bool {
	validRoles := []string{"user", "admin", "moderator"}
	for _, validRole := range validRoles {
		if role == validRole {
			return true
		}
	}
	return false
}

// Protocol validation
func IsValidProtocol(protocol string) bool {
	return protocol == "http" || protocol == "tcp"
}

// Status validation
func IsValidStatus(status string) bool {
	validStatuses := []string{"active", "inactive", "terminated", "connecting", "error"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}
