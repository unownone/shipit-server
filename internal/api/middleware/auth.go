// Package middleware provides the authentication middleware for the application
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/unownone/shipit-server/internal/auth"
	"github.com/unownone/shipit-server/internal/database/sqlc"
)

// AuthMiddleware provides authentication middleware for different types
type AuthMiddleware struct {
	jwtManager    *auth.JWTManager
	apiKeyManager *auth.APIKeyManager
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtManager *auth.JWTManager, apiKeyManager *auth.APIKeyManager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:    jwtManager,
		apiKeyManager: apiKeyManager,
	}
}

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	User     *sqlc.Users
	UserID   uuid.UUID
	UserRole auth.UserRole
	APIKey   *sqlc.GetAPIKeyByHashRow // Only set for API key auth
	AuthType string                   // "jwt" or "api_key"
	Success  bool
	Error    error
}

// authenticateJWT attempts to authenticate using JWT token
func (am *AuthMiddleware) authenticateJWT(ctx context.Context, token string) AuthResult {
	// Validate the JWT token
	user, err := am.jwtManager.GetUserFromToken(ctx, token)
	if err != nil {
		return AuthResult{
			Success: false,
			Error:   err,
		}
	}

	// Extract UUID from uuid.UUID for context storage

	return AuthResult{
		User:     user,
		UserID:   user.ID,
		UserRole: auth.UserRole(user.Role),
		AuthType: "jwt",
		Success:  true,
	}
}

// authenticateAPIKey attempts to authenticate using API key
func (am *AuthMiddleware) authenticateAPIKey(ctx context.Context, apiKey string) AuthResult {
	// Validate the API key
	user, keyInfo, err := am.apiKeyManager.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		return AuthResult{
			Success: false,
			Error:   err,
		}
	}

	return AuthResult{
		User:     user,
		UserID:   user.ID,
		UserRole: auth.UserRole(user.Role),
		APIKey:   keyInfo,
		AuthType: "api_key",
		Success:  true,
	}
}

// setAuthContext sets the authentication context in gin
func setAuthContext(c *gin.Context, result AuthResult) {
	c.Set("user", result.User)
	c.Set("user_id", result.UserID)
	c.Set("user_role", result.UserRole)
	c.Set("auth_type", result.AuthType)

	if result.APIKey != nil {
		c.Set("api_key", result.APIKey)
	}
}

// JWTAuth middleware for JWT-based authentication (web users)
func (am *AuthMiddleware) JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader(auth.JWTAuthorizationHeader)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := parts[1]

		// Authenticate using JWT
		result := am.authenticateJWT(c.Request.Context(), token)
		if !result.Success {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Set context
		setAuthContext(c, result)
		c.Next()
	}
}

// APIKeyAuth middleware for API key-based authentication (CLI agents)
func (am *AuthMiddleware) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract API key from Authorization header
		apiKey := c.GetHeader(auth.APIKeyAuthorizationHeader)
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key header is required",
			})
			c.Abort()
			return
		}
		// Authenticate using API key
		result := am.authenticateAPIKey(c.Request.Context(), apiKey)
		if !result.Success {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}

		// Set context
		setAuthContext(c, result)
		c.Next()
	}
}

// CombinedAuth middleware that tries both JWT and API key authentication
func (am *AuthMiddleware) CombinedAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header

		// check for jwt auth header
		if jwtAuthHeader := c.GetHeader(auth.JWTAuthorizationHeader); jwtAuthHeader != "" {
			parts := strings.SplitN(jwtAuthHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid authorization header format",
				})
				c.Abort()
				return
			}
			jwtAuthHeader = parts[1]
			// try jwt auth
			result := am.authenticateJWT(c.Request.Context(), jwtAuthHeader)
			if result.Success {
				setAuthContext(c, result)
				c.Next()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// check for api key auth header
		if apiKeyAuthHeader := c.GetHeader(auth.APIKeyAuthorizationHeader); apiKeyAuthHeader != "" {
			// try api key auth
			result := am.authenticateAPIKey(c.Request.Context(), apiKeyAuthHeader)
			if result.Success {
				setAuthContext(c, result)
				c.Next()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}

		// if no auth header, return unauthorized
		c.JSON(http.StatusForbidden, gin.H{
			"error": "No Auth Header Provided",
		})
		c.Abort()
	}
}

func (am *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header

		defer c.Next()

		// check for jwt auth header
		if jwtAuthHeader := c.GetHeader(auth.JWTAuthorizationHeader); jwtAuthHeader != "" {
			parts := strings.SplitN(jwtAuthHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				return
			}
			jwtAuthHeader = parts[1]
			// try jwt auth
			result := am.authenticateJWT(c.Request.Context(), jwtAuthHeader)
			if result.Success {
				setAuthContext(c, result)
				return
			}
			return
		}

		// check for api key auth header
		if apiKeyAuthHeader := c.GetHeader(auth.APIKeyAuthorizationHeader); apiKeyAuthHeader != "" {
			// try api key auth
			if result := am.authenticateAPIKey(c.Request.Context(), apiKeyAuthHeader); result.Success {
				setAuthContext(c, result)
			}
		}

	}
}

// RequireRole middleware to check if user has required role
func (am *AuthMiddleware) RequireRole(requiredRole auth.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "User role not found in context",
			})
			c.Abort()
			return
		}

		role, ok := userRole.(auth.UserRole)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user role format",
			})
			c.Abort()
			return
		}

		if !hasPermission(role, requiredRole) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Insufficient permissions. Required: %s, Have: %s", requiredRole, role),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// hasPermission checks if a user role has permission for a required role
func hasPermission(userRole, requiredRole auth.UserRole) bool {
	// Define role hierarchy: admin > moderator > user
	roleHierarchy := map[auth.UserRole]int{
		auth.RoleUser:      1,
		auth.RoleModerator: 2,
		auth.RoleAdmin:     3,
	}

	userLevel, userExists := roleHierarchy[userRole]
	requiredLevel, requiredExists := roleHierarchy[requiredRole]

	if !userExists || !requiredExists {
		return false
	}

	return userLevel >= requiredLevel
}

// GetCurrentUser helper function to get the current user from context
func GetCurrentUser(c *gin.Context) (*sqlc.Users, bool) {
	user, exists := c.Get("user")
	if !exists {
		return nil, false
	}

	userObj, ok := user.(*sqlc.Users)
	return userObj, ok
}

// GetCurrentUserID helper function to get the current user ID from context
func GetCurrentUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}

	userIDObj, ok := userID.(uuid.UUID)
	return userIDObj, ok
}

// GetCurrentUserRole helper function to get the current user role from context
func GetCurrentUserRole(c *gin.Context) (auth.UserRole, bool) {
	role, exists := c.Get("user_role")
	if !exists {
		return "", false
	}

	roleObj, ok := role.(auth.UserRole)
	return roleObj, ok
}
