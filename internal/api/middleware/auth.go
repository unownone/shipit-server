package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/auth"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
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

// JWTAuth middleware for JWT-based authentication (web users)
func (am *AuthMiddleware) JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
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

		// Validate the JWT token (now with context)
		user, err := am.jwtManager.GetUserFromToken(c.Request.Context(), token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Extract UUID from pgtype.UUID for context storage
		userID, err := uuid.FromBytes(user.ID.Bytes[:])
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID",
			})
			c.Abort()
			return
		}

		// Store user in context
		c.Set("user", user)
		c.Set("user_id", userID)
		c.Set("user_role", auth.UserRole(user.Role))

		c.Next()
	}
}

// APIKeyAuth middleware for API key-based authentication (CLI agents)
func (am *AuthMiddleware) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract API key from Authorization header
		authHeader := c.GetHeader("Authorization")
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

		apiKey := parts[1]

		// Validate the API key (now with context)
		user, keyInfo, err := am.apiKeyManager.ValidateAPIKey(c.Request.Context(), apiKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}

		// Extract UUID from pgtype.UUID for context storage
		var userID uuid.UUID
		err = userID.Scan(user.ID.Bytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid user ID",
			})
			c.Abort()
			return
		}

		// Store user and API key info in context
		c.Set("user", user)
		c.Set("user_id", userID)
		c.Set("user_role", auth.UserRole(user.Role))
		c.Set("api_key", keyInfo)

		c.Next()
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

// OptionalAuth middleware that tries to authenticate but doesn't fail if no auth provided
func (am *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		token := parts[1]

		// Try JWT first (now with context)
		if user, err := am.jwtManager.GetUserFromToken(c.Request.Context(), token); err == nil {
			// Extract UUID from pgtype.UUID
			var userID uuid.UUID
			if err := userID.Scan(user.ID.Bytes); err == nil {
				c.Set("user", user)
				c.Set("user_id", userID)
				c.Set("user_role", auth.UserRole(user.Role))
				c.Set("auth_type", "jwt")
				c.Next()
				return
			}
		}

		// Try API key (now with context)
		if user, keyInfo, err := am.apiKeyManager.ValidateAPIKey(c.Request.Context(), token); err == nil {
			// Extract UUID from pgtype.UUID
			var userID uuid.UUID
			if err := userID.Scan(user.ID.Bytes); err == nil {
				c.Set("user", user)
				c.Set("user_id", userID)
				c.Set("user_role", auth.UserRole(user.Role))
				c.Set("api_key", keyInfo)
				c.Set("auth_type", "api_key")
				c.Next()
				return
			}
		}

		// If both fail, continue without authentication
		c.Next()
	}
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