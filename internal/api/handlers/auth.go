package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/unwonone/shipit-server/internal/auth"
)

// AuthHandler handles authentication-related API endpoints
type AuthHandler struct {
	jwtManager    *auth.JWTManager
	apiKeyManager *auth.APIKeyManager
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(jwtManager *auth.JWTManager, apiKeyManager *auth.APIKeyManager) *AuthHandler {
	return &AuthHandler{
		jwtManager:    jwtManager,
		apiKeyManager: apiKeyManager,
	}
}

// ValidateTokenRequest represents token validation request
type ValidateTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// ValidateTokenResponse represents token validation response
type ValidateTokenResponse struct {
	Valid    bool   `json:"valid"`
	UserID   string `json:"user_id,omitempty"`
	AuthType string `json:"auth_type,omitempty"` // "api_key" or "jwt"
	Error    string `json:"error,omitempty"`
}

// ValidateToken validates API keys and JWT tokens - Control Plane API
// @Summary Validate authentication token
// @Description Validates both API keys and JWT tokens
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body ValidateTokenRequest true "Token validation request"
// @Success 200 {object} ValidateTokenResponse
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /auth/validate [post]
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	// Try to get token from Authorization header first
	authHeader := c.GetHeader("Authorization")
	var token string

	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = authHeader[7:] // Remove "Bearer " prefix
	} else {
		// Fallback to request body
		var req ValidateTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ValidateTokenResponse{
				Valid: false,
				Error: "Invalid request data",
			})
			return
		}
		token = req.Token
	}

	if token == "" {
		c.JSON(http.StatusBadRequest, ValidateTokenResponse{
			Valid: false,
			Error: "Token is required",
		})
		return
	}

	ctx := c.Request.Context()

	// Try API key validation first
	if user, _, err := h.apiKeyManager.ValidateAPIKey(ctx, token); err == nil {
		c.JSON(http.StatusOK, ValidateTokenResponse{
			Valid:    true,
			UserID:   user.ID.String(),
			AuthType: "api_key",
		})
		return
	}

	// Try JWT validation
	if user, err := h.jwtManager.GetUserFromToken(ctx, token); err == nil {
		c.JSON(http.StatusOK, ValidateTokenResponse{
			Valid:    true,
			UserID:   user.ID.String(),
			AuthType: "jwt",
		})
		return
	}

	// Token is invalid
	c.JSON(http.StatusUnauthorized, ValidateTokenResponse{
		Valid: false,
		Error: "Invalid or expired token",
	})
}

// GetTokenInfo provides detailed information about a token (for debugging/admin)
func (h *AuthHandler) GetTokenInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Authorization header with Bearer token required",
		})
		return
	}

	token := authHeader[7:]
	ctx := c.Request.Context()

	// Try API key validation
	if user, apiKey, err := h.apiKeyManager.ValidateAPIKey(ctx, token); err == nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":      true,
			"auth_type":  "api_key",
			"user_id":    user.ID.String(),
			"user_email": user.Email,
			"user_name":  user.Name,
			"user_role":  user.Role,
			"key_info": gin.H{
				"id":           apiKey.ID.String(),
				"name":         apiKey.Name,
				"created_at":   apiKey.CreatedAt.Time,
				"last_used_at": apiKey.LastUsedAt.Time,
				"expires_at":   apiKey.ExpiresAt.Time,
			},
		})
		return
	}

	// Try JWT validation
	if user, err := h.jwtManager.GetUserFromToken(ctx, token); err == nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":      true,
			"auth_type":  "jwt",
			"user_id":    user.ID.String(),
			"user_email": user.Email,
			"user_name":  user.Name,
			"user_role":  user.Role,
		})
		return
	}

	c.JSON(http.StatusUnauthorized, gin.H{
		"valid": false,
		"error": "Invalid or expired token",
	})
} 