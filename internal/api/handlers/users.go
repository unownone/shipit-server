package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/api/middleware"
	"github.com/unwonone/shipit-server/internal/auth"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
)

// UserHandler handles user-related API endpoints
type UserHandler struct {
	db              *database.Database
	passwordManager *auth.PasswordManager
	jwtManager      *auth.JWTManager
	apiKeyManager   *auth.APIKeyManager
	config          *config.Config
}

// NewUserHandler creates a new user handler
func NewUserHandler(
	db *database.Database,
	passwordManager *auth.PasswordManager,
	jwtManager *auth.JWTManager,
	apiKeyManager *auth.APIKeyManager,
	config *config.Config,
) *UserHandler {
	return &UserHandler{
		db:              db,
		passwordManager: passwordManager,
		jwtManager:      jwtManager,
		apiKeyManager:   apiKeyManager,
		config:          config,
	}
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Name     string `json:"name" binding:"required,min=2"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// UpdateProfileRequest represents a profile update request
type UpdateProfileRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

// CreateAPIKeyRequest represents an API key creation request
type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Register handles user registration
// @Summary Register a new user
// @Description Register a new user account
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "User registration data"
// @Success 201 {object} map[string]interface{} "User created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 409 {object} map[string]interface{} "User already exists"
// @Router /users/register [post]
func (h *UserHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	// Validate password
	if err := h.passwordManager.IsPasswordValid(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Check if user already exists
	_, err := h.db.Queries.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User with this email already exists",
		})
		return
	}

	// Hash password
	hashedPassword, err := h.passwordManager.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process password",
		})
		return
	}

	// Create user
	user, err := h.db.Queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        strings.ToLower(req.Email),
		PasswordHash: hashedPassword,
		Name:         req.Name,
		Role:         string(auth.RoleUser), // Default role
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	// Generate token pair
	accessToken, refreshToken, err := h.jwtManager.GenerateTokenPair(ctx, &user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate tokens",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":       "User registered successfully",
		"user_id":       user.ID,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// Login handles user login
func (h *UserHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	// Get user by email
	user, err := h.db.Queries.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Check if user is active
	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Account is deactivated",
		})
		return
	}

	// Verify password
	if err := h.passwordManager.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Generate token pair
	accessToken, refreshToken, err := h.jwtManager.GenerateTokenPair(ctx, &user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate tokens",
		})
		return
	}

	// Update last login
	h.db.Queries.UpdateUserLastLogin(ctx, user.ID)

	c.JSON(http.StatusOK, gin.H{
		"message":       "Login successful",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// GetProfile handles getting user profile
func (h *UserHandler) GetProfile(c *gin.Context) {
	user, exists := middleware.GetCurrentUser(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not found in context",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":             user.ID,
			"email":          user.Email,
			"name":           user.Name,
			"role":           user.Role,
			"email_verified": user.EmailVerified,
			"created_at":     user.CreatedAt.Time,
			"updated_at":     user.UpdatedAt.Time,
		},
	})
}

// UpdateProfile handles updating user profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	// Convert UUID to uuid.UUID
	var pgUserID uuid.UUID
	pgUserID.Scan(userID.String())

	// Get current user
	user, err := h.db.Queries.GetUserByID(ctx, pgUserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// Update user fields
	updateParams := sqlc.UpdateUserParams{
		ID:            user.ID,
		Name:          user.Name,
		Email:         user.Email,
		Role:          user.Role,
		EmailVerified: user.EmailVerified,
	}

	if req.Name != nil {
		updateParams.Name = *req.Name
	}

	if req.Email != nil {
		// Validate email format
		if !strings.Contains(*req.Email, "@") || len(*req.Email) < 5 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid email format",
			})
			return
		}

		// Check if email is already taken by another user
		if strings.ToLower(*req.Email) != user.Email {
			existingUser, err := h.db.Queries.GetUserByEmail(ctx, strings.ToLower(*req.Email))
			if err == nil && existingUser.ID != user.ID {
				c.JSON(http.StatusConflict, gin.H{
					"error": "Email is already taken",
				})
				return
			}
		}
		updateParams.Email = strings.ToLower(*req.Email)
	}

	// Update user
	updatedUser, err := h.db.Queries.UpdateUser(ctx, updateParams)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"user": gin.H{
			"id":    userID,
			"email": updatedUser.Email,
			"name":  updatedUser.Name,
			"role":  updatedUser.Role,
		},
	})
}

// RefreshToken handles token refresh
func (h *UserHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	// Refresh the access token
	accessToken, err := h.jwtManager.RefreshAccessToken(ctx, req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
	})
}

// Logout handles user logout
func (h *UserHandler) Logout(c *gin.Context) {
	// Get refresh token from request body or header
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Refresh token is required",
		})
		return
	}

	ctx := c.Request.Context()

	// Revoke the refresh token
	err := h.jwtManager.RevokeRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to logout",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// CreateAPIKey handles API key creation
func (h *UserHandler) CreateAPIKey(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	// Create API key
	apiKey, key, err := h.apiKeyManager.GenerateAPIKey(ctx, userID, req.Name, req.ExpiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create API key",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "API key created successfully",
		"api_key": gin.H{
			"id":         apiKey.ID,
			"name":       apiKey.Name,
			"prefix":     apiKey.Prefix,
			"key":        key, // Only returned once
			"expires_at": apiKey.ExpiresAt.Time,
			"created_at": apiKey.CreatedAt.Time,
		},
	})
}

// ListAPIKeys handles listing user's API keys
func (h *UserHandler) ListAPIKeys(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	ctx := c.Request.Context()

	// List API keys
	apiKeys, err := h.apiKeyManager.ListAPIKeys(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list API keys",
		})
		return
	}

	// Convert to response format
	keys := make([]gin.H, len(apiKeys))
	for i, key := range apiKeys {
		keys[i] = gin.H{
			"id":           key.ID,
			"name":         key.Name,
			"prefix":       key.Prefix,
			"last_used_at": key.LastUsedAt.Time,
			"expires_at":   key.ExpiresAt.Time,
			"created_at":   key.CreatedAt.Time,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"api_keys": keys,
	})
}

// RevokeAPIKey handles API key revocation
func (h *UserHandler) RevokeAPIKey(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	keyIDStr := c.Param("keyId")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid API key ID",
		})
		return
	}

	ctx := c.Request.Context()

	// Check if the API key exists and belongs to the user
	_, err = h.apiKeyManager.GetAPIKey(ctx, keyID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "API key not found",
		})
		return
	}

	// Revoke API key
	err = h.apiKeyManager.RevokeAPIKey(ctx, keyID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to revoke API key",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "API key revoked successfully",
	})
}
