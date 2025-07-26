package api

import (
	"github.com/gin-gonic/gin"
	"github.com/unwonone/shipit-server/internal/api/handlers"
	"github.com/unwonone/shipit-server/internal/api/middleware"
	"github.com/unwonone/shipit-server/internal/auth"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
)

// SetupRoutes configures all API routes
func SetupRoutes(
	router *gin.Engine,
	db *database.Database,
	config *config.Config,
	passwordManager *auth.PasswordManager,
	jwtManager *auth.JWTManager,
	apiKeyManager *auth.APIKeyManager,
) {
	// Create handlers
	userHandler := handlers.NewUserHandler(db, passwordManager, jwtManager, apiKeyManager, config)
	tunnelHandler := handlers.NewTunnelHandler(db, config)
	authHandler := handlers.NewAuthHandler(jwtManager, apiKeyManager)
	analyticsHandler := handlers.NewAnalyticsHandler(db)

	// Create middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, apiKeyManager)

	// CORS middleware
	router.Use(middleware.CORSMiddleware(&config.CORS))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		if err := db.Health(c.Request.Context()); err != nil {
			c.JSON(500, gin.H{
				"status": "unhealthy",
				"error":  "Database connection failed",
			})
			return
		}

		c.JSON(200, gin.H{
			"status":  "healthy",
			"version": "1.0.0",
		})
	})

	// API version 1
	v1 := router.Group("/api/v1")

	// Public endpoints (no auth required)
	public := v1.Group("/")
	{
		// User management
		public.POST("/users/register", userHandler.Register)
		public.POST("/users/login", userHandler.Login)
		public.POST("/users/refresh", userHandler.RefreshToken)
	}

	// JWT-protected endpoints (for web users)
	jwtProtected := v1.Group("/")
	jwtProtected.Use(authMiddleware.JWTAuth())
	{
		// User profile management
		jwtProtected.GET("/users/profile", userHandler.GetProfile)
		jwtProtected.PUT("/users/profile", userHandler.UpdateProfile)
		jwtProtected.POST("/users/logout", userHandler.Logout)

		// API key management
		jwtProtected.POST("/users/api-keys", userHandler.CreateAPIKey)
		jwtProtected.GET("/users/api-keys", userHandler.ListAPIKeys)
		jwtProtected.DELETE("/users/api-keys/:keyId", userHandler.RevokeAPIKey)

		// Analytics endpoints (JWT auth for web dashboard)
		jwtProtected.GET("/analytics/overview", analyticsHandler.GetOverview)
		jwtProtected.GET("/analytics/traffic", analyticsHandler.GetTrafficAnalytics)
	}

	// API key protected endpoints (for CLI agents and web users)
	apiProtected := v1.Group("/")
	apiProtected.Use(authMiddleware.APIKeyAuth())
	{
		// Tunnel management (Control Plane API)
		apiProtected.POST("/tunnels", tunnelHandler.CreateTunnel)
		apiProtected.GET("/tunnels", tunnelHandler.ListTunnels)
		apiProtected.GET("/tunnels/:tunnelId", tunnelHandler.GetTunnel)
		apiProtected.DELETE("/tunnels/:tunnelId", tunnelHandler.DeleteTunnel)
		apiProtected.GET("/tunnels/:tunnelId/stats", tunnelHandler.GetTunnelStats)

		// Analytics for specific tunnels (also available via API key)
		apiProtected.GET("/analytics/tunnels/:tunnel_id/stats", analyticsHandler.GetTunnelStats)
	}

	// Mixed auth endpoints (both JWT and API key accepted)
	mixed := v1.Group("/")
	mixed.Use(authMiddleware.OptionalAuth())
	{
		// Authentication validation endpoint
		mixed.POST("/auth/validate", authHandler.ValidateToken)
		mixed.GET("/auth/info", authHandler.GetTokenInfo)
	}

	// Admin endpoints (admin role required)
	admin := v1.Group("/admin")
	admin.Use(authMiddleware.JWTAuth())
	admin.Use(authMiddleware.RequireRole(auth.RoleAdmin))
	{
		// Admin can see all users
		admin.GET("/users", func(c *gin.Context) {
			// TODO: Implement admin user list endpoint
			c.JSON(200, gin.H{"message": "Admin user list endpoint"})
		})

		// Admin can see all tunnels
		admin.GET("/tunnels", func(c *gin.Context) {
			// TODO: Implement admin tunnel list endpoint
			c.JSON(200, gin.H{"message": "Admin tunnel list endpoint"})
		})

		// System statistics
		admin.GET("/stats", func(c *gin.Context) {
			// TODO: Implement system stats endpoint
			c.JSON(200, gin.H{"message": "System statistics endpoint"})
		})
	}
} 