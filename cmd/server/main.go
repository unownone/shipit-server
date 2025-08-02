// Package main is the main package for the ShipIt server
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/unownone/shipit-server/docs" // Import generated docs
	"github.com/unownone/shipit-server/internal/api"
	"github.com/unownone/shipit-server/internal/auth"
	"github.com/unownone/shipit-server/internal/config"
	"github.com/unownone/shipit-server/internal/database"
	"github.com/unownone/shipit-server/internal/database/sqlc"
	"github.com/unownone/shipit-server/internal/logger"
)

// @title           ShipIt Server API
// @version         1.0.0
// @description     A tunnel service for exposing local services to the internet
// @termsOfService  http://swagger.io/terms/

// @contact.name   ShipIt Support
// @contact.url    http://www.shipit.com/support
// @contact.email  support@shipit.com

// @license.name  MIT
// @license.url   http://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description API key authentication. Use "Bearer {api_key}" format.

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT token authentication. Use "Bearer {jwt_token}" format.

func main() {
	// Initialize logger first
	logger.Init()
	log := logger.Get()

	// Load configuration with secrets
	configPath := os.Getenv("SHIPIT_CONFIG_PATH")
	secretsPath := os.Getenv("SHIPIT_SECRETS_PATH")

	cfg, err := config.LoadWithSecrets(configPath, secretsPath)
	if err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	// Initialize database
	db, err := database.New(&cfg.Database)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	// Test database connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Health(ctx); err != nil {
		log.WithError(err).Fatal("Database health check failed")
	}

	log.Info("Database connected successfully")

	// Initialize authentication managers
	passwordManager := auth.NewPasswordManager(cfg.Auth.HashCost)
	jwtManager := auth.NewJWTManager(&cfg.JWT, db)
	apiKeyManager := auth.NewAPIKeyManager(db)

	// Create initial admin user if not exists
	if err := initializeFirstAdmin(db, passwordManager, cfg); err != nil {
		log.WithError(err).Fatal("Failed to initialize admin user")
	}

	// Set Gin mode
	gin.SetMode(cfg.Server.Environment)

	// Initialize router
	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Setup routes
	api.SetupRoutes(
		router,
		db,
		cfg,
		passwordManager,
		jwtManager,
		apiKeyManager,
	)

	// Swagger documentation endpoint
	if cfg.Server.Environment != "production" {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Start server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler: router,
	}

	log.WithField("port", cfg.Server.HTTPPort).Info("Starting server")

	if cfg.Server.Environment != "production" {
		log.WithField("swagger_url", fmt.Sprintf("http://localhost:%d/swagger/index.html", cfg.Server.HTTPPort)).
			Info("Swagger documentation available")
	}

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Background cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			ctx := context.Background()
			log.Info("Running database cleanup")

			// Cleanup expired tokens
			if err := jwtManager.CleanupExpiredTokens(ctx); err != nil {
				log.WithError(err).Error("Failed to cleanup expired tokens")
			}

			// Cleanup expired API keys
			if err := apiKeyManager.CleanupExpiredKeys(ctx); err != nil {
				log.WithError(err).Error("Failed to cleanup expired API keys")
			}

			log.Info("Database cleanup completed")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down server")

	// Context for shutdown timeout
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Server forced to shutdown")
	}

	log.Info("Server exited")
}

// initializeFirstAdmin creates the first admin user if not exists
func initializeFirstAdmin(db *database.Database, passwordManager *auth.PasswordManager, cfg *config.Config) error {
	ctx := context.Background()
	log := logger.Get()

	// Check if admin user already exists by email
	_, err := db.Queries.GetUserByEmail(ctx, cfg.Secrets.Admin.Email)
	if err == nil {
		log.Info("Admin user already exists")
		return nil
	}

	// Create admin user
	hashedPassword, err := passwordManager.HashPassword(cfg.Secrets.Admin.Password)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	adminUser, err := db.Queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        cfg.Secrets.Admin.Email,
		PasswordHash: hashedPassword,
		Name:         "Administrator",
		Role:         string(auth.RoleAdmin),
	})
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"email":   adminUser.Email,
		"user_id": adminUser.ID.String(),
	}).Info("Created admin user")

	log.WithField("password", cfg.Secrets.Admin.Password).Warn("Admin password set - please change after first login")

	return nil
}
