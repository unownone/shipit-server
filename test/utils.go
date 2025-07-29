package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/unwonone/shipit-server/internal/api"
	"github.com/unwonone/shipit-server/internal/auth"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
	"github.com/unwonone/shipit-server/internal/logger"
)

// TestSuite provides shared test infrastructure with testcontainers
type TestSuite struct {
	DB              *database.Database
	Config          *config.Config
	Router          *gin.Engine
	PasswordManager *auth.PasswordManager
	JWTManager      *auth.JWTManager
	APIKeyManager   *auth.APIKeyManager
	
	// Testcontainers
	PostgresContainer *testcontainers.DockerContainer
	
	// Test users for authentication
	TestUser     *TestUser
	TestUser2    *TestUser
	AdminUser    *TestUser
}

// TestUser represents a test user with credentials
type TestUser struct {
	ID           uuid.UUID
	Email        string
	Password     string
	Name         string
	Role         string
	AccessToken  string
	RefreshToken string
	APIKey       string
}

// APIResponse represents a generic API response
type APIResponse struct {
	StatusCode int
	Body       map[string]interface{}
	Headers    http.Header
}

// SetupTestSuite initializes test infrastructure with testcontainers
func SetupTestSuite(t *testing.T) *TestSuite {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	
	// Start PostgreSQL container
	postgresContainer, err := testcontainers.Run(ctx,
		"postgres:15-alpine",
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER": "shipit_test",
			"POSTGRES_PASSWORD": "test_password",
			"POSTGRES_DB": "shipit_test",
		}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err, "Failed to start PostgreSQL container")

	// Get database connection details
	host, err := postgresContainer.Host(ctx)
	require.NoError(t, err)
	
	port, err := postgresContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	// Create test config with container details
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Host:     host,
			Port:     port.Int(),
			User:     "shipit_test",
			Password: "test_password",
			Name:     "shipit_test",
			SSLMode:  "disable",
		},
		JWT: config.JWTConfig{
			SecretKey:            "test-jwt-secret-that-is-long-enough-for-testing",
			AccessTokenExpiry:    15 * time.Minute,
			RefreshTokenExpiry:   24 * time.Hour,
		},
		Auth: config.AuthConfig{
			HashCost: 4, // Lower cost for faster tests
		},
		Server: config.ServerConfig{
			Environment: "test",
			HTTPPort:    8080,
		},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"*"},
		},
		Tunnels: config.TunnelsConfig{
			MaxPerUser: 10,
			ConnectionPoolSize: 10,
			SubdomainLength: 10, // 2 characters
			DefaultTTL: 10 * time.Minute,
			DomainHost: "localhost", // TODO: change domain to accept any host
		},
	}

	// Wait a bit for PostgreSQL to be fully ready
	time.Sleep(2 * time.Second)

	// Set test log level if not already set
	if os.Getenv("LOG_LEVEL") == "" {
		os.Setenv("LOG_LEVEL", "info")
	}

	// Initialize logger for tests
	logger.Init()

	// Initialize database
	db, err := database.New(&cfg.Database)
	require.NoError(t, err, "Failed to connect to test database")

	// Test database connection
	testCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	err = db.Health(testCtx)
	require.NoError(t, err, "Database health check failed")

	// Run database migrations
	err = runDatabaseMigrations(cfg.Database)
	require.NoError(t, err, "Failed to run database migrations")

	// Initialize auth managers
	passwordManager := auth.NewPasswordManager(cfg.Auth.HashCost)
	jwtManager := auth.NewJWTManager(&cfg.JWT, db)
	apiKeyManager := auth.NewAPIKeyManager(db)

	// Initialize router
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Setup routes
	api.SetupRoutes(router, db, cfg, passwordManager, jwtManager, apiKeyManager)

	suite := &TestSuite{
		DB:                db,
		Config:            cfg,
		Router:            router,
		PasswordManager:   passwordManager,
		JWTManager:        jwtManager,
		APIKeyManager:     apiKeyManager,
		PostgresContainer: postgresContainer,
	}

	// Create test users
	suite.createTestUsers(t)

	return suite
}

// TearDownTestSuite cleans up test infrastructure
func (s *TestSuite) TearDownTestSuite(t *testing.T) {
	ctx := context.Background()

	if s == nil || s.DB == nil {
		return
	}

	// Clean up test data
	if s.TestUser != nil {
		s.DB.Queries.DeactivateUser(ctx, s.TestUser.ID)
	}
	if s.TestUser2 != nil {
		s.DB.Queries.DeactivateUser(ctx, s.TestUser2.ID)
	}
	if s.AdminUser != nil {
		s.DB.Queries.DeactivateUser(ctx, s.AdminUser.ID)
	}

	// Close database connection
	if s.DB != nil {
		s.DB.Close()
	}

	// Terminate PostgreSQL container
	if s.PostgresContainer != nil {
		err := s.PostgresContainer.Terminate(ctx)
		if err != nil {
			t.Logf("Failed to terminate PostgreSQL container: %v", err)
		}
	}
}

// runDatabaseMigrations runs database migrations by reading Atlas migration files
func runDatabaseMigrations(dbConfig config.DatabaseConfig) error {
	// Connect to database
	db, err := database.New(&dbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database for migrations: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Find the project root directory to locate migration files
	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	// Read and apply Atlas migration files
	migrationsDir := filepath.Join(projectRoot, "db", "migrations")
	err = applyMigrationFiles(ctx, db, migrationsDir)
	if err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	// Verify tables were created
	err = db.Health(ctx)
	if err != nil {
		return fmt.Errorf("database health check failed after migration: %w", err)
	}

	fmt.Printf("✅ Database migrations applied successfully\n")
	return nil
}

// applyMigrationFiles reads Atlas migration SQL files and applies them to the database
func applyMigrationFiles(ctx context.Context, db *database.Database, migrationsDir string) error {
	// Read migration files
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return fmt.Errorf("failed to find migration files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no migration files found in %s", migrationsDir)
	}

	// Sort files to ensure proper order
	sort.Strings(files)

	// Apply each migration file
	for _, file := range files {
		// Skip atlas.sum file
		if filepath.Ext(file) != ".sql" {
			continue
		}

		fmt.Printf("Applying migration: %s\n", filepath.Base(file))
		
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		// Execute the migration SQL
		_, err = db.Pool.Exec(ctx, string(content))
		if err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}
	}

	return nil
}

// findProjectRoot finds the project root directory by looking for db/migrations directory
func findProjectRoot() (string, error) {
	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	// Look for db/migrations directory starting from current directory and moving up
	dir := wd
	for {
		migrationsDir := filepath.Join(dir, "db", "migrations")
		if info, err := os.Stat(migrationsDir); err == nil && info.IsDir() {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("db/migrations directory not found in current directory tree")
}

// createTestUsers creates test users for authentication
func (s *TestSuite) createTestUsers(t *testing.T) {
	ctx := context.Background()

	// Create regular test user
	s.TestUser = s.createUser(t, ctx, "test@example.com", "testpassword123", "Test User", string(auth.RoleUser))
	
	// Create second test user
	s.TestUser2 = s.createUser(t, ctx, "test2@example.com", "testpassword123", "Test User 2", string(auth.RoleUser))
	
	// Create admin user
	s.AdminUser = s.createUser(t, ctx, "admin@example.com", "adminpassword123", "Admin User", string(auth.RoleAdmin))
}

// createUser creates a single test user
func (s *TestSuite) createUser(t *testing.T, ctx context.Context, email, password, name, role string) *TestUser {
	// Hash password
	hashedPassword, err := s.PasswordManager.HashPassword(password)
	require.NoError(t, err)

	// Create user in database
	user, err := s.DB.Queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:         email,
		PasswordHash:  hashedPassword,
		Name:          name,
		Role:          role,
		IsActive:      true,
		EmailVerified: false,
	})
	require.NoError(t, err)

	// Generate token pair
	accessToken, refreshToken, err := s.JWTManager.GenerateTokenPair(ctx, &user)
	require.NoError(t, err)

	// Create API key
	_, apiKey, err := s.APIKeyManager.GenerateAPIKey(ctx, user.ID, "Test Key", nil)
	require.NoError(t, err)

	return &TestUser{
		ID:           user.ID,
		Email:        email,
		Password:     password,
		Name:         name,
		Role:         role,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		APIKey:       apiKey,
	}
}

// MakeRequest makes an HTTP request and returns the response
func (s *TestSuite) MakeRequest(method, path string, body interface{}, headers map[string]string) *APIResponse {
	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			panic(fmt.Sprintf("Failed to marshal request body: %v", err))
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	s.Router.ServeHTTP(w, req)

	// Parse response body
	var responseBody map[string]interface{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
			// If JSON parsing fails, store raw body as string
			responseBody = map[string]interface{}{
				"raw_body": w.Body.String(),
			}
		}
	}

	return &APIResponse{
		StatusCode: w.Code,
		Body:       responseBody,
		Headers:    w.Header(),
	}
}

// MakeAuthenticatedRequest makes a request with JWT token
func (s *TestSuite) MakeAuthenticatedRequest(method, path string, body interface{}, user *TestUser) *APIResponse {
	headers := map[string]string{
		auth.JWTAuthorizationHeader: "Bearer " + user.AccessToken,
	}
	return s.MakeRequest(method, path, body, headers)
}

// MakeAPIKeyRequest makes a request with API key
func (s *TestSuite) MakeAPIKeyRequest(method, path string, body interface{}, user *TestUser) *APIResponse {
	headers := map[string]string{
		auth.APIKeyAuthorizationHeader: user.APIKey,
	}
	return s.MakeRequest(method, path, body, headers)
}

// AssertSuccessResponse asserts that the response is successful
func AssertSuccessResponse(t *testing.T, resp *APIResponse, expectedStatus int) {
	assert.Equal(t, expectedStatus, resp.StatusCode, "Response body: %+v", resp.Body)
}

// AssertErrorResponse asserts that the response is an error
func AssertErrorResponse(t *testing.T, resp *APIResponse, expectedStatus int, expectedError string) {
	assert.Equal(t, expectedStatus, resp.StatusCode)
	if expectedError != "" {
		if errorMsg, ok := resp.Body["error"]; ok {
			assert.Contains(t, errorMsg, expectedError)
		} else {
			t.Errorf("Expected error message containing '%s', but no error field found in response: %+v", expectedError, resp.Body)
		}
	}
}

// WaitForCondition waits for a condition to be true with timeout
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	timeoutCh := time.After(timeout)
	
	for {
		select {
		case <-ticker.C:
			if condition() {
				return
			}
		case <-timeoutCh:
			t.Fatalf("Timeout waiting for condition: %s", message)
		}
	}
}

// ContainerInfo provides information about the test containers
type ContainerInfo struct {
	PostgresHost string
	PostgresPort int
	DatabaseURL  string
}

// GetContainerInfo returns information about running test containers
func (s *TestSuite) GetContainerInfo(t *testing.T) *ContainerInfo {
	ctx := context.Background()
	
	host, err := s.PostgresContainer.Host(ctx)
	require.NoError(t, err)
	
	port, err := s.PostgresContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)
	
	dbURL, err := getConnectionString(s.PostgresContainer, s.Config)
	require.NoError(t, err)
	
	return &ContainerInfo{
		PostgresHost: host,
		PostgresPort: port.Int(),
		DatabaseURL:  dbURL,
	}
} 

func getConnectionString(container *testcontainers.DockerContainer, config *config.Config) (string, error) {
	ctx := context.Background()
	
	host, err := container.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get container host: %w", err)
	}
	
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return "", fmt.Errorf("failed to get container port: %w", err)
	}
	
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s", config.Database.User, config.Database.Password, host, port.Int(), config.Database.Name), nil
}