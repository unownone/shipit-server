package test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/unownone/shipit-server/internal/config"
	"github.com/unownone/shipit-server/internal/database"
)

// TestSimpleContainerSetup verifies basic testcontainers functionality
func TestSimpleContainerSetup(t *testing.T) {
	ctx := context.Background()

	// Start PostgreSQL container
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("shipit_test"),
		postgres.WithUsername("shipit_test"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err, "Failed to start PostgreSQL container")
	defer func() {
		err := postgresContainer.Terminate(ctx)
		if err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	// Get database connection details
	host, err := postgresContainer.Host(ctx)
	require.NoError(t, err)

	port, err := postgresContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	// Create database config
	dbConfig := &config.DatabaseConfig{
		Host:     host,
		Port:     port.Int(),
		User:     "shipit_test",
		Password: "test_password",
		Name:     "shipit_test",
		SSLMode:  "disable",
	}

	// Test database connection
	db, err := database.New(dbConfig)
	require.NoError(t, err, "Failed to connect to database")
	defer db.Close()

	// Test health check
	testCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = db.Health(testCtx)
	require.NoError(t, err, "Database health check failed")

	// Verify container info
	dbURL, err := postgresContainer.ConnectionString(ctx)
	require.NoError(t, err)

	t.Logf("Container setup successful!")
	t.Logf("Host: %s, Port: %d", host, port.Int())
	t.Logf("Database URL: %s", dbURL)

	// Verify basic database operations
	_, err = db.Pool.Exec(testCtx, "SELECT 1")
	assert.NoError(t, err, "Basic database query should work")

	// Run a simple schema creation test
	_, err = db.Pool.Exec(testCtx, `
		CREATE TABLE IF NOT EXISTS test_table (
			id SERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`)
	assert.NoError(t, err, "Should be able to create test table")

	// Insert test data
	_, err = db.Pool.Exec(testCtx, "INSERT INTO test_table (name) VALUES ($1)", "test")
	assert.NoError(t, err, "Should be able to insert test data")

	// Query test data
	var count int
	err = db.Pool.QueryRow(testCtx, "SELECT COUNT(*) FROM test_table").Scan(&count)
	assert.NoError(t, err, "Should be able to query test data")
	assert.Equal(t, 1, count, "Should have one test record")

	t.Log("✅ Testcontainers setup verification successful!")
}
