package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
	"github.com/unwonone/shipit-server/internal/logger"
)

// Database wraps the database connection and queries
type Database struct {
	Pool    *pgxpool.Pool
	Queries *sqlc.Queries
	config  *config.DatabaseConfig
}

// New creates a new database connection
func New(cfg *config.DatabaseConfig) (*Database, error) {
	// Create connection pool configuration
	poolConfig, err := pgxpool.ParseConfig(cfg.GetDSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Configure connection pool
	poolConfig.MaxConns = int32(cfg.MaxConnections)
	poolConfig.MinConns = int32(cfg.MaxIdleConnections)
	poolConfig.MaxConnLifetime = cfg.ConnectionMaxLifetime
	poolConfig.MaxConnIdleTime = 30 * time.Minute

	// Create connection pool
	pool, err := pgxpool.New(context.Background(), poolConfig.ConnString())
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create SQLC queries instance
	queries := sqlc.New(pool)

	db := &Database{
		Pool:    pool,
		Queries: queries,
		config:  cfg,
	}

	logger.Get().Info("Database connection established successfully")
	return db, nil
}

// Close closes the database connection pool
func (db *Database) Close() {
	if db.Pool != nil {
		db.Pool.Close()
		logger.Get().Info("Database connection pool closed")
	}
}

// Health checks the database connection health
func (db *Database) Health(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}

// BeginTx starts a new transaction and returns a Queries instance for the transaction
func (db *Database) BeginTx(ctx context.Context) (pgx.Tx, *sqlc.Queries, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	queries := db.Queries.WithTx(tx)
	return tx, queries, nil
}

// WithTx executes a function within a database transaction
func (db *Database) WithTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	queries := db.Queries.WithTx(tx)
	if err := fn(queries); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// RunMigrations applies database migrations using Atlas
func (db *Database) RunMigrations(ctx context.Context) error {
	// For now, we'll implement a simple version
	// In production, you'd use Atlas CLI or the Atlas Go SDK
	logger.Get().Info("Migration system using Atlas CLI - run 'atlas migrate apply --env dev' manually")
	return nil
}

// CleanupExpiredTokens cleans up expired tokens and sessions
func (db *Database) CleanupExpiredTokens(ctx context.Context) error {
	log := logger.Get()

	// Delete expired refresh tokens
	if err := db.Queries.DeleteExpiredRefreshTokens(ctx); err != nil {
		log.WithError(err).Error("Failed to delete expired refresh tokens")
	}

	// Delete expired user sessions
	if err := db.Queries.DeleteExpiredUserSessions(ctx); err != nil {
		log.WithError(err).Error("Failed to delete expired user sessions")
	}

	// Delete expired API keys
	if err := db.Queries.DeleteExpiredAPIKeys(ctx); err != nil {
		log.WithError(err).Error("Failed to delete expired API keys")
	}

	// Delete old login attempts (older than 30 days)
	cutoff := time.Now().AddDate(0, 0, -30)
	if err := db.Queries.DeleteOldLoginAttempts(ctx, pgtype.Timestamp{Time: cutoff, Valid: true}); err != nil {
		log.WithError(err).Error("Failed to delete old login attempts")
	}

	// Delete expired tunnels
	if err := db.Queries.DeleteExpiredTunnels(ctx); err != nil {
		log.WithError(err).Error("Failed to delete expired tunnels")
	}

	log.Info("Cleanup of expired tokens completed")
	return nil
}

// Stats returns database connection statistics
func (db *Database) Stats() *pgxpool.Stat {
	return db.Pool.Stat()
}