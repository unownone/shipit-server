// Package config provides the configuration for the application
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	TLS       TLSConfig       `mapstructure:"tls"`
	Auth      AuthConfig      `mapstructure:"auth"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Tunnels   TunnelsConfig   `mapstructure:"tunnels"`
	Analytics AnalyticsConfig `mapstructure:"analytics"`
	CORS      CORSConfig      `mapstructure:"cors"`
	RateLimit RateLimitConfig `mapstructure:"rate_limiting"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Secrets   *SecretsConfig  // Loaded separately for security
}

type ServerConfig struct {
	Domain      string `mapstructure:"domain"`
	HTTPPort    int    `mapstructure:"http_port"`
	HTTPSPort   int    `mapstructure:"https_port"`
	AgentPort   int    `mapstructure:"agent_port"`
	Environment string `mapstructure:"environment"`
}

type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	AutoCert bool   `mapstructure:"auto_cert"`
}

type AuthConfig struct {
	APIKeyLength     int           `mapstructure:"api_key_length"`
	HashCost         int           `mapstructure:"hash_cost"`
	MaxLoginAttempts int           `mapstructure:"max_login_attempts"`
	LockoutDuration  time.Duration `mapstructure:"lockout_duration"`
}

type JWTConfig struct {
	SecretKey          string        `mapstructure:"secret_key"`
	Issuer             string        `mapstructure:"issuer"`
	Audience           string        `mapstructure:"audience"`
	AccessTokenExpiry  time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry time.Duration `mapstructure:"refresh_token_expiry"`
	Algorithm          string        `mapstructure:"algorithm"`
}

type DatabaseConfig struct {
	Driver                string        `mapstructure:"driver"`
	Host                  string        `mapstructure:"host"`
	Port                  int           `mapstructure:"port"`
	Name                  string        `mapstructure:"name"`
	User                  string        `mapstructure:"user"`
	Password              string        `mapstructure:"password"`
	SSLMode               string        `mapstructure:"ssl_mode"`
	MaxConnections        int           `mapstructure:"max_connections"`
	MaxIdleConnections    int           `mapstructure:"max_idle_connections"`
	ConnectionMaxLifetime time.Duration `mapstructure:"connection_max_lifetime"`
}

func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode)
}



type TunnelsConfig struct {
	MaxPerUser         int           `mapstructure:"max_per_user"`
	ConnectionPoolSize int           `mapstructure:"connection_pool_size"`
	SubdomainLength    int           `mapstructure:"subdomain_length"`
	DefaultTTL         time.Duration `mapstructure:"default_ttl"`
	DomainHost         string        `mapstructure:"domain_host"`
}

type AnalyticsConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	RetentionDays   int    `mapstructure:"retention_days"`
	MetricsEndpoint string `mapstructure:"metrics_endpoint"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
}

type RateLimitConfig struct {
	Enabled               bool `mapstructure:"enabled"`
	APIRequestsPerMinute  int  `mapstructure:"api_requests_per_minute"`
	LoginAttemptsPerHour  int  `mapstructure:"login_attempts_per_hour"`
	TunnelCreationPerHour int  `mapstructure:"tunnel_creation_per_hour"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// Load reads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	return LoadWithSecrets(configPath, "")
}

// LoadWithSecrets reads configuration and secrets from separate files
func LoadWithSecrets(configPath, secretsPath string) (*Config, error) {
	viper.SetConfigName("server")
	viper.SetConfigType("yaml")

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.AddConfigPath("./configs")
		viper.AddConfigPath(".")
	}

	// Environment variable binding
	viper.SetEnvPrefix("SHIPIT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Load secrets separately
	secrets, err := LoadSecrets(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}
	cfg.Secrets = secrets

	// Override configuration with secrets
	cfg.applySecrets()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// applySecrets applies secrets to the main configuration
func (c *Config) applySecrets() {
	if c.Secrets == nil {
		return
	}

	// Apply database secrets
	if c.Secrets.Database.Password != "" {
		c.Database.Password = c.Secrets.Database.Password
	}

	// Apply JWT secrets
	if c.Secrets.JWT.SecretKey != "" {
		c.JWT.SecretKey = c.Secrets.JWT.SecretKey
	}

	// Apply TLS secrets
	if c.Secrets.TLS.CertPath != "" {
		c.TLS.CertFile = c.Secrets.TLS.CertPath
	}
	if c.Secrets.TLS.KeyPath != "" {
		c.TLS.KeyFile = c.Secrets.TLS.KeyPath
	}
}

// setDefaults sets default values for configuration
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.domain", "localhost")
	viper.SetDefault("server.http_port", 8080)
	viper.SetDefault("server.https_port", 8443)
	viper.SetDefault("server.agent_port", 7223)
	viper.SetDefault("server.environment", "development")

	// Auth defaults
	viper.SetDefault("auth.api_key_length", 32)
	viper.SetDefault("auth.hash_cost", 12)
	viper.SetDefault("auth.max_login_attempts", 5)
	viper.SetDefault("auth.lockout_duration", "15m")

	// JWT defaults
	viper.SetDefault("jwt.issuer", "shipit-server")
	viper.SetDefault("jwt.audience", "shipit-users")
	viper.SetDefault("jwt.access_token_expiry", "1h")
	viper.SetDefault("jwt.refresh_token_expiry", "168h")
	viper.SetDefault("jwt.algorithm", "HS256")

	// Database defaults
	viper.SetDefault("database.driver", "postgres")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_connections", 25)
	viper.SetDefault("database.max_idle_connections", 5)
	viper.SetDefault("database.connection_max_lifetime", "5m")



	// Tunnels defaults
	viper.SetDefault("tunnels.max_per_user", 10)
	viper.SetDefault("tunnels.connection_pool_size", 10)
	viper.SetDefault("tunnels.subdomain_length", 8)
	viper.SetDefault("tunnels.default_ttl", "24h")
	viper.SetDefault("tunnels.domain_host", "localhost")

	// Analytics defaults
	viper.SetDefault("analytics.enabled", true)
	viper.SetDefault("analytics.retention_days", 90)
	viper.SetDefault("analytics.metrics_endpoint", "/metrics")

	// CORS defaults
	viper.SetDefault("cors.allowed_origins", []string{"http://localhost:3000"})
	viper.SetDefault("cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("cors.allowed_headers", []string{"Authorization", "Content-Type"})
	viper.SetDefault("cors.allow_credentials", true)

	// Rate limiting defaults
	viper.SetDefault("rate_limiting.enabled", true)
	viper.SetDefault("rate_limiting.api_requests_per_minute", 100)
	viper.SetDefault("rate_limiting.login_attempts_per_hour", 10)
	viper.SetDefault("rate_limiting.tunnel_creation_per_hour", 20)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Domain == "" {
		return fmt.Errorf("server domain is required")
	}

	if c.JWT.SecretKey == "" || c.JWT.SecretKey == "your-256-bit-secret-change-this-in-production" {
		if c.Server.Environment == "production" {
			return fmt.Errorf("JWT secret key must be set for production environment")
		}
	}

	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	if c.Database.Name == "" {
		return fmt.Errorf("database name is required")
	}

	if c.Database.User == "" {
		return fmt.Errorf("database user is required")
	}

	// Validate secrets if present
	if c.Secrets != nil {
		if c.Server.Environment == "production" && !c.Secrets.IsProductionSecrets() {
			return fmt.Errorf("production environment requires production-grade secrets")
		}
	}

	return nil
}

// IsDevelopment returns true if the environment is development
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// DatabaseDSN returns the database connection string
func (c *Config) DatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
}


