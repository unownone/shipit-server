package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// SecretsConfig holds all sensitive configuration
type SecretsConfig struct {
	Database DatabaseSecrets `mapstructure:"database"`
	JWT      JWTSecrets      `mapstructure:"jwt"`
	API      APISecrets      `mapstructure:"api"`
	External ExternalSecrets `mapstructure:"external"`
	TLS      TLSSecrets      `mapstructure:"tls"`
	Admin    AdminSecrets    `mapstructure:"admin"`
}

type DatabaseSecrets struct {
	Password      string `mapstructure:"password"`
	EncryptionKey string `mapstructure:"encryption_key"`
}

type JWTSecrets struct {
	SecretKey     string `mapstructure:"secret_key"`
	RefreshSecret string `mapstructure:"refresh_secret"`
}

type APISecrets struct {
	RateLimitSecret string `mapstructure:"rate_limit_secret"`
	WebhookSecret   string `mapstructure:"webhook_secret"`
}

type ExternalSecrets struct {
	StripeSecretKey    string `mapstructure:"stripe_secret_key"`
	SendGridAPIKey     string `mapstructure:"sendgrid_api_key"`
	CloudflareAPIKey   string `mapstructure:"cloudflare_api_key"`
}

type TLSSecrets struct {
	CertPath   string `mapstructure:"cert_path"`
	KeyPath    string `mapstructure:"key_path"`
	CACertPath string `mapstructure:"ca_cert_path"`
}

type AdminSecrets struct {
	Email    string `mapstructure:"email"`
	Password string `mapstructure:"password"`
}

// LoadSecrets loads secrets from file and environment variables
func LoadSecrets(secretsPath string) (*SecretsConfig, error) {
	// Create a separate viper instance for secrets
	secretsViper := viper.New()
	
	secretsViper.SetConfigName("secrets")
	secretsViper.SetConfigType("yaml")
	
	if secretsPath != "" {
		secretsViper.SetConfigFile(secretsPath)
	} else {
		secretsViper.AddConfigPath("./configs")
		secretsViper.AddConfigPath(".")
	}

	// Environment variable binding for secrets
	secretsViper.SetEnvPrefix("SHIPIT_SECRET")
	secretsViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	secretsViper.AutomaticEnv()

	// Set default values
	setSecretsDefaults(secretsViper)

	// Try to read the secrets file (optional in production)
	if err := secretsViper.ReadInConfig(); err != nil {
		// In production, secrets might come only from environment variables
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read secrets config: %w", err)
		}
	}

	var secrets SecretsConfig
	if err := secretsViper.Unmarshal(&secrets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets config: %w", err)
	}

	// Override with direct environment variables (Docker secrets pattern)
	overrideFromDockerSecrets(&secrets)

	// Validate critical secrets
	if err := validateSecrets(&secrets); err != nil {
		return nil, fmt.Errorf("secrets validation failed: %w", err)
	}

	return &secrets, nil
}

// setSecretsDefaults sets default values for secrets (development only)
func setSecretsDefaults(v *viper.Viper) {
	// Database defaults
	v.SetDefault("database.password", "shipit_dev_password")
	v.SetDefault("database.encryption_key", "dev-database-encryption-key-32-chars")

	// JWT defaults
	v.SetDefault("jwt.secret_key", "dev-jwt-secret-key-change-in-production-256-bit")
	v.SetDefault("jwt.refresh_secret", "dev-refresh-secret-key-change-in-production-256")

	// API defaults
	v.SetDefault("api.rate_limit_secret", "dev-rate-limit-hmac-secret-key")
	v.SetDefault("api.webhook_secret", "dev-webhook-verification-secret")

	// Admin defaults
	v.SetDefault("admin.email", "admin@localhost")
	v.SetDefault("admin.password", "admin123456")
}

// overrideFromEnvironment loads secrets from environment variables
func overrideFromDockerSecrets(secrets *SecretsConfig) {
	// Primary: Environment variables (preferred method)
	envOverrides := map[string]*string{
		"SHIPIT_SECRET_DATABASE_PASSWORD":    &secrets.Database.Password,
		"SHIPIT_SECRET_JWT_SECRET_KEY":       &secrets.JWT.SecretKey,
		"SHIPIT_SECRET_JWT_REFRESH_SECRET":   &secrets.JWT.RefreshSecret,
		"SHIPIT_SECRET_ADMIN_EMAIL":          &secrets.Admin.Email,
		"SHIPIT_SECRET_ADMIN_PASSWORD":       &secrets.Admin.Password,
		"SHIPIT_SECRET_API_RATE_LIMIT_SECRET": &secrets.API.RateLimitSecret,
		"SHIPIT_SECRET_WEBHOOK_SECRET":       &secrets.API.WebhookSecret,
		"SHIPIT_SECRET_STRIPE_SECRET_KEY":    &secrets.External.StripeSecretKey,
		"SHIPIT_SECRET_SENDGRID_API_KEY":     &secrets.External.SendGridAPIKey,
		"SHIPIT_SECRET_CLOUDFLARE_API_KEY":   &secrets.External.CloudflareAPIKey,
	}

	for envVar, target := range envOverrides {
		if value := os.Getenv(envVar); value != "" {
			*target = value
		}
	}

	// Fallback: Docker secrets files (for legacy compatibility)
	secretFiles := map[string]*string{
		"/run/secrets/database_password":    &secrets.Database.Password,
		"/run/secrets/jwt_secret_key":       &secrets.JWT.SecretKey,
		"/run/secrets/jwt_refresh_secret":   &secrets.JWT.RefreshSecret,
		"/run/secrets/admin_password":       &secrets.Admin.Password,
		"/run/secrets/stripe_secret_key":    &secrets.External.StripeSecretKey,
		"/run/secrets/sendgrid_api_key":     &secrets.External.SendGridAPIKey,
		"/run/secrets/cloudflare_api_key":   &secrets.External.CloudflareAPIKey,
	}

	// Only read from files if environment variables are not set
	for filePath, target := range secretFiles {
		if *target == "" { // Only if not already set by environment variable
			if content, err := os.ReadFile(filePath); err == nil {
				*target = strings.TrimSpace(string(content))
			}
		}
	}
}

// validateSecrets validates that required secrets are present
func validateSecrets(secrets *SecretsConfig) error {
	environment := os.Getenv("SHIPIT_SERVER_ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	// In production, enforce stronger secret requirements
	if environment == "production" {
		if secrets.JWT.SecretKey == "" || strings.Contains(secrets.JWT.SecretKey, "dev-") {
			return fmt.Errorf("JWT secret key must be set for production environment")
		}

		if len(secrets.JWT.SecretKey) < 32 {
			return fmt.Errorf("JWT secret key must be at least 32 characters long")
		}

		if secrets.Database.Password == "" || secrets.Database.Password == "shipit_dev_password" {
			return fmt.Errorf("database password must be set for production environment")
		}

		if secrets.Admin.Password == "admin123456" {
			return fmt.Errorf("admin password must be changed for production environment")
		}
	}

	// Always validate that secrets are not empty
	if secrets.Database.Password == "" {
		return fmt.Errorf("database password is required")
	}

	if secrets.JWT.SecretKey == "" {
		return fmt.Errorf("JWT secret key is required")
	}

	return nil
}

// GetSecretValue safely retrieves a secret value with fallback
func (s *SecretsConfig) GetSecretValue(key string) string {
	switch key {
	case "database.password":
		return s.Database.Password
	case "jwt.secret_key":
		return s.JWT.SecretKey
	case "jwt.refresh_secret":
		return s.JWT.RefreshSecret
	case "admin.email":
		return s.Admin.Email
	case "admin.password":
		return s.Admin.Password
	default:
		return ""
	}
}

// IsProductionSecrets returns true if secrets are configured for production
func (s *SecretsConfig) IsProductionSecrets() bool {
	return !strings.Contains(s.JWT.SecretKey, "dev-") && 
		   s.Database.Password != "shipit_dev_password" &&
		   s.Admin.Password != "admin123456"
} 