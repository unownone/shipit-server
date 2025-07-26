# Environment Configuration Guide

ShipIt Server uses environment variables for all configuration, making it easy to deploy across different environments without changing code.

## Quick Start

```bash
# Development
make env-init        # Creates .env from template
make dev            # Start development environment

# Production
make env-prod-init   # Creates production .env template
make secrets-generate # Generate secure secrets
# Edit .env with your values
make env-validate    # Validate configuration
make docker-prod-deploy # Deploy
```

## Environment Files

| File | Purpose | Git Tracked |
|------|---------|-------------|
| `.env.example` | Development template with safe defaults | ✅ Yes |
| `.env.production.example` | Production template with security settings | ✅ Yes |
| `.env` | Your actual environment configuration | ❌ No (in .gitignore) |

## Configuration Categories

### 🌍 Environment Settings

```bash
SHIPIT_SERVER_ENVIRONMENT=development    # development, production
SHIPIT_SERVER_DOMAIN=localhost          # Your domain name
SHIPIT_SERVER_HTTP_PORT=8080            # HTTP server port
SHIPIT_SERVER_HTTPS_PORT=8443           # HTTPS server port (production)
SHIPIT_SERVER_AGENT_PORT=7223           # Agent connection port
```

### 🔒 Secrets (Critical!)

```bash
# Database
SHIPIT_SECRET_DATABASE_PASSWORD=your_secure_password

# JWT Authentication  
SHIPIT_SECRET_JWT_SECRET_KEY=your_256_bit_secret
SHIPIT_SECRET_JWT_REFRESH_SECRET=your_refresh_secret

# Initial Admin User
SHIPIT_SECRET_ADMIN_EMAIL=admin@yourdomain.com
SHIPIT_SECRET_ADMIN_PASSWORD=your_admin_password

# API Security
SHIPIT_SECRET_API_RATE_LIMIT_SECRET=your_rate_limit_secret
SHIPIT_SECRET_WEBHOOK_SECRET=your_webhook_secret
```

### 🗄️ Database Configuration

```bash
SHIPIT_DATABASE_HOST=localhost          # Database host
SHIPIT_DATABASE_PORT=5432              # Database port
SHIPIT_DATABASE_NAME=shipit            # Database name
SHIPIT_DATABASE_USER=shipit_user       # Database user
SHIPIT_DATABASE_SSL_MODE=disable       # disable, require, verify-full
SHIPIT_DATABASE_MAX_CONNECTIONS=25     # Connection pool size
SHIPIT_DATABASE_MAX_IDLE_CONNECTIONS=5 # Idle connection limit
```

### 📦 Redis Configuration

```bash
SHIPIT_REDIS_HOST=localhost            # Redis host
SHIPIT_REDIS_PORT=6379                # Redis port
SHIPIT_REDIS_PASSWORD=                # Redis password (optional)
SHIPIT_REDIS_DB=0                     # Redis database number
```

### 🔐 Authentication Settings

```bash
SHIPIT_AUTH_API_KEY_LENGTH=32         # API key length
SHIPIT_AUTH_HASH_COST=12              # bcrypt cost (12 dev, 14 prod)
SHIPIT_AUTH_MAX_LOGIN_ATTEMPTS=5      # Max failed login attempts
SHIPIT_AUTH_LOCKOUT_DURATION=15m      # Account lockout duration
```

### 🎫 JWT Configuration

```bash
SHIPIT_JWT_ISSUER=shipit-server           # JWT issuer
SHIPIT_JWT_AUDIENCE=shipit-users          # JWT audience
SHIPIT_JWT_ACCESS_TOKEN_EXPIRY=1h         # Access token lifetime
SHIPIT_JWT_REFRESH_TOKEN_EXPIRY=168h      # Refresh token lifetime (7 days)
SHIPIT_JWT_ALGORITHM=HS256                # Signing algorithm
```

### 🌐 Tunnel Settings

```bash
SHIPIT_TUNNELS_MAX_PER_USER=10        # Max tunnels per user
SHIPIT_TUNNELS_CONNECTION_POOL_SIZE=20 # Connection pool size
SHIPIT_TUNNELS_SUBDOMAIN_LENGTH=8     # Generated subdomain length
SHIPIT_TUNNELS_DEFAULT_TTL=24h        # Default tunnel lifetime
```

### 📊 Analytics & Monitoring

```bash
SHIPIT_ANALYTICS_ENABLED=true         # Enable analytics collection
SHIPIT_ANALYTICS_RETENTION_DAYS=90    # Data retention period
SHIPIT_ANALYTICS_METRICS_ENDPOINT=/metrics # Prometheus metrics endpoint
```

### 🔗 CORS Configuration

```bash
SHIPIT_CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
SHIPIT_CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
SHIPIT_CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Requested-With
SHIPIT_CORS_ALLOW_CREDENTIALS=true
```

### 🛡️ Rate Limiting

```bash
SHIPIT_RATE_LIMITING_ENABLED=true     # Enable rate limiting
SHIPIT_RATE_LIMITING_API_REQUESTS_PER_MINUTE=60    # API rate limit
SHIPIT_RATE_LIMITING_LOGIN_ATTEMPTS_PER_HOUR=10    # Login rate limit
SHIPIT_RATE_LIMITING_TUNNEL_CREATION_PER_HOUR=10   # Tunnel creation limit
```

### 📝 Logging

```bash
LOG_LEVEL=info                    # debug, info, warn, error (default: info)
```

The application uses structured JSON logging with the following features:

- **Structured Output**: All logs are in JSON format for easy parsing
- **Log Levels**: Control verbosity with `LOG_LEVEL` environment variable
- **Contextual Fields**: Logs include relevant context (user_id, request_id, etc.)
- **Error Tracking**: Errors are logged with full context and stack traces
- **Performance**: Minimal overhead with async logging

#### Log Levels

- **debug**: Detailed debugging information
- **info**: General application information (default)
- **warn**: Warning messages for potential issues
- **error**: Error messages for actual problems

#### Examples

```bash
# Development with verbose logging
LOG_LEVEL=debug make run

# Production with minimal logging
LOG_LEVEL=warn make docker-prod-deploy

# Test with info level
LOG_LEVEL=info make test
```

#### Log Output Format

```json
{
  "level": "info",
  "msg": "Database connection established successfully",
  "time": "2025-07-26T17:54:21.309+05:30"
}

{
  "level": "error",
  "msg": "Failed to connect to database",
  "error": "connection refused",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "time": "2025-07-26T17:54:21.309+05:30"
}
```

### 🔐 TLS/SSL (Production)

```bash
SHIPIT_TLS_CERT_FILE=/etc/ssl/certs/shipit.crt    # Certificate file path
SHIPIT_TLS_KEY_FILE=/etc/ssl/private/shipit.key   # Private key file path
SHIPIT_TLS_AUTO_CERT=false                        # Enable Let's Encrypt
```

### 🌐 External Services (Optional)

```bash
SHIPIT_SECRET_STRIPE_SECRET_KEY=sk_live_...       # Stripe payments
SHIPIT_SECRET_SENDGRID_API_KEY=SG....             # Email service
SHIPIT_SECRET_CLOUDFLARE_API_KEY=...              # DNS/CDN
```

## Environment-Specific Settings

### Development

```bash
SHIPIT_SERVER_ENVIRONMENT=development
SHIPIT_AUTH_HASH_COST=12                  # Faster for development
SHIPIT_JWT_ACCESS_TOKEN_EXPIRY=1h         # Longer for convenience
SHIPIT_TUNNELS_MAX_PER_USER=10           # Higher limits
SHIPIT_DATABASE_SSL_MODE=disable          # Simpler setup
SHIPIT_LOGGING_LEVEL=debug               # Verbose logging
```

### Production

```bash
SHIPIT_SERVER_ENVIRONMENT=production
SHIPIT_AUTH_HASH_COST=14                  # Stronger security
SHIPIT_JWT_ACCESS_TOKEN_EXPIRY=15m        # Shorter for security
SHIPIT_TUNNELS_MAX_PER_USER=5            # Conservative limits
SHIPIT_DATABASE_SSL_MODE=require          # Enforce SSL
SHIPIT_LOGGING_LEVEL=info                # Production logging
```

## Docker Integration

When using Docker Compose, the following variables are automatically overridden:

```bash
SHIPIT_DATABASE_HOST=postgres    # Container name
SHIPIT_REDIS_HOST=redis         # Container name
```

The `docker-compose.yml` loads your `.env` file automatically and overrides networking for containers.

## Security Best Practices

### 🔐 Secret Management

1. **Generate Strong Secrets**
   ```bash
   make secrets-generate  # Generates cryptographically secure secrets
   ```

2. **Never Commit Secrets**
   - `.env` is in `.gitignore`
   - Use different secrets for each environment
   - Rotate secrets regularly

3. **Production Requirements**
   ```bash
   make env-validate  # Validates no CHANGE_ME values remain
   ```

### 🛡️ Environment Validation

```bash
# Check for placeholder values
make env-validate

# Generate new secrets
make secrets-generate

# Example secure values
SHIPIT_SECRET_JWT_SECRET_KEY=$(openssl rand -hex 32)
SHIPIT_SECRET_DATABASE_PASSWORD=$(openssl rand -base64 32)
```

### 🔒 Access Control

- Use environment variables in CI/CD systems
- Store secrets in secure secret management systems
- Use least-privilege access principles
- Monitor secret access and rotation

## Troubleshooting

### Common Issues

1. **Missing .env file**
   ```bash
   make env-init  # Creates from template
   ```

2. **Invalid configuration**
   ```bash
   make env-validate  # Checks for issues
   ```

3. **Docker networking issues**
   - Ensure `SHIPIT_DATABASE_HOST=postgres` in Docker
   - Ensure `SHIPIT_REDIS_HOST=redis` in Docker

4. **Secret validation errors**
   - Update all `CHANGE_ME` values
   - Use `make secrets-generate` for secure values

### Debugging

```bash
# Show current config (secrets hidden)
docker exec shipit-server printenv | grep SHIPIT | grep -v SECRET

# Check if services can connect
docker exec shipit-server curl -f http://localhost:8080/health

# Validate environment
make env-validate
```

### Migration from File-based Secrets

If migrating from the old file-based secret system:

```bash
# Old method (deprecated)
echo "secret" > secrets/db_password.txt

# New method (recommended)  
echo "SHIPIT_SECRET_DATABASE_PASSWORD=secret" >> .env
```

The system supports both methods for backward compatibility, but environment variables take precedence. 