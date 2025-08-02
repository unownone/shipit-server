# ShipIt Server

[![CI/CD Pipeline](https://github.com/unownone/shipit-server/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/unownone/shipit-server/actions)
[![codecov](https://codecov.io/gh/unownone/shipit-server/graph/badge.svg?token=HO0WY5GC5W)](https://codecov.io/gh/unownone/shipit-server)
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/unownone/shipit-server?utm_source=oss&utm_medium=github&utm_campaign=unownone%2Fshipit-server&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

A secure, high-performance tunneling server that creates secure tunnels to expose local services to the internet. Supports both HTTP and TCP tunneling with comprehensive authentication, analytics, and management capabilities.

## Features

🔐 **Secure Authentication**

- JWT-based authentication for web users
- API key authentication for CLI agents
- Role-based access control (User, Moderator, Admin)
- Secure password hashing with bcrypt

🌐 **Tunneling Capabilities**

- HTTP tunnels with subdomain routing
- TCP tunnels with dynamic port allocation
- Connection pooling for high performance
- Real-time tunnel status monitoring

📊 **Analytics & Monitoring**

- Detailed tunnel usage statistics
- Request/response analytics
- Connection monitoring
- User activity tracking

📝 **Structured Logging**

- JSON-formatted logs for easy parsing
- Configurable log levels (debug, info, warn, error)
- Contextual logging with relevant fields
- Error tracking with full context

🛡️ **Security Features**

- API keys are never stored in plaintext (SHA-256 hashed)
- Secure token generation and validation
- CORS protection
- Rate limiting and abuse protection

## Quick Start

### Prerequisites

- Go 1.24+
- PostgreSQL 16+
- Redis 7+ (optional, for advanced features)
- Docker & Docker Compose (for easy setup)

### Development Setup

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd shipit-server
   ```

2. **Initialize environment variables**

   ```bash
   make env-init  # Creates .env from .env.example
   ```

3. **Start services with Docker**

   ```bash
   # Option 1: Start everything in Docker
   make docker-up-all
   
   # Option 2: Start only databases, run server locally
   make docker-up
   make deps
   make run
   ```

4. **Or use the quick setup**

   ```bash
   make dev  # Sets up .env, databases and dependencies
   make run  # Run server locally
   ```

## 📚 **API Documentation**

ShipIt Server provides a comprehensive REST API with automatic documentation generation using Swaggo.

### **Interactive Documentation**

- **Local Development**: `http://localhost:8080/swagger/index.html`
- **GitHub Pages**: `https://[username].github.io/[repo-name]/` (auto-deployed)

### **Generating Documentation**

```bash
# Generate documentation from code comments
make docs

# Or use the script directly
./scripts/generate-docs.sh
```

### **API Structure**

The API is organized into logical groups:

- **Authentication** (`/api/v1/auth/*`) - Token validation, user management
- **Users** (`/api/v1/users/*`) - Registration, login, profile management
- **Tunnels** (`/api/v1/tunnels/*`) - Tunnel creation and management
- **Analytics** (`/api/v1/analytics/*`) - Usage statistics and monitoring
- **Admin** (`/api/v1/admin/*`) - Administrative endpoints

### **Authentication Methods**

1. **JWT Authentication** (Web Users)
   - Bearer token in Authorization header
   - Used for web dashboard and user management

2. **API Key Authentication** (CLI Agents)
   - API key in Authorization header or X-API-KEY header
   - Used for tunnel creation and management

3. **Combined Authentication** (Some endpoints)
   - Accepts both JWT and API key authentication
   - Flexible for different client types

### **Key Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/users/register` | Register new user | None |
| `POST` | `/api/v1/users/login` | User login | None |
| `POST` | `/api/v1/tunnels` | Create tunnel | API Key |
| `GET` | `/api/v1/tunnels` | List tunnels | JWT/API Key |
| `GET` | `/api/v1/analytics/overview` | Analytics overview | JWT |

### **Response Formats**

All API responses follow a consistent format:

```json
{
  "status": "success",
  "data": { ... },
  "message": "Operation completed successfully"
}
```

Error responses include detailed information:

```json
{
  "error": "Error description",
  "details": "Additional error context",
  "code": "ERROR_CODE"
}
```

## 🔧 **Environment Configuration**

ShipIt uses environment variables for all configuration. This makes it easy to deploy across different environments without changing code.

### **Environment Files**

- **`.env.example`** - Development template with safe defaults
- **`.env.production.example`** - Production template with security settings
- **`.env`** - Your actual environment file (not in git)

### **Quick Setup**

```bash
# Development
make env-init               # Copy .env.example to .env
nano .env                   # Edit if needed

# Production  
make env-prod-init         # Copy .env.production.example to .env
make secrets-generate      # Generate secure random secrets
nano .env                  # Update CHANGE_ME values
make env-validate         # Validate configuration
```

### **Key Environment Variables**

```bash
# Core Settings
SHIPIT_SERVER_ENVIRONMENT=development
SHIPIT_SERVER_DOMAIN=localhost
SHIPIT_SECRET_DATABASE_PASSWORD=your_db_password
SHIPIT_SECRET_JWT_SECRET_KEY=your_jwt_secret
SHIPIT_SECRET_ADMIN_PASSWORD=your_admin_password

# Docker Overrides (automatic in docker-compose)
SHIPIT_DATABASE_HOST=postgres
SHIPIT_REDIS_HOST=redis
```

The server will start on `http://localhost:8080` with the following services:

- API endpoints: `http://localhost:8080/api/v1`
- Health check: `http://localhost:8080/health`

## 🐳 **Docker Support**

### Development with Docker

```bash
# Quick start - everything in Docker
make docker-up-all

# Or databases only, server locally
make docker-up
make run
```

### Production with Docker

```bash
# Generate production secrets
./scripts/create-prod-secrets.sh

# Deploy to production
DOMAIN=yourdomain.com docker-compose -f docker-compose.prod.yml up -d
```

### Docker Features

- ✅ **Multi-stage builds** for optimized production images
- ✅ **Secret management** with Docker secrets
- ✅ **Health checks** for all services
- ✅ **Security hardening** in production (read-only containers, dropped capabilities)
- ✅ **Resource limits** and restart policies
- ✅ **Network isolation** with custom networks

### Production Setup

#### Docker Deployment (Recommended)

1. **Set up environment**

   ```bash
   # Copy production template
   cp .env.production.example .env
   
   # Generate secure secrets
   make secrets-generate
   
   # Edit .env and replace all CHANGE_ME values
   nano .env
   ```

2. **Validate and deploy**

   ```bash
   make env-validate                    # Check configuration
   make docker-prod-deploy              # Deploy with docker-compose
   ```

#### Binary Deployment

1. **Build the binary**

   ```bash
   make build-linux
   ```

2. **Set up environment**

   ```bash
   # Create .env file
   cp .env.production.example .env
   nano .env  # Update all CHANGE_ME values
   
   # Or export environment variables directly
   export SHIPIT_SECRET_JWT_SECRET_KEY="your-secure-256-bit-secret"
   export SHIPIT_SECRET_DATABASE_PASSWORD="your-secure-password"
   export SHIPIT_SERVER_DOMAIN="yourdomain.com"
   export SHIPIT_SERVER_ENVIRONMENT="production"
   ```

3. **Run the server**

   ```bash
   ./bin/shipit-server-linux
   ```

## API Documentation

### Authentication

#### Register a User

```bash
curl -X POST http://localhost:8080/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "name": "John Doe"
  }'
```

#### Login

```bash
curl -X POST http://localhost:8080/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

#### Create API Key

```bash
curl -X POST http://localhost:8080/api/v1/users/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "CLI Development Key"
  }'
```

### Tunnel Management

#### Create HTTP Tunnel

```bash
curl -X POST http://localhost:8080/api/v1/tunnels \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "name": "My Web App",
    "protocol": "http",
    "local_port": 3000,
    "subdomain": "myapp"
  }'
```

#### Create TCP Tunnel

```bash
curl -X POST http://localhost:8080/api/v1/tunnels \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "name": "Database Tunnel",
    "protocol": "tcp",
    "local_port": 5432
  }'
```

#### List Tunnels

```bash
curl -X GET http://localhost:8080/api/v1/tunnels \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### Get Tunnel Statistics

```bash
curl -X GET http://localhost:8080/api/v1/tunnels/{tunnelId}/stats \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Configuration

The server uses a YAML configuration file (`configs/server.yaml`). Key settings include:

```yaml
server:
  domain: "localhost"           # Your domain for tunnel URLs
  http_port: 8080              # API server port
  environment: "development"    # development, staging, production

auth:
  api_key_length: 32           # Length of generated API keys
  hash_cost: 12                # bcrypt cost factor

jwt:
  secret_key: "change-me"      # JWT signing secret
  access_token_expiry: "1h"    # Access token expiration
  refresh_token_expiry: "168h" # Refresh token expiration (7 days)

database:
  host: "localhost"
  port: 5432
  name: "shipit"
  user: "shipit_user"
  password: "shipit_dev_password"

tunnels:
  max_per_user: 10             # Maximum tunnels per user
  subdomain_length: 8          # Length of auto-generated subdomains
  default_ttl: "24h"           # Default tunnel expiration
```

### Environment Variables

You can override any configuration value using environment variables with the `SHIPIT_` prefix:

```bash
SHIPIT_SERVER_DOMAIN=example.com
SHIPIT_JWT_SECRET_KEY=your-secret-key
SHIPIT_DATABASE_PASSWORD=secure-password
SHIPIT_SERVER_ENVIRONMENT=production
```

## Database Schema

The server automatically creates and migrates the following tables:

- `users` - User accounts and authentication
- `api_keys` - API keys for tunnel access (hashed)
- `refresh_tokens` - JWT refresh tokens
- `tunnels` - Tunnel configurations and status
- `tunnel_analytics` - Usage statistics and metrics
- `connections` - Active tunnel connections
- `login_attempts` - Security audit log
- `user_sessions` - Active user sessions

## Security

### API Key Security

- API keys are **never stored in plaintext**
- Keys are hashed using SHA-256 before storage
- Only the first 8 characters + "..." are shown in the UI
- Keys are generated using cryptographically secure random numbers

### Password Security

- Passwords are hashed using bcrypt with configurable cost
- Minimum password requirements enforced
- Failed login attempts are tracked and logged

### Authentication Flow

1. **Web Users**: JWT-based authentication with refresh tokens
2. **CLI Agents**: Long-lived API keys for programmatic access
3. **Role-based Access**: Different permission levels (User, Moderator, Admin)

## Performance

### Connection Pooling

- Database connection pooling with configurable limits
- Redis connection pooling for session storage
- HTTP connection keep-alive for better performance

### Monitoring

- Built-in health check endpoint
- Database connection monitoring
- Automated cleanup of expired tokens and sessions

## Development

### Project Structure

```shell
shipit-server/
├── cmd/server/          # Main application entry point
├── internal/            # Private application code
│   ├── api/            # API handlers and routes
│   ├── auth/           # Authentication management
│   ├── config/         # Configuration management
│   └── database/       # Database connection and migrations
├── pkg/types/          # Public types and interfaces
├── configs/            # Configuration files
└── scripts/            # Database and deployment scripts
```

### Running Tests

```bash
go test ./...
```

### Building for Production

```bash
# Build for current platform
go build -o shipit-server cmd/server/main.go

# Build for Linux (common for deployment)
GOOS=linux GOARCH=amd64 go build -o shipit-server-linux cmd/server/main.go
```

## 🧪 Testing

ShipIt Server features a comprehensive test suite powered by **testcontainers** for seamless testing:

### ✅ **Zero-Setup Testing**

```bash
# Just run tests - no manual database setup required!
make test

# Test the basic container setup
go test -v ./test/ -run TestSimpleContainerSetup
```

### 🚀 **Testcontainers Integration**

- **Automatic PostgreSQL containers** for each test run  
- **Perfect isolation** - each test gets a fresh database
- **No configuration needed** - works everywhere Docker works
- **CI/CD ready** - runs consistently across all environments

### 📊 **Current Status**

- ✅ **Testcontainers Setup**: Verified working with PostgreSQL
- ✅ **Database Connectivity**: Automatic container management
- ✅ **Schema Creation**: Dynamic table creation in tests
- ✅ **Data Operations**: Insert/query operations working
- 🔧 **Full API Tests**: In development (JWT/UUID handling being refined)

### 🛠 **Available Commands**

```bash
make test-status       # Check Docker status
go test ./test/        # Run all available tests
make docs             # Generate API documentation
```

### 📖 **Test Output Example**

```markdown
=== RUN   TestSimpleContainerSetup
🐳 Creating container for image postgres:15-alpine
✅ Container started: bc96165da423
⏳ Waiting for container to be ready...
🔔 Container is ready!
    Container setup successful!
    Host: localhost, Port: 53799
    Database URL: postgres://shipit_test:test_password@localhost:53799/shipit_test
    ✅ Testcontainers setup verification successful!
--- PASS: TestSimpleContainerSetup (1.81s)
```

### 📖 **Documentation**

- [Complete Testing Guide](docs/TESTING.md) - Detailed testing documentation  
- [API Documentation](http://localhost:8080/swagger/index.html) - Interactive Swagger UI

**Benefits:**

- 🎯 **No manual setup** - testcontainers handles everything
- 🔒 **Perfect isolation** - no test data contamination  
- 🚀 **Fast feedback** - optimized for developer workflow
- 📊 **Automatic cleanup** - containers removed after tests

---

## Troubleshooting

### Common Issues

1. **Database Connection Failed**

   ```bash
   # Check if PostgreSQL is running
   docker-compose ps
   
   # Check database logs
   docker-compose logs postgres
   ```

2. **JWT Token Invalid**
   - Ensure JWT secret key is set and consistent
   - Check token expiration time
   - Verify token format in Authorization header

3. **API Key Not Working**
   - Ensure API key starts with `shipit_`
   - Check if key is active and not expired
   - Verify correct Authorization header format

### Debug Mode

Set log level to debug for more verbose output:

```yaml
logging:
  level: "debug"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

[Add your license information here]

## Support

For issues and questions:

- Check the troubleshooting section above
- Review the API documentation
- Open an issue on GitHub
