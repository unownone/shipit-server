# Testing Guide

This guide covers the comprehensive test suite for the ShipIt Server API using **testcontainers** for automated database management.

## Overview

The test suite includes:
- **Authentication Tests**: User registration, login, logout, token validation
- **User Management Tests**: Profile management, API key operations
- **Tunnel Management Tests**: CRUD operations for tunnels
- **Analytics Tests**: Statistics and analytics endpoints
- **Health Check Tests**: System health monitoring
- **Automatic Database Management**: Using testcontainers for PostgreSQL

## Test Structure

```
test/
├── utils.go              # Test utilities and testcontainers setup
├── auth_test.go          # Authentication endpoint tests
├── users_test.go         # User management tests
├── tunnels_test.go       # Tunnel management tests
└── health_analytics_test.go # Health and analytics tests
```

## Prerequisites

### 1. Docker
The tests use **testcontainers** which automatically manages PostgreSQL containers. You only need Docker running:

```bash
# Check if Docker is running
make test-status

# Or manually check
docker info
```

### 2. No Manual Database Setup Required! 🎉
Unlike traditional testing setups, **testcontainers** eliminates the need for:
- ❌ Manual Docker commands
- ❌ Environment variable configuration
- ❌ Database cleanup scripts
- ❌ Port conflicts

Everything is managed automatically!

## Running Tests

### All Tests (Recommended)
```bash
make test
```

### With Coverage Report
```bash
make test-coverage
open coverage.html
```

### Complete CI Pipeline
```bash
make ci-test
```

## Testcontainers Benefits

### ✅ **Automatic Container Management**
- PostgreSQL containers are created and destroyed automatically
- Each test suite gets a fresh, isolated database
- No port conflicts or leftover containers

### ✅ **Zero Configuration**
- No environment variables needed
- No manual database setup
- Works consistently across all environments

### ✅ **Perfect Isolation**
- Each test run is completely isolated
- No data contamination between test runs
- Parallel test execution support

### ✅ **CI/CD Ready**
- Works seamlessly in GitHub Actions, Docker environments
- No external dependencies to manage
- Consistent results everywhere

## Test Features

### 1. Comprehensive API Coverage

The same comprehensive coverage as before:

- **Authentication Endpoints**
  - User registration with validation
  - Login with email/password
  - JWT token refresh
  - Token validation (JWT and API keys)
  - User logout

- **User Management**
  - Profile retrieval and updates
  - API key creation and management
  - API key revocation

- **Tunnel Operations**
  - HTTP and TCP tunnel creation
  - Tunnel listing and filtering
  - Individual tunnel retrieval
  - Tunnel deletion
  - Tunnel statistics

- **Analytics**
  - User analytics overview
  - Traffic analytics
  - Tunnel-specific analytics

### 2. Enhanced Test Infrastructure

#### Testcontainers Integration
```go
// Automatic PostgreSQL container setup
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
```

#### Automatic Container Lifecycle
```go
// Setup: Container starts automatically
suite := SetupTestSuite(t)

// Tests run with isolated database

// Cleanup: Container terminates automatically
defer suite.TearDownTestSuite(t)
```

### 3. Test Patterns

Same battle-tested patterns:
- Error and success case coverage
- Security testing (authorization, cross-user access)
- Input validation
- Response format verification

## Best Practices

### 1. **Zero Setup Required**
```bash
# Just run tests - testcontainers handles everything!
make test
```

### 2. **Debugging Container Issues**
```bash
# Check Docker status
make test-status

# View container logs
make test-logs

# Check running containers during tests
docker ps | grep testcontainers
```

### 3. **Performance Optimization**
- Containers start in parallel when possible
- Database connections are optimized for testing
- Container reuse within test suites

## Configuration

### TestSuite with Testcontainers
```go
type TestSuite struct {
    DB                *database.Database
    Config            *config.Config
    Router            *gin.Engine
    PasswordManager   *auth.PasswordManager
    JWTManager        *auth.JWTManager
    APIKeyManager     *auth.APIKeyManager
    
    // Testcontainers integration
    PostgresContainer *postgres.PostgresContainer
    
    // Test users
    TestUser     *TestUser
    TestUser2    *TestUser
    AdminUser    *TestUser
}
```

## Environment Compatibility

### ✅ **Local Development**
- Works on macOS, Linux, Windows
- Requires only Docker Desktop/Engine

### ✅ **CI/CD Environments**
- GitHub Actions
- GitLab CI
- Jenkins
- Any environment with Docker

### ✅ **Container Platforms**
- Docker
- Podman
- Docker-in-Docker (DinD)

## Migration Guide

If you were using manual database setup:

### Before (Manual)
```bash
# Old approach
make test-db        # Start container manually
make test          # Run tests
make test-db-stop  # Clean up manually
```

### After (Testcontainers)
```bash
# New approach - everything automatic!
make test          # That's it! 🎉
```

## Troubleshooting

### Docker Issues
```bash
# Check Docker status
make test-status

# Common solutions:
# 1. Start Docker Desktop
# 2. Check Docker daemon is running
# 3. Verify Docker permissions
```

### Container Port Conflicts
❌ **No longer possible!** Testcontainers uses random ports automatically.

### Database Connection Issues
❌ **Extremely rare!** Testcontainers waits for database readiness automatically.

### Test Isolation Problems
❌ **Eliminated!** Each test suite gets a fresh container.

## Performance

### Typical Test Run Times
- **Single test suite**: ~10-15 seconds (including container startup)
- **Full test suite**: ~30-45 seconds
- **With coverage**: ~45-60 seconds

### Optimization Tips
- Tests run in parallel where possible
- Container images are cached locally
- Database connections are pooled efficiently

## Adding New Tests

The same patterns apply - just focus on your test logic:

```go
func (s *TestSuite) TestNewEndpoint() {
    // No database setup needed - testcontainers handles it!
    
    resp := s.MakeRequest("POST", "/api/v1/endpoint", payload, nil)
    AssertSuccessResponse(s.T(), resp, 200)
}
```

## Summary

With **testcontainers**, testing is now:
- ✅ **Easier**: No manual setup
- ✅ **Faster**: No waiting for external dependencies  
- ✅ **Reliable**: Perfect isolation guaranteed
- ✅ **Portable**: Works everywhere Docker works

Just run `make test` and let testcontainers handle the rest! 🚀 