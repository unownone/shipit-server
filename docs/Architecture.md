# ShipIt Server Architecture

## Overview

The ShipIt server is the central nervous system of the tunneling service, responsible for managing all tunnel operations, routing traffic, and providing APIs for client agents. It implements a clear separation between Control Plane (management) and Data Plane (traffic forwarding) operations.

## 1. Requirements

### 1.1 Functional Requirements

#### Core Tunneling

- **Reverse Tunnel Management**: Establish and maintain persistent connections from client agents
- **HTTP Traffic Forwarding**: Route HTTP requests from visitors to appropriate client agents
- **TCP Traffic Forwarding**: Forward raw TCP connections to client agents
- **Subdomain Routing**: Support `<prefix>.<domain>` routing for HTTP tunnels
- **Connection Pooling**: Maintain pools of persistent connections for low-latency forwarding

#### Authentication & Security

- **API Key Authentication**: Secure authentication using bearer tokens (for CLI agents)
- **JWT Authentication**: User session management for web interface and analytics
- **User Management**: Registration, login, logout, and profile management
- **TLS Encryption**: All communications encrypted with TLS
- **Input Validation**: Rigorous validation of all user inputs
- **Rate Limiting**: Protection against abuse and DoS attacks

#### Tunnel Lifecycle

- **Tunnel Creation**: API endpoints for creating new tunnels
- **Tunnel Termination**: Graceful shutdown of tunnels
- **State Management**: Track active tunnels and their connection pools
- **Subdomain Assignment**: Dynamic or user-requested subdomain allocation

### 1.2 Non-Functional Requirements

#### Performance

- **High Throughput**: Handle thousands of concurrent connections
- **Low Latency**: Minimize overhead in data forwarding path
- **Scalable**: Support hundreds of active tunnels simultaneously

#### Reliability

- **Connection Recovery**: Handle network interruptions gracefully
- **State Consistency**: Maintain accurate tunnel state
- **Error Handling**: Comprehensive error handling and logging

#### Security

- **Secure by Default**: All endpoints secured with TLS
- **API Security**: Protected API endpoints with proper authentication
- **Attack Surface Minimization**: Minimal exposed services and ports

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Visitor     │    │   Client Agent  │    │     Server      │
│  (Web Browser)  │    │   (CLI Tool)    │    │  (Central Hub)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. HTTP Request       │                       │
         │ GET example.com       │                       │
         ├──────────────────────────────────────────────▶│
         │                       │                       │
         │                       │ 2. Forward Request    │
         │                       │◀──────────────────────┤
         │                       │                       │
         │                       │ 3. Local Request      │
         │                       │ localhost:8080        │
         │                       ├─────────────────────▶ │
         │                       │                    ┌──┴──┐
         │                       │ 4. Response        │Local│
         │                       │◀───────────────────┤ App │
         │                       │                    └──┬──┘
         │                       │ 5. Forward Response   │
         │                       ├──────────────────────▶│
         │ 6. HTTP Response      │                       │
         │◀──────────────────────────────────────────────┤
```

### 2.2 Component Architecture

#### 2.2.1 Control Plane vs Data Plane Separation

**Control Plane** (Management Operations):

- Authentication & authorization
- Tunnel lifecycle management
- Configuration management
- Analytics endpoints
- Port: 443 (HTTPS API)

**Data Plane** (Traffic Forwarding):

- High-throughput data forwarding
- Connection pool management
- Protocol multiplexing
- Port: 7223 (Custom TLS protocol)

#### 2.2.2 Core Components

```
┌─────────────────────────────────────────────────────┐
│                   ShipIt Server                     │
├─────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────────────────┐│
│  │ Public Listener │  │     Agent Listener          ││
│  │ (HTTP/S Traffic)│  │  (Control + Data Plane)     ││
│  │ Ports: 80, 443 │  │     Port: 7223              ││
│  └─────────────────┘  └─────────────────────────────┘│
│           │                          │               │
│           ▼                          ▼               │
│  ┌─────────────────┐  ┌─────────────────────────────┐│
│  │ Tunnel Manager  │  │      API Handler            ││
│  │ (State & Route) │  │  (Control Plane Logic)      ││
│  └─────────────────┘  └─────────────────────────────┘│
│           │                          │               │
│           └────────────┬─────────────┘               │
│                        ▼                             │
│              ┌─────────────────┐                     │
│              │ Connection Pool │                     │
│              │   Management    │                     │
│              └─────────────────┘                     │
└─────────────────────────────────────────────────────┘
```

## 3. API Design

### 3.1 Authentication System

#### Two-Tier Authentication Model

**API Keys (for CLI Agents)**

- Long-lived tokens for programmatic access
- Used by CLI clients for tunnel operations
- Format: `Authorization: Bearer <api-key>`

**JWT Tokens (for User Sessions)**

- Short-lived tokens for web interface access
- Used for analytics dashboard and user management
- Format: `Authorization: Bearer <jwt-token>`

#### JWT Authentication Flow

```
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Web Client │    │   ShipIt Server │    │    Database     │
│ (Dashboard) │    │                 │    │                 │
└─────────────┘    └─────────────────┘    └─────────────────┘
       │                     │                     │
       │ 1. POST /api/users/login              │
       │ { email, password }   │                     │
       ├─────────────────────▶│                     │
       │                     │ 2. Validate User     │
       │                     ├─────────────────────▶│
       │                     │ 3. User Data         │
       │                     │◀─────────────────────┤
       │ 4. JWT + Refresh     │                     │
       │ { jwt_token, refresh_token }                │
       │◀─────────────────────┤                     │
       │                     │                     │
       │ 5. API Requests      │                     │
       │ Authorization: Bearer <jwt>                 │
       ├─────────────────────▶│                     │
       │                     │ 6. Validate JWT      │
       │                     │ (middleware)         │
       │ 7. Protected Data    │                     │
       │◀─────────────────────┤                     │
```

#### User-API Key Relationship

- Each user can have multiple API keys for different environments
- API keys are linked to user accounts for analytics and management
- CLI operations are tied to user identity through API keys
- Web dashboard shows all tunnels and analytics for the authenticated user

### 3.2 Control Plane API

#### Authentication Headers

- **Tunnel API**: `Authorization: Bearer <api-key>`
- **User API**: `Authorization: Bearer <jwt-token>`

#### Endpoints

**Tunnel Management**

```
POST /api/tunnels
- Create a new tunnel
- Body: { "protocol": "http|tcp", "local_port": 8080, "subdomain": "optional" }
- Response: { "tunnel_id": "uuid", "public_url": "https://abc123.example.com", "public_port": 34567 }

GET /api/tunnels
- List active tunnels for authenticated user
- Response: [{ "tunnel_id": "uuid", "protocol": "http", "public_url": "...", "status": "active" }]

DELETE /api/tunnels/{tunnel_id}
- Terminate a specific tunnel
- Response: { "status": "terminated" }
```

**Authentication (API Key Validation)**

```
POST /api/auth/validate
- Validate API key
- Response: { "valid": true, "user_id": "uuid" }
```

**User Management (JWT-based)**

```
POST /api/users/register
- User registration
- Body: { "email": "user@example.com", "password": "secure_password", "name": "John Doe" }
- Response: { "user_id": "uuid", "email": "user@example.com", "created_at": "2024-01-01T00:00:00Z" }

POST /api/users/login
- User login
- Body: { "email": "user@example.com", "password": "secure_password" }
- Response: { "jwt_token": "eyJ...", "refresh_token": "refresh_...", "expires_in": 3600 }

POST /api/users/logout
- User logout (invalidate JWT)
- Headers: Authorization: Bearer <jwt-token>
- Response: { "status": "logged_out" }

POST /api/users/refresh
- Refresh JWT token
- Body: { "refresh_token": "refresh_..." }
- Response: { "jwt_token": "eyJ...", "expires_in": 3600 }

GET /api/users/profile
- Get user profile
- Headers: Authorization: Bearer <jwt-token>
- Response: { "user_id": "uuid", "email": "...", "name": "...", "created_at": "...", "api_keys": [...] }

PUT /api/users/profile
- Update user profile
- Headers: Authorization: Bearer <jwt-token>
- Body: { "name": "New Name", "email": "new@example.com" }
- Response: { "user_id": "uuid", "updated_fields": ["name", "email"] }
```

**API Key Management (JWT-based)**

```
POST /api/users/api-keys
- Generate new API key for tunneling
- Headers: Authorization: Bearer <jwt-token>
- Body: { "name": "My Development Key", "expires_at": "2024-12-31T23:59:59Z" }
- Response: { "api_key": "shipit_...", "key_id": "uuid", "name": "...", "created_at": "..." }

GET /api/users/api-keys
- List user's API keys
- Headers: Authorization: Bearer <jwt-token>
- Response: [{ "key_id": "uuid", "name": "...", "created_at": "...", "last_used": "...", "expires_at": "..." }]

DELETE /api/users/api-keys/{key_id}
- Revoke API key
- Headers: Authorization: Bearer <jwt-token>
- Response: { "status": "revoked", "key_id": "uuid" }
```

**Analytics (JWT-based)**

```
GET /api/analytics/overview
- Get user's analytics overview
- Headers: Authorization: Bearer <jwt-token>
- Query: ?period=24h|7d|30d
- Response: { "total_tunnels": 5, "total_requests": 1234, "total_bandwidth": "2.3GB", "active_tunnels": 2 }

GET /api/analytics/tunnels/{tunnel_id}/stats
- Get specific tunnel analytics
- Headers: Authorization: Bearer <jwt-token>
- Query: ?period=24h|7d|30d&metrics=requests,bandwidth,latency
- Response: { "tunnel_id": "...", "metrics": {...}, "time_series": [...] }

GET /api/analytics/traffic
- Get traffic analytics
- Headers: Authorization: Bearer <jwt-token>
- Response: { "top_visitors": [...], "top_paths": [...], "status_codes": {...}, "user_agents": [...] }
```

### 3.3 Data Plane Protocol

#### Connection Establishment

1. Client establishes TLS connection to port 7223
2. Client sends tunnel registration message
3. Server validates and acknowledges
4. Client maintains connection pool (default: 10 connections)

#### Message Format

```
┌─────────────────┬─────────────────┬─────────────────┐
│   Message Type  │   Tunnel ID     │     Payload     │
│    (1 byte)     │   (16 bytes)    │   (variable)    │
└─────────────────┴─────────────────┴─────────────────┘

Message Types:
- 0x01: Tunnel Registration
- 0x02: Data Forward (Server → Client)
- 0x03: Data Response (Client → Server)
- 0x04: Connection Close
- 0x05: Heartbeat
```

## 4. Routing Logic

### 4.1 HTTP Routing (Layer 7)

#### Subdomain-Based Routing

- **DNS Requirement**: Wildcard A record `*.example.com → server_ip`
- **Routing Logic**: Extract subdomain from `Host` header
- **Example**: `my-app.example.com` → tunnel with subdomain `my-app`

#### Path-Based Routing (Future)

- **DNS Requirement**: Single A record `example.com → server_ip`
- **Routing Logic**: Extract first path segment
- **Example**: `example.com/my-app/api` → tunnel `my-app`, forward `/api`

### 4.2 TCP Routing (Layer 4)

#### Single Port Forwarding

- **Allocation**: Server assigns random high port (e.g., 34567)
- **Routing**: Direct port mapping to tunnel
- **Example**: `example.com:34567` → tunnel requesting TCP forwarding

## 5. Implementation Plan

### 5.1 Phase 1: MVP Foundation

#### Week 1-2: Core Infrastructure

1. **Project Setup**
   - Initialize Go module
   - Set up project structure
   - Configure logging and configuration management
   - Database setup (PostgreSQL) and migrations

2. **Basic Server Framework**
   - HTTP server for public traffic (ports 80/443)
   - TCP server for agent connections (port 7223)
   - Basic TLS configuration
   - Database connection and ORM setup

#### Week 3-4: Authentication System

1. **User Management Foundation**
   - User registration and login endpoints
   - Password hashing (bcrypt)
   - Basic user model and database schema
   - JWT token generation and validation

2. **API Key System**
   - API key generation and validation
   - Bearer token middleware for tunnel operations
   - Secure key storage and association with users

#### Week 5-6: Control Plane APIs

1. **Tunnel Management API**
   - POST /api/tunnels (tunnel creation)
   - DELETE /api/tunnels/{id} (tunnel termination)
   - Basic request validation
   - User-tunnel association

2. **User Management API**
   - User profile endpoints
   - API key management endpoints
   - JWT refresh token mechanism
   - Basic analytics endpoints

#### Week 7-8: Data Plane

1. **Tunnel Manager**
   - In-memory tunnel registry
   - Connection pool management
   - Subdomain assignment logic

2. **Traffic Forwarding**
   - HTTP request routing
   - Basic reverse proxy implementation
   - Connection pooling for agents

### 5.2 Phase 2: Core Features

#### Week 9-10: Enhanced Routing

1. **Subdomain Validation**
   - Custom subdomain requests
   - Conflict detection
   - DNS wildcard support verification

2. **TCP Forwarding**
   - Single port TCP tunnels
   - Dynamic port allocation
   - Raw TCP data forwarding

#### Week 11-12: Web Dashboard & Analytics

1. **Analytics Collection**
   - Prometheus metrics integration
   - Traffic analytics collection
   - User behavior tracking
   - Performance metrics

2. **Web Dashboard**
   - User authentication frontend
   - Tunnel management interface
   - Real-time analytics display
   - API key management UI

#### Week 13-14: Reliability & Testing

1. **Connection Management**
   - Heartbeat/keepalive mechanism
   - Dead connection detection
   - Automatic reconnection handling

2. **Error Handling & Testing**
   - Comprehensive error responses
   - Connection state recovery
   - Graceful shutdown procedures
   - Integration tests and API testing

### 5.3 Phase 3: Production Readiness

#### Week 15-16: Security Hardening

1. **Rate Limiting**
   - API endpoint protection
   - Connection rate limiting
   - Abuse detection

2. **TLS Enhancement**
   - Let's Encrypt integration (autocert)
   - Automatic HTTPS for subdomains
   - Certificate management

#### Week 17-18: Monitoring & Operations

1. **Advanced Monitoring**
   - Comprehensive health checks
   - Performance optimization
   - Resource monitoring

2. **Operational Tools**
   - Admin endpoints
   - Tunnel inspection tools
   - Configuration management
   - Deployment automation

## 6. File Structure

```
shipit-server/
├── cmd/
│   └── server/
│       └── main.go              # Server entry point
├── internal/
│   ├── api/
│   │   ├── handlers/
│   │   │   ├── tunnels.go       # Tunnel management handlers
│   │   │   ├── users.go         # User management handlers
│   │   │   ├── auth.go          # Authentication handlers
│   │   │   └── analytics.go     # Analytics handlers
│   │   ├── middleware/
│   │   │   ├── auth.go          # Authentication middleware
│   │   │   ├── jwt.go           # JWT middleware
│   │   │   └── cors.go          # CORS middleware
│   │   └── routes.go            # Route definitions
│   ├── tunnel/
│   │   ├── manager.go           # Tunnel state management
│   │   ├── connection.go        # Connection pool handling
│   │   └── routing.go           # Request routing logic
│   ├── agent/
│   │   ├── listener.go          # Agent connection handling
│   │   ├── protocol.go          # Data plane protocol
│   │   └── pool.go              # Connection pool management
│   ├── auth/
│   │   ├── apikeys.go           # API key management
│   │   ├── jwt.go               # JWT token management
│   │   ├── password.go          # Password hashing
│   │   └── session.go           # Session management
│   ├── user/
│   │   ├── service.go           # User business logic
│   │   ├── repository.go        # User data access
│   │   └── models.go            # User data models
│   ├── analytics/
│   │   ├── collector.go         # Metrics collection
│   │   ├── service.go           # Analytics business logic
│   │   └── models.go            # Analytics data models
│   ├── database/
│   │   ├── migrations/          # Database migrations
│   │   ├── connection.go        # Database connection
│   │   └── models.go            # Database models
│   └── config/
│       └── config.go            # Configuration management
├── pkg/
│   └── types/
│       ├── tunnel.go            # Tunnel data structures
│       ├── user.go              # User data structures
│       └── analytics.go         # Analytics data structures
├── web/
│   ├── static/                  # Static assets
│   ├── templates/               # HTML templates
│   └── dashboard/               # Dashboard frontend
├── configs/
│   ├── server.yaml              # Server configuration
│   └── database.yaml            # Database configuration
├── deployments/
│   ├── docker/
│   │   └── Dockerfile           # Container definition
│   └── k8s/                     # Kubernetes manifests
├── scripts/
│   ├── migrate.sh               # Database migration script
│   └── generate-keys.sh         # JWT key generation
├── go.mod
└── go.sum
```

## 7. Configuration

### 7.1 Server Configuration

```yaml
server:
  domain: "example.com"
  http_port: 80
  https_port: 443
  agent_port: 7223
  environment: "development"  # development, staging, production
  
tls:
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
  auto_cert: true  # Let's Encrypt

auth:
  api_key_length: 32
  hash_cost: 12    # bcrypt cost

jwt:
  secret_key: "your-256-bit-secret"
  issuer: "shipit-server"
  audience: "shipit-users"
  access_token_expiry: "1h"
  refresh_token_expiry: "168h"  # 7 days
  algorithm: "HS256"

database:
  driver: "postgres"  # postgres, mysql, sqlite
  host: "localhost"
  port: 5432
  name: "shipit"
  user: "shipit_user"
  password: "secure_password"
  ssl_mode: "require"
  max_connections: 25
  max_idle_connections: 5
  connection_max_lifetime: "5m"


  host: "localhost"
  port: 6379
  password: ""
  db: 0
  max_retries: 3
  pool_size: 10

tunnels:
  max_per_user: 10
  connection_pool_size: 10
  subdomain_length: 8

analytics:
  enabled: true
  retention_days: 90
  metrics_endpoint: "/metrics"
  prometheus_enabled: true

cors:
  allowed_origins: ["http://localhost:3000", "https://app.example.com"]
  allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowed_headers: ["Authorization", "Content-Type"]
  allow_credentials: true

rate_limiting:
  api_requests_per_minute: 60
  login_attempts_per_hour: 5
  tunnel_creation_per_hour: 10
```

### 7.2 Database Configuration

```yaml
# database.yaml
database:
  migrations:
    auto_migrate: true
    migration_path: "./internal/database/migrations"
  
  connection_pool:
    max_open_connections: 25
    max_idle_connections: 5
    connection_max_lifetime: "5m"
    connection_max_idle_time: "30m"

  logging:
    enabled: true
    log_level: "warn"  # silent, error, warn, info
    slow_threshold: "200ms"
```

## 8. Success Metrics

### 8.1 Phase 1 Success Criteria

- [ ] Client can establish tunnel via API
- [ ] HTTP requests successfully routed to local services
- [ ] Stable connection management
- [ ] Basic security (TLS + API keys)

### 8.2 Phase 2 Success Criteria

- [ ] Custom subdomain support
- [ ] TCP tunnel functionality
- [ ] Connection recovery mechanisms
- [ ] Production-grade error handling

### 8.3 Phase 3 Success Criteria

- [ ] Automatic HTTPS for all tunnels
- [ ] Comprehensive monitoring
- [ ] Rate limiting and abuse protection
- [ ] Operational readiness

This architecture provides a solid foundation for building the ShipIt server with clear separation of concerns, scalable design, and a practical implementation roadmap.
