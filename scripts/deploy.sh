#!/bin/bash

# ShipIt Server Deployment Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${ENVIRONMENT:-production}
DOMAIN=${DOMAIN:-localhost}
DEPLOY_DIR=${DEPLOY_DIR:-/opt/shipit}

echo -e "${GREEN}🚀 Starting ShipIt Server Deployment${NC}"
echo "Environment: $ENVIRONMENT"
echo "Domain: $DOMAIN"
echo "Deploy Directory: $DEPLOY_DIR"

# Check if running as root for production deployment
if [[ "$ENVIRONMENT" == "production" && $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Production deployment must be run as root${NC}"
   exit 1
fi

# Create deployment directory
echo -e "${YELLOW}📁 Setting up deployment directory...${NC}"
mkdir -p $DEPLOY_DIR
mkdir -p $DEPLOY_DIR/configs
mkdir -p $DEPLOY_DIR/secrets
mkdir -p $DEPLOY_DIR/logs

# Check for required secrets
echo -e "${YELLOW}🔐 Checking secrets...${NC}"
if [[ ! -f "./secrets/db_password.txt" ]]; then
    echo -e "${RED}❌ Missing database password secret${NC}"
    echo "Create: ./secrets/db_password.txt"
    exit 1
fi

if [[ ! -f "./secrets/jwt_secret.txt" ]]; then
    echo -e "${RED}❌ Missing JWT secret${NC}"
    echo "Create: ./secrets/jwt_secret.txt"
    exit 1
fi

if [[ ! -f "./secrets/admin_password.txt" ]]; then
    echo -e "${RED}❌ Missing admin password secret${NC}"
    echo "Create: ./secrets/admin_password.txt"
    exit 1
fi

# Validate secret strength for production
if [[ "$ENVIRONMENT" == "production" ]]; then
    echo -e "${YELLOW}🔍 Validating production secrets...${NC}"
    
    # Check JWT secret length
    jwt_secret_length=$(wc -c < ./secrets/jwt_secret.txt | xargs)
    if [[ $jwt_secret_length -lt 32 ]]; then
        echo -e "${RED}❌ JWT secret must be at least 32 characters for production${NC}"
        exit 1
    fi
    
    # Check if secrets contain default values
    if grep -q "dev-" ./secrets/jwt_secret.txt; then
        echo -e "${RED}❌ JWT secret contains development values${NC}"
        exit 1
    fi
    
    if grep -q "admin123456" ./secrets/admin_password.txt; then
        echo -e "${RED}❌ Admin password must be changed for production${NC}"
        exit 1
    fi
fi

# Build application
echo -e "${YELLOW}🔨 Building application...${NC}"
if command -v make &> /dev/null; then
    make build-linux
else
    GOOS=linux GOARCH=amd64 go build -o bin/shipit-server-linux cmd/server/main.go
fi

# Copy files
echo -e "${YELLOW}📦 Copying application files...${NC}"
cp bin/shipit-server-linux $DEPLOY_DIR/shipit-server
chmod +x $DEPLOY_DIR/shipit-server

# Copy configurations
if [[ -f "configs/${ENVIRONMENT}.yaml" ]]; then
    cp configs/${ENVIRONMENT}.yaml $DEPLOY_DIR/configs/server.yaml
else
    cp configs/server.yaml $DEPLOY_DIR/configs/
fi

# Copy secrets
cp -r secrets/ $DEPLOY_DIR/
chmod 600 $DEPLOY_DIR/secrets/*

# Create systemd service for production
if [[ "$ENVIRONMENT" == "production" ]]; then
    echo -e "${YELLOW}⚙️  Creating systemd service...${NC}"
    cat > /etc/systemd/system/shipit-server.service << EOF
[Unit]
Description=ShipIt Tunneling Server
After=network.target postgresql.service

[Service]
Type=simple
User=shipit
Group=shipit
WorkingDirectory=$DEPLOY_DIR
ExecStart=$DEPLOY_DIR/shipit-server
Restart=always
RestartSec=10

# Environment variables
Environment=SHIPIT_SERVER_ENVIRONMENT=production
Environment=SHIPIT_SERVER_DOMAIN=$DOMAIN
Environment=SHIPIT_CONFIG_PATH=$DEPLOY_DIR/configs/server.yaml
Environment=SHIPIT_SECRETS_PATH=$DEPLOY_DIR/configs/secrets.yaml

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$DEPLOY_DIR/logs

[Install]
WantedBy=multi-user.target
EOF

    # Create shipit user if it doesn't exist
    if ! id "shipit" &>/dev/null; then
        echo -e "${YELLOW}👤 Creating shipit user...${NC}"
        useradd -r -s /bin/false -d $DEPLOY_DIR shipit
    fi
    
    # Set ownership
    chown -R shipit:shipit $DEPLOY_DIR
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable shipit-server
fi

# Create environment file
echo -e "${YELLOW}📝 Creating environment configuration...${NC}"
cat > $DEPLOY_DIR/.env << EOF
SHIPIT_SERVER_ENVIRONMENT=$ENVIRONMENT
SHIPIT_SERVER_DOMAIN=$DOMAIN
SHIPIT_CONFIG_PATH=$DEPLOY_DIR/configs/server.yaml
SHIPIT_SECRETS_PATH=$DEPLOY_DIR/configs/secrets.yaml
EOF

# Create start script
cat > $DEPLOY_DIR/start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source .env
exec ./shipit-server
EOF
chmod +x $DEPLOY_DIR/start.sh

# Deploy with Docker Compose
if [[ -f "docker-compose.yml" && "$1" == "--docker" ]]; then
    echo -e "${YELLOW}🐳 Deploying with Docker Compose...${NC}"
    docker-compose -f docker-compose.yml up -d --build
    echo -e "${GREEN}✅ Docker deployment complete${NC}"
elif [[ "$ENVIRONMENT" == "production" ]]; then
    echo -e "${YELLOW}🚀 Starting production service...${NC}"
    systemctl start shipit-server
    systemctl status shipit-server --no-pager
    echo -e "${GREEN}✅ Production deployment complete${NC}"
else
    echo -e "${GREEN}✅ Development deployment complete${NC}"
    echo "Run: $DEPLOY_DIR/start.sh"
fi

# Show status
echo ""
echo -e "${GREEN}🎉 Deployment Summary${NC}"
echo "Environment: $ENVIRONMENT"
echo "Domain: $DOMAIN"
echo "Deploy Path: $DEPLOY_DIR"
echo "Secrets: $DEPLOY_DIR/secrets/"
echo "Config: $DEPLOY_DIR/configs/"

if [[ "$ENVIRONMENT" == "production" ]]; then
    echo "Service: systemctl status shipit-server"
    echo "Logs: journalctl -u shipit-server -f"
else
    echo "Start: $DEPLOY_DIR/start.sh"
fi

echo ""
echo -e "${YELLOW}⚠️  Remember to:${NC}"
echo "1. Update DNS records to point to this server"
echo "2. Configure SSL certificates"
echo "3. Set up monitoring and backups"
echo "4. Secure your secrets files" 