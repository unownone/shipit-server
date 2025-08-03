#!/bin/bash

# Production Secrets Generator for ShipIt Server
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🔐 Generating Production Secrets for ShipIt Server${NC}"

# Create secrets directory
mkdir -p secrets

# Function to generate secure random password
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $((length * 3/4)) | tr -d "=+/" | cut -c1-${length}
}

# Function to generate secure hex key
generate_hex_key() {
    local length=${1:-64}
    openssl rand -hex $((length / 2))
}

# Generate database password
echo -e "${YELLOW}Generating database password...${NC}"
DB_PASSWORD=$(generate_password 32)
echo "$DB_PASSWORD" > secrets/prod_db_password.txt

# Generate JWT secret (256-bit)
echo -e "${YELLOW}Generating JWT secret key...${NC}"
JWT_SECRET=$(generate_hex_key 64)
echo "$JWT_SECRET" > secrets/prod_jwt_secret.txt



# Generate admin password
echo -e "${YELLOW}Generating admin password...${NC}"
ADMIN_PASSWORD=$(generate_password 24)
echo "$ADMIN_PASSWORD" > secrets/prod_admin_password.txt

# Set secure permissions
chmod 600 secrets/prod_*

echo -e "${GREEN}✅ Production secrets generated successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 Generated secrets:${NC}"
echo "Database password: secrets/prod_db_password.txt"
echo "JWT secret key: secrets/prod_jwt_secret.txt"

echo "Admin password: secrets/prod_admin_password.txt"
echo ""
echo -e "${RED}⚠️  IMPORTANT SECURITY NOTES:${NC}"
echo "1. These files contain sensitive credentials"
echo "2. Keep them secure and backed up safely"
echo "3. Never commit them to version control"
echo "4. Rotate them regularly in production"
echo "5. Use a proper secrets management system for production"
echo ""
echo -e "${GREEN}🚀 Ready for production deployment!${NC}"
echo "Use: docker-compose -f docker-compose.prod.yml up -d" 