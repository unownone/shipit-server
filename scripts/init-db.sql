-- ShipIt Server Database Initialization

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create indexes for performance
-- These will be added after tables are created in migrations

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE shipit TO shipit_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO shipit_user; 