-- Tunnels for HTTP/TCP forwarding
CREATE TABLE tunnels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    protocol VARCHAR(10) NOT NULL CHECK (protocol IN ('http', 'tcp')),
    subdomain VARCHAR(255), -- For HTTP tunnels
    custom_domain VARCHAR(255), -- For custom domain tunnels
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port <= 65535),
    public_port INTEGER, -- For TCP tunnels
    status VARCHAR(20) NOT NULL DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'terminated', 'connecting', 'error')),
    auth_token VARCHAR(255), -- Token for tunnel authentication
    max_connections INTEGER DEFAULT 10,
    expires_at TIMESTAMPTZ,
    metadata JSONB, -- Additional tunnel configuration
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tunnel Analytics for usage tracking
CREATE TABLE tunnel_analytics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tunnel_id UUID NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    requests_count BIGINT NOT NULL DEFAULT 0,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    response_time_avg REAL, -- Average response time in milliseconds
    error_count BIGINT NOT NULL DEFAULT 0,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Connection tracking
CREATE TABLE connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tunnel_id UUID NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    remote_addr INET NOT NULL,
    local_addr INET NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ
); 