-- Users table indexes
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE is_active = true;
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token) WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;

-- API Keys indexes
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id) WHERE is_active = true;
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX idx_api_keys_hash ON api_keys(hash) WHERE is_active = true;
CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_api_keys_last_used_at ON api_keys(last_used_at);

-- Refresh Tokens indexes
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id) WHERE is_revoked = false;
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash) WHERE is_revoked = false;
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- User Sessions indexes
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id) WHERE is_active = true;
CREATE INDEX idx_user_sessions_session_token ON user_sessions(session_token) WHERE is_active = true;
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

-- Login Attempts indexes
CREATE INDEX idx_login_attempts_email_time ON login_attempts(email, created_at DESC);
CREATE INDEX idx_login_attempts_ip_time ON login_attempts(ip_address, created_at DESC);
CREATE INDEX idx_login_attempts_created_at ON login_attempts(created_at);

-- Tunnels indexes
CREATE INDEX idx_tunnels_user_id ON tunnels(user_id);
CREATE INDEX idx_tunnels_status ON tunnels(status);
CREATE INDEX idx_tunnels_protocol ON tunnels(protocol);
CREATE UNIQUE INDEX idx_tunnels_subdomain ON tunnels(subdomain) WHERE subdomain IS NOT NULL AND status = 'active';
CREATE UNIQUE INDEX idx_tunnels_custom_domain ON tunnels(custom_domain) WHERE custom_domain IS NOT NULL AND status = 'active';
CREATE UNIQUE INDEX idx_tunnels_public_port ON tunnels(public_port) WHERE public_port IS NOT NULL AND status = 'active';
CREATE INDEX idx_tunnels_expires_at ON tunnels(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_tunnels_created_at ON tunnels(created_at);

-- Tunnel Analytics indexes
CREATE INDEX idx_tunnel_analytics_tunnel_id ON tunnel_analytics(tunnel_id);
CREATE INDEX idx_tunnel_analytics_timestamp ON tunnel_analytics(timestamp);
CREATE INDEX idx_tunnel_analytics_tunnel_time ON tunnel_analytics(tunnel_id, timestamp DESC);

-- Connections indexes
CREATE INDEX idx_connections_tunnel_id ON connections(tunnel_id);
CREATE INDEX idx_connections_active ON connections(tunnel_id, is_active) WHERE is_active = true;
CREATE INDEX idx_connections_started_at ON connections(started_at);
CREATE INDEX idx_connections_remote_addr ON connections(remote_addr); 