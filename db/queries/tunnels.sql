-- name: CreateTunnel :one
INSERT INTO tunnels (
    user_id, name, protocol, subdomain, custom_domain, target_host, target_port, 
    public_port, status, auth_token, max_connections, expires_at, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
) RETURNING *;

-- name: GetTunnelByID :one
SELECT * FROM tunnels WHERE id = $1;

-- name: GetTunnelBySubdomain :one
SELECT * FROM tunnels WHERE subdomain = $1 AND status = 'active';

-- name: GetTunnelByPublicPort :one
SELECT * FROM tunnels WHERE public_port = $1 AND status = 'active';

-- name: UpdateTunnel :one
UPDATE tunnels 
SET name = $2, target_host = $3, target_port = $4, max_connections = $5, 
    expires_at = $6, metadata = $7, updated_at = NOW()
WHERE id = $1 AND user_id = $8
RETURNING *;

-- name: UpdateTunnelStatus :exec
UPDATE tunnels 
SET status = $2, updated_at = NOW()
WHERE id = $1;

-- name: DeleteTunnel :exec
DELETE FROM tunnels WHERE id = $1 AND user_id = $2;

-- name: ListTunnelsByUser :many
SELECT * FROM tunnels 
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListActiveTunnels :many
SELECT * FROM tunnels 
WHERE status = 'active'
ORDER BY created_at DESC;

-- name: CountTunnelsByUser :one
SELECT COUNT(*) FROM tunnels WHERE user_id = $1;

-- name: CountActiveTunnelsByUser :one
SELECT COUNT(*) FROM tunnels WHERE user_id = $1 AND status = 'active';

-- name: GetTunnelsByStatus :many
SELECT * FROM tunnels WHERE status = $1 ORDER BY created_at DESC;

-- name: DeleteExpiredTunnels :exec
DELETE FROM tunnels WHERE expires_at IS NOT NULL AND expires_at < NOW();

-- name: CheckSubdomainAvailability :one
SELECT COUNT(*) FROM tunnels 
WHERE subdomain = $1 AND status = 'active';

-- name: CheckPublicPortAvailability :one
SELECT COUNT(*) FROM tunnels 
WHERE public_port = $1 AND status = 'active';

-- name: GetNextAvailablePort :one
SELECT COALESCE(MIN(port_num), 0) as next_port
FROM generate_series($1, $2) AS port_num
WHERE port_num NOT IN (
    SELECT public_port FROM tunnels 
    WHERE public_port IS NOT NULL AND status = 'active'
); 