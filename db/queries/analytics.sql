-- name: CreateTunnelAnalytics :one
INSERT INTO tunnel_analytics (
    tunnel_id, requests_count, bytes_in, bytes_out, response_time_avg, error_count
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: UpdateTunnelAnalytics :exec
UPDATE tunnel_analytics 
SET requests_count = requests_count + $2,
    bytes_in = bytes_in + $3,
    bytes_out = bytes_out + $4,
    error_count = error_count + $5,
    response_time_avg = CASE 
        WHEN requests_count = 0 THEN $6
        ELSE (response_time_avg * requests_count + $6) / (requests_count + 1)
    END
WHERE tunnel_id = $1 AND DATE(timestamp) = CURRENT_DATE;

-- name: GetTunnelAnalytics :many
SELECT * FROM tunnel_analytics 
WHERE tunnel_id = $1 AND timestamp >= $2 AND timestamp <= $3
ORDER BY timestamp DESC;

-- name: GetTunnelAnalyticsSummary :one
SELECT 
    tunnel_id,
    SUM(requests_count) as total_requests,
    SUM(bytes_in) as total_bytes_in,
    SUM(bytes_out) as total_bytes_out,
    AVG(response_time_avg) as avg_response_time,
    SUM(error_count) as total_errors
FROM tunnel_analytics 
WHERE tunnel_id = $1 AND timestamp >= $2
GROUP BY tunnel_id;

-- name: CreateConnection :one
INSERT INTO connections (
    tunnel_id, remote_addr, local_addr, bytes_in, bytes_out
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: UpdateConnection :exec
UPDATE connections 
SET bytes_in = $2, bytes_out = $3, is_active = $4, ended_at = CASE WHEN $4 = false THEN NOW() ELSE ended_at END
WHERE id = $1;

-- name: GetActiveConnections :many
SELECT * FROM connections 
WHERE tunnel_id = $1 AND is_active = true
ORDER BY started_at DESC;

-- name: CountActiveConnections :one
SELECT COUNT(*) FROM connections 
WHERE tunnel_id = $1 AND is_active = true;

-- name: GetConnectionHistory :many
SELECT * FROM connections 
WHERE tunnel_id = $1 AND started_at >= $2
ORDER BY started_at DESC
LIMIT $3 OFFSET $4;

-- name: CloseInactiveConnections :exec
UPDATE connections 
SET is_active = false, ended_at = NOW()
WHERE tunnel_id = $1 AND is_active = true AND started_at < $2;

-- name: DeleteOldConnections :exec
DELETE FROM connections 
WHERE ended_at IS NOT NULL AND ended_at < $1; 