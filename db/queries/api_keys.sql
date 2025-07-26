-- name: CreateAPIKey :one
INSERT INTO api_keys (
    user_id, name, prefix, hash, expires_at, scopes
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetAPIKeyByPrefix :one
SELECT * FROM api_keys 
WHERE prefix = $1 AND is_active = true;

-- name: GetAPIKeyByHash :one
SELECT ak.*, u.id as user_id, u.email, u.name as user_name, u.role, u.is_active as user_active
FROM api_keys ak
JOIN users u ON ak.user_id = u.id
WHERE ak.hash = $1 AND ak.is_active = true AND u.is_active = true;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys 
SET last_used_at = NOW(), updated_at = NOW()
WHERE id = $1;

-- name: ListAPIKeysByUser :many
SELECT id, user_id, name, prefix, is_active, last_used_at, expires_at, scopes, created_at, updated_at
FROM api_keys 
WHERE user_id = $1 AND is_active = true
ORDER BY created_at DESC;

-- name: RevokeAPIKey :exec
UPDATE api_keys 
SET is_active = false, updated_at = NOW()
WHERE id = $1 AND user_id = $2;

-- name: RevokeAllUserAPIKeys :exec
UPDATE api_keys 
SET is_active = false, updated_at = NOW()
WHERE user_id = $1;

-- name: DeleteExpiredAPIKeys :exec
DELETE FROM api_keys 
WHERE expires_at IS NOT NULL AND expires_at < NOW();

-- name: CountAPIKeysByUser :one
SELECT COUNT(*) FROM api_keys 
WHERE user_id = $1 AND is_active = true; 