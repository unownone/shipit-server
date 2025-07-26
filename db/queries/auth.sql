-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id, token_hash, expires_at
) VALUES (
    $1, $2, $3
) RETURNING *;

-- name: GetRefreshToken :one
SELECT rt.*, u.id as user_id, u.email, u.name, u.role, u.is_active as user_active
FROM refresh_tokens rt
JOIN users u ON rt.user_id = u.id
WHERE rt.token_hash = $1 AND rt.is_revoked = false AND rt.expires_at > NOW() AND u.is_active = true;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens 
SET is_revoked = true
WHERE token_hash = $1;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens 
SET is_revoked = true
WHERE user_id = $1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < NOW();

-- name: CreateUserSession :one
INSERT INTO user_sessions (
    user_id, session_token, ip_address, user_agent, expires_at
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetUserSession :one
SELECT us.*, u.id as user_id, u.email, u.name, u.role, u.is_active as user_active
FROM user_sessions us
JOIN users u ON us.user_id = u.id
WHERE us.session_token = $1 AND us.is_active = true AND us.expires_at > NOW() AND u.is_active = true;

-- name: UpdateUserSession :exec
UPDATE user_sessions 
SET updated_at = NOW()
WHERE session_token = $1;

-- name: RevokeUserSession :exec
UPDATE user_sessions 
SET is_active = false, updated_at = NOW()
WHERE session_token = $1;

-- name: RevokeAllUserSessions :exec
UPDATE user_sessions 
SET is_active = false, updated_at = NOW()
WHERE user_id = $1;

-- name: DeleteExpiredUserSessions :exec
DELETE FROM user_sessions WHERE expires_at < NOW();

-- name: CreateLoginAttempt :one
INSERT INTO login_attempts (
    email, ip_address, success, failure_reason, user_agent
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetRecentLoginAttempts :many
SELECT * FROM login_attempts 
WHERE email = $1 AND created_at > $2
ORDER BY created_at DESC;

-- name: CountFailedLoginAttempts :one
SELECT COUNT(*) FROM login_attempts 
WHERE email = $1 AND success = false AND created_at > $2;

-- name: DeleteOldLoginAttempts :exec
DELETE FROM login_attempts WHERE created_at < $1; 