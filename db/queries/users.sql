-- name: CreateUser :one
INSERT INTO users (
    email, password_hash, name, role, is_active, email_verified
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 AND is_active = true;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND is_active = true;

-- name: UpdateUser :one
UPDATE users 
SET name = $2, email = $3, role = $4, email_verified = $5, updated_at = NOW()
WHERE id = $1 AND is_active = true
RETURNING *;

-- name: UpdateUserPassword :exec
UPDATE users 
SET password_hash = $2, updated_at = NOW()
WHERE id = $1 AND is_active = true;

-- name: DeactivateUser :exec
UPDATE users 
SET is_active = false, updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users 
SET last_login_at = NOW(), failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
WHERE id = $1;

-- name: IncrementFailedLoginAttempts :exec
UPDATE users 
SET failed_login_attempts = failed_login_attempts + 1, updated_at = NOW()
WHERE email = $1;

-- name: LockUser :exec
UPDATE users 
SET locked_until = $2, updated_at = NOW()
WHERE email = $1;

-- name: SetEmailVerificationToken :exec
UPDATE users 
SET email_verification_token = $2, updated_at = NOW()
WHERE id = $1;

-- name: VerifyEmail :exec
UPDATE users 
SET email_verified = true, email_verification_token = NULL, updated_at = NOW()
WHERE email_verification_token = $1;

-- name: SetPasswordResetToken :exec
UPDATE users 
SET password_reset_token = $2, password_reset_expires_at = $3, updated_at = NOW()
WHERE email = $1;

-- name: ResetPassword :exec
UPDATE users 
SET password_hash = $2, password_reset_token = NULL, password_reset_expires_at = NULL, updated_at = NOW()
WHERE password_reset_token = $1 AND password_reset_expires_at > NOW();

-- name: ListUsers :many
SELECT * FROM users 
WHERE is_active = true
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE is_active = true; 