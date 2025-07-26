-- Create "login_attempts" table
CREATE TABLE "login_attempts" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "email" character varying(255) NOT NULL,
  "ip_address" inet NOT NULL,
  "success" boolean NOT NULL,
  "failure_reason" character varying(255) NULL,
  "user_agent" text NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id")
);
-- Create index "idx_login_attempts_created_at" to table: "login_attempts"
CREATE INDEX "idx_login_attempts_created_at" ON "login_attempts" ("created_at");
-- Create index "idx_login_attempts_email_time" to table: "login_attempts"
CREATE INDEX "idx_login_attempts_email_time" ON "login_attempts" ("email", "created_at" DESC);
-- Create index "idx_login_attempts_ip_time" to table: "login_attempts"
CREATE INDEX "idx_login_attempts_ip_time" ON "login_attempts" ("ip_address", "created_at" DESC);
-- Create "users" table
CREATE TABLE "users" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "email" character varying(255) NOT NULL,
  "password_hash" character varying(255) NOT NULL,
  "name" character varying(255) NOT NULL,
  "role" character varying(50) NOT NULL DEFAULT 'user',
  "is_active" boolean NOT NULL DEFAULT true,
  "email_verified" boolean NOT NULL DEFAULT false,
  "email_verification_token" character varying(255) NULL,
  "password_reset_token" character varying(255) NULL,
  "password_reset_expires_at" timestamptz NULL,
  "last_login_at" timestamptz NULL,
  "failed_login_attempts" integer NOT NULL DEFAULT 0,
  "locked_until" timestamptz NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "users_role_check" CHECK ((role)::text = ANY ((ARRAY['user'::character varying, 'admin'::character varying, 'moderator'::character varying])::text[]))
);
-- Create index "idx_users_created_at" to table: "users"
CREATE INDEX "idx_users_created_at" ON "users" ("created_at");
-- Create index "idx_users_email" to table: "users"
CREATE UNIQUE INDEX "idx_users_email" ON "users" ("email") WHERE (is_active = true);
-- Create index "idx_users_email_verification_token" to table: "users"
CREATE INDEX "idx_users_email_verification_token" ON "users" ("email_verification_token") WHERE (email_verification_token IS NOT NULL);
-- Create index "idx_users_password_reset_token" to table: "users"
CREATE INDEX "idx_users_password_reset_token" ON "users" ("password_reset_token") WHERE (password_reset_token IS NOT NULL);
-- Create index "idx_users_role" to table: "users"
CREATE INDEX "idx_users_role" ON "users" ("role");
-- Create "api_keys" table
CREATE TABLE "api_keys" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "name" character varying(255) NOT NULL,
  "prefix" character varying(16) NOT NULL,
  "hash" character varying(64) NOT NULL,
  "is_active" boolean NOT NULL DEFAULT true,
  "last_used_at" timestamptz NULL,
  "expires_at" timestamptz NULL,
  "scopes" text[] NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "api_keys_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_api_keys_expires_at" to table: "api_keys"
CREATE INDEX "idx_api_keys_expires_at" ON "api_keys" ("expires_at") WHERE (expires_at IS NOT NULL);
-- Create index "idx_api_keys_hash" to table: "api_keys"
CREATE INDEX "idx_api_keys_hash" ON "api_keys" ("hash") WHERE (is_active = true);
-- Create index "idx_api_keys_last_used_at" to table: "api_keys"
CREATE INDEX "idx_api_keys_last_used_at" ON "api_keys" ("last_used_at");
-- Create index "idx_api_keys_prefix" to table: "api_keys"
CREATE UNIQUE INDEX "idx_api_keys_prefix" ON "api_keys" ("prefix");
-- Create index "idx_api_keys_user_id" to table: "api_keys"
CREATE INDEX "idx_api_keys_user_id" ON "api_keys" ("user_id") WHERE (is_active = true);
-- Create "tunnels" table
CREATE TABLE "tunnels" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "name" character varying(255) NOT NULL,
  "protocol" character varying(10) NOT NULL,
  "subdomain" character varying(255) NULL,
  "custom_domain" character varying(255) NULL,
  "target_host" character varying(255) NOT NULL,
  "target_port" integer NOT NULL,
  "public_port" integer NULL,
  "status" character varying(20) NOT NULL DEFAULT 'inactive',
  "auth_token" character varying(255) NULL,
  "max_connections" integer NULL DEFAULT 10,
  "expires_at" timestamptz NULL,
  "metadata" jsonb NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "tunnels_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "tunnels_protocol_check" CHECK ((protocol)::text = ANY ((ARRAY['http'::character varying, 'tcp'::character varying])::text[])),
  CONSTRAINT "tunnels_status_check" CHECK ((status)::text = ANY ((ARRAY['active'::character varying, 'inactive'::character varying, 'terminated'::character varying, 'connecting'::character varying, 'error'::character varying])::text[])),
  CONSTRAINT "tunnels_target_port_check" CHECK ((target_port > 0) AND (target_port <= 65535))
);
-- Create index "idx_tunnels_created_at" to table: "tunnels"
CREATE INDEX "idx_tunnels_created_at" ON "tunnels" ("created_at");
-- Create index "idx_tunnels_custom_domain" to table: "tunnels"
CREATE UNIQUE INDEX "idx_tunnels_custom_domain" ON "tunnels" ("custom_domain") WHERE ((custom_domain IS NOT NULL) AND ((status)::text = 'active'::text));
-- Create index "idx_tunnels_expires_at" to table: "tunnels"
CREATE INDEX "idx_tunnels_expires_at" ON "tunnels" ("expires_at") WHERE (expires_at IS NOT NULL);
-- Create index "idx_tunnels_protocol" to table: "tunnels"
CREATE INDEX "idx_tunnels_protocol" ON "tunnels" ("protocol");
-- Create index "idx_tunnels_public_port" to table: "tunnels"
CREATE UNIQUE INDEX "idx_tunnels_public_port" ON "tunnels" ("public_port") WHERE ((public_port IS NOT NULL) AND ((status)::text = 'active'::text));
-- Create index "idx_tunnels_status" to table: "tunnels"
CREATE INDEX "idx_tunnels_status" ON "tunnels" ("status");
-- Create index "idx_tunnels_subdomain" to table: "tunnels"
CREATE UNIQUE INDEX "idx_tunnels_subdomain" ON "tunnels" ("subdomain") WHERE ((subdomain IS NOT NULL) AND ((status)::text = 'active'::text));
-- Create index "idx_tunnels_user_id" to table: "tunnels"
CREATE INDEX "idx_tunnels_user_id" ON "tunnels" ("user_id");
-- Create "connections" table
CREATE TABLE "connections" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tunnel_id" uuid NOT NULL,
  "remote_addr" inet NOT NULL,
  "local_addr" inet NOT NULL,
  "is_active" boolean NOT NULL DEFAULT true,
  "bytes_in" bigint NOT NULL DEFAULT 0,
  "bytes_out" bigint NOT NULL DEFAULT 0,
  "started_at" timestamptz NOT NULL DEFAULT now(),
  "ended_at" timestamptz NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "connections_tunnel_id_fkey" FOREIGN KEY ("tunnel_id") REFERENCES "tunnels" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_connections_active" to table: "connections"
CREATE INDEX "idx_connections_active" ON "connections" ("tunnel_id", "is_active") WHERE (is_active = true);
-- Create index "idx_connections_remote_addr" to table: "connections"
CREATE INDEX "idx_connections_remote_addr" ON "connections" ("remote_addr");
-- Create index "idx_connections_started_at" to table: "connections"
CREATE INDEX "idx_connections_started_at" ON "connections" ("started_at");
-- Create index "idx_connections_tunnel_id" to table: "connections"
CREATE INDEX "idx_connections_tunnel_id" ON "connections" ("tunnel_id");
-- Create "refresh_tokens" table
CREATE TABLE "refresh_tokens" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "token_hash" character varying(64) NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "refresh_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_refresh_tokens_expires_at" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_expires_at" ON "refresh_tokens" ("expires_at");
-- Create index "idx_refresh_tokens_token_hash" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_token_hash" ON "refresh_tokens" ("token_hash") WHERE (is_revoked = false);
-- Create index "idx_refresh_tokens_user_id" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_user_id" ON "refresh_tokens" ("user_id") WHERE (is_revoked = false);
-- Create "tunnel_analytics" table
CREATE TABLE "tunnel_analytics" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "tunnel_id" uuid NOT NULL,
  "requests_count" bigint NOT NULL DEFAULT 0,
  "bytes_in" bigint NOT NULL DEFAULT 0,
  "bytes_out" bigint NOT NULL DEFAULT 0,
  "response_time_avg" real NULL,
  "error_count" bigint NOT NULL DEFAULT 0,
  "timestamp" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "tunnel_analytics_tunnel_id_fkey" FOREIGN KEY ("tunnel_id") REFERENCES "tunnels" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_tunnel_analytics_timestamp" to table: "tunnel_analytics"
CREATE INDEX "idx_tunnel_analytics_timestamp" ON "tunnel_analytics" ("timestamp");
-- Create index "idx_tunnel_analytics_tunnel_id" to table: "tunnel_analytics"
CREATE INDEX "idx_tunnel_analytics_tunnel_id" ON "tunnel_analytics" ("tunnel_id");
-- Create index "idx_tunnel_analytics_tunnel_time" to table: "tunnel_analytics"
CREATE INDEX "idx_tunnel_analytics_tunnel_time" ON "tunnel_analytics" ("tunnel_id", "timestamp" DESC);
-- Create "user_sessions" table
CREATE TABLE "user_sessions" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "session_token" character varying(255) NOT NULL,
  "ip_address" inet NULL,
  "user_agent" text NULL,
  "is_active" boolean NOT NULL DEFAULT true,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "user_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_user_sessions_expires_at" to table: "user_sessions"
CREATE INDEX "idx_user_sessions_expires_at" ON "user_sessions" ("expires_at");
-- Create index "idx_user_sessions_session_token" to table: "user_sessions"
CREATE INDEX "idx_user_sessions_session_token" ON "user_sessions" ("session_token") WHERE (is_active = true);
-- Create index "idx_user_sessions_user_id" to table: "user_sessions"
CREATE INDEX "idx_user_sessions_user_id" ON "user_sessions" ("user_id") WHERE (is_active = true);
