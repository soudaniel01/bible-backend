-- Criação de índices para otimização de performance

-- Índices para tabela users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at);

-- Índices para tabela refresh_tokens
CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_token_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_token_revoked ON refresh_tokens(revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_token_created_at ON refresh_tokens(created_at);

-- Índices compostos para refresh_tokens
CREATE INDEX IF NOT EXISTS idx_refresh_token_user_revoked ON refresh_tokens(user_id, revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires_revoked ON refresh_tokens(expires_at, revoked);

-- Índices para tabela login_audit
CREATE INDEX IF NOT EXISTS idx_login_audit_user_id ON login_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_login_audit_email ON login_audit(email);
CREATE INDEX IF NOT EXISTS idx_login_audit_client_ip ON login_audit(client_ip);
CREATE INDEX IF NOT EXISTS idx_login_audit_success ON login_audit(success);
CREATE INDEX IF NOT EXISTS idx_login_audit_timestamp ON login_audit(login_timestamp);
CREATE INDEX IF NOT EXISTS idx_login_audit_session_id ON login_audit(session_id);

-- Índices compostos para login_audit (otimização de consultas de auditoria)
CREATE INDEX IF NOT EXISTS idx_login_audit_user_timestamp ON login_audit(user_id, login_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_login_audit_email_timestamp ON login_audit(email, login_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_login_audit_ip_timestamp ON login_audit(client_ip, login_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_login_audit_ip_success_timestamp ON login_audit(client_ip, success, login_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_login_audit_email_success_timestamp ON login_audit(email, success, login_timestamp DESC);

-- Índices para consultas de atividade suspeita
CREATE INDEX IF NOT EXISTS idx_login_audit_failed_attempts_ip ON login_audit(client_ip, login_timestamp) WHERE success = false;
CREATE INDEX IF NOT EXISTS idx_login_audit_failed_attempts_email ON login_audit(email, login_timestamp) WHERE success = false;

-- Comentários explicativos
COMMENT ON INDEX idx_users_email IS 'Índice único para email de usuários - usado em autenticação';
COMMENT ON INDEX idx_refresh_token_hash IS 'Índice único para hash de refresh tokens - usado em validação';
COMMENT ON INDEX idx_login_audit_user_timestamp IS 'Índice composto para histórico de login por usuário';
COMMENT ON INDEX idx_login_audit_ip_success_timestamp IS 'Índice para detecção de atividade suspeita por IP';
COMMENT ON INDEX idx_login_audit_email_success_timestamp IS 'Índice para detecção de atividade suspeita por email';