-- Criação inicial das tabelas do sistema de autenticação

-- Tabela de usuários
CREATE TABLE users (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'USER',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) DEFAULT 'system',
    last_modified_by VARCHAR(255) DEFAULT 'system'
);

-- Tabela de refresh tokens
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255) DEFAULT 'system',
    last_modified_by VARCHAR(255) DEFAULT 'system',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabela de auditoria de login
CREATE TABLE login_audit (
    id UUID PRIMARY KEY,
    user_id UUID,
    email VARCHAR(255) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255),
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    login_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_id VARCHAR(255),
    device_info VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Inserir usuário SUPER_ADMIN inicial
-- Senha padrão: admin123 (deve ser alterada após primeiro login)
-- Hash BCrypt da senha 'admin123': $2a$10$N.zmdr9k7uOCQb1VYnUIVOr5/.F1EJ6NjjKX8yLW.hHnhRjXz8W2i
INSERT INTO users (id, name, email, password, role, created_at, updated_at, created_by, last_modified_by) 
VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    'Super Admin',
    'soudaniel@gmail.com',
    '$2a$10$N.zmdr9k7uOCQb1VYnUIVOr5/.F1EJ6NjjKX8yLW.hHnhRjXz8W2i',
    'SUPER_ADMIN',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    'system',
    'system'
) ON CONFLICT (email) DO NOTHING;

-- Inserir usuário comum de exemplo
INSERT INTO users (id, name, email, password, role, created_at, updated_at, created_by, last_modified_by) 
VALUES (
    '550e8400-e29b-41d4-a716-446655440002',
    'Regular User',
    'user@example.com',
    '$2a$10$N.zmdr9k7uOCQb1VYnUIVOr5/.F1EJ6NjjKX8yLW.hHnhRjXz8W2i',
    'USER',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    'system',
    'system'
) ON CONFLICT (email) DO NOTHING;
