-- Tabela de organizações (agência/afiliado unificados como parceiro)
CREATE TABLE IF NOT EXISTS organization (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    person_type VARCHAR(20) NOT NULL, -- INDIVIDUAL / COMPANY
    document VARCHAR(32) NOT NULL UNIQUE, -- CPF/CNPJ
    email VARCHAR(255),
    phone VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    last_modified_by VARCHAR(255)
);

-- Tabela de perfis: 1:1 com users (um profile É o user), opcionalmente vinculado à organization
CREATE TABLE IF NOT EXISTS profile (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE,
    organization_id UUID NULL,
    display_name VARCHAR(255) NOT NULL,
    handle VARCHAR(50) NOT NULL UNIQUE,
    bio TEXT,
    avatar_url VARCHAR(1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    last_modified_by VARCHAR(255),
    CONSTRAINT fk_profile_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_profile_org FOREIGN KEY (organization_id) REFERENCES organization(id) ON DELETE SET NULL
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_profile_handle ON profile(handle);
CREATE INDEX IF NOT EXISTS idx_profile_org ON profile(organization_id);

-- Adicionar coluna organization_id em users (para escopo de acesso do PARTNER e também users criados como profiles)
ALTER TABLE users
ADD COLUMN IF NOT EXISTS organization_id UUID NULL;

ALTER TABLE users
ADD CONSTRAINT fk_users_org FOREIGN KEY (organization_id) REFERENCES organization(id) ON DELETE SET NULL;