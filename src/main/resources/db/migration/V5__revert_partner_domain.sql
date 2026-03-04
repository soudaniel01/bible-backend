-- Reverter domínio partner: remover tabelas e coluna/constraint adicionadas em V4
-- Ordem de remoção ajustada para evitar erro de dependência (FK)

-- 1. Remover constraint em users que aponta para organization
ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_org;

-- 2. Remover coluna organization_id em users
ALTER TABLE users DROP COLUMN IF EXISTS organization_id;

-- 3. Remover tabela profile (que depende de organization e users)
DROP TABLE IF EXISTS profile;

-- 4. Remover tabela organization (agora sem dependências)
DROP TABLE IF EXISTS organization;
