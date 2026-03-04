-- Adicionar coluna device_info na tabela refresh_tokens
-- Idempotente: usa IF NOT EXISTS para evitar erro se já existir

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS device_info VARCHAR(255);
