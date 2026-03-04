
-- Normaliza dados legados após remoção do role ADMIN no enum UserRole
-- Converte ADMIN -> USER
UPDATE users
SET role = 'USER'
WHERE role = 'ADMIN';