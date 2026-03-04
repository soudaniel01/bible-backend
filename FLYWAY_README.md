# Flyway Database Migration Guide

## Visão Geral

Este projeto utiliza Flyway para gerenciamento de migrações de banco de dados em produção, garantindo versionamento e controle das mudanças no schema.

## Configuração por Ambiente

### Desenvolvimento (Padrão)
- **Flyway**: Desabilitado (`spring.flyway.enabled=false`)
- **JPA DDL**: `update` (Hibernate gerencia o schema automaticamente)
- **Inicialização**: Dados de teste carregados via JPA

### Testes
- **Flyway**: Desabilitado (`spring.flyway.enabled=false`)
- **JPA DDL**: `create-drop` (Schema recriado a cada execução)
- **Inicialização**: Dados de teste gerenciados pelo Hibernate

### Produção
- **Flyway**: Habilitado (`spring.flyway.enabled=true`)
- **JPA DDL**: `none` (Schema gerenciado exclusivamente pelo Flyway)
- **Inicialização**: Dados iniciais via migrações Flyway

## Scripts de Migração

### V1__init.sql
- Criação das tabelas principais:
  - `users` (usuários do sistema)
  - `refresh_tokens` (tokens de refresh)
  - `login_audit` (auditoria de login)
- Inserção de usuários iniciais (SUPER_ADMIN, ADMIN, USER)

### V2__indexes.sql
- Índices de performance para:
  - Consultas de autenticação
  - Auditoria de login
  - Detecção de atividade suspeita
  - Otimização de refresh tokens

## Como Executar em Produção

### 1. Configurar Variáveis de Ambiente
```bash
# Habilitar Flyway
export FLYWAY_ENABLED=true

# Configurar JPA para produção
export JPA_DDL_AUTO=none
export JPA_DEFER_INIT=false

# Configurações do banco
export DB_URL=jdbc:postgresql://localhost:5432/production_db
export DB_USER=prod_user
export DB_PASS=secure_password

# Configurações de segurança
export SECURITY_TOKEN_SECRET=your-super-secure-secret-key
export FRONTEND_ALLOWED_ORIGINS=https://your-domain.com
```

### 2. Executar com Profile de Produção
```bash
java -jar auth-api.jar --spring.profiles.active=prod
```

### 3. Verificar Migrações
O Flyway executará automaticamente as migrações na inicialização. Logs indicarão:
```
Flyway Community Edition X.X.X by Redgate
Database: jdbc:postgresql://localhost:5432/production_db (PostgreSQL X.X)
Successfully validated X migrations (execution time 00:00.XXXs)
Current version of schema "public": X
Migrating schema "public" to version "X - description"
Successfully applied X migrations to schema "public" (execution time 00:00.XXXs)
```

## Adicionando Novas Migrações

### Convenção de Nomenclatura
- `VX__description.sql` (onde X é o número sequencial)
- Exemplo: `V3__add_user_preferences_table.sql`

### Localização
```
src/main/resources/db/migration/
├── V1__init.sql
├── V2__indexes.sql
└── V3__your_new_migration.sql
```

### Exemplo de Nova Migração
```sql
-- V3__add_user_preferences_table.sql
CREATE TABLE user_preferences (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    preference_key VARCHAR(100) NOT NULL,
    preference_value TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, preference_key)
);

CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);
CREATE INDEX idx_user_preferences_key ON user_preferences(preference_key);
```

## Comandos Úteis

### Verificar Status das Migrações
```bash
# Via Maven (desenvolvimento)
mvn flyway:info -Dflyway.configFiles=src/main/resources/application-prod.properties

# Via linha de comando
flyway -configFiles=application-prod.properties info
```

### Validar Migrações
```bash
mvn flyway:validate -Dflyway.configFiles=src/main/resources/application-prod.properties
```

## Segurança e Boas Práticas

1. **Backup**: Sempre faça backup do banco antes de executar migrações em produção
2. **Testes**: Teste todas as migrações em ambiente de staging primeiro
3. **Rollback**: Prepare scripts de rollback para mudanças críticas
4. **Monitoramento**: Monitore logs durante a execução das migrações
5. **Validação**: Use `flyway:validate` para verificar integridade

## Troubleshooting

### Erro de Dependência Circular
Se encontrar erro de dependência circular entre Flyway e EntityManagerFactory:
- Verifique se `spring.flyway.enabled=false` em desenvolvimento
- Confirme que `FlywayConfig.java` está presente
- Use profile correto (`prod` para produção)

### Migração Falhou
```bash
# Reparar estado do Flyway
flyway -configFiles=application-prod.properties repair

# Forçar baseline (apenas se necessário)
flyway -configFiles=application-prod.properties baseline
```

### Verificar Tabela de Controle
```sql
SELECT * FROM flyway_schema_history ORDER BY installed_rank;
```