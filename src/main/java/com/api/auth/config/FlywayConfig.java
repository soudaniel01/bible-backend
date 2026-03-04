package com.api.auth.config;

import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuração personalizada do Flyway para evitar dependência circular
 * com o EntityManagerFactory quando ambos estão habilitados.
 */
@Configuration
@ConditionalOnProperty(name = "spring.flyway.enabled", havingValue = "true")
public class FlywayConfig {

    /**
     * Estratégia personalizada de migração do Flyway que resolve
     * o conflito de dependência circular com JPA/Hibernate.
     * 
     * Esta configuração garante que o Flyway execute as migrações
     * antes da inicialização do EntityManagerFactory.
     */
    @Bean
    public FlywayMigrationStrategy flywayMigrationStrategy() {
        return flyway -> {
            // Executa as migrações do Flyway
            flyway.migrate();
        };
    }
}