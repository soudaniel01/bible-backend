package com.api.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.api.auth.security.AuthenticatedUser;

import java.util.Optional;

/**
 * Configuração para auditoria automática JPA.
 * Habilita o rastreamento automático de criação e modificação de entidades.
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaAuditingConfig {

    /**
     * Provedor de auditor que captura o usuário atual do contexto de segurança.
     * Retorna o email do usuário autenticado ou "system" para operações automáticas.
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return Optional.of("system");
            }
            
            // Se o principal é do tipo AuthenticatedUser (JWT)
            if (authentication.getPrincipal() instanceof AuthenticatedUser) {
                AuthenticatedUser user = (AuthenticatedUser) authentication.getPrincipal();
                return Optional.of(user.getEmail());
            }
            
            // Fallback para outros tipos de autenticação
            String principal = authentication.getName();
            return Optional.of(principal != null ? principal : "system");
        };
    }
}