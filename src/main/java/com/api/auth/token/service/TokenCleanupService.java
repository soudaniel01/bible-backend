package com.api.auth.token.service;

import com.api.auth.token.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Serviço para limpeza automática de tokens expirados.
 * Executa diariamente para manter a performance do banco de dados.
 */
@Service
public class TokenCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(TokenCleanupService.class);

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    /**
     * Executa limpeza diária de refresh tokens expirados.
     * Roda todos os dias às 02:00 AM.
     */
    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        try {
            logger.info("Iniciando limpeza de refresh tokens expirados...");
            
            Instant now = Instant.now();
            int deletedCount = refreshTokenRepository.deleteByExpiresAtBefore(now);
            
            logger.info("Limpeza concluída. {} refresh tokens expirados foram removidos.", deletedCount);
        } catch (Exception e) {
            logger.error("Erro durante a limpeza de refresh tokens expirados", e);
        }
    }

    /**
     * Executa limpeza de tokens revogados antigos.
     * Roda semanalmente aos domingos às 03:00 AM.
     */
    @Scheduled(cron = "0 0 3 * * SUN")
    @Transactional
    public void cleanupRevokedTokens() {
        try {
            logger.info("Iniciando limpeza de refresh tokens revogados antigos...");
            
            // Remove tokens revogados há mais de 30 dias
            Instant cutoffDate = Instant.now().minusSeconds(30 * 24 * 60 * 60); // 30 dias
            int deletedCount = refreshTokenRepository.deleteByRevokedTrueAndCreatedAtBefore(cutoffDate);
            
            logger.info("Limpeza de tokens revogados concluída. {} tokens foram removidos.", deletedCount);
        } catch (Exception e) {
            logger.error("Erro durante a limpeza de refresh tokens revogados", e);
        }
    }
}