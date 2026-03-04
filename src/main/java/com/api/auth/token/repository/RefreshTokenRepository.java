package com.api.auth.token.repository;

import com.api.auth.token.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    /**
     * Busca um refresh token pelo hash que não esteja revogado
     */
    Optional<RefreshTokenEntity> findByTokenHashAndRevokedFalse(String tokenHash);

    /**
     * Busca um refresh token pelo hash (independente do status de revogação)
     * Usado para detectar reuso de tokens e identificar o usuário
     */
    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    /**
     * Revoga todos os tokens ativos de um usuário
     */
    @Modifying
    @Transactional
    @Query("UPDATE RefreshTokenEntity rt SET rt.revoked = true WHERE rt.userId = :userId AND rt.revoked = false")
    void revokeAllByUserId(@Param("userId") UUID userId);

    /**
     * Remove tokens expirados do banco (limpeza)
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshTokenEntity rt WHERE rt.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") Instant now);

    /**
     * Conta quantos tokens ativos um usuário possui
     */
    @Query("""
        SELECT COUNT(rt)
        FROM RefreshTokenEntity rt
        WHERE rt.userId = :userId
          AND rt.revoked = false
          AND rt.expiresAt > :now
    """)
    long countActiveTokensByUserId(@Param("userId") UUID userId, @Param("now") Instant now);

    /**
     * Remove refresh tokens expirados
     */
    @Modifying
    @Query("DELETE FROM RefreshTokenEntity rt WHERE rt.expiresAt < :cutoffDate")
    int deleteByExpiresAtBefore(@Param("cutoffDate") Instant cutoffDate);

    /**
     * Remove refresh tokens revogados antigos
     */
    @Modifying
    @Query("DELETE FROM RefreshTokenEntity rt WHERE rt.revoked = true AND rt.createdAt < :cutoffDate")
    int deleteByRevokedTrueAndCreatedAtBefore(@Param("cutoffDate") Instant cutoffDate);

    /**
     * Busca todos os tokens ativos de um usuário
     */
    @Query("""
        SELECT rt
        FROM RefreshTokenEntity rt
        WHERE rt.userId = :userId
          AND rt.revoked = false
          AND rt.expiresAt > :now
    """)
    java.util.List<RefreshTokenEntity> findActiveTokensByUserId(@Param("userId") UUID userId, @Param("now") Instant now);
}