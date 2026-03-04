package com.api.auth.audit.repository;

import com.api.auth.audit.entity.LoginAuditEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Repositório para auditoria de login.
 * Fornece métodos para consultar histórico de tentativas de login.
 */
@Repository
public interface LoginAuditRepository extends JpaRepository<LoginAuditEntity, UUID> {

    /**
     * Busca tentativas de login por usuário
     */
    Page<LoginAuditEntity> findByUserIdOrderByLoginTimestampDesc(UUID userId, Pageable pageable);

    /**
     * Busca tentativas de login por email
     */
    Page<LoginAuditEntity> findByEmailOrderByLoginTimestampDesc(String email, Pageable pageable);

    /**
     * Busca tentativas de login falhadas por IP em um período
     */
    @Query("""
        SELECT la FROM LoginAuditEntity la 
        WHERE la.clientIp = :clientIp 
        AND la.success = false 
        AND la.loginTimestamp >= :since
        ORDER BY la.loginTimestamp DESC
    """)
    List<LoginAuditEntity> findFailedLoginsByIpSince(@Param("clientIp") String clientIp, 
                                                     @Param("since") Instant since);

    /**
     * Conta tentativas de login falhadas por IP em um período
     */
    @Query("""
        SELECT COUNT(la) FROM LoginAuditEntity la 
        WHERE la.clientIp = :clientIp 
        AND la.success = false 
        AND la.loginTimestamp >= :since
    """)
    long countFailedLoginsByIpSince(@Param("clientIp") String clientIp, 
                                   @Param("since") Instant since);

    /**
     * Busca tentativas de login falhadas por usuário em um período
     */
    @Query("""
        SELECT COUNT(la) FROM LoginAuditEntity la 
        WHERE la.email = :email 
        AND la.success = false 
        AND la.loginTimestamp >= :since
    """)
    long countFailedLoginsByEmailSince(@Param("email") String email, 
                                      @Param("since") Instant since);

    /**
     * Busca logins bem-sucedidos por usuário
     */
    @Query("""
        SELECT la FROM LoginAuditEntity la 
        WHERE la.userId = :userId 
        AND la.success = true 
        ORDER BY la.loginTimestamp DESC
    """)
    Page<LoginAuditEntity> findSuccessfulLoginsByUserId(@Param("userId") UUID userId, Pageable pageable);

    /**
     * Remove registros de auditoria antigos (para limpeza)
     */
    void deleteByLoginTimestampBefore(Instant cutoffDate);
    
    /**
     * Remove tentativas de login falhadas por email
     */
    @Modifying
    @Query("DELETE FROM LoginAuditEntity la WHERE la.email = :email AND la.success = :success")
    void deleteByEmailAndSuccess(@Param("email") String email, @Param("success") boolean success);

    // Novo: último timestamp de falha por IP dentro da janela
    @Query("""
        SELECT MAX(la.loginTimestamp) FROM LoginAuditEntity la
        WHERE la.clientIp = :clientIp
        AND la.success = false
        AND la.loginTimestamp >= :since
    """)
    Instant findLastFailedLoginTimestampByIpSince(@Param("clientIp") String clientIp,
                                                  @Param("since") Instant since);

    // Novo: último timestamp de falha por email dentro da janela
    @Query("""
        SELECT MAX(la.loginTimestamp) FROM LoginAuditEntity la
        WHERE la.email = :email
        AND la.success = false
        AND la.loginTimestamp >= :since
    """)
    Instant findLastFailedLoginTimestampByEmailSince(@Param("email") String email,
                                                     @Param("since") Instant since);

    /**
     * Busca todas as tentativas de login falhadas após uma data
     */
    List<LoginAuditEntity> findBySuccessFalseAndLoginTimestampAfter(Instant since);

    /**
     * Conta tentativas por usuário após uma data
     */
    long countByUserIdAndLoginTimestampAfter(UUID userId, Instant since);
}