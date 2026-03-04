package com.api.auth.audit.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Entidade para auditoria de tentativas de login.
 * Registra informações detalhadas sobre cada tentativa de autenticação.
 */
@Entity
@Table(name = "login_audit", indexes = {
    @Index(name = "idx_login_audit_user_id", columnList = "user_id"),
    @Index(name = "idx_login_audit_timestamp", columnList = "login_timestamp"),
    @Index(name = "idx_login_audit_success", columnList = "success"),
    @Index(name = "idx_login_audit_ip", columnList = "client_ip"),
    @Index(name = "idx_login_audit_email_ts", columnList = "email, login_timestamp"),
    @Index(name = "idx_login_audit_ip_ts", columnList = "client_ip, login_timestamp")
})
public class LoginAuditEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "user_id", columnDefinition = "UUID")
    private UUID userId;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @Column(name = "client_ip", nullable = false, length = 45) // IPv6 support
    private String clientIp;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "success", nullable = false)
    private boolean success;

    @Column(name = "failure_reason", length = 500)
    private String failureReason;

    @CreationTimestamp
    @Column(name = "login_timestamp", nullable = false)
    private Instant loginTimestamp;

    @Column(name = "session_id", length = 500)
    private String sessionId; // ID do refresh token gerado

    @Column(name = "device_info", length = 255)
    private String deviceInfo;

    // Constructors
    public LoginAuditEntity() {}

    public LoginAuditEntity(UUID userId, String email, String clientIp, String userAgent, 
                           boolean success, String failureReason, String sessionId, String deviceInfo) {
        this.userId = userId;
        this.email = email;
        this.clientIp = clientIp;
        this.userAgent = userAgent;
        this.success = success;
        this.failureReason = failureReason;
        this.sessionId = sessionId;
        this.deviceInfo = deviceInfo;
    }

    // Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }

    public Instant getLoginTimestamp() {
        return loginTimestamp;
    }

    public void setLoginTimestamp(Instant loginTimestamp) {
        this.loginTimestamp = loginTimestamp;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LoginAuditEntity that = (LoginAuditEntity) o;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}