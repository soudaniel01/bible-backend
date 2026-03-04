package com.api.auth.audit.dto;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class SuspendedConnectionResponse {
    private String email;
    private String clientIp;
    private String userAgent;
    private String deviceInfo;
    private String suspensionReason;
    private long failedAttempts;
    private Instant lastFailedAttempt;
    private long remainingTimeMinutes;
    private Instant suspensionExpiresAt;

    public SuspendedConnectionResponse() {}

    public SuspendedConnectionResponse(String email, String clientIp, String userAgent, 
                                     String deviceInfo, String suspensionReason, 
                                     long failedAttempts, Instant lastFailedAttempt, 
                                     long remainingTimeMinutes, Instant suspensionExpiresAt) {
        this.email = email;
        this.clientIp = clientIp;
        this.userAgent = userAgent;
        this.deviceInfo = deviceInfo;
        this.suspensionReason = suspensionReason;
        this.failedAttempts = failedAttempts;
        this.lastFailedAttempt = lastFailedAttempt;
        this.remainingTimeMinutes = remainingTimeMinutes;
        this.suspensionExpiresAt = suspensionExpiresAt;
    }

    // Getters and Setters
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

    public String getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public String getSuspensionReason() {
        return suspensionReason;
    }

    public void setSuspensionReason(String suspensionReason) {
        this.suspensionReason = suspensionReason;
    }

    public long getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(long failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public Instant getLastFailedAttempt() {
        return lastFailedAttempt;
    }

    public void setLastFailedAttempt(Instant lastFailedAttempt) {
        this.lastFailedAttempt = lastFailedAttempt;
    }

    public long getRemainingTimeMinutes() {
        return remainingTimeMinutes;
    }

    public void setRemainingTimeMinutes(long remainingTimeMinutes) {
        this.remainingTimeMinutes = remainingTimeMinutes;
    }

    public Instant getSuspensionExpiresAt() {
        return suspensionExpiresAt;
    }

    public void setSuspensionExpiresAt(Instant suspensionExpiresAt) {
        this.suspensionExpiresAt = suspensionExpiresAt;
    }
}