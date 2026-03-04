package com.api.auth.audit.dto;

import java.time.Instant;
import java.util.UUID;

public class LoginAuditResponse {
    private UUID id;
    private UUID userId;
    private String userEmail;
    private boolean success;
    private String ipAddress;
    private String userAgent;
    private String deviceInfo;
    private Instant timestamp;

    public LoginAuditResponse() {}

    public LoginAuditResponse(UUID id, UUID userId, String userEmail, boolean success, 
                             String ipAddress, String userAgent, String deviceInfo, Instant timestamp) {
        this.id = id;
        this.userId = userId;
        this.userEmail = userEmail;
        this.success = success;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.deviceInfo = deviceInfo;
        this.timestamp = timestamp;
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

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
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

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}