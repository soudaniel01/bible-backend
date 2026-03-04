package com.api.auth.audit.service;

import com.api.auth.audit.entity.LoginAuditEntity;
import com.api.auth.audit.repository.LoginAuditRepository;
import com.api.auth.util.NetworkUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Value;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Serviço para auditoria de tentativas de login.
 * Registra e consulta informações sobre autenticação de usuários.
 */
@Service
@Transactional
public class LoginAuditService {

    private static final Logger logger = LoggerFactory.getLogger(LoginAuditService.class);

    @Autowired
    private LoginAuditRepository loginAuditRepository;

    @Value("${app.login.suspension.email.window-minutes:2}")
    private int emailSuspensionWindowMinutes;

    @Value("${app.login.suspension.email.max-attempts:5}")
    private int emailSuspensionMaxAttempts;

    @Value("${app.login.suspension.ip.window-minutes:2}")
    private int ipSuspensionWindowMinutes;

    @Value("${app.login.suspension.ip.max-attempts:10}")
    private int ipSuspensionMaxAttempts;

    @Autowired
    private NetworkUtil networkUtil;

    /**
     * Registra uma tentativa de login bem-sucedida
     */
    public void recordSuccessfulLogin(UUID userId, String email, HttpServletRequest request, String sessionId) {
        try {
            String clientIp = networkUtil.getClientIpAddress(request);
            String userAgent = networkUtil.getUserAgent(request);
            String deviceInfo = networkUtil.buildDeviceInfo(clientIp, userAgent);

            LoginAuditEntity audit = new LoginAuditEntity(
                userId, email, clientIp, userAgent, true, null, sessionId, deviceInfo
            );

            loginAuditRepository.save(audit);
            logger.info("Login bem-sucedido registrado para usuário: {} de IP: {}", email, clientIp);
        } catch (Exception e) {
            logger.error("Erro ao registrar login bem-sucedido para usuário: {}", email, e);
        }
    }

    /**
     * Registra uma tentativa de login falhada
     */
    public void recordFailedLogin(String email, HttpServletRequest request, String failureReason) {
        try {
            String clientIp = networkUtil.getClientIpAddress(request);
            String userAgent = networkUtil.getUserAgent(request);
            String deviceInfo = networkUtil.buildDeviceInfo(clientIp, userAgent);

            LoginAuditEntity audit = new LoginAuditEntity(
                null, email, clientIp, userAgent, false, failureReason, null, deviceInfo
            );

            loginAuditRepository.save(audit);
            logger.warn("Login falhado registrado para email: {} de IP: {} - Razão: {}", 
                       email, clientIp, failureReason);
        } catch (Exception e) {
            logger.error("Erro ao registrar login falhado para email: {}", email, e);
        }
    }

    /**
     * Verifica se um IP está sendo usado para muitas tentativas falhadas
     */
    public boolean isIpSuspicious(String clientIp, int maxAttempts, int timeWindowMinutes) {
        Instant since = Instant.now().minus(timeWindowMinutes, ChronoUnit.MINUTES);
        long failedAttempts = loginAuditRepository.countFailedLoginsByIpSince(clientIp, since);
        return failedAttempts >= maxAttempts;
    }

    /**
     * Verifica se um email está sendo usado para muitas tentativas falhadas
     */
    public boolean isEmailSuspicious(String email, int maxAttempts, int timeWindowMinutes) {
        Instant since = Instant.now().minus(timeWindowMinutes, ChronoUnit.MINUTES);
        long failedAttempts = loginAuditRepository.countFailedLoginsByEmailSince(email, since);
        return failedAttempts >= maxAttempts;
    }

    /**
     * Busca histórico de login por usuário
     */
    @Transactional(readOnly = true)
    public Page<LoginAuditEntity> getLoginHistoryByUserId(UUID userId, Pageable pageable) {
        return loginAuditRepository.findByUserIdOrderByLoginTimestampDesc(userId, pageable);
    }

    /**
     * Busca histórico de login por email
     */
    @Transactional(readOnly = true)
    public Page<LoginAuditEntity> getLoginHistoryByEmail(String email, Pageable pageable) {
        return loginAuditRepository.findByEmailOrderByLoginTimestampDesc(email, pageable);
    }

    /**
     * Busca logins bem-sucedidos por usuário
     */
    @Transactional(readOnly = true)
    public Page<LoginAuditEntity> getSuccessfulLoginsByUserId(UUID userId, Pageable pageable) {
        return loginAuditRepository.findSuccessfulLoginsByUserId(userId, pageable);
    }

    /**
     * Extrai o endereço IP real do cliente, considerando proxies e load balancers
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headerNames = {
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded",
            "X-Cluster-Client-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // X-Forwarded-For pode conter múltiplos IPs separados por vírgula
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                // Sanitiza e valida o IP
                ip = sanitizeIp(ip);
                if (isValidIp(ip)) {
                    return ip;
                }
            }
        }

        // Fallback para o IP remoto direto
        String remoteAddr = request.getRemoteAddr();
        return sanitizeIp(remoteAddr);
    }

    /**
     * Sanitiza o endereço IP removendo caracteres inválidos
     */
    private String sanitizeIp(String ip) {
        if (ip == null) {
            return "unknown";
        }
        // Remove espaços e caracteres não permitidos em IPs
        return ip.trim().replaceAll("[^0-9a-fA-F:.]", "");
    }

    /**
     * Valida se o IP está em formato válido (IPv4 ou IPv6 básico)
     */
    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            return false;
        }
        // Validação básica para IPv4 e IPv6
        return ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$") || // IPv4
               ip.matches("^[0-9a-fA-F:]+$"); // IPv6 básico
    }

    /**
     * Extrai e normaliza o User-Agent
     */
    private String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) {
            return "unknown";
        }
        // Limita o tamanho e remove caracteres problemáticos
        if (userAgent.length() > 255) {
            userAgent = userAgent.substring(0, 255);
        }
        return userAgent.replaceAll("[\\r\\n\\t]", " ").trim();
    }

    /**
     * Constrói informações do dispositivo normalizadas
     */
    private String buildDeviceInfo(String clientIp, String userAgent) {
        String deviceInfo = String.format("IP: %s, UA: %s", clientIp, userAgent);
        // Garante que não exceda 255 caracteres
        if (deviceInfo.length() > 255) {
            deviceInfo = deviceInfo.substring(0, 255);
        }
        return deviceInfo;
    }

    /**
     * Busca conexões suspensas devido ao rate limiting
     */
    @Transactional(readOnly = true)
    public java.util.List<com.api.auth.audit.dto.SuspendedConnectionResponse> getSuspendedConnections() {
        java.util.List<com.api.auth.audit.dto.SuspendedConnectionResponse> suspendedConnections = new java.util.ArrayList<>();
        
        // Busca tentativas falhadas recentes (janelas configuráveis)
        Instant ipSince = Instant.now().minus(ipSuspensionWindowMinutes, ChronoUnit.MINUTES);
        Instant emailSince = Instant.now().minus(emailSuspensionWindowMinutes, ChronoUnit.MINUTES);
        
        // Busca todas as tentativas falhadas recentes
        java.util.List<LoginAuditEntity> recentFailures = loginAuditRepository.findBySuccessFalseAndLoginTimestampAfter(emailSince);
        
        // Agrupa por email para verificar suspensões por email
        java.util.Map<String, java.util.List<LoginAuditEntity>> failuresByEmail = recentFailures.stream()
            .collect(java.util.stream.Collectors.groupingBy(LoginAuditEntity::getEmail));
        
        for (java.util.Map.Entry<String, java.util.List<LoginAuditEntity>> entry : failuresByEmail.entrySet()) {
            String email = entry.getKey();
            java.util.List<LoginAuditEntity> emailFailures = entry.getValue();
            
            if (emailFailures.size() >= emailSuspensionMaxAttempts) {
                LoginAuditEntity lastFailure = emailFailures.stream()
                    .max(java.util.Comparator.comparing(LoginAuditEntity::getLoginTimestamp))
                    .orElse(null);
                
                if (lastFailure != null) {
                    Instant suspensionExpires = lastFailure.getLoginTimestamp().plus(emailSuspensionWindowMinutes, ChronoUnit.MINUTES);
                    long remainingMinutes = ChronoUnit.MINUTES.between(Instant.now(), suspensionExpires);
                    
                    if (remainingMinutes > 0) {
                        suspendedConnections.add(new com.api.auth.audit.dto.SuspendedConnectionResponse(
                            email,
                            lastFailure.getClientIp(),
                            lastFailure.getUserAgent(),
                            lastFailure.getDeviceInfo(),
                            "Email bloqueado por muitas tentativas (" + emailFailures.size() + " tentativas em " + emailSuspensionWindowMinutes + " min)",
                            emailFailures.size(),
                            lastFailure.getLoginTimestamp(),
                            remainingMinutes,
                            suspensionExpires
                        ));
                    }
                }
            }
        }
        
        // Agrupa por IP para verificar suspensões por IP
        java.util.Map<String, java.util.List<LoginAuditEntity>> failuresByIp = recentFailures.stream()
            .filter(audit -> audit.getLoginTimestamp().isAfter(ipSince))
            .collect(java.util.stream.Collectors.groupingBy(LoginAuditEntity::getClientIp));
        
        for (java.util.Map.Entry<String, java.util.List<LoginAuditEntity>> entry : failuresByIp.entrySet()) {
            String ip = entry.getKey();
            java.util.List<LoginAuditEntity> ipFailures = entry.getValue();
            
            if (ipFailures.size() >= ipSuspensionMaxAttempts) {
                LoginAuditEntity lastFailure = ipFailures.stream()
                    .max(java.util.Comparator.comparing(LoginAuditEntity::getLoginTimestamp))
                    .orElse(null);
                
                if (lastFailure != null) {
                    Instant suspensionExpires = lastFailure.getLoginTimestamp().plus(ipSuspensionWindowMinutes, ChronoUnit.MINUTES);
                    long remainingMinutes = ChronoUnit.MINUTES.between(Instant.now(), suspensionExpires);
                    
                    if (remainingMinutes > 0) {
                        boolean alreadyAdded = suspendedConnections.stream()
                            .anyMatch(conn -> conn.getEmail().equals(lastFailure.getEmail()) && 
                                           conn.getClientIp().equals(ip));
                        
                        if (!alreadyAdded) {
                            suspendedConnections.add(new com.api.auth.audit.dto.SuspendedConnectionResponse(
                                lastFailure.getEmail(),
                                ip,
                                lastFailure.getUserAgent(),
                                lastFailure.getDeviceInfo(),
                                "IP bloqueado por muitas tentativas (" + ipFailures.size() + " tentativas em " + ipSuspensionWindowMinutes + " min)",
                                ipFailures.size(),
                                lastFailure.getLoginTimestamp(),
                                remainingMinutes,
                                suspensionExpires
                            ));
                        }
                    }
                }
            }
        }
        
        return suspendedConnections;
    }

    /**
     * Remove registros de auditoria antigos (para manutenção)
     */
    public void cleanupOldAuditRecords(int daysToKeep) {
        Instant cutoffDate = Instant.now().minus(daysToKeep, ChronoUnit.DAYS);
        loginAuditRepository.deleteByLoginTimestampBefore(cutoffDate);
        logger.info("Registros de auditoria anteriores a {} foram removidos", cutoffDate);
    }

    /**
     * Calcula segundos restantes de suspensão por IP na janela informada.
     */
    public long getRemainingSuspensionSecondsForIp(String clientIp, int timeWindowMinutes) {
        Instant since = Instant.now().minus(timeWindowMinutes, java.time.temporal.ChronoUnit.MINUTES);
        Instant last = loginAuditRepository.findLastFailedLoginTimestampByIpSince(clientIp, since);
        if (last == null) {
            return timeWindowMinutes * 60L;
        }
        Instant expires = last.plus(timeWindowMinutes, java.time.temporal.ChronoUnit.MINUTES);
        long seconds = java.time.Duration.between(Instant.now(), expires).getSeconds();
        return Math.max(0L, seconds);
    }

    /**
     * Calcula segundos restantes de suspensão por email na janela informada.
     */
    public long getRemainingSuspensionSecondsForEmail(String email, int timeWindowMinutes) {
        Instant since = Instant.now().minus(timeWindowMinutes, java.time.temporal.ChronoUnit.MINUTES);
        Instant last = loginAuditRepository.findLastFailedLoginTimestampByEmailSince(email, since);
        if (last == null) {
            return timeWindowMinutes * 60L;
        }
        Instant expires = last.plus(timeWindowMinutes, java.time.temporal.ChronoUnit.MINUTES);
        long seconds = java.time.Duration.between(Instant.now(), expires).getSeconds();
        return Math.max(0L, seconds);
    }
}