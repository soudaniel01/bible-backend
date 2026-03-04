package com.api.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Utilitário para operações relacionadas a rede e IP.
 */
@Component
public class NetworkUtil {

    private static final String[] IP_HEADER_NAMES = {
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Forwarded",
        "X-Cluster-Client-IP",
        "Proxy-Client-IP",
        "WL-Proxy-Client-IP",
        "HTTP_CLIENT_IP",
        "HTTP_X_FORWARDED_FOR"
    };

    /**
     * Extrai o endereço IP real do cliente, considerando proxies e load balancers.
     */
    public String getClientIpAddress(HttpServletRequest request) {
        for (String headerName : IP_HEADER_NAMES) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // X-Forwarded-For pode conter múltiplos IPs separados por vírgula
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                ip = sanitizeIp(ip);
                if (isValidIp(ip)) {
                    return normalizeIp(ip);
                }
            }
        }

        String remoteAddr = request.getRemoteAddr();
        return normalizeIp(sanitizeIp(remoteAddr));
    }

    /**
     * Sanitiza o endereço IP removendo caracteres inválidos.
     */
    public String sanitizeIp(String ip) {
        if (ip == null) {
            return "unknown";
        }
        return ip.trim().replaceAll("[^0-9a-fA-F:.]", "");
    }

    /**
     * Valida se o IP está em formato válido (IPv4 ou IPv6 básico).
     */
    public boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            return false;
        }
        return ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$") || // IPv4
               ip.matches("^[0-9a-fA-F:]+$"); // IPv6 básico
    }

    /**
     * Normaliza o IP para formato padrão (ex.: mapeia loopback IPv6 para IPv4).
     */
    public String normalizeIp(String ip) {
        if (ip == null || "unknown".equalsIgnoreCase(ip)) {
            return "unknown";
        }
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) {
            return "127.0.0.1";
        }
        return ip;
    }

    /**
     * Extrai e normaliza o User-Agent.
     */
    public String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) {
            return "unknown";
        }
        if (userAgent.length() > 255) {
            userAgent = userAgent.substring(0, 255);
        }
        return userAgent.replaceAll("[\\r\\n\\t]", " ").trim();
    }

    /**
     * Constrói informações do dispositivo normalizadas.
     */
    public String buildDeviceInfo(String clientIp, String userAgent) {
        String deviceInfo = String.format("IP: %s, UA: %s", clientIp, userAgent);
        if (deviceInfo.length() > 255) {
            deviceInfo = deviceInfo.substring(0, 255);
        }
        return deviceInfo;
    }

    /**
     * Extrai informações completas do dispositivo da requisição.
     */
    public String extractDeviceInfo(HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        String userAgent = getUserAgent(request);
        return buildDeviceInfo(clientIp, userAgent);
    }
}