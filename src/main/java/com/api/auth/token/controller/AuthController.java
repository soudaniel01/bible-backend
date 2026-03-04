package com.api.auth.token.controller;

import com.api.auth.audit.service.LoginAuditService;
import com.api.auth.token.dto.LoginRequest;
import com.api.auth.token.dto.LoginResponse;
import com.api.auth.user.service.UserService;
import com.api.auth.util.NetworkUtil;
import com.api.auth.token.dto.RefreshRequest;
import com.api.auth.token.dto.TokenResponse;
import com.api.auth.token.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.ResponseCookie;
import org.springframework.beans.factory.annotation.Value;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Endpoints para autenticação com refresh token")
public class AuthController {

    private final RefreshTokenService refreshTokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private LoginAuditService loginAuditService;
    
    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;
    
    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    public AuthController(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    @Value("${app.login.suspension.ip.window-minutes:2}")
    private int ipSuspensionWindowMinutes;

    @Value("${app.login.suspension.ip.max-attempts:10}")
    private int ipSuspensionMaxAttempts;

    @Value("${app.login.suspension.email.window-minutes:2}")
    private int emailSuspensionWindowMinutes;

    @Value("${app.login.suspension.email.max-attempts:5}")
    private int emailSuspensionMaxAttempts;

    @Value("${app.jwt.use-cookie:true}")
    private boolean useCookie;
    
    @Value("${app.security.same-site:Lax}")
    private String sameSite;
    
    @Value("${app.security.secure-cookie:false}")
    private boolean secureCookie;

    @Autowired
    private NetworkUtil networkUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) throws Exception {
        String deviceInfo = networkUtil.extractDeviceInfo(request);
        
        try {
            // Verifica se o IP ou email estão suspeitos (muitas tentativas falhadas)
            String clientIp = networkUtil.getClientIpAddress(request);
            if (loginAuditService.isIpSuspicious(clientIp, ipSuspensionMaxAttempts, ipSuspensionWindowMinutes)) {
                loginAuditService.recordFailedLogin(loginRequest.getEmail(), request, "Muitas tentativas de login - IP");
                
                long seconds = loginAuditService.getRemainingSuspensionSecondsForIp(clientIp, ipSuspensionWindowMinutes);
                if (seconds <= 0) seconds = ipSuspensionWindowMinutes * 60L;
                long minutes = Math.max(1L, (seconds + 59) / 60);

                Map<String, String> error = new HashMap<>();
                error.put("message", "Muitas tentativas. Tente novamente em " + minutes + " minutos.");
                return ResponseEntity.status(429)
                        .header("Retry-After", String.valueOf(seconds))
                        .body(error);
            }
            
            if (loginAuditService.isEmailSuspicious(loginRequest.getEmail(), emailSuspensionMaxAttempts, emailSuspensionWindowMinutes)) {
                loginAuditService.recordFailedLogin(loginRequest.getEmail(), request, "Muitas tentativas de login - Email");
                
                long seconds = loginAuditService.getRemainingSuspensionSecondsForEmail(loginRequest.getEmail(), emailSuspensionWindowMinutes);
                if (seconds <= 0) seconds = emailSuspensionWindowMinutes * 60L;
                long minutes = Math.max(1L, (seconds + 59) / 60);

                Map<String, String> error = new HashMap<>();
                error.put("message", "Muitas tentativas. Tente novamente em " + minutes + " minutos.");
                return ResponseEntity.status(429)
                        .header("Retry-After", String.valueOf(seconds))
                        .body(error);
            }
            
            // Valida credenciais e obtém usuário
            var user = userService.findByEmailForLogin(loginRequest.getEmail(), loginRequest.getPassword());
            
            // Cria resposta com access e refresh tokens
            LoginResponse response = refreshTokenService.createLoginResponse(user, deviceInfo);
            
            // Registra login bem-sucedido
            loginAuditService.recordSuccessfulLogin(
                user.getId(), 
                user.getEmail(), 
                request, 
                response.getRefreshToken()
            );
            
            // Define o cookie HttpOnly com o refresh token se configurado
            if (useCookie) {
                String cookie = createSecureRefreshTokenCookie(response.getRefreshToken());
                // Remove refresh token do body
                response.setRefreshToken(null);
                
                return ResponseEntity.ok()
                    .header("Set-Cookie", cookie)
                    .body(response);
            } else {
                return ResponseEntity.ok(response);
            }
        } catch (Exception e) {
            // Registra tentativa de login falhada
            loginAuditService.recordFailedLogin(loginRequest.getEmail(), request, e.getMessage());

            Map<String, String> error = new HashMap<>();
            error.put("message", "Credenciais inválidas. Múltiplos erros podem suspender o login por alguns minutos.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @PostMapping("/refresh")
    @Operation(
        summary = "Renovar access token",
        description = "Renova o access token usando um refresh token válido via HttpOnly cookie ou RequestBody. O refresh token é rotacionado (o antigo é revogado e um novo é gerado)."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token renovado com sucesso"),
        @ApiResponse(responseCode = "401", description = "Refresh token inválido, expirado ou revogado"),
        @ApiResponse(responseCode = "400", description = "Dados de entrada inválidos")
    })
    public ResponseEntity<?> refreshToken(
            @CookieValue(value = "refresh_token", required = false) String refreshTokenFromCookie,
            @RequestBody(required = false) RefreshRequest refreshRequest,
            HttpServletRequest request) {
        
        try {
            // Prioriza cookie HttpOnly, depois RequestBody como fallback
            String refreshToken = null;
            if (refreshTokenFromCookie != null && !refreshTokenFromCookie.trim().isEmpty()) {
                refreshToken = refreshTokenFromCookie;
            } else if (refreshRequest != null && refreshRequest.getRefreshToken() != null) {
                refreshToken = refreshRequest.getRefreshToken();
            }
            
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "invalid_request");
                error.put("error_description", "Refresh token not provided via cookie or request body");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
            }
            
            String deviceInfo = networkUtil.extractDeviceInfo(request);
            
            Optional<TokenResponse> tokenResponse = refreshTokenService.refreshAccessToken(
                refreshToken, 
                deviceInfo
            );
            
            if (tokenResponse.isPresent()) {
                TokenResponse response = tokenResponse.get();
                
                // Se o token veio via cookie OU se useCookie=true, retorna via cookie
                if ((refreshTokenFromCookie != null && !refreshTokenFromCookie.trim().isEmpty()) || useCookie) {
                    String cookie = createSecureRefreshTokenCookie(response.getRefreshToken());
                    
                    // Se useCookie=true, remove do body
                    if (useCookie) {
                        response.setRefreshToken(null);
                    }
                    
                    return ResponseEntity.ok()
                        .header("Set-Cookie", cookie)
                        .body(response);
                } else {
                    return ResponseEntity.ok(response);
                }
            } else {
                Map<String, String> error = new HashMap<>();
                error.put("error", "invalid_grant");
                error.put("error_description", "Refresh token is invalid, expired, or revoked");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
            }
            
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "server_error");
            error.put("error_description", "An error occurred while processing the request");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/logout")
    @Operation(
        summary = "Fazer logout",
        description = "Revoga o refresh token fornecido via cookie ou RequestBody, invalidando-o para uso futuro."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Logout realizado com sucesso"),
        @ApiResponse(responseCode = "400", description = "Dados de entrada inválidos")
    })
    public ResponseEntity<?> logout(
            @CookieValue(value = "refresh_token", required = false) String refreshTokenFromCookie,
            @RequestBody(required = false) RefreshRequest refreshRequest) {
        try {
            // Prioriza cookie HttpOnly, depois RequestBody como fallback
            String refreshToken = null;
            boolean hadCookie = false;
            
            if (refreshTokenFromCookie != null && !refreshTokenFromCookie.trim().isEmpty()) {
                refreshToken = refreshTokenFromCookie;
                hadCookie = true;
            } else if (refreshRequest != null && refreshRequest.getRefreshToken() != null) {
                refreshToken = refreshRequest.getRefreshToken();
            }
            
            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                refreshTokenService.revokeRefreshToken(refreshToken);
            }
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout successful");
            
            // Se havia cookie, limpa ele na resposta
            if (hadCookie) {
                return ResponseEntity.ok()
                    .header("Set-Cookie", createClearRefreshTokenCookie())
                    .body(response);
            } else {
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "server_error");
            error.put("error_description", "An error occurred while processing logout");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/logout-all")
    @Operation(
        summary = "Fazer logout de todos os dispositivos",
        description = "Revoga todos os refresh tokens ativos do usuário, forçando re-login em todos os dispositivos."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Logout de todos os dispositivos realizado com sucesso"),
        @ApiResponse(responseCode = "401", description = "Token de acesso inválido"),
        @ApiResponse(responseCode = "400", description = "Dados de entrada inválidos")
    })
    public ResponseEntity<?> logoutAll(
            @CookieValue(value = "refresh_token", required = false) String refreshTokenFromCookie,
            @RequestBody(required = false) RefreshRequest refreshRequest) {
        try {
            // Prioriza cookie HttpOnly, depois RequestBody como fallback
            String refreshToken = null;
            boolean hadCookie = false;
            
            if (refreshTokenFromCookie != null && !refreshTokenFromCookie.trim().isEmpty()) {
                refreshToken = refreshTokenFromCookie;
                hadCookie = true;
            } else if (refreshRequest != null && refreshRequest.getRefreshToken() != null) {
                refreshToken = refreshRequest.getRefreshToken();
            }
            
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "invalid_request");
                error.put("error_description", "Refresh token not provided via cookie or request body");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
            }
            
            // Revoga todos os tokens do usuário baseado no refresh token fornecido
            boolean success = refreshTokenService.revokeAllUserTokensByRefreshToken(refreshToken);
            
            if (!success) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "invalid_grant");
                error.put("error_description", "Refresh token is invalid, expired, or revoked");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
            }
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout from all devices successful");
            
            // Se havia cookie, limpa ele na resposta
            if (hadCookie) {
                return ResponseEntity.ok()
                    .header("Set-Cookie", createClearRefreshTokenCookie())
                    .body(response);
            } else {
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "server_error");
            error.put("error_description", "An error occurred while processing logout");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Obtém o endereço IP real do cliente
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
                // Sanitiza o IP removendo caracteres inválidos
                ip = sanitizeIp(ip);
                if (isValidIp(ip)) {
                    return ip;
                }
            }
        }

        // Fallback para o IP remoto direto
        return sanitizeIp(request.getRemoteAddr());
    }

    private String sanitizeIp(String ip) {
        if (ip == null) {
            return "unknown";
        }
        // Remove espaços e caracteres não permitidos em IPs
        return ip.trim().replaceAll("[^0-9a-fA-F:.]", "");
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            return false;
        }
        // Validação básica para IPv4 e IPv6
        return ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$") || // IPv4
               ip.matches("^[0-9a-fA-F:]+$"); // IPv6 básico
    }
    
    /**
     * Cria um cookie HttpOnly seguro para o refresh token
     * 
     * @param refreshToken O refresh token a ser armazenado no cookie
     * @return String formatada do cookie com atributos de segurança
     */
    private String createSecureRefreshTokenCookie(String refreshToken) {
        // Duração do cookie: 30 dias (mesmo tempo do refresh token)
        int maxAge = 30 * 24 * 60 * 60; // 30 dias em segundos
        
        // Determina se deve usar Secure baseado na configuração ou ambiente
        boolean useSecure = secureCookie || sslEnabled || "prod".equals(activeProfile) || "production".equals(activeProfile);
        
        ResponseCookie cookie = ResponseCookie.from("refresh_token", refreshToken)
                .maxAge(maxAge)
                .path("/")
                .httpOnly(true)
                .sameSite(sameSite)
                .secure(useSecure)
                .build();
        
        return cookie.toString();
    }
    
    /**
     * Cria um cookie para limpar/remover o refresh token
     * 
     * @return String formatada do cookie para remoção
     */
    private String createClearRefreshTokenCookie() {
        // Determina se deve usar Secure baseado na configuração ou ambiente
        boolean useSecure = secureCookie || sslEnabled || "prod".equals(activeProfile) || "production".equals(activeProfile);
        
        ResponseCookie cookie = ResponseCookie.from("refresh_token", "")
                .maxAge(0)
                .path("/")
                .httpOnly(true)
                .sameSite(sameSite)
                .secure(useSecure)
                .build();
        
        return cookie.toString();
    }
}