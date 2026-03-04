package com.api.auth.audit.controller;

import com.api.auth.audit.dto.LoginAuditResponse;
import com.api.auth.audit.entity.LoginAuditEntity;
import com.api.auth.audit.service.LoginAuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Controlador para consultas de auditoria.
 * Permite aos administradores visualizar histórico de login e atividades suspeitas.
 */
@RestController
@RequestMapping("/api/audit")
@Tag(name = "Auditoria", description = "Endpoints para consulta de logs de auditoria")
@SecurityRequirement(name = "bearerAuth")
public class AuditController {

    @Autowired
    private LoginAuditService loginAuditService;

    /**
     * Busca histórico de login por usuário (apenas administradores)
     */
    @GetMapping("/login-history/user/{userId}")
    @Operation(summary = "Histórico de login por usuário", 
               description = "Retorna o histórico de tentativas de login de um usuário específico")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Page<LoginAuditResponse>> getLoginHistoryByUserId(
            @Parameter(description = "ID do usuário") @PathVariable String userId,
            @Parameter(description = "Página (0-based)") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamanho da página") @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        UUID userUuid = UUID.fromString(userId);
        Page<LoginAuditEntity> history = loginAuditService.getLoginHistoryByUserId(userUuid, pageable);
        Page<LoginAuditResponse> response = history.map(this::convertToDto);
        return ResponseEntity.ok(response);
    }

    /**
     * Busca histórico de login por email (apenas administradores)
     */
    @GetMapping("/login-history/email/{email}")
    @Operation(summary = "Histórico de login por email", 
               description = "Retorna o histórico de tentativas de login de um email específico")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Page<LoginAuditResponse>> getLoginHistoryByEmail(
            @Parameter(description = "Email do usuário") @PathVariable String email,
            @Parameter(description = "Página (0-based)") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamanho da página") @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<LoginAuditEntity> history = loginAuditService.getLoginHistoryByEmail(email, pageable);
        Page<LoginAuditResponse> response = history.map(this::convertToDto);
        return ResponseEntity.ok(response);
    }

    /**
     * Busca logins bem-sucedidos por usuário (usuário pode ver próprio histórico)
     */
    @GetMapping("/successful-logins/user/{userId}")
    @Operation(summary = "Logins bem-sucedidos por usuário", 
               description = "Retorna apenas os logins bem-sucedidos de um usuário")
    @PreAuthorize("hasRole('SUPER_ADMIN') or #userId == authentication.principal.userId")
    public ResponseEntity<Page<LoginAuditResponse>> getSuccessfulLoginsByUserId(
            @Parameter(description = "ID do usuário") @PathVariable String userId,
            @Parameter(description = "Página (0-based)") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamanho da página") @RequestParam(defaultValue = "10") int size) {
        
        Pageable pageable = PageRequest.of(page, size);
        UUID userUuid = UUID.fromString(userId);
        Page<LoginAuditEntity> history = loginAuditService.getSuccessfulLoginsByUserId(userUuid, pageable);
        Page<LoginAuditResponse> response = history.map(this::convertToDto);
        return ResponseEntity.ok(response);
    }

    /**
     * Verifica se um IP está suspeito (apenas administradores)
     */
    @GetMapping("/suspicious-ip/{ip}")
    @Operation(summary = "Verifica IP suspeito", 
               description = "Verifica se um IP tem muitas tentativas de login falhadas recentemente")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Boolean> checkSuspiciousIp(
            @Parameter(description = "Endereço IP") @PathVariable String ip,
            @Parameter(description = "Máximo de tentativas") @RequestParam(defaultValue = "10") int maxAttempts,
            @Parameter(description = "Janela de tempo em minutos") @RequestParam(defaultValue = "60") int timeWindowMinutes) {
        
        boolean isSuspicious = loginAuditService.isIpSuspicious(ip, maxAttempts, timeWindowMinutes);
        return ResponseEntity.ok(isSuspicious);
    }

    /**
     * Verifica se um email está suspeito (apenas administradores)
     */
    @GetMapping("/suspicious-email/{email}")
    @Operation(summary = "Verifica email suspeito", 
               description = "Verifica se um email tem muitas tentativas de login falhadas recentemente")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Boolean> checkSuspiciousEmail(
            @Parameter(description = "Email") @PathVariable String email,
            @Parameter(description = "Máximo de tentativas") @RequestParam(defaultValue = "5") int maxAttempts,
            @Parameter(description = "Janela de tempo em minutos") @RequestParam(defaultValue = "30") int timeWindowMinutes) {
        
        boolean isSuspicious = loginAuditService.isEmailSuspicious(email, maxAttempts, timeWindowMinutes);
        return ResponseEntity.ok(isSuspicious);
    }

    /**
     * Limpa registros de auditoria antigos (apenas administradores)
     */
    @DeleteMapping("/cleanup")
    @Operation(summary = "Limpa registros antigos", 
               description = "Remove registros de auditoria mais antigos que o número de dias especificado")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<String> cleanupOldRecords(
            @Parameter(description = "Dias para manter") @RequestParam(defaultValue = "90") int daysToKeep) {
        
        loginAuditService.cleanupOldAuditRecords(daysToKeep);
        return ResponseEntity.ok("Registros de auditoria antigos foram removidos com sucesso");
    }

    /**
     * Converte LoginAuditEntity para LoginAuditResponse (DTO)
     */
    private LoginAuditResponse convertToDto(LoginAuditEntity entity) {
        return new LoginAuditResponse(
            entity.getId(),
            entity.getUserId(),
            entity.getEmail(),
            entity.isSuccess(),
            entity.getClientIp(),
            entity.getUserAgent(),
            entity.getDeviceInfo(),
            entity.getLoginTimestamp()
        );
    }
}