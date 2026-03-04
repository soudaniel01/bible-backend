package com.api.auth.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.api.auth.security.AuthenticatedUser;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth-test")
@Tag(name = "Auth Test", description = "Testes e exemplos de autenticação")
public class AuthTestController {

    @GetMapping("/me")
    @Operation(
        summary = "Obter informações do usuário autenticado",
        description = "Retorna as informações do usuário extraídas diretamente do JWT",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }
        
        Map<String, Object> response = new HashMap<>();
        
        // Verifica se o principal é do novo tipo AuthenticatedUser
        if (authentication.getPrincipal() instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) authentication.getPrincipal();
            response.put("source", "JWT_CLAIMS");
            response.put("id", user.getId());
            response.put("email", user.getEmail());
            response.put("role", user.getRole());
            response.put("authorities", authentication.getAuthorities());
        } else {
            // Fallback para tokens antigos
            response.put("source", "DATABASE_FALLBACK");
            response.put("principal", authentication.getPrincipal().toString());
            response.put("authorities", authentication.getAuthorities());
        }
        
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/role-check")
    @Operation(
        summary = "Verificar role do usuário",
        description = "Demonstra como acessar o role diretamente do principal",
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<Map<String, Object>> checkRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }
        
        Map<String, Object> response = new HashMap<>();
        
        if (authentication.getPrincipal() instanceof AuthenticatedUser) {
            AuthenticatedUser user = (AuthenticatedUser) authentication.getPrincipal();
            response.put("email", user.getEmail());
            response.put("role", user.getRole());
            response.put("hasUserRole", authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")));
            response.put("hasSuperAdminRole", authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_SUPER_ADMIN")));
        } else {
            response.put("message", "Token antigo - informações limitadas");
            response.put("authorities", authentication.getAuthorities());
        }
        
        return ResponseEntity.ok(response);
    }
}