package com.api.auth.user.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.api.auth.security.AuthenticatedUser;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.service.AdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
// Adicionado:
import com.api.auth.user.dto.UserResponse;

@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin", description = "Operações administrativas")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {

    @Autowired
    private AdminService adminService;
    
    @Autowired
    private com.api.auth.audit.service.LoginAuditService loginAuditService;

    /**
     * Endpoint para criar novos USERs (apenas SUPER_ADMIN)
     */
    @PostMapping("/create-user")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<?> createUser(@RequestBody UserEntity userEntity, Authentication authentication) {
        try {
            userEntity.setRole(UserRole.USER);
            UserEntity newUser = adminService.createUser(userEntity);
            return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    /**
     * Endpoint para listar usuários (apenas SUPER_ADMIN)
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<List<UserResponse>> listUsers(Authentication authentication) {
        List<UserResponse> users = adminService.getAllUsers()
            .stream()
            .map(UserResponse::new)
            .toList();
        return ResponseEntity.ok(users);
    }

    /**
     * Endpoint para editar usuários (apenas SUPER_ADMIN)
     */
    @PutMapping("/edit/{userId}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<?> editUser(@PathVariable UUID userId, @RequestBody UserEntity userEntity, Authentication authentication) {
        try {
            UserEntity updatedUser = adminService.updateUser(userId, userEntity);
            return ResponseEntity.ok(updatedUser);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    /**
     * Endpoint para excluir usuários (apenas SUPER_ADMIN)
     */
    @DeleteMapping("/delete/{userId}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable UUID userId, Authentication authentication) {
        try {
            adminService.deleteUser(userId);
            return ResponseEntity.ok("Usuário excluído com sucesso");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    /**
     * Endpoint para obter informações sobre os roles
     */
    @GetMapping("/roles-info")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<?> getRolesInfo() {
        return ResponseEntity.ok(new Object() {
            public final String SUPER_ADMIN = UserRole.SUPER_ADMIN.getDescription();
            public final String USER = UserRole.USER.getDescription();
        });
    }

    /**
     * Lista conexões suspensas devido ao rate limiting
     */
    @GetMapping("/suspended-connections")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @Operation(summary = "Listar conexões suspensas", 
               description = "Lista todas as conexões (emails/IPs) que estão temporariamente suspensas devido ao rate limiting")
    public ResponseEntity<java.util.List<com.api.auth.audit.dto.SuspendedConnectionResponse>> getSuspendedConnections() {
        try {
            java.util.List<com.api.auth.audit.dto.SuspendedConnectionResponse> suspendedConnections = 
                loginAuditService.getSuspendedConnections();
            return ResponseEntity.ok(suspendedConnections);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(null);
        }
    }
}
