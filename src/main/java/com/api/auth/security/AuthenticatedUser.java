package com.api.auth.security;

import java.util.UUID;

/**
 * Classe que representa um usuário autenticado com informações extraídas do JWT
 */
public class AuthenticatedUser {
    
    private final String id;
    private final String email;
    private final String role;
    
    public AuthenticatedUser(String id, String email, String role) {
        this.id = id;
        this.email = email;
        this.role = role;
    }
    
    public String getId() {
        return id;
    }
    
    public UUID getIdAsUUID() {
        return UUID.fromString(id);
    }
    
    public String getEmail() {
        return email;
    }
    
    public String getRole() {
        return role;
    }
    
    @Override
    public String toString() {
        return "AuthenticatedUser{" +
                "id='" + id + '\'' +
                ", email='" + email + '\'' +
                ", role='" + role + '\'' +
                '}';
    }
}