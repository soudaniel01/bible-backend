package com.api.auth.user.dto;

import com.api.auth.user.entity.UserEntity;
import java.util.UUID;

public class UserResponse {
    
    private UUID id;
    private String email;
    private String name;
    private String role;
    
    public UserResponse() {}
    
    public UserResponse(UUID id, String email, String name, String role) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.role = role;
    }
    
    // Construtor de conveniência para criar a partir de UserEntity
    public UserResponse(UserEntity user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.name = user.getName();
        this.role = user.getRole().toString();
    }
    
    public UUID getId() {
        return id;
    }
    
    public void setId(UUID id) {
        this.id = id;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getRole() {
        return role;
    }
    
    public void setRole(String role) {
        this.role = role;
    }
}