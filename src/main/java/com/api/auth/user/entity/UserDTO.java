package com.api.auth.user.entity;

import java.rmi.server.UID;
import java.util.UUID;

public class UserDTO {

    private UUID id;
    private String email;
    private String password;

    public UserDTO() {
    }

    public UserDTO(String email, String password, Integer id) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }
}
