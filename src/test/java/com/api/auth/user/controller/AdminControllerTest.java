package com.api.auth.user.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import com.api.auth.user.entity.UserDTO;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.service.AdminService;

@ExtendWith(MockitoExtension.class)
class AdminControllerTest {

    @Mock
    private AdminService adminService;
    
    @InjectMocks
    private AdminController adminController;
    
    private UserEntity userEntity;
    private UserEntity adminEntity;
    private UserDTO userDTO;
    private UUID userId;
    
    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        userEntity = new UserEntity();
        userEntity.setId(userId);
        userEntity.setEmail("user@example.com");
        userEntity.setPassword("password123");
        userEntity.setRole(UserRole.USER);
        
        // Removido adminEntity (ADMIN não existe mais)
        
        userDTO = new UserDTO();
        userDTO.setEmail("newuser@example.com");
        userDTO.setPassword("password123");
    }
    
    // Removido o teste createAdmin_ShouldCreateAdminUser completamente
    
    @Test
    void createUser_ShouldCreateRegularUser() {
        // Given
        UserEntity userEntity = new UserEntity();
        userEntity.setEmail("test@example.com");
        userEntity.setPassword("password");

        Authentication authentication = mock(Authentication.class);

        UserEntity newUser = new UserEntity();
        newUser.setEmail(userEntity.getEmail());
        newUser.setPassword(userEntity.getPassword());
        newUser.setRole(UserRole.USER);

        when(adminService.createUser(any(UserEntity.class))).thenReturn(newUser);

        // When
        ResponseEntity<?> response = adminController.createUser(userEntity, authentication);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        verify(adminService, times(1)).createUser(any(UserEntity.class));
    }
    
    // Note: Security and authorization tests would be better as integration tests
    // These unit tests focus on the controller logic without Spring Security context
}
