package com.api.auth.user.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class AuthUserServiceTest {

    @Mock
    private UserRepository userRepository;
    
    @InjectMocks
    private AuthUserService authUserService;
    
    private UserEntity userEntity;
    private UserEntity adminEntity;
    private UserEntity superAdminEntity;
    
    @BeforeEach
    void setUp() {
        userEntity = new UserEntity();
        userEntity.setId(UUID.randomUUID());
        userEntity.setEmail("user@example.com");
        userEntity.setPassword("password123");
        userEntity.setRole(UserRole.USER);
        
        // Removido adminEntity (ADMIN não existe mais)
        
        superAdminEntity = new UserEntity();
        superAdminEntity.setId(UUID.randomUUID());
        superAdminEntity.setEmail("superadmin@example.com");
        superAdminEntity.setPassword("password123");
        superAdminEntity.setRole(UserRole.SUPER_ADMIN);
    }
    
    @Test
    void loadUserByUsername_WithExistingUser_ShouldReturnUserDetails() {
        // Given
        String email = "user@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(userEntity));
        
        // When
        UserDetails result = authUserService.loadUserByUsername(email);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(email);
        assertThat(result.getPassword()).isEqualTo("password123");
        assertThat(result.getAuthorities()).hasSize(1);
        assertThat(result.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_USER");
        assertThat(result.isAccountNonExpired()).isTrue();
        assertThat(result.isAccountNonLocked()).isTrue();
        assertThat(result.isCredentialsNonExpired()).isTrue();
        assertThat(result.isEnabled()).isTrue();
        
        verify(userRepository, times(1)).findByEmail(email);
    }
    
    @Test
    void loadUserByUsername_WithExistingSuperAdmin_ShouldReturnUserDetailsWithBothAuthorities() {
        // Given
        String email = "superadmin@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(superAdminEntity));
        
        // When
        UserDetails result = authUserService.loadUserByUsername(email);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(email);
        assertThat(result.getPassword()).isEqualTo("password123");
        assertThat(result.getAuthorities()).hasSize(2);
        
        boolean hasSuperAdminRole = result.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_SUPER_ADMIN"));
        boolean hasUserRole = result.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER"));

        assertThat(hasSuperAdminRole).isTrue();
        assertThat(hasUserRole).isTrue();

        verify(userRepository, times(1)).findByEmail(email);
    }
    
    @Test
    void loadUserByUsername_WithNonExistingUser_ShouldThrowUsernameNotFoundException() {
        // Given
        String email = "nonexistent@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        
        // When & Then
        UsernameNotFoundException exception = assertThrows(
            UsernameNotFoundException.class, 
            () -> authUserService.loadUserByUsername(email)
        );
        
        assertThat(exception.getMessage()).isEqualTo("User not found");
        verify(userRepository, times(1)).findByEmail(email);
    }
    
    @Test
    void loadUserByUsername_WithNullEmail_ShouldThrowUsernameNotFoundException() {
        // Given
        String email = null;
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        
        // When & Then
        UsernameNotFoundException exception = assertThrows(
            UsernameNotFoundException.class, 
            () -> authUserService.loadUserByUsername(email)
        );
        
        assertThat(exception.getMessage()).isEqualTo("User not found");
        verify(userRepository, times(1)).findByEmail(email);
    }
    
    @Test
    void loadUserByUsername_WithEmptyEmail_ShouldThrowUsernameNotFoundException() {
        // Given
        String email = "";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        
        // When & Then
        UsernameNotFoundException exception = assertThrows(
            UsernameNotFoundException.class, 
            () -> authUserService.loadUserByUsername(email)
        );
        
        assertThat(exception.getMessage()).isEqualTo("User not found");
        verify(userRepository, times(1)).findByEmail(email);
    }
    
    @Test
    void loadUserByUsername_WithWhitespaceEmail_ShouldThrowUsernameNotFoundException() {
        // Given
        String email = "   ";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
        
        // When & Then
        UsernameNotFoundException exception = assertThrows(
            UsernameNotFoundException.class, 
            () -> authUserService.loadUserByUsername(email)
        );
        
        assertThat(exception.getMessage()).isEqualTo("User not found");
        verify(userRepository, times(1)).findByEmail(email);
    }
}
