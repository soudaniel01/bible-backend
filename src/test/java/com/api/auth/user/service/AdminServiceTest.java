package com.api.auth.user.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.doNothing;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    @Mock
    private UserRepository userRepository;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @InjectMocks
    private AdminService adminService;
    
    private UserEntity userEntity;
    private UserEntity adminEntity;
    private UserEntity superAdminEntity;
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
        
        superAdminEntity = new UserEntity();
        superAdminEntity.setId(UUID.randomUUID());
        superAdminEntity.setEmail("superadmin@example.com");
        superAdminEntity.setPassword("password123");
        superAdminEntity.setRole(UserRole.SUPER_ADMIN);
    }
    
    @Test
    void createUser_ShouldEncodePasswordAndSaveUser() {
        // Given
        String encodedPassword = "encodedPassword123";
        when(passwordEncoder.encode(anyString())).thenReturn(encodedPassword);
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);
        
        // When
        UserEntity result = adminService.createUser(userEntity);
        
        // Then
        verify(passwordEncoder, times(1)).encode("password123");
        verify(userRepository, times(1)).save(userEntity);
        assertThat(result).isEqualTo(userEntity);
        assertThat(userEntity.getPassword()).isEqualTo(encodedPassword);
    }
    
    @Test
    void findById_WithExistingUser_ShouldReturnUser() {
        // Given
        when(userRepository.findById(userId)).thenReturn(Optional.of(userEntity));
        
        // When
        UserEntity result = adminService.findById(userId);
        
        // Then
        assertThat(result).isEqualTo(userEntity);
        verify(userRepository, times(1)).findById(userId);
    }
    
    @Test
    void findById_WithNonExistingUser_ShouldReturnNull() {
        // Given
        when(userRepository.findById(userId)).thenReturn(Optional.empty());
        
        // When
        UserEntity result = adminService.findById(userId);
        
        // Then
        assertThat(result).isNull();
        verify(userRepository, times(1)).findById(userId);
    }
    
    @Test
    void updateUser_WithValidData_ShouldUpdateAndReturnUser() {
        // Given
        UserEntity updatedData = new UserEntity();
        updatedData.setEmail("newemail@example.com");
        updatedData.setPassword("newpassword");
        
        String encodedPassword = "encodedNewPassword";
        when(userRepository.findById(userId)).thenReturn(Optional.of(userEntity));
        when(passwordEncoder.encode("newpassword")).thenReturn(encodedPassword);
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);
        
        // When
        UserEntity result = adminService.updateUser(userId, updatedData);
        
        // Then
        assertThat(result).isEqualTo(userEntity);
        assertThat(userEntity.getEmail()).isEqualTo("newemail@example.com");
        assertThat(userEntity.getPassword()).isEqualTo(encodedPassword);
        verify(userRepository, times(1)).findById(userId);
        verify(passwordEncoder, times(1)).encode("newpassword");
        verify(userRepository, times(1)).save(userEntity);
    }
    
    @Test
    void updateUser_WithNonExistingUser_ShouldThrowException() {
        // Given
        UserEntity updatedData = new UserEntity();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());
        
        // When & Then
        assertThrows(RuntimeException.class, () -> {
            adminService.updateUser(userId, updatedData);
        });
        
        verify(userRepository, times(1)).findById(userId);
    }
    
    @Test
    void updateUser_WithEmptyPassword_ShouldNotEncodePassword() {
        // Given
        UserEntity updatedData = new UserEntity();
        updatedData.setEmail("newemail@example.com");
        updatedData.setPassword(""); // Empty password
        
        when(userRepository.findById(userId)).thenReturn(Optional.of(userEntity));
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);
        
        String originalPassword = userEntity.getPassword();
        
        // When
        UserEntity result = adminService.updateUser(userId, updatedData);
        
        // Then
        assertThat(result).isEqualTo(userEntity);
        assertThat(userEntity.getEmail()).isEqualTo("newemail@example.com");
        assertThat(userEntity.getPassword()).isEqualTo(originalPassword); // Password unchanged
        verify(userRepository, times(1)).findById(userId);
        verify(passwordEncoder, times(0)).encode(anyString()); // Password encoder not called
        verify(userRepository, times(1)).save(userEntity);
    }
    
    @Test
    void deleteUser_WithExistingUser_ShouldDeleteUser() {
        // Given
        when(userRepository.existsById(userId)).thenReturn(true);
        doNothing().when(userRepository).deleteById(userId);
        
        // When
        adminService.deleteUser(userId);
        
        // Then
        verify(userRepository, times(1)).existsById(userId);
        verify(userRepository, times(1)).deleteById(userId);
    }
    
    @Test
    void deleteUser_WithNonExistingUser_ShouldThrowException() {
        // Given
        when(userRepository.existsById(userId)).thenReturn(false);
        
        // When & Then
        assertThrows(RuntimeException.class, () -> {
            adminService.deleteUser(userId);
        });
        
        verify(userRepository, times(1)).existsById(userId);
        verify(userRepository, times(0)).deleteById(userId);
    }
    
    @Test
    void getUsersByRole_WithSuperAdmin_ShouldReturnUsers() {
        // Given
        List<UserEntity> allUsers = Arrays.asList(userEntity, superAdminEntity);
        when(userRepository.findAll()).thenReturn(allUsers);
    
        // When
        List<UserEntity> result = adminService.getUsersByRole(UserRole.SUPER_ADMIN);
    
        // Then
        assertThat(result).hasSize(1);
        assertThat(result).containsExactly(userEntity);
        verify(userRepository, times(1)).findAll();
    }
    
    @Test
    void getUsersByRole_WithUser_ShouldReturnEmptyList() {
        // Given
        List<UserEntity> allUsers = Arrays.asList(userEntity, superAdminEntity);
        when(userRepository.findAll()).thenReturn(allUsers);
        
        // When
        List<UserEntity> result = adminService.getUsersByRole(UserRole.USER);
        
        // Then
        assertThat(result).isEmpty();
        verify(userRepository, times(1)).findAll();
    }
    
    @Test
    void canManageUser_WithSuperAdminManagingUser_ShouldReturnTrue() {
        // When
        boolean result = adminService.canManageUser(UserRole.SUPER_ADMIN, UserRole.USER);
    
        // Then
        assertThat(result).isTrue();
    }
    
    @Test
    void canManageUser_WithUserManagingAnyone_ShouldReturnFalse() {
        // When
        boolean result = adminService.canManageUser(UserRole.USER, UserRole.USER);
        
        // Then
        assertThat(result).isFalse();
    }
    
    @Test
    void getAllUsers_ShouldReturnAllUsers() {
        // Given
        List<UserEntity> allUsers = Arrays.asList(userEntity, superAdminEntity);
        when(userRepository.findAll()).thenReturn(allUsers);
    
        // When
        List<UserEntity> result = adminService.getAllUsers();
    
        // Then
        assertThat(result).hasSize(2);
        assertThat(result).containsExactlyInAnyOrder(userEntity, superAdminEntity);
        verify(userRepository, times(1)).findAll();
    }
    
    @Test
    void findByRole_ShouldReturnUsersWithSpecificRole() {
        // Given
        UserEntity anotherUser = new UserEntity();
        anotherUser.setId(UUID.randomUUID());
        anotherUser.setEmail("user2@example.com");
        anotherUser.setRole(UserRole.USER);
    
        List<UserEntity> allUsers = Arrays.asList(userEntity, anotherUser, superAdminEntity);
        when(userRepository.findAll()).thenReturn(allUsers);
    
        // When
        List<UserEntity> result = adminService.findByRole(UserRole.USER);
    
        // Then
        assertThat(result).hasSize(2);
        assertThat(result).containsExactlyInAnyOrder(userEntity, anotherUser);
        verify(userRepository, times(1)).findAll();
    }
    
    @Test
    void countByRole_ShouldReturnCorrectCount() {
        // Given
        UserEntity anotherUser = new UserEntity();
        anotherUser.setId(UUID.randomUUID());
        anotherUser.setEmail("user2@example.com");
        anotherUser.setRole(UserRole.USER);
    
        List<UserEntity> allUsers = Arrays.asList(userEntity, anotherUser, superAdminEntity);
        when(userRepository.findAll()).thenReturn(allUsers);
    
        // When
        long result = adminService.countByRole(UserRole.USER);
    
        // Then
        assertThat(result).isEqualTo(2);
        verify(userRepository, times(1)).findAll();
    }
}
