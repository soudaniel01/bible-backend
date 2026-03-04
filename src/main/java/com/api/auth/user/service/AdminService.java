package com.api.auth.user.service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.api.auth.exception.BusinessException;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;

@Service
public class AdminService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder encoder;
    
    @Autowired
    private com.api.auth.audit.repository.LoginAuditRepository loginAuditRepository;

    /**
     * Cria um novo usuário com role específico
     */
    public UserEntity createUser(UserEntity userEntity) {
        // Criptografa a senha
        var passwordEncoder = this.encoder.encode(userEntity.getPassword());
        userEntity.setPassword(passwordEncoder);
        
        return this.userRepository.save(userEntity);
    }

    /**
     * Busca usuário por ID
     */
    public UserEntity findById(UUID userId) {
        return this.userRepository.findById(userId).orElse(null);
    }

    /**
     * Atualiza um usuário existente
     */
    public UserEntity updateUser(UUID userId, UserEntity updatedUser) {
        UserEntity existingUser = this.userRepository.findById(userId)
            .orElseThrow(() -> new BusinessException("Usuário não encontrado", "USER_NOT_FOUND", 404));
        
        // Atualiza apenas os campos permitidos
        if (updatedUser.getEmail() != null) {
            existingUser.setEmail(updatedUser.getEmail());
        }
        
        if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
            var passwordEncoder = this.encoder.encode(updatedUser.getPassword());
            existingUser.setPassword(passwordEncoder);
        }
        
        return this.userRepository.save(existingUser);
    }

    /**
     * Exclui um usuário
     */
    public void deleteUser(UUID userId) {
        if (!this.userRepository.existsById(userId)) {
            throw new BusinessException("Usuário não encontrado", "USER_NOT_FOUND", 404);
        }
        this.userRepository.deleteById(userId);
    }

    /**
     * Retorna usuários que o role atual pode gerenciar
     */
    public List<UserEntity> getUsersByRole(UserRole currentUserRole) {
        List<UserEntity> allUsers = this.userRepository.findAll();
        
        return allUsers.stream()
            .filter(user -> currentUserRole.canManage(user.getRole()))
            .collect(Collectors.toList());
    }

    /**
     * Verifica se um usuário pode gerenciar outro baseado na hierarquia
     */
    public boolean canManageUser(UserRole managerRole, UserRole targetRole) {
        return managerRole.canManage(targetRole);
    }

    /**
     * Retorna todos os usuários (apenas para SUPER_ADMIN)
     */
    public List<UserEntity> getAllUsers() {
        return this.userRepository.findAll();
    }

    /**
     * Busca usuários por role específico
     */
    public List<UserEntity> findByRole(UserRole role) {
        List<UserEntity> allUsers = this.userRepository.findAll();
        return allUsers.stream()
            .filter(user -> user.getRole() == role)
            .collect(Collectors.toList());
    }

    /**
     * Conta usuários por role
     */
    public long countByRole(UserRole role) {
        return this.userRepository.findAll().stream()
            .filter(user -> user.getRole() == role)
            .count();
    }

    /**
     * Busca usuário por email
     */
    public UserEntity findByEmail(String email) {
        return this.userRepository.findByEmail(email).orElse(null);
    }

    /**
     * Salva usuário (para promoção de role)
     */
    public UserEntity saveUser(UserEntity user) {
        return this.userRepository.save(user);
    }
    
    /**
     * Limpa tentativas de login falhadas para um email específico
     */
    @Transactional
    public void clearFailedLoginAttempts(String email) {
        loginAuditRepository.deleteByEmailAndSuccess(email, false);
    }
}
