package com.api.auth.user.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.security.sasl.AuthenticationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.repository.UserRepository;
import com.api.auth.providers.JWTProvider;

@Service
public class UserService {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder encoder;
	
	@Autowired
	private JWTProvider jwtProvider;
	
	
	public UserEntity save(UserEntity userEntity) {
		var passwordEncoder = this.encoder.encode(userEntity.getPassword());
		userEntity.setPassword(passwordEncoder);
		return this.userRepository.save(userEntity);
	}


	
	public List<UserEntity> findAll(){
		return this.userRepository.findAll();
	}
	
	/**
	 * Busca usuário por ID
	 */
	public Optional<UserEntity> findById(String userId) {
		try {
			UUID uuid = UUID.fromString(userId);
			return this.userRepository.findById(uuid);
		} catch (IllegalArgumentException e) {
			return Optional.empty();
		}
	}
	
	/**
	 * Gera access token para um usuário (delegado para JWTProvider)
	 */
	public String generateAccessToken(UserEntity user) {
		return jwtProvider.generateAccessToken(user);
	}
	
	/**
	 * Valida credenciais e retorna usuário para login
	 */
	public UserEntity findByEmailForLogin(String email, String password) throws AuthenticationException {
		var user = this.userRepository.findByEmail(email).orElseThrow(
				() -> {
					throw new UsernameNotFoundException("Email/Senha invalido");
				}
			);
				
		var passwordMatches = this.encoder.matches(password, user.getPassword());
		if(!passwordMatches) {
			throw new AuthenticationException("Login/Senha invalido");
		}
		
		return user;
	}
	
}
