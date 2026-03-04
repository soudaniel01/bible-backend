package com.api.auth.user.controller;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

import com.api.auth.token.dto.LoginRequest;
import com.api.auth.token.dto.LoginResponse;
import com.api.auth.token.entity.RefreshTokenEntity;
import com.api.auth.token.service.RefreshTokenService;
import com.api.auth.user.dto.RegisterRequest;
import com.api.auth.user.dto.UserResponse;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@Tag(name = "User", description = "Operações de usuário")
public class UserController {

	@Autowired
	private UserService service;
	
	@Autowired
	private RefreshTokenService refreshTokenService;
	
	@PostMapping
	public ResponseEntity<UserResponse> save(@RequestBody @Valid RegisterRequest registerRequest) {
		UserEntity userEntity = new UserEntity();
        userEntity.setEmail(registerRequest.getEmail());
        userEntity.setPassword(registerRequest.getPassword());
        userEntity.setName(registerRequest.getName());
        userEntity.setRole(UserRole.USER);

		var newUser = this.service.save(userEntity);

		UserResponse userResponse = new UserResponse(newUser);

		return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
	}
	

	
	@GetMapping
	public ResponseEntity<List<UserResponse>> findAll(){
		var users = this.service.findAll();
		List<UserResponse> userResponses = users.stream()
			.map(UserResponse::new)
			.toList();
		return ResponseEntity.ok().body(userResponses);
	}
	
	/**
	 * Endpoint para listar sessões ativas de um usuário (útil para administração)
	 */
	@GetMapping("/{userId}/sessions")
	@Operation(summary = "Listar sessões ativas do usuário", description = "Retorna todas as sessões ativas de um usuário específico")
	@SecurityRequirement(name = "bearerAuth")
	public ResponseEntity<Map<String, Object>> getUserActiveSessions(@PathVariable String userId) {
		try {
			List<RefreshTokenEntity> activeSessions = refreshTokenService.getActiveTokensByUserId(userId);
			long activeCount = refreshTokenService.countActiveTokensByUserId(userId);
			
			Map<String, Object> response = new HashMap<>();
			response.put("userId", userId);
			response.put("activeSessionsCount", activeCount);
			response.put("sessions", activeSessions.stream().map(token -> {
				Map<String, Object> sessionInfo = new HashMap<>();
				sessionInfo.put("id", token.getId());
				sessionInfo.put("deviceInfo", token.getDeviceInfo());
				sessionInfo.put("createdAt", token.getCreatedAt());
				sessionInfo.put("expiresAt", token.getExpiresAt());
				sessionInfo.put("isExpired", token.isExpired());
				return sessionInfo;
			}).toList());
			
			return ResponseEntity.ok(response);
		} catch (Exception e) {
			Map<String, Object> error = new HashMap<>();
			error.put("error", "Failed to retrieve user sessions");
			error.put("message", e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
		}
	}
	


}
