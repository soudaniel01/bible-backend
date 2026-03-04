package com.api.auth.user.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.api.auth.user.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, UUID>{

	Optional<UserEntity> findByEmail(String email);
	
}
