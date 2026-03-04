package com.api.auth.user.entity;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
})
@Getter
@Setter
public class UserEntity implements UserDetails {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
        private UUID id;
        private String email;
        private String password;
        private String name;

        @Enumerated(EnumType.STRING)
        private UserRole role = UserRole.USER;

        @CreationTimestamp
        @Column(name = "created_at", nullable = false, updatable = false)
        private Instant createdAt;

        @UpdateTimestamp
        @Column(name = "updated_at")
        private Instant updatedAt;

        @Column(name = "created_by", length = 255)
        private String createdBy = "system";

        @Column(name = "last_modified_by", length = 255)
        private String lastModifiedBy = "system";

        // Removido: campo organizationId
        // @Column(name = "organization_id")
        // private java.util.UUID organizationId;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
                switch(this.role) {
                        case SUPER_ADMIN:
                                return List.of(
                                        new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"),
                                        new SimpleGrantedAuthority("ROLE_USER")
                                );
                        case USER:
                        default:
                                return List.of(new SimpleGrantedAuthority("ROLE_USER"));
                }
        }

        @Override
        public String getPassword() {
                return this.password;
        }

        @Override
        public String getUsername() {
                return this.email;
        }

        @Override
        public boolean isAccountNonExpired() {
                return true;
        }

        @Override
        public boolean isAccountNonLocked() {
                return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
                return true;
        }

        @Override
        public boolean isEnabled() {
                return true;
        }

        public void setPassword(String password) {
                this.password = password;
        }

        public UUID getId() {
                return this.id;
        }

        public void setId(UUID id) {
                this.id = id;
        }

        public String getEmail() {
                return this.email;
        }

        public void setEmail(String email) {
                this.email = email;
        }

        public UserRole getRole() {
                return this.role;
        }

        public void setRole(UserRole role) {
                this.role = role;
        }

        public String getName() {
                return this.name;
        }

        public void setName(String name) {
                this.name = name;
        }

        @Override
        public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UserEntity that = (UserEntity) o;
                return id != null && id.equals(that.id);
        }

        @Override
        public int hashCode() {
                return getClass().hashCode();
        }

        // Removidos getters/setters de organizationId
        // public java.util.UUID getOrganizationId() {
        // return this.organizationId;
        // }

        // public void setOrganizationId(java.util.UUID organizationId) {
        // this.organizationId = organizationId;
        // }
}
