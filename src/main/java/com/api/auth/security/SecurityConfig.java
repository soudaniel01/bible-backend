package com.api.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.Customizer;
import org.springframework.http.HttpMethod;

import com.api.auth.security.ratelimit.RateLimitFilter;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

	@Autowired
	private SecurityFilter securityFilter;

	@Autowired
	private SensitiveHeadersSanitizerFilter sensitiveHeadersSanitizerFilter;

	@Autowired(required = false)
	private RateLimitFilter rateLimitFilter;

    @org.springframework.beans.factory.annotation.Value("${spring.profiles.active:dev}")
    private String activeProfile;
	
	private static final String[] SWAGGER_LIST = {
			"/swagger-ui/**",
			"/v3/api-docs/**",
			"/swagger-resources/**"
	};
	
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
                httpSecurity.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .contentTypeOptions(Customizer.withDefaults())
                        .frameOptions(frameOptions -> frameOptions.deny())
                        .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                                .maxAgeInSeconds(31536000) // 1 ano
                                .includeSubDomains(true)
                                .preload(true)
                        )
                        .addHeaderWriter((request, response) -> {
                            String csp = "prod".equals(activeProfile) 
                                ? "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"
                                : "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';";
                            response.setHeader("Content-Security-Policy", csp);
                        })
                )
                .authorizeHttpRequests(auth -> {
                        auth.requestMatchers("/api/auth/login").permitAll();
                        // Corrigido: refresh deve ser público para funcionar com access token expirado
                        auth.requestMatchers("/api/auth/refresh").permitAll();
                        // Logout deve ser permitido publicamente pois depende apenas do refresh token (que pode estar no cookie)
                        auth.requestMatchers("/api/auth/logout", "/api/auth/logout-all").permitAll();
                        
                        // Registro de usuários continua aberto
                        auth.requestMatchers(HttpMethod.POST, "/api/users").permitAll();

                        // Novos endpoints de domínio parceiro (autenticados; regras finas aplicadas nos controllers)
                        auth.requestMatchers("/api/organizations/**").hasAnyRole("SUPER_ADMIN", "PARTNER");
                        auth.requestMatchers("/api/profiles/**").hasAnyRole("SUPER_ADMIN", "PARTNER");
                        
                        // Sessões e demais operações de /api/users só para SUPER_ADMIN
                        auth.requestMatchers("/api/users/*/sessions").hasRole("SUPER_ADMIN");
                        auth.requestMatchers("/api/users/**").hasRole("SUPER_ADMIN");
                        
                        // Endpoints administrativos só para SUPER_ADMIN
                        auth.requestMatchers("/api/admin/**").hasRole("SUPER_ADMIN");
                        
                        // Health e Swagger liberados
                        auth.requestMatchers("/api/health", "/actuator/health/**", "/actuator/info").permitAll();
                        auth.requestMatchers(SWAGGER_LIST).permitAll();
                        auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                        
                        auth.anyRequest().authenticated();
                })
                .cors(Customizer.withDefaults())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(401);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Authentication required\"}");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(403);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Access denied\"}");
                        })
                )
                .addFilterBefore(this.securityFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(this.sensitiveHeadersSanitizerFilter, SecurityFilter.class);

				if (rateLimitFilter != null) {
					httpSecurity.addFilterBefore(rateLimitFilter, SecurityFilter.class);
				}
                return httpSecurity.build();
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
                return configuration.getAuthenticationManager();
        }
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
}
