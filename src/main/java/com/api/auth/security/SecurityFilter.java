package com.api.auth.security;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.api.auth.providers.JWTProvider;
import com.api.auth.security.AuthenticatedUser;
import com.api.auth.user.repository.UserRepository;

@Component
public class SecurityFilter extends OncePerRequestFilter {

        @Autowired
        private JWTProvider jwtProvider;

        @Autowired
        private UserRepository userRepository;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String header = request.getHeader("Authorization");
		
		if(header != null) {
			// Tenta usar o novo método que extrai claims do JWT
			var authenticatedUser = this.jwtProvider.validateTokenAndExtractUser(header);
			
			if(authenticatedUser != null) {
				// Cria authorities baseadas no role do JWT
				var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + authenticatedUser.getRole()));
				
				// Cria autenticação com o AuthenticatedUser como principal
				var authentication = new UsernamePasswordAuthenticationToken(authenticatedUser, null, authorities);
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);
				
				// Mantém compatibilidade com código existente
				request.setAttribute("user_id", authenticatedUser.getId());
				
			} else {
				// Fallback para tokens antigos - usa método original
				var subjectToken = this.jwtProvider.validateToken(header);
				if(subjectToken.isEmpty()) {
					response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					return;
				}
				request.setAttribute("user_id", subjectToken);
				var userOpt = this.userRepository.findById(UUID.fromString(subjectToken));
				if(userOpt.isPresent()) {
					var user = userOpt.get();
					UsernamePasswordAuthenticationToken authenticationToken =
							new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				} else {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
			}
		}
		
		filterChain.doFilter(request, response);
		
	}

}
