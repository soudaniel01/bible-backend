package com.api.auth.security.ratelimit;

import java.io.IOException;
import java.time.Duration;
import java.util.Locale;
import java.util.OptionalLong;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class RateLimitFilter extends OncePerRequestFilter {

    private static final String RATE_LIMITED_BODY = "{\"error\":\"RATE_LIMITED\",\"message\":\"Too many requests\"}";

    private final RateLimitProperties properties;
    private final RateLimitService rateLimitService;
    private final LoginPenaltyService loginPenaltyService;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(
            RateLimitProperties properties,
            RateLimitService rateLimitService,
            LoginPenaltyService loginPenaltyService,
            ObjectMapper objectMapper) {
        this.properties = properties;
        this.rateLimitService = rateLimitService;
        this.loginPenaltyService = loginPenaltyService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String method = request.getMethod();
        String path = request.getRequestURI();

        boolean isLogin = HttpMethod.POST.matches(method) && "/api/auth/login".equals(path);
        boolean isRefresh = HttpMethod.POST.matches(method) && "/api/auth/refresh".equals(path);

        if (!isLogin && !isRefresh) {
            filterChain.doFilter(request, response);
            return;
        }

        String ip = resolveClientIp(request);

        if (isRefresh) {
            ConsumptionProbe probe = rateLimitService.tryConsumeRefreshIp(ip);
            if (!probe.isConsumed()) {
                writeRateLimited(response, nanosToSecondsCeil(probe.getNanosToWaitForRefill()));
                return;
            }
            filterChain.doFilter(request, response);
            return;
        }

        ContentCachingRequestWrapper cachingWrapper = new ContentCachingRequestWrapper(request);
        CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(cachingWrapper);

        String principal = extractPrincipal(wrappedRequest);

        if (StringUtils.hasText(principal)) {
            OptionalLong retryAfter = loginPenaltyService.getRetryAfterSecondsIfBlocked(ip, principal);
            if (retryAfter.isPresent()) {
                writeRateLimited(response, retryAfter.getAsLong());
                return;
            }
        }

        ConsumptionProbe ipProbe = rateLimitService.tryConsumeLoginIp(ip);
        if (!ipProbe.isConsumed()) {
            writeRateLimited(response, nanosToSecondsCeil(ipProbe.getNanosToWaitForRefill()));
            return;
        }

        if (StringUtils.hasText(principal)) {
            ConsumptionProbe principalProbe = rateLimitService.tryConsumeLoginPrincipal(ip, principal);
            if (!principalProbe.isConsumed()) {
                writeRateLimited(response, nanosToSecondsCeil(principalProbe.getNanosToWaitForRefill()));
                return;
            }
        }

        filterChain.doFilter(wrappedRequest, response);

        if (StringUtils.hasText(principal)) {
            int status = response.getStatus();
            if (status == 200) {
                loginPenaltyService.reset(ip, principal);
            } else if (status == 401) {
                loginPenaltyService.recordFailure(ip, principal);
            }
        }
    }

    private String extractPrincipal(CachedBodyHttpServletRequest request) {
        String contentType = request.getContentType();
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).contains(MediaType.APPLICATION_JSON_VALUE)) {
            return null;
        }

        byte[] body = request.getCachedBody();
        if (body == null || body.length == 0) {
            return null;
        }

        try {
            JsonNode root = objectMapper.readTree(body);
            if (root == null || !root.isObject()) {
                return null;
            }
            JsonNode email = root.get("email");
            if (email != null && email.isTextual() && StringUtils.hasText(email.asText())) {
                return normalizePrincipal(email.asText());
            }
            JsonNode username = root.get("username");
            if (username != null && username.isTextual() && StringUtils.hasText(username.asText())) {
                return normalizePrincipal(username.asText());
            }
            return null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String normalizePrincipal(String principal) {
        return principal.trim().toLowerCase(Locale.ROOT);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwardedFor)) {
            String first = forwardedFor.split(",")[0].trim();
            if (StringUtils.hasText(first)) {
                return stripPort(first);
            }
        }
        String remoteAddr = request.getRemoteAddr();
        if (!StringUtils.hasText(remoteAddr)) {
            return "unknown";
        }
        return stripPort(remoteAddr);
    }

    private String stripPort(String ip) {
        int colon = ip.indexOf(':');
        if (colon > 0 && ip.indexOf('.') > 0) {
            return ip.substring(0, colon);
        }
        return ip;
    }

    private void writeRateLimited(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(429);
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        if (retryAfterSeconds > 0) {
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        }
        response.getWriter().write(RATE_LIMITED_BODY);
    }

    private long nanosToSecondsCeil(long nanos) {
        if (nanos <= 0) {
            return 0;
        }
        return Duration.ofNanos(nanos).toSeconds() + (nanos % 1_000_000_000L == 0 ? 0 : 1);
    }
}
