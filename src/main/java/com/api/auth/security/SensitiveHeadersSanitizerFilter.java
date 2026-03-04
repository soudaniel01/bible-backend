package com.api.auth.security;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SensitiveHeadersSanitizerFilter extends OncePerRequestFilter {

    private static final String REDACTED = "***REDACTED***";
    private static final Set<String> SENSITIVE_HEADER_NAMES;

    static {
        Set<String> names = new HashSet<>();
        names.add("authorization");
        names.add("cookie");
        names.add("set-cookie");
        names.add("x-api-key");
        SENSITIVE_HEADER_NAMES = Collections.unmodifiableSet(names);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpServletRequest sanitizedRequest = new SanitizedHeadersRequestWrapper(request);
        filterChain.doFilter(sanitizedRequest, response);
    }

    private static class SanitizedHeadersRequestWrapper extends HttpServletRequestWrapper {

        SanitizedHeadersRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            String value = super.getHeader(name);
            if (value == null) {
                return null;
            }
            if (isSensitive(name)) {
                return REDACTED;
            }
            return value;
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            Enumeration<String> values = super.getHeaders(name);
            if (values == null) {
                return null;
            }
            List<String> list = Collections.list(values);
            if (list.isEmpty()) {
                return Collections.emptyEnumeration();
            }
            if (isSensitive(name)) {
                return Collections.enumeration(Collections.nCopies(list.size(), REDACTED));
            }
            return Collections.enumeration(list);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return super.getHeaderNames();
        }

        private static boolean isSensitive(String name) {
            if (name == null) {
                return false;
            }
            return SENSITIVE_HEADER_NAMES.contains(name.toLowerCase(Locale.ROOT));
        }
    }
}
