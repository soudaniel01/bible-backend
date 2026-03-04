package com.api.auth.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

class SensitiveHeadersSanitizerFilterTest {

    @Test
    void shouldExposeRedactedValuesForSensitiveHeadersToDownstreamChain() throws ServletException, IOException {
        SensitiveHeadersSanitizerFilter filter = new SensitiveHeadersSanitizerFilter();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer real-token");
        request.addHeader("Cookie", "refresh_token=real-cookie");
        request.addHeader("X-Api-Key", "real-key");
        request.addHeader("X-Not-Sensitive", "ok");

        MockHttpServletResponse response = new MockHttpServletResponse();
        CapturingFilterChain chain = new CapturingFilterChain();

        filter.doFilter(request, response, chain);

        HttpServletRequest wrapped = chain.capturedRequest;
        assertThat(wrapped).isNotNull();

        assertThat(wrapped.getHeader("Authorization")).isEqualTo("***REDACTED***");
        assertThat(wrapped.getHeader("Cookie")).isEqualTo("***REDACTED***");
        assertThat(wrapped.getHeader("Set-Cookie")).isNull();
        assertThat(wrapped.getHeader("X-Api-Key")).isEqualTo("***REDACTED***");
        assertThat(wrapped.getHeader("X-Not-Sensitive")).isEqualTo("ok");

        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer real-token");
        assertThat(request.getHeader("Cookie")).isEqualTo("refresh_token=real-cookie");
    }

    private static class CapturingFilterChain implements FilterChain {
        private HttpServletRequest capturedRequest;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) {
            this.capturedRequest = (HttpServletRequest) request;
        }
    }
}

