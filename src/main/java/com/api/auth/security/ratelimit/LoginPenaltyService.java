package com.api.auth.security.ratelimit;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

public class LoginPenaltyService {

    private static final class PenaltyState {
        private int consecutiveFailures;
        private Instant cooldownUntil;
    }

    private final ConcurrentHashMap<String, PenaltyState> states = new ConcurrentHashMap<>();
    private final Clock clock;
    private final RateLimitProperties properties;

    public LoginPenaltyService(Clock clock, RateLimitProperties properties) {
        this.clock = clock;
        this.properties = properties;
    }

    public OptionalLong getRetryAfterSecondsIfBlocked(String ip, String principal) {
        if (!properties.getPenalty().isEnabled()) {
            return OptionalLong.empty();
        }
        String key = key(ip, principal);
        PenaltyState state = states.get(key);
        if (state == null || state.cooldownUntil == null) {
            return OptionalLong.empty();
        }
        long seconds = state.cooldownUntil.getEpochSecond() - Instant.now(clock).getEpochSecond();
        if (seconds <= 0) {
            return OptionalLong.empty();
        }
        return OptionalLong.of(seconds);
    }

    public void recordFailure(String ip, String principal) {
        if (!properties.getPenalty().isEnabled()) {
            return;
        }
        String key = key(ip, principal);
        states.compute(key, (ignored, state) -> {
            PenaltyState next = (state == null) ? new PenaltyState() : state;
            next.consecutiveFailures = next.consecutiveFailures + 1;
            long cooldownSeconds = Math.max(1, properties.getPenalty().getCooldownSeconds());
            Instant now = Instant.now(clock);
            Instant base = next.cooldownUntil != null && next.cooldownUntil.isAfter(now) ? next.cooldownUntil : now;
            next.cooldownUntil = base.plusSeconds(cooldownSeconds);
            return next;
        });
    }

    public void reset(String ip, String principal) {
        if (!properties.getPenalty().isEnabled()) {
            return;
        }
        states.remove(key(ip, principal));
    }

    private String key(String ip, String principal) {
        Objects.requireNonNull(ip, "ip");
        Objects.requireNonNull(principal, "principal");
        return ip + ":" + principal;
    }
}
