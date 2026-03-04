package com.api.auth.security.ratelimit;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;

public class RateLimitService {

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final RateLimitProperties properties;

    public RateLimitService(RateLimitProperties properties) {
        this.properties = properties;
    }

    public ConsumptionProbe tryConsumeLoginIp(String ip) {
        return tryConsume("login:ip:" + ip, properties.getLogin().getIp());
    }

    public ConsumptionProbe tryConsumeLoginPrincipal(String ip, String principal) {
        return tryConsume("login:principal:" + ip + ":" + principal, properties.getLogin().getPrincipal());
    }

    public ConsumptionProbe tryConsumeRefreshIp(String ip) {
        return tryConsume("refresh:ip:" + ip, properties.getRefresh().getIp());
    }

    private ConsumptionProbe tryConsume(String key, RateLimitProperties.WindowedLimit limit) {
        Objects.requireNonNull(key, "key");
        Bucket bucket = buckets.computeIfAbsent(key, ignored -> createBucket(limit));
        return bucket.tryConsumeAndReturnRemaining(1);
    }

    private Bucket createBucket(RateLimitProperties.WindowedLimit limit) {
        long capacity = Math.max(1, limit.getCapacity());
        long windowSeconds = Math.max(1, limit.getWindowSeconds());
        return Bucket.builder()
                .addLimit(b -> b.capacity(capacity).refillGreedy(capacity, Duration.ofSeconds(windowSeconds)))
                .build();
    }
}
