package com.api.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.context.annotation.ComponentScan;

@Configuration
@ComponentScan(basePackages = { "com.api" })
@EntityScan(basePackages = { "com.api" })
@EnableJpaRepositories(basePackages = { "com.api" })
public class ScanningConfig {
}