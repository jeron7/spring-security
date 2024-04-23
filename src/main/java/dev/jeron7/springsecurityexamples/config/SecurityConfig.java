package dev.jeron7.springsecurityexamples.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

    private final int hashCost;

    public SecurityConfig(@Value("${app.security.hash_cost:11}") String hashCost) {
        this.hashCost = Integer.parseInt(hashCost);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(hashCost);
    }
}
