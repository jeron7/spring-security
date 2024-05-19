package dev.jeron7.springsecurityexamples.config;

import dev.jeron7.springsecurityexamples.account.AccountRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Objects;

@Configuration
@EnableSpringDataWebSupport
public class AppConfig {

    private final int hashCost;

    private final AccountRepository accountRepository;

    public AppConfig(@Value("${app.security.hash_cost:11}") String hashCost, AccountRepository accountRepository) {
        this.hashCost = Integer.parseInt(hashCost);
        this.accountRepository = Objects.requireNonNull(accountRepository);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return email -> accountRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User was not found!"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(hashCost);
    }
}
