package dev.jeron7.springsecurityexamples.token;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends CrudRepository<Token, UUID> {
    Token findByAccessToken(String accessToken);

    boolean existsByAccessTokenAndActive(String accessToken, boolean active);
}
