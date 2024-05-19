package dev.jeron7.springsecurityexamples.auth;

import java.util.UUID;

public interface TokenStrategy {

    boolean verify(String token);

    String getEmail(String token);

    UUID getId(String token);

    String generateToken(UUID id, String email, long millisToExpire);
}
