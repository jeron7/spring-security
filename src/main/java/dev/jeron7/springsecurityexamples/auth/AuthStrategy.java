package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.Account;

public interface AuthStrategy {

    boolean verify(String token);

    String getEmail(String token);

    String generateAccessToken(Account account, long millisToExpire);

    String generateRefreshToken(Account account, long millisToExpire);
}
