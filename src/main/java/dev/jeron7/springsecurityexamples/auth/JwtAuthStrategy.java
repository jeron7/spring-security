package dev.jeron7.springsecurityexamples.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import dev.jeron7.springsecurityexamples.account.Account;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtAuthStrategy implements AuthStrategy {

    private final long expireAccessToken;
    private final RSAKeyProvider keyProvider;

    public JwtAuthStrategy(@Value("${app.security.expire_access_token:3600}") long expireAccessToken,
                           RSAKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
        this.expireAccessToken = expireAccessToken * 1000;
    }

    @Override
    public String getEmail(String token) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        if (verify(token)) {
            var decodedJwt = JWT.require(algorithm).build().verify(token);
            return decodedJwt.getSubject();
        }
        return null;
    }

    @Override
    public boolean verify(String token) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        try {
            JWT.require(algorithm).build().verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    @Override
    public String generateAccessToken(Account account) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        var issuedAt = new Date();
        var expireAt = new Date(issuedAt.getTime() + expireAccessToken);

        return JWT.create()
                .withSubject(account.getUsername())
                .withIssuedAt(issuedAt)
                .withExpiresAt(expireAt)
                .sign(algorithm);
    }

    @Override
    public String generateRefreshToken(Account account) {
        return null;
    }
}
