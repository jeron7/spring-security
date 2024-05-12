package dev.jeron7.springsecurityexamples.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import dev.jeron7.springsecurityexamples.account.Account;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.MalformedInputException;
import java.util.Date;

@Component
public class JwtAuthStrategy implements AuthStrategy {

    private final RSAKeyProvider keyProvider;

    public JwtAuthStrategy(RSAKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
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
            var decodedToken = JWT.decode(token);
            return decodedToken.getExpiresAt().after(new Date());
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    @Override
    public String generateAccessToken(Account account, long millisToExpire) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        var issuedAt = new Date();
        var expireAt = new Date(issuedAt.getTime() + millisToExpire);

        return JWT.create()
                .withSubject(account.getUsername())
                .withIssuedAt(issuedAt)
                .withExpiresAt(expireAt)
                .sign(algorithm);
    }

    @Override
    public String generateRefreshToken(Account account, long minutesToExpire) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        var issuedAt = new Date();
        var expireAt = new Date(issuedAt.getTime() + minutesToExpire);

        return JWT.create()
                .withIssuedAt(issuedAt)
                .withExpiresAt(expireAt)
                .sign(algorithm);
    }
}
