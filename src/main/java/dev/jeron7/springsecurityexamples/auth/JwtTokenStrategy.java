package dev.jeron7.springsecurityexamples.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.RegisteredClaims;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import dev.jeron7.springsecurityexamples.account.Account;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenStrategy implements TokenStrategy {

    private final RSAKeyProvider keyProvider;

    public JwtTokenStrategy(RSAKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }


    @Override
    public UUID getId(String token) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        if (verify(token)) {
            var decodedJwt = JWT.require(algorithm).build().verify(token);
            return UUID.fromString(decodedJwt.getId());
        }
        return null;
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

    public String generateToken(UUID id, String email, long millisToExpire) {
        Algorithm algorithm = Algorithm.RSA256(keyProvider);

        var issuedAt = new Date();
        var expireAt = new Date(issuedAt.getTime() + millisToExpire);
        var tokenBuilder = JWT.create()
                .withJWTId(id.toString())
                .withIssuedAt(issuedAt)
                .withExpiresAt(expireAt);

        if (email != null)
            tokenBuilder.withSubject(email);

        return tokenBuilder.sign(algorithm);
    }
}
