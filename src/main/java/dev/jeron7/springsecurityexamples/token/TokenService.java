package dev.jeron7.springsecurityexamples.token;

import dev.jeron7.springsecurityexamples.account.Account;
import dev.jeron7.springsecurityexamples.auth.TokenStrategy;
import dev.jeron7.springsecurityexamples.auth.dtos.LoginDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.UUID;

@Component
public class TokenService {

    private final long millisToExpireAccessToken;
    private final long millisToExpireRefreshToken;
    private final TokenRepository tokenRepository;
    private final TokenStrategy tokenStrategy;


    public TokenService(@Value("${app.security.expire_access_token:3600}") long millisToExpireAccessToken,
                        TokenRepository tokenRepository,
                        TokenStrategy tokenStrategy) {
        this.millisToExpireAccessToken = millisToExpireAccessToken * 1000;
        this.millisToExpireRefreshToken = this.millisToExpireAccessToken * 2;
        this.tokenRepository = Objects.requireNonNull(tokenRepository);
        this.tokenStrategy = Objects.requireNonNull(tokenStrategy);
    }

    public LoginDto createTokens(Account account) {
        UUID tokenId = UUID.randomUUID();
        var accessToken = tokenStrategy.generateToken(tokenId, account.getUsername(), millisToExpireAccessToken);
        var refreshToken = tokenStrategy.generateToken(tokenId, null, millisToExpireRefreshToken);

        tokenRepository.save(new Token(tokenId, accessToken, refreshToken, account));

        return new LoginDto(accessToken, refreshToken, millisToExpireAccessToken / 1000);
    }

    public boolean isValidAndActiveAccessToken(String tokenStr) {
        var foundToken = findByTokenStr(tokenStr);
        if (foundToken != null && foundToken.getAccessToken().equals(tokenStr) && foundToken.isActive()) {
            if (!tokenStrategy.verify(tokenStr)) {
                disableToken(foundToken);
                return false;
            }
            return true;
        }
        return false;
    }

    public boolean isValidAndActiveRefreshToken(String tokenStr) {
        var foundToken = findByTokenStr(tokenStr);
        if (foundToken != null && foundToken.getRefreshToken().equals(tokenStr) && foundToken.isActive()) {
            if (!tokenStrategy.verify(tokenStr)) {
                disableToken(foundToken);
                return false;
            }
            return true;
        }
        return false;
    }

    public Token findByTokenStr(String tokenStr) {
        var id = tokenStrategy.getId(tokenStr);
        return tokenRepository.findById(id).orElse(null);
    }

    public void disableToken(Token token) {
        if (token == null || !token.isActive())
            return;

        token.setActive(false);
        tokenRepository.save(token);
    }

    public void disableAccountTokens(Account account) {
        if (account == null)
            return;

        tokenRepository.findByAccountAndActiveTrue(account).forEach(this::disableToken);
    }
}
