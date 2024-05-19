package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.AccountService;
import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.auth.dtos.AccessTokenDto;
import dev.jeron7.springsecurityexamples.auth.dtos.BasicCredentialsDto;
import dev.jeron7.springsecurityexamples.auth.dtos.LoginDto;
import dev.jeron7.springsecurityexamples.token.TokenRepository;
import dev.jeron7.springsecurityexamples.token.TokenService;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class AuthManager {

    private final AccountService accountService;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public AuthManager(@Value("${app.security.expire_access_token:3600}") long millisToExpireAccessToken,
                       TokenStrategy tokenStrategy,
                       AccountService accountService,
                       TokenRepository tokenRepository,
                       PasswordEncoder passwordEncoder, TokenService tokenService) {
        this.tokenService = Objects.requireNonNull(tokenService);
        this.accountService = Objects.requireNonNull(accountService);
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder);
    }

    public LoginDto login(BasicCredentialsDto credentialsDto) {
        var account = accountService.findByEmail(credentialsDto.email());
        if (Objects.isNull(account))
            throw new UsernameNotFoundException("User not found!");

        if (!passwordEncoder.matches(credentialsDto.password(), account.getPassword()))
            throw new AuthenticationCredentialsNotFoundException("Password is wrong!");

        return tokenService.createTokens(account);
    }

    public AccountDetailsDto register(CreateAccountDto createDto) throws BadRequestException {
        var foundAccount = accountService.findByEmail(createDto.email());
        if (!Objects.isNull(foundAccount))
            throw new BadRequestException("Email already registered!");

        var encodedPass = passwordEncoder.encode(createDto.password());
        var toCreate = new CreateAccountDto(createDto.firstName(), createDto.lastName(), createDto.email(), encodedPass);
        return AccountDetailsDto.from(accountService.create(toCreate));
    }

    public AccountDetailsDto verify(AccessTokenDto accessTokenDto) throws BadRequestException {
        var accessToken = accessTokenDto.accessToken();

        if (!tokenService.isValidAndActiveAccessToken(accessToken))
            throw new BadRequestException("Invalid or expired token!");

        var token = tokenService.findByTokenStr(accessToken);
        return AccountDetailsDto.from(token.getAccount());
    }

    public LoginDto refreshToken(String refreshToken) {
        if (!tokenService.isValidAndActiveRefreshToken(refreshToken)) {
            throw new AuthenticationCredentialsNotFoundException("Invalid refresh token!");
        }

        var account = tokenService.findByTokenStr(refreshToken).getAccount();
        tokenService.disableAccountTokens(account);
        return tokenService.createTokens(account);
    }
}
