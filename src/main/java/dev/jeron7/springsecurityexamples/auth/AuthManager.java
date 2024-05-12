package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.Account;
import dev.jeron7.springsecurityexamples.account.AccountService;
import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.auth.dtos.BasicCredentialsDto;
import dev.jeron7.springsecurityexamples.auth.dtos.LoginDto;
import dev.jeron7.springsecurityexamples.auth.dtos.AccessTokenDto;
import dev.jeron7.springsecurityexamples.token.Token;
import dev.jeron7.springsecurityexamples.token.TokenRepository;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class AuthManager {

    private final long millisToExpireAccessToken;
    private final long millisToExpireRefreshToken;
    private final AuthStrategy authStrategy;
    private final AccountService accountService;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthManager(@Value("${app.security.expire_access_token:3600}") long millisToExpireAccessToken,
                       AuthStrategy authStrategy,
                       AccountService accountService,
                       TokenRepository tokenRepository,
                       PasswordEncoder passwordEncoder) {
        this.millisToExpireAccessToken = millisToExpireAccessToken * 1000;
        this.millisToExpireRefreshToken = this.millisToExpireAccessToken * 2;
        this.authStrategy = Objects.requireNonNull(authStrategy);
        this.accountService = Objects.requireNonNull(accountService);
        this.tokenRepository = Objects.requireNonNull(tokenRepository);
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder);
    }

    public LoginDto login(BasicCredentialsDto credentialsDto) {
        var account = accountService.findByEmail(credentialsDto.email());
        if (Objects.isNull(account))
            throw new UsernameNotFoundException("User not found!");

        if (!passwordEncoder.matches(credentialsDto.password(), account.getPassword()))
            throw new AuthenticationCredentialsNotFoundException("Password is wrong!");

        return createTokens(account);
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
        if (!authStrategy.verify(accessToken)) {
            var token = tokenRepository.findByAccessToken(accessToken);
            disableToken(token);
            throw new BadRequestException("Invalid or expired token!");
        }

        var email = authStrategy.getEmail(accessToken);
        var foundUser = accountService.findByEmail(email);
        return AccountDetailsDto.from(foundUser);
    }

    private LoginDto createTokens(Account account) {
        var accessToken = authStrategy.generateAccessToken(account, millisToExpireAccessToken);
        var refreshToken = authStrategy.generateRefreshToken(account, millisToExpireRefreshToken);

        tokenRepository.save(new Token(accessToken, refreshToken));

        return new LoginDto(accessToken, refreshToken, millisToExpireAccessToken / 1000);
    }

    private void disableToken(Token token) {
        if (token != null) {
            token.setActive(false);
            tokenRepository.save(token);
        }
    }
}
