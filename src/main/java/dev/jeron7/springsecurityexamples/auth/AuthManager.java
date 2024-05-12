package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.Account;
import dev.jeron7.springsecurityexamples.account.AccountService;
import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.auth.dtos.BasicCredentialsDto;
import dev.jeron7.springsecurityexamples.auth.dtos.TokenDto;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class AuthManager {

    private final AuthStrategy authStrategy;
    private final AccountService accountService;
    private final PasswordEncoder passwordEncoder;

    public AuthManager(AuthStrategy authStrategy, AccountService accountService, PasswordEncoder passwordEncoder) {
        this.authStrategy = Objects.requireNonNull(authStrategy);
        this.accountService = Objects.requireNonNull(accountService);
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder);
    }

    public TokenDto login(BasicCredentialsDto credentialsDto) {
        var account = accountService.findByEmail(credentialsDto.email());
        if (Objects.isNull(account))
            throw new UsernameNotFoundException("User not found!");

        if (!passwordEncoder.matches(credentialsDto.password(), account.getPassword()))
            throw new AuthenticationCredentialsNotFoundException("Password is wrong!");

        var token = authStrategy.generateAccessToken(account);
        return new TokenDto(token);
    }

    public AccountDetailsDto register(CreateAccountDto createDto) throws BadRequestException {
        var foundAccount = accountService.findByEmail(createDto.email());
        if (!Objects.isNull(foundAccount))
            throw new BadRequestException("Email already registered!");

        var encodedPass = passwordEncoder.encode(createDto.password());
        var toCreate = new CreateAccountDto(createDto.firstName(), createDto.lastName(), createDto.email(), encodedPass);
        return AccountDetailsDto.from(accountService.create(toCreate));
    }

    public AccountDetailsDto verify(TokenDto tokenDto) throws BadRequestException {
        var token = tokenDto.token();
        if (!authStrategy.verify(token))
            throw new BadRequestException("Invalid token!");
        var email = authStrategy.getEmail(token);
        var foundUser = accountService.findByEmail(email);
        return AccountDetailsDto.from(foundUser);
    }
}
