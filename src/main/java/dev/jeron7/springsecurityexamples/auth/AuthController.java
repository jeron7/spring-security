package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.AccountService;
import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.auth.dtos.BasicCredentialsDto;
import dev.jeron7.springsecurityexamples.auth.dtos.TokenDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.util.Objects;

@RestController
public class AuthController {

    private final AuthStrategy authStrategy;
    private final AccountService accountService;

    public AuthController(AccountService accountService, JwtAuthStrategy authStrategy) throws NoSuchAlgorithmException {
        this.accountService = Objects.requireNonNull(accountService);
        this.authStrategy = authStrategy;
    }

    @PostMapping("/auth/verify")
    public ResponseEntity<?> verify(@RequestBody TokenDto tokenDto) {
        var token = tokenDto.token();
        if (!authStrategy.verify(token))
            return ResponseEntity.status(401).body("Invalid token!");
        var email = authStrategy.getEmail(token);
        var foundUser = accountService.findByEmail(email);
        return ResponseEntity.status(401).body(AccountDetailsDto.from(foundUser));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody BasicCredentialsDto credentials) {
        var account = accountService.findByEmail(credentials.email());
        if (account == null)
            return ResponseEntity.notFound().build();

        var token = authStrategy.generateAccessToken(account);
        return ResponseEntity.ok(new TokenDto(token));
    }

    @PostMapping("/auth/sign-in")
    public ResponseEntity<?> createAccount(@RequestBody CreateAccountDto createAccountDto) {
        return ResponseEntity.ok(this.accountService.register(createAccountDto));
    }
}
