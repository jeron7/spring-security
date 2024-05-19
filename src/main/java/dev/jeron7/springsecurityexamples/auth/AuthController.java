package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.auth.dtos.AccessTokenDto;
import dev.jeron7.springsecurityexamples.auth.dtos.BasicCredentialsDto;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.InputMismatchException;
import java.util.Objects;

@RestController
@RequestMapping("auth")
public class AuthController {

    private final AuthManager authManager;

    public AuthController(AuthManager authManager) {
        this.authManager = Objects.requireNonNull(authManager);
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@RequestBody BasicCredentialsDto credentials) {
        try {
            var token = authManager.login(credentials);
            return ResponseEntity.ok(token);
        } catch (AuthenticationCredentialsNotFoundException _) {
            return ResponseEntity.badRequest().build();
        } catch (UsernameNotFoundException _) {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("create")
    public ResponseEntity<?> create(@RequestBody CreateAccountDto createAccountDto) {
        try{
            var registered = authManager.register(createAccountDto);
            return ResponseEntity.ok(registered);
        } catch (BadRequestException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("refresh")
    public ResponseEntity<?> refreshToken(@RequestHeader(name = "Authorization") String authHeader) {
        try {
            if (!authHeader.startsWith("Bearer"))
                throw new InputMismatchException("");
            var refreshToken = authHeader.substring(7);
            return ResponseEntity.ok(authManager.refreshToken(refreshToken));
        } catch (AuthenticationCredentialsNotFoundException _) {
            return ResponseEntity.badRequest().build();
        } catch (UsernameNotFoundException _) {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("verify")
    public ResponseEntity<?> verify(@RequestBody AccessTokenDto accessTokenDto) {
        try {
            AccountDetailsDto foundUser = authManager.verify(accessTokenDto);
            return ResponseEntity.ok(foundUser);
        } catch (BadRequestException e) {
            return ResponseEntity.status(401).build();
        }
    }
}
