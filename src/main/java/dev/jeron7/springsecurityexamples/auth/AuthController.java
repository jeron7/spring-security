package dev.jeron7.springsecurityexamples.auth;

import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.auth.dtos.BasicCredentialsDto;
import dev.jeron7.springsecurityexamples.auth.dtos.TokenDto;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
            var registered = this.authManager.register(createAccountDto);
            return ResponseEntity.ok(registered);
        } catch (BadRequestException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("verify")
    public ResponseEntity<?> verify(@RequestBody TokenDto tokenDto) {
        try {
            AccountDetailsDto foundUser = authManager.verify(tokenDto);
            return ResponseEntity.ok(foundUser);
        } catch (BadRequestException e) {
            return ResponseEntity.status(401).build();
        }
    }

    @PostMapping("logout")
    public ResponseEntity<?> logout() {
        return null;
    }
}
