package dev.jeron7.springsecurityexamples.account;

import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class AccountService {

    private final AccountRepository accountRepository;

    private final PasswordEncoder passwordEncoder;

    public AccountService(AccountRepository accountRepository, PasswordEncoder passwordEncoder) {
        this.accountRepository = Objects.requireNonNull(accountRepository);
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder);
    }

    public AccountDetailsDto register(CreateAccountDto createAccountDto) {
        var toCreate = new Account(
                createAccountDto.firstName(),
                createAccountDto.lastName(),
                createAccountDto.email(),
                passwordEncoder.encode(createAccountDto.password())
        );
        var saved = accountRepository.save(toCreate);
        return AccountDetailsDto.from(saved);
    }

    public Account findByEmail(String email) {
        return accountRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Account not found!"));
    }
}
