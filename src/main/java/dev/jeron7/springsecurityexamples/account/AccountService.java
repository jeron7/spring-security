package dev.jeron7.springsecurityexamples.account;

import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.UUID;

@Service
public class AccountService {

    private final AccountRepository accountRepository;

    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = Objects.requireNonNull(accountRepository);
    }

    public Account save(Account toCreate) {
        return accountRepository.save(toCreate);
    }

    public Account findByEmail(String email) {
        return accountRepository.findByEmail(email).orElse(null);
    }

    public Account findById(UUID id) {
        return accountRepository.findById(id).orElse(null);
    }

    public Page<AccountDetailsDto> findAll(Pageable pageable) {
        return accountRepository.findAll(pageable).map(AccountDetailsDto::from);
    }
}
