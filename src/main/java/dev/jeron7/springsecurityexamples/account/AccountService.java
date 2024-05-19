package dev.jeron7.springsecurityexamples.account;

import dev.jeron7.springsecurityexamples.account.dtos.AccountDetailsDto;
import dev.jeron7.springsecurityexamples.account.dtos.CreateAccountDto;
import dev.jeron7.springsecurityexamples.account.dtos.UpdateAccountDto;
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

    public Account create(CreateAccountDto toCreateDto) {
        var toCreate = new Account(toCreateDto.firstName(),
                toCreateDto.lastName(),
                toCreateDto.email(),
                toCreateDto.password());
        return accountRepository.save(toCreate);
    }

    public Account update(Account toUpdateAccount, UpdateAccountDto updates) {
        toUpdateAccount.setFirstName(!Objects.isNull(updates.firstName()) ? updates.firstName() : toUpdateAccount.getFirstName());
        toUpdateAccount.setLastName(!Objects.isNull(updates.lastName()) ? updates.lastName() : toUpdateAccount.getLastName());
        toUpdateAccount.setRole(!Objects.isNull(updates.role()) ? updates.role() : toUpdateAccount.getRole());
        return accountRepository.save(toUpdateAccount);
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
